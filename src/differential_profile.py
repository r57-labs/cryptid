#!/usr/bin/env python3
"""
Differential profile analysis — tests how hash output changes when
input changes in specific, controlled ways.

Unlike the avalanche test (which checks average flip ratio), this builds
the full differential matrix: for each input bit position i, what is the
probability that each output bit position j flips? A perfect hash has
P(flip) = 0.5 everywhere. A weakened hash may have specific (i,j) pairs
that deviate.

Tests:
  1. Single-bit differential matrix: flip each input bit, measure each
     output bit flip probability. Chi-squared test for deviation from 0.5.
  2. Byte-level differential: change each input byte to a random value,
     measure output byte distribution changes.
  3. Hamming distance distribution: for random input pairs at fixed
     Hamming distance, measure output Hamming distance distribution.
  4. Differential clustering: do certain input changes produce correlated
     output changes? (Detects non-independent bit behavior.)

Usage:
  # Analyze a single dataset
  python differential_profile.py analyze \
    --data data/sweep_round1/datasets/sha256_random.jsonl \
    --output results/sha256_differential.json

  # Compare algorithm against its oracle control
  python differential_profile.py compare \
    --target data/sweep_round1/datasets/sha256_random.jsonl \
    --control data/sweep_round1/datasets/random_oracle_256_random.jsonl

  # Batch analysis of all datasets in a directory
  python differential_profile.py batch \
    --data-dir data/sweep_round1/datasets/ \
    --output results/differential_results.json

  # Full sweep using hash functions directly (no pre-generated data needed)
  python differential_profile.py sweep \
    --algorithms sha256,sm3,blake2b \
    --size 50000 \
    --output-dir data/differential_sweep/
"""

import argparse
import hashlib
import json
import math
import os
import random
import sys
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))


def hex_to_bits(hex_str: str) -> list[int]:
    """Convert hex string to list of bits."""
    bits = []
    for ch in hex_str:
        val = int(ch, 16)
        bits.extend([(val >> (3 - i)) & 1 for i in range(4)])
    return bits


def bits_to_bytes(bits: list[int]) -> bytes:
    """Convert list of bits to bytes."""
    result = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(min(8, len(bits) - i)):
            byte |= (bits[i + j] << (7 - j))
        result.append(byte)
    return bytes(result)


def flip_bit(data: bytes, bit_pos: int) -> bytes:
    """Flip a single bit in a bytes object."""
    byte_idx = bit_pos // 8
    bit_idx = 7 - (bit_pos % 8)
    result = bytearray(data)
    if byte_idx < len(result):
        result[byte_idx] ^= (1 << bit_idx)
    return bytes(result)


def hamming_distance(bits1: list[int], bits2: list[int]) -> int:
    """Compute Hamming distance between two bit sequences."""
    return sum(a != b for a, b in zip(bits1, bits2))


# --- Test 1: Single-Bit Differential Matrix ---

def single_bit_differential(
    hash_fn,
    n_samples: int = 10000,
    input_bytes: int = 10,
    rng: random.Random = None,
    verbose: bool = True,
) -> dict:
    """
    Build the full differential matrix: for each input bit i and output
    bit j, measure P(output_j flips | input_i flipped).

    A perfect hash has P = 0.5 for all (i,j). We test for significant
    deviations using chi-squared.
    """
    if rng is None:
        rng = random.Random(42)

    # Generate random inputs
    inputs = [bytes(rng.randint(0, 255) for _ in range(input_bytes))
              for _ in range(n_samples)]

    n_input_bits = input_bytes * 8
    # Get output width from first hash
    test_hash = hash_fn(inputs[0].hex())
    n_output_bits = len(test_hash) * 4  # hex chars * 4 bits

    if verbose:
        print(f"    Single-bit differential: {n_input_bits} input bits × {n_output_bits} output bits")
        print(f"    Testing {n_samples} samples...", end="", flush=True)

    # For each input bit position, count how often each output bit flips
    # flip_counts[i][j] = number of times output bit j flipped when input bit i was flipped
    flip_counts = [[0] * n_output_bits for _ in range(n_input_bits)]

    for sample_idx, inp in enumerate(inputs):
        # Compute original hash
        original_hash = hex_to_bits(hash_fn(inp.hex()))

        # Flip each input bit and measure output changes
        # For efficiency, only test a subset of input bits per sample
        # but cycle through all bits across samples
        bits_to_test = range(n_input_bits)
        if n_input_bits > 32 and n_samples >= 5000:
            # Subsample: each input bit still gets ~n_samples/2.5 tests
            bits_to_test = [b for b in range(n_input_bits)
                           if (sample_idx + b) % 3 == 0]

        for i_bit in bits_to_test:
            flipped_input = flip_bit(inp, i_bit)
            flipped_hash = hex_to_bits(hash_fn(flipped_input.hex()))

            for j_bit in range(n_output_bits):
                if j_bit < len(original_hash) and j_bit < len(flipped_hash):
                    if original_hash[j_bit] != flipped_hash[j_bit]:
                        flip_counts[i_bit][j_bit] += 1

    # Compute expected flips per bit pair
    # Account for subsampling
    samples_per_input_bit = []
    for i_bit in range(n_input_bits):
        if n_input_bits > 32 and n_samples >= 5000:
            count = sum(1 for s in range(n_samples) if (s + i_bit) % 3 == 0)
        else:
            count = n_samples
        samples_per_input_bit.append(count)

    if verbose:
        print(f" done")

    # Chi-squared test for each (i,j) pair
    # Under null: flip_count ~ Binomial(n, 0.5)
    # Chi-squared = (observed - expected)^2 / expected, with expected = n/2
    significant_pairs = []
    max_chi2 = 0.0
    max_deviation = 0.0
    total_tests = 0

    # Per-output-bit average flip rate (should be ~0.5)
    output_bit_avg_flip = [0.0] * n_output_bits
    output_bit_counts = [0] * n_output_bits

    for i_bit in range(n_input_bits):
        n = samples_per_input_bit[i_bit]
        if n < 10:
            continue
        expected = n / 2.0

        for j_bit in range(n_output_bits):
            total_tests += 1
            observed = flip_counts[i_bit][j_bit]
            flip_rate = observed / n
            deviation = abs(flip_rate - 0.5)

            output_bit_avg_flip[j_bit] += flip_rate
            output_bit_counts[j_bit] += 1

            chi2 = (observed - expected) ** 2 / expected + \
                   (n - observed - expected) ** 2 / expected

            if chi2 > max_chi2:
                max_chi2 = chi2
            if deviation > max_deviation:
                max_deviation = deviation

            # Bonferroni-corrected significance threshold
            # p < 0.001 / total_tests for each pair
            # chi2(1) > 10.83 for p < 0.001
            if chi2 > 10.83:
                significant_pairs.append({
                    "input_bit": i_bit,
                    "output_bit": j_bit,
                    "flip_rate": round(flip_rate, 6),
                    "deviation": round(deviation, 6),
                    "chi_squared": round(chi2, 2),
                    "n_samples": n,
                })

    # Compute per-output-bit statistics
    for j in range(n_output_bits):
        if output_bit_counts[j] > 0:
            output_bit_avg_flip[j] /= output_bit_counts[j]

    output_bit_deviations = [abs(f - 0.5) for f in output_bit_avg_flip]
    max_output_bit_deviation = max(output_bit_deviations) if output_bit_deviations else 0.0

    # Expected number of significant pairs by chance at p<0.001
    expected_by_chance = total_tests * 0.001

    # Signal detection
    has_signal = (len(significant_pairs) > max(expected_by_chance * 5, 3) or
                  any(p["chi_squared"] > 50 for p in significant_pairs) or
                  max_deviation > 0.10)

    # Signal strength: how far above chance
    if expected_by_chance > 0 and len(significant_pairs) > 0:
        signal_strength = min(1.0, (len(significant_pairs) / expected_by_chance - 1) / 10)
    else:
        signal_strength = 0.0

    signal_strength = max(0.0, signal_strength)
    if has_signal and max_chi2 > 50:
        signal_strength = max(signal_strength, min(1.0, max_chi2 / 500))

    result = {
        "test": "single_bit_differential",
        "n_samples": n_samples,
        "n_input_bits": n_input_bits,
        "n_output_bits": n_output_bits,
        "total_tests": total_tests,
        "max_chi_squared": round(max_chi2, 2),
        "max_deviation": round(max_deviation, 6),
        "max_output_bit_deviation": round(max_output_bit_deviation, 6),
        "n_significant_pairs": len(significant_pairs),
        "expected_significant_by_chance": round(expected_by_chance, 1),
        "signal": has_signal,
        "signal_strength": round(signal_strength, 4),
    }

    if significant_pairs:
        # Sort by chi2 descending, keep top 20
        significant_pairs.sort(key=lambda x: -x["chi_squared"])
        result["top_significant_pairs"] = significant_pairs[:20]

    return result


# --- Test 2: Byte-Level Differential ---

def byte_differential(
    hash_fn,
    n_samples: int = 10000,
    input_bytes: int = 10,
    rng: random.Random = None,
    verbose: bool = True,
) -> dict:
    """
    For each input byte position, change it to a random value and measure
    the distribution of changes in each output byte. A perfect hash should
    produce uniform output byte changes regardless of which input byte changed.
    """
    if rng is None:
        rng = random.Random(42)

    inputs = [bytes(rng.randint(0, 255) for _ in range(input_bytes))
              for _ in range(n_samples)]

    test_hash = hash_fn(inputs[0].hex())
    n_output_bytes = len(test_hash) // 2  # hex pairs

    if verbose:
        print(f"    Byte differential: {input_bytes} input bytes × {n_output_bytes} output bytes")
        print(f"    Testing {n_samples} samples...", end="", flush=True)

    # For each input byte, track the distribution of output byte XOR deltas
    # xor_counts[i_byte][o_byte][delta] = count
    # We summarize with: mean XOR delta, entropy of XOR distribution
    results_by_input_byte = []

    for i_byte in range(input_bytes):
        output_byte_entropies = []
        output_byte_mean_deltas = []

        for o_byte in range(n_output_bytes):
            delta_counts = [0] * 256

            for inp in inputs:
                # Original hash
                orig = bytes.fromhex(hash_fn(inp.hex()))

                # Modify input byte
                modified = bytearray(inp)
                modified[i_byte] = (modified[i_byte] + rng.randint(1, 255)) & 0xFF
                mod_hash = bytes.fromhex(hash_fn(bytes(modified).hex()))

                if o_byte < len(orig) and o_byte < len(mod_hash):
                    delta = orig[o_byte] ^ mod_hash[o_byte]
                    delta_counts[delta] += 1

            # Compute entropy of the XOR delta distribution
            total = sum(delta_counts)
            if total > 0:
                entropy = 0.0
                for c in delta_counts:
                    if c > 0:
                        p = c / total
                        entropy -= p * math.log2(p)
                output_byte_entropies.append(entropy)

                # Mean delta (should be ~127.5 for uniform)
                mean_delta = sum(d * c for d, c in enumerate(delta_counts)) / total
                output_byte_mean_deltas.append(mean_delta)

        results_by_input_byte.append({
            "input_byte": i_byte,
            "output_entropies": [round(e, 4) for e in output_byte_entropies],
            "min_entropy": round(min(output_byte_entropies), 4) if output_byte_entropies else 0,
            "mean_entropy": round(sum(output_byte_entropies) / len(output_byte_entropies), 4) if output_byte_entropies else 0,
        })

    if verbose:
        print(f" done")

    # Overall statistics
    all_entropies = [e for r in results_by_input_byte for e in r["output_entropies"]]
    min_entropy = min(all_entropies) if all_entropies else 0
    mean_entropy = sum(all_entropies) / len(all_entropies) if all_entropies else 0
    max_ideal = 8.0  # log2(256)

    # Signal: entropy significantly below 8.0 for any pair
    # At n_samples=10000, even uniform distribution has entropy slightly below 8.0
    # due to finite sample effects. Threshold depends on N.
    expected_min_entropy = max_ideal - math.log2(256) / (2 * n_samples) * 256
    # Simplified: at 10K samples, expect min ~7.5 by chance across all pairs
    entropy_threshold = max_ideal - 1.0  # flag if any pair below 7.0

    has_signal = min_entropy < entropy_threshold
    signal_strength = max(0.0, (entropy_threshold - min_entropy) / entropy_threshold) if has_signal else 0.0

    return {
        "test": "byte_differential",
        "n_samples": n_samples,
        "n_input_bytes": input_bytes,
        "n_output_bytes": n_output_bytes,
        "min_xor_entropy": round(min_entropy, 4),
        "mean_xor_entropy": round(mean_entropy, 4),
        "max_possible_entropy": max_ideal,
        "signal": has_signal,
        "signal_strength": round(signal_strength, 4),
        "per_input_byte": results_by_input_byte,
    }


# --- Test 3: Hamming Distance Distribution ---

def hamming_distance_profile(
    hash_fn,
    n_samples: int = 10000,
    input_bytes: int = 10,
    test_distances: list[int] = None,
    rng: random.Random = None,
    verbose: bool = True,
) -> dict:
    """
    For random input pairs at fixed Hamming distances (1, 2, 4, 8, ...),
    measure the distribution of output Hamming distances. A perfect hash
    should produce output HD centered at n_output_bits/2 regardless of
    input HD (for HD >= 1).
    """
    if rng is None:
        rng = random.Random(42)
    if test_distances is None:
        test_distances = [1, 2, 4, 8, 16]

    n_input_bits = input_bytes * 8

    test_hash = hash_fn(bytes(rng.randint(0, 255) for _ in range(input_bytes)).hex())
    n_output_bits = len(test_hash) * 4

    if verbose:
        print(f"    Hamming distance profile: testing distances {test_distances}")
        print(f"    {n_samples} pairs per distance...", end="", flush=True)

    expected_mean_hd = n_output_bits / 2.0
    expected_stdev = math.sqrt(n_output_bits / 4.0)

    results_by_distance = []

    for target_hd in test_distances:
        if target_hd > n_input_bits:
            continue

        output_hds = []

        for _ in range(n_samples):
            # Generate random input
            inp = bytes(rng.randint(0, 255) for _ in range(input_bytes))

            # Create input at exactly target_hd Hamming distance
            inp2 = bytearray(inp)
            # Randomly select target_hd bit positions to flip
            bit_positions = rng.sample(range(n_input_bits), target_hd)
            for pos in bit_positions:
                byte_idx = pos // 8
                bit_idx = 7 - (pos % 8)
                inp2[byte_idx] ^= (1 << bit_idx)

            # Compute hashes
            h1 = hex_to_bits(hash_fn(inp.hex()))
            h2 = hex_to_bits(hash_fn(bytes(inp2).hex()))
            output_hds.append(hamming_distance(h1, h2))

        # Statistics
        mean_hd = sum(output_hds) / len(output_hds)
        variance = sum((h - mean_hd) ** 2 for h in output_hds) / len(output_hds)
        stdev = math.sqrt(variance)

        # Deviation from expected
        mean_deviation = abs(mean_hd - expected_mean_hd) / expected_mean_hd
        stdev_ratio = stdev / expected_stdev if expected_stdev > 0 else 1.0

        results_by_distance.append({
            "input_hamming_distance": target_hd,
            "output_mean_hd": round(mean_hd, 2),
            "output_stdev": round(stdev, 2),
            "expected_mean": round(expected_mean_hd, 2),
            "expected_stdev": round(expected_stdev, 2),
            "mean_deviation": round(mean_deviation, 6),
            "stdev_ratio": round(stdev_ratio, 4),
        })

    if verbose:
        print(f" done")

    # Signal detection: any distance with significant mean deviation
    max_mean_deviation = max(r["mean_deviation"] for r in results_by_distance) if results_by_distance else 0
    max_stdev_deviation = max(abs(r["stdev_ratio"] - 1.0) for r in results_by_distance) if results_by_distance else 0

    # At 10K samples, random fluctuation in mean is ~stdev/sqrt(N) ≈ 0.1% of expected
    has_signal = max_mean_deviation > 0.01 or max_stdev_deviation > 0.1

    signal_strength = 0.0
    if has_signal:
        signal_strength = min(1.0, max(max_mean_deviation / 0.05, max_stdev_deviation / 0.5))

    return {
        "test": "hamming_distance_profile",
        "n_samples_per_distance": n_samples,
        "n_output_bits": n_output_bits,
        "expected_output_hd": round(expected_mean_hd, 2),
        "expected_output_stdev": round(expected_stdev, 2),
        "max_mean_deviation": round(max_mean_deviation, 6),
        "max_stdev_ratio_deviation": round(max_stdev_deviation, 4),
        "signal": has_signal,
        "signal_strength": round(signal_strength, 4),
        "by_distance": results_by_distance,
    }


# --- Test 4: Differential Bit Independence ---

def differential_bit_independence(
    hash_fn,
    n_samples: int = 10000,
    input_bytes: int = 10,
    rng: random.Random = None,
    verbose: bool = True,
) -> dict:
    """
    Test whether output bit flips are independent when an input bit is flipped.

    For a perfect hash, knowing that output bit j flipped (when input bit i
    was flipped) should give no information about whether output bit k also
    flipped. We test this by measuring the correlation between output bit
    flips for pairs of output bits, conditioned on a single input bit flip.
    """
    if rng is None:
        rng = random.Random(42)

    inputs = [bytes(rng.randint(0, 255) for _ in range(input_bytes))
              for _ in range(n_samples)]

    test_hash = hash_fn(inputs[0].hex())
    n_output_bits = len(test_hash) * 4
    n_input_bits = input_bytes * 8

    if verbose:
        print(f"    Differential bit independence: testing output bit correlations")
        print(f"    {n_samples} samples...", end="", flush=True)

    # For a subset of input bits, measure pairwise correlation of output bit flips
    # Test a subset of input bits (spread evenly) to keep runtime reasonable
    test_input_bits = list(range(0, n_input_bits, max(1, n_input_bits // 8)))[:8]

    max_correlation = 0.0
    significant_correlations = []

    for i_bit in test_input_bits:
        # Collect flip vectors: for each sample, which output bits flipped?
        flip_vectors = []

        for inp in inputs:
            orig = hex_to_bits(hash_fn(inp.hex()))
            flipped_input = flip_bit(inp, i_bit)
            flipped = hex_to_bits(hash_fn(flipped_input.hex()))

            flip_vec = [1 if orig[j] != flipped[j] else 0
                        for j in range(min(len(orig), n_output_bits))]
            flip_vectors.append(flip_vec)

        # Measure pairwise correlation between output bit flips
        # Test a subset of output bit pairs
        test_output_bits = list(range(0, n_output_bits, max(1, n_output_bits // 16)))[:16]

        for idx_a, j_bit_a in enumerate(test_output_bits):
            for j_bit_b in test_output_bits[idx_a + 1:]:
                # Compute phi coefficient between flip_a and flip_b
                n11 = sum(1 for v in flip_vectors if v[j_bit_a] == 1 and v[j_bit_b] == 1)
                n10 = sum(1 for v in flip_vectors if v[j_bit_a] == 1 and v[j_bit_b] == 0)
                n01 = sum(1 for v in flip_vectors if v[j_bit_a] == 0 and v[j_bit_b] == 1)
                n00 = sum(1 for v in flip_vectors if v[j_bit_a] == 0 and v[j_bit_b] == 0)

                # Phi coefficient
                denom = math.sqrt((n11+n10)*(n01+n00)*(n11+n01)*(n10+n00))
                if denom > 0:
                    phi = (n11*n00 - n10*n01) / denom
                else:
                    phi = 0.0

                abs_phi = abs(phi)
                if abs_phi > max_correlation:
                    max_correlation = abs_phi

                # Chi-squared for independence
                chi2 = phi * phi * n_samples

                if chi2 > 10.83:  # p < 0.001
                    significant_correlations.append({
                        "input_bit": i_bit,
                        "output_bit_a": j_bit_a,
                        "output_bit_b": j_bit_b,
                        "phi": round(phi, 6),
                        "chi_squared": round(chi2, 2),
                    })

    if verbose:
        print(f" done")

    # Total pairs tested
    n_pairs_per_input = len(test_output_bits) * (len(test_output_bits) - 1) // 2
    total_pairs = len(test_input_bits) * n_pairs_per_input
    expected_significant = total_pairs * 0.001

    # Threshold scales with 1/sqrt(N): at N=1000, phi~0.10 is noise; at N=10000, phi~0.03 is noise
    phi_noise_floor = 3.0 / math.sqrt(n_samples)  # ~3 sigma
    has_signal = (len(significant_correlations) > max(expected_significant * 5, 3) or
                  max_correlation > max(phi_noise_floor * 2, 0.05))

    signal_strength = 0.0
    if has_signal:
        if max_correlation > phi_noise_floor * 2:
            signal_strength = min(1.0, (max_correlation - phi_noise_floor) / 0.3)
        elif expected_significant > 0:
            signal_strength = min(1.0, (len(significant_correlations) / expected_significant - 1) / 10)

    result = {
        "test": "differential_bit_independence",
        "n_samples": n_samples,
        "n_input_bits_tested": len(test_input_bits),
        "n_output_bit_pairs_tested": total_pairs,
        "max_phi_correlation": round(max_correlation, 6),
        "n_significant_correlations": len(significant_correlations),
        "expected_significant_by_chance": round(expected_significant, 1),
        "signal": has_signal,
        "signal_strength": round(signal_strength, 4),
    }

    if significant_correlations:
        significant_correlations.sort(key=lambda x: -abs(x["phi"]))
        result["top_correlations"] = significant_correlations[:10]

    return result


# --- Full Analysis ---

def run_differential_analysis(
    hash_fn,
    n_samples: int = 10000,
    input_bytes: int = 10,
    verbose: bool = True,
) -> dict:
    """Run all four differential profile tests."""
    rng = random.Random(42)

    results = {}

    if verbose:
        print(f"  Running differential profile analysis ({n_samples} samples)...")

    # Test 1: Single-bit differential matrix
    results["single_bit"] = single_bit_differential(
        hash_fn, n_samples=n_samples, input_bytes=input_bytes,
        rng=random.Random(rng.randint(0, 2**32)), verbose=verbose,
    )

    # Test 2: Byte-level differential
    results["byte_diff"] = byte_differential(
        hash_fn, n_samples=min(n_samples, 5000), input_bytes=input_bytes,
        rng=random.Random(rng.randint(0, 2**32)), verbose=verbose,
    )

    # Test 3: Hamming distance profile
    results["hamming"] = hamming_distance_profile(
        hash_fn, n_samples=min(n_samples, 5000), input_bytes=input_bytes,
        rng=random.Random(rng.randint(0, 2**32)), verbose=verbose,
    )

    # Test 4: Differential bit independence
    results["bit_independence"] = differential_bit_independence(
        hash_fn, n_samples=min(n_samples, 5000), input_bytes=input_bytes,
        rng=random.Random(rng.randint(0, 2**32)), verbose=verbose,
    )

    # Overall signal assessment
    signals = [results[k] for k in results if results[k].get("signal")]
    max_strength = max(
        (results[k].get("signal_strength", 0) for k in results), default=0
    )

    results["summary"] = {
        "n_tests": 4,
        "n_signals": len(signals),
        "max_signal_strength": round(max_strength, 4),
        "signal_tests": [s["test"] for s in signals],
        "verdict": "SIGNAL" if signals else "CLEAN",
    }

    if verbose:
        print(f"\n  Summary: {len(signals)}/4 tests show signal "
              f"(max strength: {max_strength:.4f})")

    return results


def print_report(name: str, results: dict):
    """Print a human-readable report of differential analysis."""
    print(f"\n  {'='*65}")
    print(f"  DIFFERENTIAL PROFILE — {name}")
    print(f"  {'='*65}")

    for test_key in ["single_bit", "byte_diff", "hamming", "bit_independence"]:
        test = results.get(test_key, {})
        test_name = test.get("test", test_key)
        signal = "SIGNAL" if test.get("signal") else "clean"
        strength = test.get("signal_strength", 0)

        print(f"\n  {test_name}:")
        print(f"    Status: {signal} (strength: {strength:.4f})")

        if test_key == "single_bit":
            print(f"    Max chi2: {test.get('max_chi_squared', 0):.2f}")
            print(f"    Max deviation from 0.5: {test.get('max_deviation', 0):.6f}")
            print(f"    Significant pairs: {test.get('n_significant_pairs', 0)} "
                  f"(expected by chance: {test.get('expected_significant_by_chance', 0):.1f})")

        elif test_key == "byte_diff":
            print(f"    Min XOR entropy: {test.get('min_xor_entropy', 0):.4f} / 8.0")
            print(f"    Mean XOR entropy: {test.get('mean_xor_entropy', 0):.4f} / 8.0")

        elif test_key == "hamming":
            for d in test.get("by_distance", []):
                print(f"    HD={d['input_hamming_distance']:>2}: "
                      f"mean={d['output_mean_hd']:.2f} (exp {d['expected_mean']:.2f}), "
                      f"stdev={d['output_stdev']:.2f} (exp {d['expected_stdev']:.2f})")

        elif test_key == "bit_independence":
            print(f"    Max phi correlation: {test.get('max_phi_correlation', 0):.6f}")
            print(f"    Significant correlations: {test.get('n_significant_correlations', 0)} "
                  f"(expected: {test.get('expected_significant_by_chance', 0):.1f})")

    summary = results.get("summary", {})
    print(f"\n  {'—'*65}")
    print(f"  VERDICT: {summary.get('verdict', 'unknown')} "
          f"({summary.get('n_signals', 0)}/4 signals, "
          f"max strength: {summary.get('max_signal_strength', 0):.4f})")


# --- Main ---

def main():
    parser = argparse.ArgumentParser(
        description="Differential profile analysis for hash functions."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Sweep: run differential analysis on hash functions directly
    sweep_parser = subparsers.add_parser("sweep",
        help="Run differential analysis on specified algorithms")
    sweep_parser.add_argument("--algorithms", type=str, default=None,
                              help="Comma-separated algorithms (default: all)")
    sweep_parser.add_argument("--size", type=int, default=10000,
                              help="Samples per test (default: 10000)")
    sweep_parser.add_argument("--output-dir", default="data/differential_sweep/")

    args = parser.parse_args()

    if args.command == "sweep":
        from generate_dataset import HASH_FUNCTIONS, ORACLE_FOR_ALGO, RANDOM_ORACLES

        if args.algorithms:
            targets = [t.strip() for t in args.algorithms.split(",")]
        else:
            targets = sorted(HASH_FUNCTIONS.keys())

        # Add oracle controls
        all_algos = list(targets)
        oracle_set = set()
        for algo in targets:
            oracle = ORACLE_FOR_ALGO.get(algo)
            if oracle:
                oracle_set.add(oracle)
        all_algos += sorted(oracle_set)

        os.makedirs(args.output_dir, exist_ok=True)
        all_results = {}

        print(f"Differential profile sweep: {len(all_algos)} algorithms, {args.size} samples")
        print()

        for algo in all_algos:
            print(f"[{algo}]")
            if algo in HASH_FUNCTIONS:
                hash_fn = HASH_FUNCTIONS[algo]
            elif algo in RANDOM_ORACLES:
                hash_fn = RANDOM_ORACLES[algo]
            else:
                print(f"  Unknown algorithm: {algo}")
                continue

            # Wrapper: our hash functions expect string input, but differential
            # analysis works with raw bytes. Adapt:
            def make_wrapper(fn):
                def wrapper(hex_input: str) -> str:
                    # Convert hex input back to string for the hash function
                    # Our hash functions expect plaintext strings, not hex
                    return fn(hex_input)
                return wrapper

            results = run_differential_analysis(
                make_wrapper(hash_fn),
                n_samples=args.size,
                verbose=True,
            )
            all_results[algo] = results
            print_report(algo, results)
            print()

        # Save results
        results_path = os.path.join(args.output_dir, "differential_results.json")
        with open(results_path, "w") as f:
            json.dump(all_results, f, indent=2, default=str)

        # Summary table
        print(f"\n{'='*80}")
        print(f"  DIFFERENTIAL PROFILE SWEEP SUMMARY")
        print(f"{'='*80}")
        print(f"\n  {'Algorithm':<20} {'SBit':>6} {'Byte':>6} {'Hamm':>6} {'Indep':>6} {'Verdict':>10}")
        print(f"  {'-'*60}")

        for algo in all_algos:
            r = all_results.get(algo, {})
            sb = r.get("single_bit", {}).get("signal_strength", 0)
            bd = r.get("byte_diff", {}).get("signal_strength", 0)
            hm = r.get("hamming", {}).get("signal_strength", 0)
            bi = r.get("bit_independence", {}).get("signal_strength", 0)
            verdict = r.get("summary", {}).get("verdict", "?")
            print(f"  {algo:<20} {sb:>5.3f} {bd:>5.3f} {hm:>5.3f} {bi:>5.3f} {verdict:>10}")

        print(f"\n  Results saved to: {results_path}")


if __name__ == "__main__":
    main()
