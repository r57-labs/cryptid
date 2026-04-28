#!/usr/bin/env python3
"""
Extended analysis module — additional detection methods beyond the core
statistical suite and differential profile.

Tests:
  1. Near-collision frequency: do partial collisions (first k bits matching)
     occur more often than expected for pairs of similar inputs?
  2. Output sequence correlation: are consecutive hashes of sequential inputs
     truly independent? Catches PRNG-style short-cycle weaknesses.
  3. Fixed-point and cycle detection: does H(H(...H(x)...)) cycle back?
     Are there inputs where H(x) has a predictable relationship to x?

Usage:
  python extended_analysis.py sweep \
    --algorithms sha256,crc32,djb2 \
    --size 50000 \
    --output-dir data/extended_sweep/

  python extended_analysis.py sweep \
    --size 100000 \
    --output-dir data/extended_final/
"""

import argparse
import hashlib
import json
import math
import os
import random
import sys
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))


def hex_to_bits(hex_str: str) -> list[int]:
    """Convert hex string to list of bits."""
    bits = []
    for ch in hex_str:
        val = int(ch, 16)
        bits.extend([(val >> (3 - i)) & 1 for i in range(4)])
    return bits


# --- Test 1: Near-Collision Frequency Analysis ---

def near_collision_analysis(
    hash_fn,
    n_samples: int = 10000,
    input_bytes: int = 10,
    prefix_lengths: list[int] = None,
    rng: random.Random = None,
    verbose: bool = True,
) -> dict:
    """
    Test whether partial collisions occur more often than expected.

    For pairs of inputs differing by 1 bit, measure how often the first
    k bits of their outputs match. For a perfect hash, P(k-bit prefix match)
    = 2^(-k). Elevated rates suggest incomplete diffusion.

    We also test random (unrelated) input pairs as a control.
    """
    if rng is None:
        rng = random.Random(42)

    test_hash = hash_fn(bytes(rng.randint(0, 255) for _ in range(input_bytes)).hex())
    n_output_bits = len(test_hash) * 4

    if prefix_lengths is None:
        # Test prefix lengths up to half the output width
        max_prefix = min(n_output_bits // 2, 32)
        prefix_lengths = [k for k in [4, 8, 12, 16, 20, 24, 28, 32] if k <= max_prefix]

    if verbose:
        print(f"    Near-collision: testing prefix lengths {prefix_lengths}")
        print(f"    {n_samples} pairs (1-bit diff + random control)...", end="", flush=True)

    n_input_bits = input_bytes * 8

    # Count prefix matches for 1-bit-different pairs and random pairs
    similar_prefix_matches = {k: 0 for k in prefix_lengths}
    random_prefix_matches = {k: 0 for k in prefix_lengths}

    for _ in range(n_samples):
        # Generate a random input
        inp1 = bytes(rng.randint(0, 255) for _ in range(input_bytes))
        h1_bits = hex_to_bits(hash_fn(inp1.hex()))

        # Create 1-bit-different input
        flip_pos = rng.randint(0, n_input_bits - 1)
        inp2 = bytearray(inp1)
        byte_idx = flip_pos // 8
        bit_idx = 7 - (flip_pos % 8)
        inp2[byte_idx] ^= (1 << bit_idx)
        h2_bits = hex_to_bits(hash_fn(bytes(inp2).hex()))

        # Create random (unrelated) input
        inp3 = bytes(rng.randint(0, 255) for _ in range(input_bytes))
        h3_bits = hex_to_bits(hash_fn(inp3.hex()))

        # Check prefix matches
        for k in prefix_lengths:
            if h1_bits[:k] == h2_bits[:k]:
                similar_prefix_matches[k] += 1
            if h1_bits[:k] == h3_bits[:k]:
                random_prefix_matches[k] += 1

    if verbose:
        print(f" done")

    # Compute expected rates and deviations
    results_by_prefix = []
    max_deviation_ratio = 0.0
    has_signal = False

    for k in prefix_lengths:
        expected_rate = 2 ** (-k)
        expected_count = n_samples * expected_rate

        sim_rate = similar_prefix_matches[k] / n_samples
        rand_rate = random_prefix_matches[k] / n_samples

        # How many times more frequent than expected?
        sim_ratio = sim_rate / expected_rate if expected_rate > 0 else 0
        rand_ratio = rand_rate / expected_rate if expected_rate > 0 else 0

        # Deviation: ratio of similar-pair rate to random-pair rate
        # If similar pairs have MORE partial collisions than random pairs,
        # that means input similarity leaks into output similarity
        if rand_rate > 0:
            sim_vs_rand = sim_rate / rand_rate
        elif sim_rate > 0:
            sim_vs_rand = float('inf')
        else:
            sim_vs_rand = 1.0

        deviation = abs(sim_vs_rand - 1.0)
        if deviation > max_deviation_ratio:
            max_deviation_ratio = deviation

        # Statistical significance: use binomial test approximation
        # For similar pairs, is the rate significantly above expected?
        if expected_count > 0:
            z_score_sim = (similar_prefix_matches[k] - expected_count) / max(math.sqrt(expected_count), 1)
        else:
            z_score_sim = 0

        # Flag if similar-pair rate is significantly elevated vs both
        # expected AND random-pair rate
        if z_score_sim > 5 and sim_vs_rand > 1.5:
            has_signal = True

        results_by_prefix.append({
            "prefix_bits": k,
            "expected_rate": round(expected_rate, 8),
            "similar_pair_matches": similar_prefix_matches[k],
            "similar_pair_rate": round(sim_rate, 8),
            "random_pair_matches": random_prefix_matches[k],
            "random_pair_rate": round(rand_rate, 8),
            "similar_vs_expected_ratio": round(sim_ratio, 4),
            "similar_vs_random_ratio": round(sim_vs_rand, 4) if sim_vs_rand != float('inf') else 999.0,
            "z_score": round(z_score_sim, 2),
        })

    signal_strength = 0.0
    if has_signal:
        signal_strength = min(1.0, max_deviation_ratio / 5.0)

    return {
        "test": "near_collision",
        "n_samples": n_samples,
        "n_output_bits": n_output_bits,
        "max_similar_vs_random_deviation": round(max_deviation_ratio, 4),
        "signal": has_signal,
        "signal_strength": round(signal_strength, 4),
        "by_prefix": results_by_prefix,
    }


# --- Test 2: Output Sequence Correlation ---

def sequence_correlation_analysis(
    hash_fn,
    n_samples: int = 10000,
    input_bytes: int = 10,
    rng: random.Random = None,
    verbose: bool = True,
) -> dict:
    """
    Hash sequential inputs (counter mode) and test whether consecutive
    outputs are independent.

    Tests:
      - Autocorrelation: correlation between hash(i) and hash(i+1) at
        each bit position
      - Run length: distribution of consecutive 0s or 1s at each output
        bit position across the sequence
      - Inter-output Hamming distance: is HD between consecutive outputs
        consistently ~n/2?
    """
    if rng is None:
        rng = random.Random(42)

    # Generate a random base input, then increment a counter portion
    base = bytes(rng.randint(0, 255) for _ in range(input_bytes))

    # Hash sequential inputs: base + counter
    hashes = []
    for i in range(n_samples):
        # Construct input: base bytes + 4-byte counter
        counter_bytes = i.to_bytes(4, 'big')
        inp = base + counter_bytes
        h = hash_fn(inp.hex())
        hashes.append(hex_to_bits(h))

    n_output_bits = len(hashes[0])

    if verbose:
        print(f"    Sequence correlation: {n_samples} sequential hashes, {n_output_bits}-bit output")

    # Test 2a: Bit-level autocorrelation
    # For each output bit position, compute correlation between h[i] and h[i+1]
    max_autocorr = 0.0
    autocorr_significant = 0
    n_autocorr_tests = 0

    # Test a subset of bit positions for efficiency
    test_bits = list(range(0, n_output_bits, max(1, n_output_bits // 32)))[:32]

    for bit_pos in test_bits:
        n_autocorr_tests += 1
        seq = [hashes[i][bit_pos] for i in range(n_samples)]

        # Pearson correlation between seq[:-1] and seq[1:]
        n = len(seq) - 1
        mean = sum(seq) / len(seq)
        var = sum((x - mean) ** 2 for x in seq) / len(seq)

        if var < 1e-10:
            continue

        cov = sum((seq[i] - mean) * (seq[i+1] - mean) for i in range(n)) / n
        autocorr = cov / var if var > 0 else 0

        abs_ac = abs(autocorr)
        if abs_ac > max_autocorr:
            max_autocorr = abs_ac

        # Significance: under null, autocorr ~ N(0, 1/sqrt(n))
        z = abs_ac * math.sqrt(n)
        if z > 3.29:  # p < 0.001
            autocorr_significant += 1

    # Test 2b: Inter-output Hamming distance
    hd_values = []
    for i in range(min(n_samples - 1, 10000)):
        hd = sum(a != b for a, b in zip(hashes[i], hashes[i+1]))
        hd_values.append(hd)

    expected_hd = n_output_bits / 2.0
    expected_hd_stdev = math.sqrt(n_output_bits / 4.0)
    mean_hd = sum(hd_values) / len(hd_values)
    hd_stdev = math.sqrt(sum((h - mean_hd)**2 for h in hd_values) / len(hd_values))
    hd_mean_deviation = abs(mean_hd - expected_hd) / expected_hd

    # Test 2c: Run length distribution
    # For each tested bit, count runs of consecutive same values
    max_run_deviation = 0.0
    for bit_pos in test_bits[:8]:  # Test fewer bits, runs are expensive
        seq = [hashes[i][bit_pos] for i in range(n_samples)]

        # Count run lengths
        runs = []
        current_run = 1
        for i in range(1, len(seq)):
            if seq[i] == seq[i-1]:
                current_run += 1
            else:
                runs.append(current_run)
                current_run = 1
        runs.append(current_run)

        # Expected mean run length for random bits: 2.0
        # Expected distribution: P(run length = k) = 2^(-k)
        if runs:
            mean_run = sum(runs) / len(runs)
            run_deviation = abs(mean_run - 2.0) / 2.0
            if run_deviation > max_run_deviation:
                max_run_deviation = run_deviation

    if verbose:
        print(f"      Autocorrelation: max={max_autocorr:.6f}, significant={autocorr_significant}/{n_autocorr_tests}")
        print(f"      Sequential HD: mean={mean_hd:.2f} (exp {expected_hd:.2f}), stdev={hd_stdev:.2f}")
        print(f"      Run length deviation: {max_run_deviation:.6f}")

    # Signal detection
    autocorr_noise_floor = 3.0 / math.sqrt(n_samples)
    has_autocorr_signal = (max_autocorr > autocorr_noise_floor * 2 or
                           autocorr_significant > max(n_autocorr_tests * 0.01, 2))
    has_hd_signal = hd_mean_deviation > 0.01 or abs(hd_stdev / expected_hd_stdev - 1.0) > 0.1
    has_run_signal = max_run_deviation > 0.1

    has_signal = has_autocorr_signal or has_hd_signal or has_run_signal

    signal_strength = 0.0
    if has_signal:
        components = []
        if has_autocorr_signal:
            components.append(min(1.0, max_autocorr / 0.1))
        if has_hd_signal:
            components.append(min(1.0, hd_mean_deviation / 0.05))
        if has_run_signal:
            components.append(min(1.0, max_run_deviation / 0.3))
        signal_strength = max(components) if components else 0.0

    return {
        "test": "sequence_correlation",
        "n_samples": n_samples,
        "n_output_bits": n_output_bits,
        "autocorrelation": {
            "max_autocorrelation": round(max_autocorr, 6),
            "n_significant": autocorr_significant,
            "n_tests": n_autocorr_tests,
            "noise_floor": round(autocorr_noise_floor, 6),
        },
        "sequential_hamming_distance": {
            "mean": round(mean_hd, 2),
            "stdev": round(hd_stdev, 2),
            "expected_mean": round(expected_hd, 2),
            "expected_stdev": round(expected_hd_stdev, 2),
            "mean_deviation": round(hd_mean_deviation, 6),
        },
        "run_length": {
            "max_deviation": round(max_run_deviation, 6),
        },
        "signal": has_signal,
        "signal_strength": round(signal_strength, 4),
    }


# --- Test 3: Fixed-Point and Cycle Detection ---

def cycle_detection(
    hash_fn,
    n_starts: int = 1000,
    max_chain: int = 10000,
    input_bytes: int = 10,
    rng: random.Random = None,
    verbose: bool = True,
) -> dict:
    """
    Test for short cycles and fixed points in iterated hashing.

    For each starting point, compute H(H(H(...H(x)...))) and check:
    - Fixed points: H(x) = x (interpreting output as next input)
    - Short cycles: sequence returns to a previous value within max_chain steps
    - Convergence: do different starting points tend to reach common values?

    Uses Floyd's cycle detection algorithm for efficiency.
    """
    if rng is None:
        rng = random.Random(42)

    test_hash = hash_fn(bytes(rng.randint(0, 255) for _ in range(input_bytes)).hex())
    output_hex_len = len(test_hash)

    if verbose:
        print(f"    Cycle detection: {n_starts} starting points, max chain {max_chain}")
        print(f"    Output width: {output_hex_len} hex chars...", end="", flush=True)

    fixed_points = 0
    short_cycles = []  # cycles shorter than max_chain
    chain_endpoints = Counter()  # where do chains end up?

    def iterate(hex_val):
        """Hash the hex string, treating it as the next input."""
        # Pad or truncate to input_bytes for consistency
        padded = (hex_val * ((input_bytes * 2 // len(hex_val)) + 1))[:input_bytes * 2]
        return hash_fn(padded)[:output_hex_len]

    for start_idx in range(n_starts):
        # Random starting point
        start = bytes(rng.randint(0, 255) for _ in range(output_hex_len // 2)).hex()

        # Check fixed point
        h1 = iterate(start)
        if h1 == start[:output_hex_len]:
            fixed_points += 1

        # Floyd's cycle detection (tortoise and hare)
        tortoise = iterate(start)
        hare = iterate(iterate(start))

        steps = 1
        found_cycle = False
        while tortoise != hare and steps < max_chain:
            tortoise = iterate(tortoise)
            hare = iterate(iterate(hare))
            steps += 1

        if tortoise == hare and steps < max_chain:
            # Found a cycle — measure its length
            cycle_len = 1
            hare = iterate(tortoise)
            while tortoise != hare:
                hare = iterate(hare)
                cycle_len += 1

            short_cycles.append({
                "start_index": start_idx,
                "entry_steps": steps,
                "cycle_length": cycle_len,
            })
            found_cycle = True

        # Record endpoint for convergence analysis
        endpoint = tortoise[:8]  # first 8 hex chars as bucket
        chain_endpoints[endpoint] += 1

    if verbose:
        print(f" done")

    # Convergence: if chains converge, some endpoints appear much more often
    # than expected. Expected: roughly uniform across 16^8 possibilities.
    # But with only n_starts samples, most endpoints appear once.
    max_endpoint_count = chain_endpoints.most_common(1)[0][1] if chain_endpoints else 0
    n_unique_endpoints = len(chain_endpoints)
    convergence_ratio = max_endpoint_count / max(n_starts, 1)

    # For a perfect hash, virtually no short cycles should be found
    # Expected: probability of cycle within k steps ≈ k^2 / 2^n for n-bit hash
    # For 32-bit hash and k=10000: ~10^8 / 4*10^9 ≈ 2.5% per start
    # For 64-bit hash: essentially zero
    # For 128+ bit hash: completely zero
    output_bits = output_hex_len * 4
    if output_bits <= 32:
        expected_cycle_fraction = min(1.0, (max_chain ** 2) / (2 ** output_bits))
    else:
        expected_cycle_fraction = 0.0

    expected_cycles = n_starts * expected_cycle_fraction
    actual_cycles = len(short_cycles)

    has_signal = False
    signal_strength = 0.0

    if fixed_points > 0:
        has_signal = True
        signal_strength = min(1.0, fixed_points / 3.0)

    if actual_cycles > max(expected_cycles * 3, 5):
        has_signal = True
        if expected_cycles > 0:
            signal_strength = max(signal_strength,
                                  min(1.0, (actual_cycles / expected_cycles - 1) / 10))
        else:
            signal_strength = max(signal_strength, min(1.0, actual_cycles / 10))

    if convergence_ratio > 0.05:  # >5% of chains hit same endpoint
        has_signal = True
        signal_strength = max(signal_strength, min(1.0, convergence_ratio / 0.2))

    if verbose:
        print(f"      Fixed points: {fixed_points}")
        print(f"      Short cycles: {actual_cycles} (expected ~{expected_cycles:.1f} for {output_bits}-bit)")
        print(f"      Convergence: max endpoint count {max_endpoint_count}/{n_starts}, "
              f"{n_unique_endpoints} unique endpoints")

    result = {
        "test": "cycle_detection",
        "n_starts": n_starts,
        "max_chain_length": max_chain,
        "output_bits": output_bits,
        "fixed_points": fixed_points,
        "short_cycles_found": actual_cycles,
        "expected_short_cycles": round(expected_cycles, 1),
        "convergence_ratio": round(convergence_ratio, 4),
        "n_unique_endpoints": n_unique_endpoints,
        "signal": has_signal,
        "signal_strength": round(signal_strength, 4),
    }

    if short_cycles:
        # Report shortest cycles
        short_cycles.sort(key=lambda x: x["cycle_length"])
        result["shortest_cycles"] = short_cycles[:5]

    return result


# --- Full Extended Analysis ---

def run_extended_analysis(
    hash_fn,
    n_samples: int = 10000,
    input_bytes: int = 10,
    verbose: bool = True,
) -> dict:
    """Run all three extended analysis tests."""
    rng = random.Random(42)
    results = {}

    if verbose:
        print(f"  Running extended analysis ({n_samples} samples)...")

    # Test 1: Near-collision
    results["near_collision"] = near_collision_analysis(
        hash_fn, n_samples=n_samples, input_bytes=input_bytes,
        rng=random.Random(rng.randint(0, 2**32)), verbose=verbose,
    )

    # Test 2: Sequence correlation
    results["sequence"] = sequence_correlation_analysis(
        hash_fn, n_samples=n_samples, input_bytes=input_bytes,
        rng=random.Random(rng.randint(0, 2**32)), verbose=verbose,
    )

    # Test 3: Cycle detection (fewer iterations, it's expensive)
    n_cycle_starts = min(500, n_samples // 10)
    max_chain = min(5000, n_samples)
    results["cycles"] = cycle_detection(
        hash_fn, n_starts=n_cycle_starts, max_chain=max_chain,
        input_bytes=input_bytes,
        rng=random.Random(rng.randint(0, 2**32)), verbose=verbose,
    )

    # Summary
    signals = [k for k in results if results[k].get("signal")]
    max_strength = max((results[k].get("signal_strength", 0) for k in results), default=0)

    results["summary"] = {
        "n_tests": 3,
        "n_signals": len(signals),
        "max_signal_strength": round(max_strength, 4),
        "signal_tests": signals,
        "verdict": "SIGNAL" if signals else "CLEAN",
    }

    if verbose:
        print(f"\n  Summary: {len(signals)}/3 tests show signal "
              f"(max strength: {max_strength:.4f})")

    return results


def print_report(name: str, results: dict):
    """Print human-readable report."""
    print(f"\n  {'='*65}")
    print(f"  EXTENDED ANALYSIS — {name}")
    print(f"  {'='*65}")

    nc = results.get("near_collision", {})
    signal = "SIGNAL" if nc.get("signal") else "clean"
    print(f"\n  near_collision:")
    print(f"    Status: {signal} (strength: {nc.get('signal_strength', 0):.4f})")
    for p in nc.get("by_prefix", [])[:4]:
        print(f"    k={p['prefix_bits']:>2}: similar={p['similar_pair_rate']:.6f} "
              f"random={p['random_pair_rate']:.6f} "
              f"ratio={p['similar_vs_random_ratio']:.2f} "
              f"z={p['z_score']:.1f}")

    seq = results.get("sequence", {})
    signal = "SIGNAL" if seq.get("signal") else "clean"
    print(f"\n  sequence_correlation:")
    print(f"    Status: {signal} (strength: {seq.get('signal_strength', 0):.4f})")
    ac = seq.get("autocorrelation", {})
    print(f"    Max autocorrelation: {ac.get('max_autocorrelation', 0):.6f} "
          f"(noise floor: {ac.get('noise_floor', 0):.6f})")
    hd = seq.get("sequential_hamming_distance", {})
    print(f"    Sequential HD: mean={hd.get('mean', 0):.2f} "
          f"(exp {hd.get('expected_mean', 0):.2f})")

    cyc = results.get("cycles", {})
    signal = "SIGNAL" if cyc.get("signal") else "clean"
    print(f"\n  cycle_detection:")
    print(f"    Status: {signal} (strength: {cyc.get('signal_strength', 0):.4f})")
    print(f"    Fixed points: {cyc.get('fixed_points', 0)}")
    print(f"    Short cycles: {cyc.get('short_cycles_found', 0)} "
          f"(expected: {cyc.get('expected_short_cycles', 0):.1f})")
    print(f"    Convergence ratio: {cyc.get('convergence_ratio', 0):.4f}")

    summary = results.get("summary", {})
    print(f"\n  {'—'*65}")
    print(f"  VERDICT: {summary.get('verdict', '?')} "
          f"({summary.get('n_signals', 0)}/3 signals, "
          f"max strength: {summary.get('max_signal_strength', 0):.4f})")


# --- Main ---

def main():
    parser = argparse.ArgumentParser(
        description="Extended analysis: near-collision, sequence correlation, cycle detection."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    sweep_parser = subparsers.add_parser("sweep",
        help="Run extended analysis on specified algorithms")
    sweep_parser.add_argument("--algorithms", type=str, default=None,
                              help="Comma-separated algorithms (default: all)")
    sweep_parser.add_argument("--size", type=int, default=10000,
                              help="Samples per test (default: 10000)")
    sweep_parser.add_argument("--output-dir", default="data/extended_sweep/")

    args = parser.parse_args()

    if args.command == "sweep":
        from generate_dataset import HASH_FUNCTIONS, ORACLE_FOR_ALGO, RANDOM_ORACLES

        if args.algorithms:
            targets = [t.strip() for t in args.algorithms.split(",")]
        else:
            targets = sorted(HASH_FUNCTIONS.keys())

        all_algos = list(targets)
        oracle_set = set()
        for algo in targets:
            oracle = ORACLE_FOR_ALGO.get(algo)
            if oracle:
                oracle_set.add(oracle)
        all_algos += sorted(oracle_set)

        os.makedirs(args.output_dir, exist_ok=True)
        all_results = {}

        print(f"Extended analysis sweep: {len(all_algos)} algorithms, {args.size} samples")
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

            def make_wrapper(fn):
                def wrapper(hex_input):
                    return fn(hex_input)
                return wrapper

            results = run_extended_analysis(
                make_wrapper(hash_fn),
                n_samples=args.size,
                verbose=True,
            )
            all_results[algo] = results
            print_report(algo, results)
            print()

        # Save results
        results_path = os.path.join(args.output_dir, "extended_results.json")
        with open(results_path, "w") as f:
            json.dump(all_results, f, indent=2, default=str)

        # Summary table
        print(f"\n{'='*85}")
        print(f"  EXTENDED ANALYSIS SWEEP SUMMARY")
        print(f"{'='*85}")
        print(f"\n  {'Algorithm':<20} {'NearCol':>8} {'SeqCorr':>8} {'Cycles':>8} {'Verdict':>10}")
        print(f"  {'-'*60}")

        for algo in all_algos:
            r = all_results.get(algo, {})
            nc = r.get("near_collision", {}).get("signal_strength", 0)
            sq = r.get("sequence", {}).get("signal_strength", 0)
            cy = r.get("cycles", {}).get("signal_strength", 0)
            verdict = r.get("summary", {}).get("verdict", "?")
            print(f"  {algo:<20} {nc:>7.3f} {sq:>7.3f} {cy:>7.3f} {verdict:>10}")

        print(f"\n  Results saved to: {results_path}")


if __name__ == "__main__":
    main()
