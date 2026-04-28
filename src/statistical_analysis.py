#!/usr/bin/env python3
"""
Statistical analysis module for hash function weakness detection.

Performs direct mathematical tests on input→output relationships without
neural network training. Complements the NN-based approaches by detecting
different types of anomalies.

Tests performed:
  1. Bit correlation matrix: for each (input_bit, output_bit) pair, test
     whether they are correlated beyond chance (chi-squared).
  2. Output entropy: measure per-byte and per-bit entropy of hash outputs.
     A perfect hash should have maximum entropy.
  3. Avalanche analysis: for pairs of similar inputs (1-bit difference),
     measure how many output bits change. Should be ~50% (half the bits).
  4. Frequency analysis: chi-squared test on output byte value distributions,
     conditioned on input features.
  5. Mutual information estimate: permutation-tested MI between input and
     output byte subsequences. Uses shuffled null distribution instead of
     analytical bias correction (which fails at large N).
  6. Multi-byte interaction: tests XOR/sum/parity of all input byte pairs
     and triples against each output bit. Catches subset_leak-style
     weaknesses that single-feature tests miss.

Each test produces a signal_strength score (0.0 = no anomaly, higher = stronger).
A composite confidence score combines all tests with weighting.

Usage:
  python statistical_analysis.py \
    --data data/raw/crc32_random.jsonl \
    --output results/stats_crc32.json

  python statistical_analysis.py \
    --data-dir data/calibration/datasets/ \
    --output results/stats_all_variants.json
"""

import argparse
import json
import math
import os
import sys
from collections import Counter
from pathlib import Path


# --- Data Loading ---

def load_records(filepath: str) -> list[dict]:
    """Load JSONL records."""
    records = []
    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def hex_to_bits(hex_str: str) -> list[int]:
    """Convert hex string to bit list."""
    bits = []
    for ch in hex_str:
        val = int(ch, 16)
        bits.extend([(val >> i) & 1 for i in range(3, -1, -1)])
    return bits


def text_to_bits(text: str, n_bytes: int = 8) -> list[int]:
    """Convert text to bit list (first n_bytes)."""
    raw = list(text.encode("utf-8"))[:n_bytes]
    raw += [0] * (n_bytes - len(raw))
    bits = []
    for b in raw:
        bits.extend([(b >> i) & 1 for i in range(7, -1, -1)])
    return bits


# --- Test 1: Bit Correlation Matrix ---

def bit_correlation_analysis(
    records: list[dict],
    input_bytes: int = 4,
    verbose: bool = False,
) -> dict:
    """
    For each (input_bit, output_bit) pair, compute correlation and
    chi-squared statistic. Detect signal via:
      - Max chi-squared (any single pair with extreme correlation)
      - Count of significant pairs vs expected by chance
    """
    n_input_bits = input_bytes * 8
    n_output_bits = len(hex_to_bits(records[0]["hash"]))
    n = len(records)

    # Pre-compute all bit vectors
    input_bits_all = []
    output_bits_all = []
    for r in records:
        input_bits_all.append(text_to_bits(r["plaintext"], input_bytes))
        output_bits_all.append(hex_to_bits(r["hash"]))

    significant_pairs = []
    max_chi_sq = 0.0
    max_correlation = 0.0
    all_chi_sq = []

    for i_bit in range(n_input_bits):
        for o_bit in range(n_output_bits):
            counts = [[0, 0], [0, 0]]
            for k in range(n):
                iv = input_bits_all[k][i_bit] if i_bit < len(input_bits_all[k]) else 0
                ov = output_bits_all[k][o_bit] if o_bit < len(output_bits_all[k]) else 0
                counts[iv][ov] += 1

            row_totals = [counts[0][0] + counts[0][1], counts[1][0] + counts[1][1]]
            col_totals = [counts[0][0] + counts[1][0], counts[0][1] + counts[1][1]]

            chi_sq = 0.0
            for r_idx in range(2):
                for c_idx in range(2):
                    expected = row_totals[r_idx] * col_totals[c_idx] / n if n > 0 else 1
                    if expected > 0:
                        chi_sq += (counts[r_idx][c_idx] - expected) ** 2 / expected

            denom = math.sqrt(
                row_totals[0] * row_totals[1] * col_totals[0] * col_totals[1]
            ) if all(x > 0 for x in row_totals + col_totals) else 1
            phi = (counts[0][0] * counts[1][1] - counts[0][1] * counts[1][0]) / denom

            all_chi_sq.append(chi_sq)

            if chi_sq > max_chi_sq:
                max_chi_sq = chi_sq
            if abs(phi) > abs(max_correlation):
                max_correlation = phi

            # p=0.001 threshold for 1 df
            if chi_sq > 10.83:
                significant_pairs.append({
                    "input_bit": i_bit,
                    "output_bit": o_bit,
                    "chi_squared": chi_sq,
                    "phi_correlation": phi,
                    "counts": counts,
                })

    mean_chi_sq = sum(all_chi_sq) / len(all_chi_sq) if all_chi_sq else 0
    n_total_pairs = n_input_bits * n_output_bits
    expected_significant = n_total_pairs * 0.001

    # Signal detection: use max chi-squared as primary indicator.
    # A single strongly correlated pair is enough — don't require many pairs.
    # For n=2000, a correlation of 0.55 on a single bit pair gives chi2 ≈ 605.
    # For n=10000, same correlation gives chi2 ≈ 3025.
    # Threshold: chi2 > 50 indicates a meaningful single-pair correlation.
    # Also flag if many more pairs are significant than expected.
    signal_max = max_chi_sq > 50
    signal_count = len(significant_pairs) > max(expected_significant * 3, 5)
    signal = signal_max or signal_count

    # Signal strength: how extreme is the max chi-squared?
    # Normalize: 0 at threshold (50), 1.0 at very strong (1000+)
    signal_strength = max(0.0, (max_chi_sq - 50) / 950) if max_chi_sq > 50 else 0.0
    signal_strength = min(signal_strength, 1.0)

    return {
        "test": "bit_correlation",
        "n_input_bits": n_input_bits,
        "n_output_bits": n_output_bits,
        "n_total_pairs": n_total_pairs,
        "n_samples": n,
        "mean_chi_squared": mean_chi_sq,
        "expected_mean_chi_squared": 1.0,
        "max_chi_squared": max_chi_sq,
        "max_abs_correlation": abs(max_correlation),
        "n_significant_pairs_p001": len(significant_pairs),
        "expected_significant_by_chance": expected_significant,
        "significant_pairs": sorted(significant_pairs, key=lambda x: -x["chi_squared"])[:20],
        "signal": signal,
        "signal_strength": signal_strength,
    }


# --- Test 2: Output Entropy ---

def entropy_analysis(records: list[dict]) -> dict:
    """
    Measure per-byte and per-bit entropy of hash outputs.
    Perfect hash: per-bit entropy = 1.0, per-byte entropy = 8.0.
    """
    n_output_bytes = len(bytes.fromhex(records[0]["hash"]))
    n = len(records)

    bit_entropies = []
    output_bits_all = [hex_to_bits(r["hash"]) for r in records]
    n_bits = len(output_bits_all[0])

    for bit_pos in range(n_bits):
        count_1 = sum(bits[bit_pos] for bits in output_bits_all)
        count_0 = n - count_1
        p1 = count_1 / n if n > 0 else 0.5
        p0 = count_0 / n if n > 0 else 0.5

        if p0 > 0 and p1 > 0:
            entropy = -(p0 * math.log2(p0) + p1 * math.log2(p1))
        else:
            entropy = 0.0
        bit_entropies.append(entropy)

    byte_entropies = []
    for byte_pos in range(n_output_bytes):
        byte_values = [bytes.fromhex(r["hash"])[byte_pos] for r in records]
        counts = Counter(byte_values)
        entropy = sum(-(c / n) * math.log2(c / n) for c in counts.values() if c > 0)
        byte_entropies.append(entropy)

    mean_bit_entropy = sum(bit_entropies) / len(bit_entropies)
    min_bit_entropy = min(bit_entropies)
    mean_byte_entropy = sum(byte_entropies) / len(byte_entropies)
    min_byte_entropy = min(byte_entropies)

    signal = min_bit_entropy < 0.95 or min_byte_entropy < 7.5

    # Signal strength: how far below ideal is the worst bit?
    # 0.0 at threshold (0.95), 1.0 at severe (0.5 or below)
    if min_bit_entropy < 0.95:
        signal_strength = min(1.0, (0.95 - min_bit_entropy) / 0.45)
    elif min_byte_entropy < 7.5:
        signal_strength = min(1.0, (7.5 - min_byte_entropy) / 3.5)
    else:
        signal_strength = 0.0

    return {
        "test": "output_entropy",
        "n_samples": n,
        "n_output_bits": n_bits,
        "n_output_bytes": n_output_bytes,
        "mean_bit_entropy": mean_bit_entropy,
        "min_bit_entropy": min_bit_entropy,
        "ideal_bit_entropy": 1.0,
        "mean_byte_entropy": mean_byte_entropy,
        "min_byte_entropy": min_byte_entropy,
        "ideal_byte_entropy": 8.0,
        "bit_entropy_deficit": 1.0 - mean_bit_entropy,
        "byte_entropy_deficit": 8.0 - mean_byte_entropy,
        "lowest_entropy_bit": bit_entropies.index(min_bit_entropy),
        "lowest_entropy_byte": byte_entropies.index(min_byte_entropy),
        "signal": signal,
        "signal_strength": signal_strength,
    }


# --- Test 3: Avalanche Analysis ---

def avalanche_analysis(records: list[dict], n_pairs: int = 2000) -> dict:
    """
    For pairs of similar inputs (1-byte difference), measure how many
    output bits change. Perfect avalanche: ~50% of bits flip.
    """
    n_output_bits = len(hex_to_bits(records[0]["hash"]))
    n = min(n_pairs, len(records) - 1)

    flip_ratios = []
    for i in range(n):
        bits1 = hex_to_bits(records[i]["hash"])
        bits2 = hex_to_bits(records[i + 1]["hash"])
        flipped = sum(a != b for a, b in zip(bits1, bits2))
        flip_ratios.append(flipped / n_output_bits)

    mean_flip = sum(flip_ratios) / len(flip_ratios) if flip_ratios else 0
    min_flip = min(flip_ratios) if flip_ratios else 0
    max_flip = max(flip_ratios) if flip_ratios else 0

    if len(flip_ratios) > 1:
        variance = sum((x - mean_flip) ** 2 for x in flip_ratios) / (len(flip_ratios) - 1)
        stdev = math.sqrt(variance)
    else:
        stdev = 0.0

    expected_stdev = math.sqrt(0.25 / n_output_bits)

    deviation = abs(mean_flip - 0.5)
    stdev_ratio = stdev / expected_stdev if expected_stdev > 0 else 1.0
    signal = deviation > 0.02 or stdev_ratio > 2.0

    # Signal strength
    if deviation > 0.02:
        signal_strength = min(1.0, (deviation - 0.02) / 0.18)
    elif stdev_ratio > 2.0:
        signal_strength = min(1.0, (stdev_ratio - 2.0) / 3.0)
    else:
        signal_strength = 0.0

    return {
        "test": "avalanche",
        "n_pairs": n,
        "n_output_bits": n_output_bits,
        "mean_flip_ratio": mean_flip,
        "expected_flip_ratio": 0.5,
        "deviation_from_expected": deviation,
        "stdev_flip_ratio": stdev,
        "expected_stdev": expected_stdev,
        "stdev_ratio": stdev_ratio,
        "min_flip_ratio": min_flip,
        "max_flip_ratio": max_flip,
        "signal": signal,
        "signal_strength": signal_strength,
    }


# --- Test 4: Conditional Frequency Analysis ---

# Raised threshold from 310 to 400 to reduce false positives.
# At 255 df, chi2=400 corresponds to roughly p < 1e-5.
# Real weaknesses in testing produced chi2 of 1000-1800, so 400 provides
# clear separation while eliminating borderline false positives (~318).
FREQ_CHI2_THRESHOLD = 400

def frequency_analysis(records: list[dict]) -> dict:
    """
    Chi-squared test on output byte distributions conditioned on input features.
    If the hash is random, output distribution should be independent of input features.
    """
    n = len(records)
    results = {}

    features = {
        "input_length_parity": lambda r: len(r["plaintext"]) % 2,
        "first_char_high_bit": lambda r: (ord(r["plaintext"][0]) >> 6) & 1 if r["plaintext"] else 0,
        "ascii_sum_parity": lambda r: sum(ord(c) for c in r["plaintext"]) % 2,
    }

    n_output_bytes = len(bytes.fromhex(records[0]["hash"]))
    global_max_chi_sq = 0.0

    for feat_name, feat_fn in features.items():
        groups = {0: [], 1: []}
        for r in records:
            groups[feat_fn(r)].append(r)

        max_chi_sq = 0.0
        significant_bytes = 0
        byte_chi_sqs = []

        for byte_pos in range(n_output_bytes):
            counts_0 = Counter()
            counts_1 = Counter()
            for r in groups[0]:
                counts_0[bytes.fromhex(r["hash"])[byte_pos]] += 1
            for r in groups[1]:
                counts_1[bytes.fromhex(r["hash"])[byte_pos]] += 1

            all_values = set(counts_0.keys()) | set(counts_1.keys())
            n0 = len(groups[0])
            n1 = len(groups[1])

            if n0 == 0 or n1 == 0:
                byte_chi_sqs.append(0.0)
                continue

            chi_sq = 0.0
            for val in all_values:
                o0 = counts_0.get(val, 0)
                o1 = counts_1.get(val, 0)
                total = o0 + o1
                e0 = total * n0 / (n0 + n1)
                e1 = total * n1 / (n0 + n1)
                if e0 > 0:
                    chi_sq += (o0 - e0) ** 2 / e0
                if e1 > 0:
                    chi_sq += (o1 - e1) ** 2 / e1

            byte_chi_sqs.append(chi_sq)
            if chi_sq > max_chi_sq:
                max_chi_sq = chi_sq
            if chi_sq > FREQ_CHI2_THRESHOLD:
                significant_bytes += 1

        if max_chi_sq > global_max_chi_sq:
            global_max_chi_sq = max_chi_sq

        results[feat_name] = {
            "max_chi_squared": max_chi_sq,
            "n_significant_bytes": significant_bytes,
            "n_output_bytes": n_output_bytes,
            "group_sizes": {str(k): len(v) for k, v in groups.items()},
            "byte_chi_squareds": byte_chi_sqs,
        }

    has_signal = any(r["n_significant_bytes"] > 0 for r in results.values())

    # Signal strength: based on how far above threshold the max chi2 is
    if global_max_chi_sq > FREQ_CHI2_THRESHOLD:
        signal_strength = min(1.0, (global_max_chi_sq - FREQ_CHI2_THRESHOLD) / 1600)
    else:
        signal_strength = 0.0

    return {
        "test": "conditional_frequency",
        "n_samples": n,
        "features_tested": list(features.keys()),
        "results_by_feature": results,
        "signal": has_signal,
        "signal_strength": signal_strength,
        "max_chi_squared_overall": global_max_chi_sq,
        "threshold": FREQ_CHI2_THRESHOLD,
    }


# --- Test 5: Mutual Information Estimate (Permutation Test) ---

import random

def _compute_mi(input_bins: list[int], output_bins: list[int], n: int) -> float:
    """Compute mutual information in bits between two discrete sequences."""
    joint_counts = Counter(zip(input_bins, output_bins))
    input_counts = Counter(input_bins)
    output_counts = Counter(output_bins)

    mi = 0.0
    for (x, y), count in joint_counts.items():
        p_xy = count / n
        p_x = input_counts[x] / n
        p_y = output_counts[y] / n
        if p_xy > 0 and p_x > 0 and p_y > 0:
            mi += p_xy * math.log2(p_xy / (p_x * p_y))
    return mi


def mutual_information_analysis(
    records: list[dict],
    input_bytes: int = 2,
    output_bytes: int = 2,
    n_permutations: int = 200,
    significance_percentile: float = 99.0,
    seed: int = 42,
) -> dict:
    """
    Estimate mutual information between input and output byte subsequences
    using a permutation test to determine significance.

    Instead of an analytical bias correction (which fails at large N), we:
      1. Compute MI on the real (input, output) pairing.
      2. Shuffle the output column n_permutations times and compute MI each time.
      3. Flag signal only if real MI exceeds the given percentile of the
         shuffled MI distribution.

    This correctly accounts for the finite-sample MI bias at any sample size,
    because the shuffled distribution captures exactly that bias.
    """
    n = len(records)
    rng = random.Random(seed)

    # Extract first byte of input and output as bin labels
    input_bins = []
    output_bins = []
    for r in records:
        pt = r["plaintext"].encode("utf-8")
        h = bytes.fromhex(r["hash"])
        input_bins.append(pt[0] if pt else 0)
        output_bins.append(h[0] if h else 0)

    # Real MI
    real_mi = _compute_mi(input_bins, output_bins, n)

    # Permutation distribution: shuffle outputs, compute MI each time
    shuffled_mis = []
    shuffled_outputs = list(output_bins)
    for _ in range(n_permutations):
        rng.shuffle(shuffled_outputs)
        shuffled_mis.append(_compute_mi(input_bins, shuffled_outputs, n))

    shuffled_mis.sort()
    # Percentile threshold
    threshold_idx = int(len(shuffled_mis) * significance_percentile / 100)
    threshold_idx = min(threshold_idx, len(shuffled_mis) - 1)
    mi_threshold = shuffled_mis[threshold_idx]

    mean_shuffled = sum(shuffled_mis) / len(shuffled_mis)
    max_shuffled = shuffled_mis[-1]

    # Signal: real MI must exceed the percentile threshold
    signal = real_mi > mi_threshold

    # Signal strength: how far above the shuffled distribution?
    # Use (real - threshold) / threshold as a ratio, capped at 1.0
    # This scales naturally: just-above-threshold ≈ 0, far-above ≈ 1.0
    if signal and mi_threshold > 0:
        excess_ratio = (real_mi - mi_threshold) / mi_threshold
        signal_strength = min(1.0, excess_ratio / 2.0)  # 2x above threshold = 1.0
    elif signal:
        signal_strength = min(1.0, real_mi / 0.01)
    else:
        signal_strength = 0.0

    return {
        "test": "mutual_information",
        "n_samples": n,
        "input_bytes_used": 1,
        "output_bytes_used": 1,
        "mutual_information_bits": real_mi,
        "permutation_threshold": mi_threshold,
        "mean_shuffled_mi": mean_shuffled,
        "max_shuffled_mi": max_shuffled,
        "n_permutations": n_permutations,
        "significance_percentile": significance_percentile,
        "n_input_bins": len(set(input_bins)),
        "n_output_bins": len(set(output_bins)),
        "signal": signal,
        "signal_strength": signal_strength,
    }


# --- Test 6: Multi-Byte Input Interaction Detection ---

from itertools import combinations


def interaction_analysis(
    records: list[dict],
    max_input_bytes: int = 10,
    max_triple_bytes: int = 8,
    n_output_bits: int = 32,
) -> dict:
    """
    Detect multi-byte input interactions leaked into output bits.

    For each pair and triple of input bytes, compute XOR/sum/parity
    features and test whether any output bit is correlated with that
    feature beyond chance (chi-squared test).

    This catches subset_leak-style weaknesses where a function of
    multiple input bytes is leaked into specific output bits — something
    the single-feature tests miss entirely.

    Parameters:
      max_input_bytes: how many input bytes to consider (capped by data)
      max_triple_bytes: only test triples among the first N bytes (keeps
                        C(N,3) manageable)
      n_output_bits: how many output bits to test against
    """
    n = len(records)

    # Extract raw input/output bytes
    input_bytes_all = []
    output_bits_all = []
    for r in records:
        pt = list(r["plaintext"].encode("utf-8"))
        h = hex_to_bits(r["hash"])
        # Pad input to max_input_bytes
        pt = pt[:max_input_bytes]
        pt += [0] * (max_input_bytes - len(pt))
        input_bytes_all.append(pt)
        output_bits_all.append(h[:n_output_bits])

    actual_input_bytes = min(max_input_bytes, len(input_bytes_all[0]))
    actual_output_bits = min(n_output_bits, len(output_bits_all[0]))

    # Chi-squared threshold at p=0.001 for 1 df
    CHI2_THRESHOLD = 10.83
    # Stronger threshold for declaring "signal" given multiple testing
    # With ~45 pairs × 3 ops × 32 bits = 4320 tests, expect ~4.3 by chance at p=0.001
    # Use chi2 > 30 (p < 1e-7) for individual hits, and require pattern
    STRONG_CHI2 = 30.0

    def _test_feature_vs_bits(feature_values: list[int], label: str) -> list[dict]:
        """Test a binary feature against all output bits."""
        hits = []
        for o_bit in range(actual_output_bits):
            counts = [[0, 0], [0, 0]]
            for k in range(n):
                fv = feature_values[k] & 1  # ensure binary
                ov = output_bits_all[k][o_bit]
                counts[fv][ov] += 1

            row_totals = [counts[0][0] + counts[0][1], counts[1][0] + counts[1][1]]
            col_totals = [counts[0][0] + counts[1][0], counts[0][1] + counts[1][1]]

            if any(x == 0 for x in row_totals + col_totals):
                continue

            expected = [[row_totals[r] * col_totals[c] / n for c in range(2)] for r in range(2)]
            chi_sq = sum(
                (counts[r][c] - expected[r][c]) ** 2 / expected[r][c]
                for r in range(2) for c in range(2)
                if expected[r][c] > 0
            )

            if chi_sq > CHI2_THRESHOLD:
                # Compute correlation strength
                denom = math.sqrt(
                    row_totals[0] * row_totals[1] * col_totals[0] * col_totals[1]
                )
                phi = (counts[0][0] * counts[1][1] - counts[0][1] * counts[1][0]) / denom
                hits.append({
                    "feature": label,
                    "output_bit": o_bit,
                    "chi_squared": chi_sq,
                    "phi_correlation": phi,
                    "strong": chi_sq > STRONG_CHI2,
                })
        return hits

    all_hits = []
    strong_hits = []

    # --- Single-byte features (parity, high bit) ---
    # Catches subset_leak with single input byte
    for i in range(actual_input_bytes):
        # Byte parity (XOR of all bits)
        parity_feature = [bin(input_bytes_all[k][i]).count('1') % 2 for k in range(n)]
        hits = _test_feature_vs_bits(parity_feature, f"byte_parity({i})")
        all_hits.extend(hits)
        strong_hits.extend(h for h in hits if h["strong"])

        # High bit
        high_feature = [input_bytes_all[k][i] >> 7 for k in range(n)]
        hits = _test_feature_vs_bits(high_feature, f"byte_high({i})")
        all_hits.extend(hits)
        strong_hits.extend(h for h in hits if h["strong"])

        # Low bit
        low_feature = [input_bytes_all[k][i] & 1 for k in range(n)]
        hits = _test_feature_vs_bits(low_feature, f"byte_low({i})")
        all_hits.extend(hits)
        strong_hits.extend(h for h in hits if h["strong"])

    # --- Pair interactions ---
    byte_indices = list(range(actual_input_bytes))
    pair_combos = list(combinations(byte_indices, 2))

    for (i, j) in pair_combos:
        # XOR of byte pair → parity bit
        xor_feature = [input_bytes_all[k][i] ^ input_bytes_all[k][j] for k in range(n)]
        xor_parity = [v & 1 for v in xor_feature]
        hits = _test_feature_vs_bits(xor_parity, f"xor_pair({i},{j})_lsb")
        all_hits.extend(hits)
        strong_hits.extend(h for h in hits if h["strong"])

        # Sum parity
        sum_feature = [(input_bytes_all[k][i] + input_bytes_all[k][j]) & 1 for k in range(n)]
        hits = _test_feature_vs_bits(sum_feature, f"sum_pair({i},{j})_parity")
        all_hits.extend(hits)
        strong_hits.extend(h for h in hits if h["strong"])

        # XOR high bit
        xor_high = [(input_bytes_all[k][i] ^ input_bytes_all[k][j]) >> 7 for k in range(n)]
        hits = _test_feature_vs_bits(xor_high, f"xor_pair({i},{j})_msb")
        all_hits.extend(hits)
        strong_hits.extend(h for h in hits if h["strong"])

    # --- Triple interactions (limited to first max_triple_bytes) ---
    triple_indices = list(range(min(actual_input_bytes, max_triple_bytes)))
    triple_combos = list(combinations(triple_indices, 3))

    for (i, j, k_idx) in triple_combos:
        # XOR of triple → parity bit
        xor_feature = [
            input_bytes_all[m][i] ^ input_bytes_all[m][j] ^ input_bytes_all[m][k_idx]
            for m in range(n)
        ]
        xor_parity = [v & 1 for v in xor_feature]
        hits = _test_feature_vs_bits(xor_parity, f"xor_triple({i},{j},{k_idx})_lsb")
        all_hits.extend(hits)
        strong_hits.extend(h for h in hits if h["strong"])

        # XOR high bit
        xor_high = [(input_bytes_all[m][i] ^ input_bytes_all[m][j] ^ input_bytes_all[m][k_idx]) >> 7
                     for m in range(n)]
        hits = _test_feature_vs_bits(xor_high, f"xor_triple({i},{j},{k_idx})_msb")
        all_hits.extend(hits)
        strong_hits.extend(h for h in hits if h["strong"])

    # Expected false positives at p=0.001
    n_single_tests = actual_input_bytes * 3 * actual_output_bits  # 3 features per byte
    n_tests = n_single_tests + len(pair_combos) * 3 * actual_output_bits + len(triple_combos) * 2 * actual_output_bits
    expected_hits_by_chance = n_tests * 0.001
    expected_strong_by_chance = n_tests * 1e-7  # chi2>30 ≈ p<1e-7

    # Signal detection:
    # - Any single extremely strong hit (chi2 > 100, roughly p < 1e-22) is enough
    # - Otherwise, require multiple strong hits above chance
    has_extreme_hit = any(h["chi_squared"] > 100 for h in strong_hits)
    has_many_strong = len(strong_hits) > max(expected_strong_by_chance * 10, 3)
    signal = has_extreme_hit or has_many_strong

    # Signal strength: based on how many strong hits and how extreme
    if strong_hits:
        max_chi2 = max(h["chi_squared"] for h in strong_hits)
        # Normalize: 0 at STRONG_CHI2 (30), 1.0 at very extreme (500+)
        chi2_strength = min(1.0, (max_chi2 - STRONG_CHI2) / 470)
        # Also factor in count of strong hits
        count_strength = min(1.0, len(strong_hits) / 10)
        signal_strength = max(chi2_strength, count_strength) if signal else 0.0
    else:
        signal_strength = 0.0

    return {
        "test": "interaction",
        "n_samples": n,
        "n_input_bytes": actual_input_bytes,
        "n_output_bits": actual_output_bits,
        "n_pair_combos": len(pair_combos),
        "n_triple_combos": len(triple_combos),
        "n_total_tests": n_tests,
        "n_hits_p001": len(all_hits),
        "n_strong_hits": len(strong_hits),
        "expected_hits_by_chance": expected_hits_by_chance,
        "expected_strong_by_chance": expected_strong_by_chance,
        "top_hits": sorted(strong_hits, key=lambda x: -x["chi_squared"])[:20],
        "signal": signal,
        "signal_strength": signal_strength,
    }


# --- Composite Confidence Score ---

def compute_composite_score(results: dict) -> dict:
    """
    Compute a weighted composite confidence score across all tests.

    Weights reflect how informative each test is:
      - bit_correlation: 0.25 (direct evidence of input→output relationship)
      - frequency:       0.25 (strong discriminator of planted biases)
      - interaction:     0.20 (multi-byte input relationships — catches subset_leak)
      - entropy:         0.15 (catches output distribution anomalies)
      - avalanche:       0.08 (catches diffusion weakness)
      - mutual_info:     0.07 (general information-theoretic, permutation-calibrated)

    Score interpretation:
      0.00       = no anomaly detected
      0.01-0.10  = noise / borderline (likely clean)
      0.10-0.30  = weak signal (investigate further)
      0.30-0.60  = moderate signal (likely weakened)
      0.60+      = strong signal (almost certainly weakened)
    """
    weights = {
        "bit_correlation": 0.25,
        "frequency": 0.25,
        "interaction": 0.20,
        "entropy": 0.15,
        "avalanche": 0.08,
        "mutual_information": 0.07,
    }

    test_map = {
        "bit_correlation": results.get("bit_correlation", {}),
        "frequency": results.get("frequency", {}),
        "interaction": results.get("interaction", {}),
        "entropy": results.get("entropy", {}),
        "avalanche": results.get("avalanche", {}),
        "mutual_information": results.get("mutual_information", {}),
    }

    weighted_sum = 0.0
    component_scores = {}

    for test_name, weight in weights.items():
        test_result = test_map.get(test_name, {})
        strength = test_result.get("signal_strength", 0.0)
        weighted_contribution = strength * weight
        weighted_sum += weighted_contribution
        component_scores[test_name] = {
            "signal_strength": strength,
            "weight": weight,
            "weighted_contribution": weighted_contribution,
        }

    # Classify
    if weighted_sum >= 0.60:
        classification = "STRONG — almost certainly weakened"
    elif weighted_sum >= 0.30:
        classification = "MODERATE — likely weakened, investigate further"
    elif weighted_sum >= 0.10:
        classification = "WEAK — possible anomaly, may be noise"
    else:
        classification = "CLEAN — no significant anomaly detected"

    return {
        "composite_score": weighted_sum,
        "classification": classification,
        "component_scores": component_scores,
    }


# --- Full Analysis ---

def run_full_analysis(records: list[dict], verbose: bool = True) -> dict:
    """Run all statistical tests on a dataset."""
    results = {}

    if verbose:
        print("  Running bit correlation analysis...")
    results["bit_correlation"] = bit_correlation_analysis(records)

    if verbose:
        print("  Running entropy analysis...")
    results["entropy"] = entropy_analysis(records)

    if verbose:
        print("  Running avalanche analysis...")
    results["avalanche"] = avalanche_analysis(records)

    if verbose:
        print("  Running conditional frequency analysis...")
    results["frequency"] = frequency_analysis(records)

    if verbose:
        print("  Running mutual information analysis...")
    results["mutual_information"] = mutual_information_analysis(records)

    if verbose:
        print("  Running multi-byte interaction analysis...")
    results["interaction"] = interaction_analysis(records)

    # Overall signal (binary)
    signals = {name: test["signal"] for name, test in results.items()}
    results["overall"] = {
        "signals_detected": signals,
        "any_signal": any(signals.values()),
        "n_tests_with_signal": sum(signals.values()),
        "n_tests_total": len(signals),
    }

    # Composite confidence score
    results["composite"] = compute_composite_score(results)

    return results


# --- Reporting ---

def print_report(results: dict, label: str = ""):
    """Print human-readable report."""
    if label:
        print(f"\n{'='*60}")
        print(f"  {label}")
        print(f"{'='*60}")

    # Bit correlation
    bc = results["bit_correlation"]
    sig_str = f" (strength: {bc['signal_strength']:.2f})" if bc['signal'] else ""
    print(f"\n  Bit Correlation:{sig_str}")
    print(f"    Mean chi-squared:      {bc['mean_chi_squared']:.4f} (expected ~1.0)")
    print(f"    Max chi-squared:       {bc['max_chi_squared']:.4f}")
    print(f"    Max |correlation|:     {bc['max_abs_correlation']:.4f}")
    print(f"    Significant pairs:     {bc['n_significant_pairs_p001']} (expected ~{bc['expected_significant_by_chance']:.1f} by chance)")
    print(f"    Signal: {'YES' if bc['signal'] else 'no'}")

    # Entropy
    ent = results["entropy"]
    sig_str = f" (strength: {ent['signal_strength']:.2f})" if ent['signal'] else ""
    print(f"\n  Output Entropy:{sig_str}")
    print(f"    Mean bit entropy:      {ent['mean_bit_entropy']:.6f} (ideal: 1.0)")
    print(f"    Min bit entropy:       {ent['min_bit_entropy']:.6f} (at bit {ent['lowest_entropy_bit']})")
    print(f"    Mean byte entropy:     {ent['mean_byte_entropy']:.4f} (ideal: 8.0)")
    print(f"    Signal: {'YES' if ent['signal'] else 'no'}")

    # Avalanche
    av = results["avalanche"]
    sig_str = f" (strength: {av['signal_strength']:.2f})" if av['signal'] else ""
    print(f"\n  Avalanche:{sig_str}")
    print(f"    Mean flip ratio:       {av['mean_flip_ratio']:.4f} (expected: 0.5)")
    print(f"    Stdev:                 {av['stdev_flip_ratio']:.4f} (expected ~{av['expected_stdev']:.4f})")
    print(f"    Signal: {'YES' if av['signal'] else 'no'}")

    # Frequency
    freq = results["frequency"]
    sig_str = f" (strength: {freq['signal_strength']:.2f})" if freq['signal'] else ""
    print(f"\n  Conditional Frequency:{sig_str}")
    for feat, fres in freq["results_by_feature"].items():
        flag = f" ← SIGNAL (chi2={fres['max_chi_squared']:.0f})" if fres['n_significant_bytes'] > 0 else ""
        print(f"    {feat}: max_chi2={fres['max_chi_squared']:.1f}{flag}")
    print(f"    Signal: {'YES' if freq['signal'] else 'no'}")

    # Mutual information
    mi = results["mutual_information"]
    sig_str = f" (strength: {mi['signal_strength']:.2f})" if mi['signal'] else ""
    print(f"\n  Mutual Information (permutation test):{sig_str}")
    print(f"    Real MI:               {mi['mutual_information_bits']:.6f} bits")
    print(f"    Permutation threshold: {mi['permutation_threshold']:.6f} bits (p{mi.get('significance_percentile', 99):.0f})")
    print(f"    Mean shuffled MI:      {mi['mean_shuffled_mi']:.6f} bits")
    print(f"    Signal: {'YES' if mi['signal'] else 'no'}")

    # Interaction
    inter = results.get("interaction", {})
    if inter:
        sig_str = f" (strength: {inter['signal_strength']:.2f})" if inter.get('signal') else ""
        print(f"\n  Multi-Byte Interaction:{sig_str}")
        print(f"    Tests run:             {inter.get('n_total_tests', 0)} (pairs × ops × output bits)")
        print(f"    Hits at p<0.001:       {inter.get('n_hits_p001', 0)} (expected ~{inter.get('expected_hits_by_chance', 0):.1f} by chance)")
        print(f"    Strong hits (p<1e-7):  {inter.get('n_strong_hits', 0)}")
        if inter.get('top_hits'):
            print(f"    Top hit:               {inter['top_hits'][0]['feature']} → bit {inter['top_hits'][0]['output_bit']} "
                  f"(chi2={inter['top_hits'][0]['chi_squared']:.1f}, phi={inter['top_hits'][0]['phi_correlation']:.3f})")
        print(f"    Signal: {'YES' if inter.get('signal') else 'no'}")

    # Composite score
    comp = results["composite"]
    print(f"\n  {'─'*50}")
    print(f"  COMPOSITE SCORE: {comp['composite_score']:.3f}")
    print(f"  VERDICT: {comp['classification']}")
    print(f"  {'─'*50}")


# --- Main ---

def main():
    parser = argparse.ArgumentParser(
        description="Statistical analysis for hash function weakness detection."
    )
    parser.add_argument("--data", help="Path to JSONL dataset")
    parser.add_argument("--control", help="Path to control dataset for comparison")
    parser.add_argument("--data-dir", help="Directory of JSONL files (analyze all)")
    parser.add_argument("--output", default="results/stats_results.json")

    args = parser.parse_args()

    if args.data_dir:
        all_results = {}
        jsonl_files = sorted(Path(args.data_dir).glob("*.jsonl"))

        if not jsonl_files:
            print(f"No JSONL files found in {args.data_dir}")
            return

        print(f"Found {len(jsonl_files)} datasets to analyze\n")

        for filepath in jsonl_files:
            name = filepath.stem
            print(f"Analyzing: {name}")
            records = load_records(str(filepath))
            results = run_full_analysis(records)
            all_results[name] = results
            print_report(results, name)

        # Summary table
        print(f"\n{'='*80}")
        print("  SUMMARY TABLE")
        print(f"{'='*80}")
        print(f"\n  {'Variant':<22} {'BitCorr':>8} {'Entropy':>8} {'Avalnch':>8} {'Freq':>8} {'MI':>8} {'Inter':>8} {'Score':>8}  {'Verdict'}")
        print(f"  {'-'*105}")

        for name, results in sorted(all_results.items(), key=lambda x: -x[1]["composite"]["composite_score"]):
            signals = results["overall"]["signals_detected"]
            comp = results["composite"]
            row = f"  {name:<22}"
            for test in ["bit_correlation", "entropy", "avalanche", "frequency", "mutual_information", "interaction"]:
                strength = results.get(test, {}).get("signal_strength", 0.0)
                if signals.get(test, False):
                    row += f" {strength:>7.2f}*"
                else:
                    row += f" {'—':>8}"
            row += f" {comp['composite_score']:>7.3f}  {comp['classification']}"
            print(row)

        print(f"\n  * = signal detected; number = signal strength (0-1)")
        print(f"  Score thresholds: <0.10 clean, 0.10-0.30 weak, 0.30-0.60 moderate, >0.60 strong")

        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w") as f:
            json.dump(all_results, f, indent=2)
        print(f"\nAll results saved to {args.output}")

    elif args.data:
        print(f"Analyzing: {args.data}")
        records = load_records(args.data)
        results = run_full_analysis(records)
        print_report(results, args.data)

        full_output = {"target": results}

        if args.control:
            print(f"\nAnalyzing control: {args.control}")
            ctrl_records = load_records(args.control)
            ctrl_results = run_full_analysis(ctrl_records)
            print_report(ctrl_results, f"CONTROL: {args.control}")
            full_output["control"] = ctrl_results

        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w") as f:
            json.dump(full_output, f, indent=2)
        print(f"\nResults saved to {args.output}")

    else:
        parser.error("Either --data or --data-dir is required.")


if __name__ == "__main__":
    main()
