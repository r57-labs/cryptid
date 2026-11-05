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
  3. Inter-record distance: Hamming distance between the digests of
     consecutive (unrelated) records. Should be ~50% of the output width.
     (Not an avalanche test -- see differential_profile.single_bit_differential.)
  4. Frequency analysis: chi-squared test on output byte value distributions,
     conditioned on input features.
  5. Mutual information estimate: permutation-tested MI between input and
     output byte subsequences. Uses shuffled null distribution instead of
     analytical bias correction (which fails at large N).
  6. Multi-byte interaction: tests parity/high/low bits of each of the
     first 10 input bytes, XOR/sum features of all pairs among them, and XOR
     features of triples among the first 8, against the first 32 output
     bits. Catches subset_leak-style weaknesses that single-feature tests
     miss.

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


# --- Bitset helpers ---
#
# Several tests compare binary input features against binary output bits
# over all records. Packing each column as one Python int (record s at bit
# s) turns each 2x2 contingency table into three popcounts, which is what
# lets the suite cover every input and output bit instead of a window.

def _pack_columns(rows: list[list[int]], n_cols: int) -> list[int]:
    """rows[s][b] in {0,1} -> list of n_cols ints with bit s set iff rows[s][b]."""
    cols = [0] * n_cols
    for s_idx, row in enumerate(rows):
        bit = 1 << s_idx
        for b in range(min(n_cols, len(row))):
            if row[b]:
                cols[b] |= bit
    return cols


def _pack_feature(values: list[int]) -> int:
    """Binary feature values per record -> packed int column."""
    v = 0
    for s_idx, x in enumerate(values):
        if x & 1:
            v |= 1 << s_idx
    return v


def _chi2_phi_2x2(col_a: int, col_b: int, n: int):
    """Chi-squared and phi for two packed binary columns over n records.

    Returns (chi2, phi, counts) or None when a marginal is empty (the test is
    undefined for a constant column).
    """
    n11 = (col_a & col_b).bit_count()
    na = col_a.bit_count()
    nb = col_b.bit_count()
    n10 = na - n11
    n01 = nb - n11
    n00 = n - na - n01
    row_totals = (n - na, na)
    col_totals = (n - nb, nb)
    if min(row_totals) == 0 or min(col_totals) == 0:
        return None
    counts = [[n00, n01], [n10, n11]]
    chi2 = 0.0
    for r_idx in range(2):
        for c_idx in range(2):
            expected = row_totals[r_idx] * col_totals[c_idx] / n
            chi2 += (counts[r_idx][c_idx] - expected) ** 2 / expected
    phi = (n00 * n11 - n01 * n10) / math.sqrt(row_totals[0] * row_totals[1] * col_totals[0] * col_totals[1])
    return chi2, phi, counts


# --- Test 1: Bit Correlation Matrix ---

def bit_correlation_analysis(
    records: list[dict],
    input_bytes: int = 10,
    verbose: bool = False,
) -> dict:
    """
    For each (input_bit, output_bit) pair -- input bits are the first
    input_bytes*8 (default 80, i.e. the whole generated message) bits of the
    UTF-8 plaintext, output bits are the full digest -- compute the
    chi-squared statistic and phi coefficient. Detect signal via:
      - Max chi-squared (any single pair with extreme correlation)
      - Count of significant pairs vs expected by chance

    (Earlier revisions scanned only the first 32 input bits; planted
    correlations from input bits 32-39 were systematically missed.)
    """
    n_input_bits = input_bytes * 8
    n_output_bits = len(hex_to_bits(records[0]["hash"]))
    n = len(records)

    input_cols = _pack_columns([text_to_bits(r["plaintext"], input_bytes) for r in records], n_input_bits)
    output_cols = _pack_columns([hex_to_bits(r["hash"]) for r in records], n_output_bits)

    significant_pairs = []
    max_chi_sq = 0.0
    max_correlation = 0.0
    chi_sq_sum = 0.0
    n_evaluated = 0

    for i_bit in range(n_input_bits):
        ci = input_cols[i_bit]
        for o_bit in range(n_output_bits):
            res = _chi2_phi_2x2(ci, output_cols[o_bit], n)
            if res is None:
                continue  # constant input bit (e.g. padding) or constant output bit
            chi_sq, phi, counts = res
            chi_sq_sum += chi_sq
            n_evaluated += 1

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

    mean_chi_sq = chi_sq_sum / n_evaluated if n_evaluated else 0
    n_total_pairs = n_input_bits * n_output_bits
    expected_significant = n_evaluated * 0.001

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
        "n_pairs_evaluated": n_evaluated,
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

    # Thresholds. The fixed values (bit 0.95, byte 7.5) are what the
    # meta-learner was calibrated with and apply unchanged from roughly
    # N = 1,000 up. Below that the plug-in entropy estimate is biased low
    # (a 256-symbol byte cannot even reach 8 bits from 200 samples:
    # log2(200) = 7.64), so a fixed threshold flagged every correct function
    # at small N. The N-aware forms below only ever relax the fixed ones:
    # the byte threshold follows the Miller-Madow bias 255/(2N ln 2) less a
    # margin for the minimum over all output bytes; the bit threshold is the
    # entropy of a bit whose frequency sits 5 sigma from 1/2.
    delta = 5.0 * 0.5 / math.sqrt(n)
    bit_threshold = min(0.95, 1.0 - (2.0 / math.log(2)) * delta * delta - 0.01)
    expected_byte_entropy = 8.0 - 255.0 / (2.0 * n * math.log(2))
    byte_threshold = min(7.5, expected_byte_entropy - max(0.25, 8.0 / math.sqrt(n)))

    signal = min_bit_entropy < bit_threshold or min_byte_entropy < byte_threshold

    # Signal strength: how far below ideal is the worst bit?
    # 0.0 at threshold, 1.0 at severe (0.5 or below)
    if min_bit_entropy < bit_threshold:
        signal_strength = min(1.0, (bit_threshold - min_bit_entropy) / 0.45)
    elif min_byte_entropy < byte_threshold:
        signal_strength = min(1.0, (byte_threshold - min_byte_entropy) / 3.5)
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
        "bit_threshold": round(bit_threshold, 4),
        "byte_threshold": round(byte_threshold, 4),
        "signal": signal,
        "signal_strength": signal_strength,
    }


# --- Test 3: Inter-Record Distance ---

def record_distance_analysis(records: list[dict], n_pairs: int = 2000) -> dict:
    """
    Inter-record output distance: the Hamming distance between the digests
    of consecutive records, which for a uniform output should be centred on
    half the output width with the binomial standard deviation.

    This is NOT an avalanche test. The records are unrelated inputs, so it
    says nothing about how the output responds to a one-bit input change;
    it is a cheap check that the output distribution is consistent across
    the dataset. The empirical avalanche (Strict Avalanche Criterion) test
    is single_bit_differential in differential_profile.py, which needs a
    callable hash function. (Earlier revisions mislabelled this test
    "avalanche".)
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
        "test": "record_distance",
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
    max_triple_bytes: int = 10,
    n_output_bits: int = None,
) -> dict:
    """
    Detect multi-byte input interactions leaked into output bits.

    For each input byte (parity, high bit, low bit), each pair of input
    bytes (low bit, high bit and full parity of the XOR; parity of the sum)
    and each triple among the first max_triple_bytes (low bit, high bit and
    full parity of the XOR), test whether any output bit is correlated with
    that binary feature beyond chance (chi-squared on the 2x2 table).

    The full-parity features were added after a held-out evaluation showed
    the classifier missing leaks of parity(b_i ^ b_j ^ b_k): the low- and
    high-bit features see one bit of the XOR, and single-byte parities are
    independent of a multi-byte parity. Triples now range over all bytes
    (the earlier limit of 8 missed any leak involving byte 9).

    This catches subset_leak-style weaknesses where a function of
    multiple input bytes is leaked into specific output bits — something
    the single-feature tests miss entirely.

    Parameters:
      max_input_bytes: how many input bytes to consider (capped by data)
      max_triple_bytes: only test triples among the first N bytes (keeps
                        C(N,3) manageable)
      n_output_bits: how many output bits to test against (default: all;
                     earlier revisions tested only the first 32)
    """
    n = len(records)

    input_bytes_all = []
    output_rows = []
    for r in records:
        pt = list(r["plaintext"].encode("utf-8"))[:max_input_bytes]
        pt += [0] * (max_input_bytes - len(pt))
        input_bytes_all.append(pt)
        output_rows.append(hex_to_bits(r["hash"]))

    actual_input_bytes = max_input_bytes
    full_output_bits = len(output_rows[0])
    actual_output_bits = full_output_bits if n_output_bits is None else min(n_output_bits, full_output_bits)
    output_cols = _pack_columns(output_rows, actual_output_bits)

    # Chi-squared threshold at p=0.001 for 1 df
    CHI2_THRESHOLD = 10.83
    # Stronger threshold for declaring "signal" given multiple testing
    # Use chi2 > 30 (p < 1e-7) for individual hits, and require pattern
    STRONG_CHI2 = 30.0

    all_hits = []
    strong_hits = []
    n_tests = 0

    def _test_feature_vs_bits(feature_values: list[int], label: str):
        """Test a binary feature against all output bits."""
        nonlocal n_tests
        fcol = _pack_feature(feature_values)
        for o_bit in range(actual_output_bits):
            n_tests += 1
            res = _chi2_phi_2x2(fcol, output_cols[o_bit], n)
            if res is None:
                continue
            chi_sq, phi, _ = res
            if chi_sq > CHI2_THRESHOLD:
                hit = {
                    "feature": label,
                    "output_bit": o_bit,
                    "chi_squared": chi_sq,
                    "phi_correlation": phi,
                    "strong": chi_sq > STRONG_CHI2,
                }
                all_hits.append(hit)
                if hit["strong"]:
                    strong_hits.append(hit)

    # --- Single-byte features (parity, high bit, low bit) ---
    for i in range(actual_input_bytes):
        _test_feature_vs_bits([bin(input_bytes_all[k][i]).count("1") % 2 for k in range(n)], f"byte_parity({i})")
        _test_feature_vs_bits([input_bytes_all[k][i] >> 7 for k in range(n)], f"byte_high({i})")
        _test_feature_vs_bits([input_bytes_all[k][i] & 1 for k in range(n)], f"byte_low({i})")

    POPCOUNT_PARITY = [bin(v).count("1") & 1 for v in range(256)]

    # --- Pair interactions ---
    pair_combos = list(combinations(range(actual_input_bytes), 2))
    for (i, j) in pair_combos:
        xor_vals = [input_bytes_all[k][i] ^ input_bytes_all[k][j] for k in range(n)]
        _test_feature_vs_bits([v & 1 for v in xor_vals], f"xor_pair({i},{j})_lsb")
        _test_feature_vs_bits([v >> 7 for v in xor_vals], f"xor_pair({i},{j})_msb")
        _test_feature_vs_bits([POPCOUNT_PARITY[v] for v in xor_vals], f"xor_pair({i},{j})_parity")
        _test_feature_vs_bits([(input_bytes_all[k][i] + input_bytes_all[k][j]) & 1 for k in range(n)],
                              f"sum_pair({i},{j})_parity")

    # --- Triple interactions ---
    triple_combos = list(combinations(range(min(actual_input_bytes, max_triple_bytes)), 3))
    for (i, j, k_idx) in triple_combos:
        xor_vals = [input_bytes_all[m][i] ^ input_bytes_all[m][j] ^ input_bytes_all[m][k_idx] for m in range(n)]
        _test_feature_vs_bits([v & 1 for v in xor_vals], f"xor_triple({i},{j},{k_idx})_lsb")
        _test_feature_vs_bits([v >> 7 for v in xor_vals], f"xor_triple({i},{j},{k_idx})_msb")
        _test_feature_vs_bits([POPCOUNT_PARITY[v] for v in xor_vals], f"xor_triple({i},{j},{k_idx})_parity")

    expected_hits_by_chance = n_tests * 0.001
    expected_strong_by_chance = n_tests * 1e-7  # chi2>30 ≈ p<1e-7

    # Signal detection:
    # - Any single extremely strong hit (chi2 > 100, roughly p < 1e-22) is enough
    # - Otherwise, require multiple strong hits above chance
    has_extreme_hit = any(h["chi_squared"] > 100 for h in strong_hits)
    has_many_strong = len(strong_hits) > max(expected_strong_by_chance * 10, 3)
    signal = has_extreme_hit or has_many_strong

    if strong_hits:
        max_chi2 = max(h["chi_squared"] for h in strong_hits)
        chi2_strength = min(1.0, (max_chi2 - STRONG_CHI2) / 470)
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
      - record_distance: 0.08 (output distribution consistency)
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
        "record_distance": 0.08,
        "mutual_information": 0.07,
    }

    test_map = {
        "bit_correlation": results.get("bit_correlation", {}),
        "frequency": results.get("frequency", {}),
        "interaction": results.get("interaction", {}),
        "entropy": results.get("entropy", {}),
        "record_distance": results.get("record_distance", {}),
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
        print("  Running inter-record distance analysis...")
    results["record_distance"] = record_distance_analysis(records)

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

    # Inter-record distance
    av = results["record_distance"]
    sig_str = f" (strength: {av['signal_strength']:.2f})" if av['signal'] else ""
    print(f"\n  Inter-record distance:{sig_str}")
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
        print(f"\n  {'Variant':<22} {'BitCorr':>8} {'Entropy':>8} {'RecDist':>8} {'Freq':>8} {'MI':>8} {'Inter':>8} {'Score':>8}  {'Verdict'}")
        print(f"  {'-'*105}")

        for name, results in sorted(all_results.items(), key=lambda x: -x[1]["composite"]["composite_score"]):
            signals = results["overall"]["signals_detected"]
            comp = results["composite"]
            row = f"  {name:<22}"
            for test in ["bit_correlation", "entropy", "record_distance", "frequency", "mutual_information", "interaction"]:
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
