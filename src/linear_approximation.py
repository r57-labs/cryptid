#!/usr/bin/env python3
"""
Linear approximation testing — generalized correlation analysis.

Tests whether any linear combination of input bits is correlated with any
linear combination of output bits. This generalizes single-bit correlation
(which tests individual bit pairs) to multi-bit XOR masks.

A backdoor could be designed so that no single bit-to-bit correlation exists,
but a specific multi-bit combination leaks information. For example:
  input_bit_3 XOR input_bit_7  correlates with  output_bit_12 XOR output_bit_25

For a perfect hash, every linear approximation should have bias ~0 (the XOR
of masked bits should be equally likely to be 0 or 1).

Testing strategy:
  - Exhaustive low-weight masks: all 1-bit and 2-bit input/output combinations
  - Sampled 3-bit masks: random selection (too many to test exhaustively)
  - Structured masks: byte-aligned patterns (parity of specific bytes)

The "linear bias" is |P(input_mask XOR = output_mask XOR) - 0.5|.
For a perfect function this is O(1/sqrt(N)); for a weak function some
masks will have significantly elevated bias.

Usage:
  python linear_approximation.py sweep \
    --algorithms sha256,crc32,djb2 \
    --size 50000 \
    --output-dir data/linear_sweep/

  python linear_approximation.py sweep \
    --size 100000 \
    --output-dir data/linear_final/
"""

import argparse
import hashlib
import json
import math
import os
import random
import sys
import time
from itertools import combinations
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))


def hex_to_bits(hex_str: str) -> list[int]:
    """Convert hex string to list of bits."""
    bits = []
    for ch in hex_str:
        val = int(ch, 16)
        bits.extend([(val >> (3 - i)) & 1 for i in range(4)])
    return bits


def apply_mask(bits: list[int], positions: tuple) -> int:
    """XOR the bits at the given positions."""
    result = 0
    for pos in positions:
        if pos < len(bits):
            result ^= bits[pos]
    return result


# --- Linear Approximation Table ---

def linear_approximation_analysis(
    hash_fn,
    n_samples: int = 10000,
    input_bytes: int = 10,
    max_input_bits: int = 80,
    max_output_bits: int = 256,
    max_multi_output_bits: int = 256,
    n_level4: int = 100000,
    rng: random.Random = None,
    verbose: bool = True,
) -> dict:
    """
    Compute linear approximation biases for low-weight masks.

    Coverage: every generated input bit (input_bytes*8, default 80) and the
    first max_output_bits digest bits for single-output-bit masks; multi-bit
    output masks use the first max_multi_output_bits digest bits. Levels
    1, 2, 3 and 5 are exhaustive over that range; level 4 (2x2) is sampled.
    Mask parities are evaluated as big-int bitset operations, which is what
    makes the exhaustive 3-bit level (C(80,3) x 256 = 21M tests) affordable.

    Tests:
      Level 1: All 1-bit input × 1-bit output pairs (bit_correlation equivalent, full width)
      Level 2: All 2-bit input × 1-bit output combinations
      Level 3: All 1-bit input × 2-bit output combinations
      Level 4: Sampled 2×2 combinations
      Level 5: All 3-bit input × 1-bit output combinations
      Level 6: Byte-parity masks (structured patterns)
    """
    if rng is None:
        rng = random.Random(42)

    # Generate random inputs and compute hashes
    if verbose:
        print(f"    Generating {n_samples} input/output pairs...", end="", flush=True)

    n_input_bits = min(input_bytes * 8, max_input_bits)
    inputs_bits = []
    outputs_bits = []
    n_output_bits = None

    for _ in range(n_samples):
        inp = bytes(rng.randint(0, 255) for _ in range(input_bytes))
        h = hash_fn(inp)
        inp_bits = []
        for b in inp:
            inp_bits.extend([(b >> (7 - i)) & 1 for i in range(8)])

        out_bits = hex_to_bits(h)
        if n_output_bits is None:
            n_output_bits = min(len(out_bits), max_output_bits)

        inputs_bits.append(inp_bits[:n_input_bits])
        outputs_bits.append(out_bits[:n_output_bits])

    if verbose:
        print(f" done ({n_input_bits} input bits, {n_output_bits} output bits)")

    # Pre-compute: one Python big-int per bit position, with sample s at
    # bit s. XOR-ing masks and counting agreements then costs a handful of
    # word-wide operations per test instead of a Python loop over samples.
    # (Equivalent to the earlier per-sample loop; roughly 50x faster.)
    def _column(rows, b):
        v = 0
        for s_idx, row in enumerate(rows):
            if row[b]:
                v |= 1 << s_idx
        return v

    input_cols = [_column(inputs_bits, b) for b in range(n_input_bits)]
    output_cols = [_column(outputs_bits, b) for b in range(n_output_bits)]
    all_ones = (1 << n_samples) - 1

    all_biases = []
    significant_approximations = []
    max_bias = 0.0
    total_tests = 0

    # Chi-squared threshold for significance
    # At p<0.001, chi2(1) > 10.83
    chi2_threshold = 10.83

    def test_mask_pair(in_positions: tuple, out_positions: tuple):
        """Test a single (input_mask, output_mask) pair for bias."""
        nonlocal max_bias, total_tests

        total_tests += 1

        in_xor = 0
        for pos in in_positions:
            in_xor ^= input_cols[pos]
        out_xor = 0
        for pos in out_positions:
            out_xor ^= output_cols[pos]

        # Count samples where the input mask parity equals the output mask parity
        agreements = ((in_xor ^ out_xor) ^ all_ones).bit_count()

        # Bias = |P(agree) - 0.5|
        p_agree = agreements / n_samples
        bias = abs(p_agree - 0.5)

        if bias > max_bias:
            max_bias = bias

        # Chi-squared test
        expected = n_samples / 2.0
        chi2 = (agreements - expected) ** 2 / expected + \
               (n_samples - agreements - expected) ** 2 / expected

        if chi2 > chi2_threshold:
            significant_approximations.append({
                "input_mask": in_positions,
                "output_mask": out_positions,
                "input_weight": len(in_positions),
                "output_weight": len(out_positions),
                "bias": round(bias, 6),
                "p_agree": round(p_agree, 6),
                "chi_squared": round(chi2, 2),
            })

        return bias

    # Level 1: 1-bit × 1-bit (exhaustive)
    if verbose:
        print(f"    Level 1: 1×1 masks ({n_input_bits}×{n_output_bits} = {n_input_bits * n_output_bits} tests)...",
              end="", flush=True)

    for i in range(n_input_bits):
        for j in range(n_output_bits):
            test_mask_pair((i,), (j,))

    level1_tests = total_tests
    level1_sig = len(significant_approximations)
    if verbose:
        print(f" {level1_sig} significant")

    # Output bits for multi-bit masks (pairs / triples get expensive quickly)
    out_bits_multi = list(range(min(n_output_bits, max_multi_output_bits)))

    # Level 2: all 2-bit input masks × every output bit
    input_pairs = list(combinations(range(n_input_bits), 2))
    if verbose:
        print(f"    Level 2: 2×1 masks ({len(input_pairs)}×{n_output_bits} = "
              f"{len(input_pairs) * n_output_bits} tests)...", end="", flush=True)
    for i_pair in input_pairs:
        for j in range(n_output_bits):
            test_mask_pair(i_pair, (j,))
    level2_sig = len(significant_approximations) - level1_sig
    if verbose:
        print(f" {level2_sig} significant")

    # Level 3: every input bit × all 2-bit output masks (within out_bits_multi)
    output_pairs = list(combinations(out_bits_multi, 2))
    if verbose:
        print(f"    Level 3: 1×2 masks ({n_input_bits}×{len(output_pairs)} = "
              f"{n_input_bits * len(output_pairs)} tests)...", end="", flush=True)
    for i in range(n_input_bits):
        for j_pair in output_pairs:
            test_mask_pair((i,), j_pair)
    level3_sig = len(significant_approximations) - level1_sig - level2_sig
    if verbose:
        print(f" {level3_sig} significant")

    # Level 4: sampled 2×2 combinations
    n_level4 = min(n_level4, len(input_pairs) * len(output_pairs))
    if verbose:
        print(f"    Level 4: 2×2 masks ({n_level4} sampled tests)...", end="", flush=True)
    rng4 = random.Random(44)
    for _ in range(n_level4):
        test_mask_pair(rng4.choice(input_pairs), rng4.choice(output_pairs))
    level4_sig = len(significant_approximations) - level1_sig - level2_sig - level3_sig
    if verbose:
        print(f" {level4_sig} significant")

    # Level 5: all 3-bit input masks × output bits (within out_bits_multi)
    input_triples = combinations(range(n_input_bits), 3)
    n_triples = n_input_bits * (n_input_bits - 1) * (n_input_bits - 2) // 6
    if verbose:
        print(f"    Level 5: 3×1 masks ({n_triples}×{len(out_bits_multi)} = "
              f"{n_triples * len(out_bits_multi)} tests)...", end="", flush=True)
    for i_triple in input_triples:
        for j in out_bits_multi:
            test_mask_pair(i_triple, (j,))
    level5_sig = len(significant_approximations) - level1_sig - level2_sig - level3_sig - level4_sig
    if verbose:
        print(f" {level5_sig} significant")

    # Level 6: byte-parity masks (structured): parity of each input byte and
    # each input byte pair vs parity of each output byte
    if verbose:
        print(f"    Level 6: byte-parity masks...", end="", flush=True)
    n_in_bytes = n_input_bits // 8
    n_out_bytes = n_output_bits // 8
    for ib in range(n_in_bytes):
        in_mask = tuple(range(ib * 8, (ib + 1) * 8))
        for ob in range(n_out_bytes):
            test_mask_pair(in_mask, tuple(range(ob * 8, (ob + 1) * 8)))
    for ib1, ib2 in combinations(range(n_in_bytes), 2):
        in_mask = tuple(range(ib1 * 8, (ib1 + 1) * 8)) + tuple(range(ib2 * 8, (ib2 + 1) * 8))
        for ob in range(n_out_bytes):
            test_mask_pair(in_mask, tuple(range(ob * 8, (ob + 1) * 8)))
    level6_sig = len(significant_approximations) - level1_sig - level2_sig - level3_sig - level4_sig - level5_sig
    if verbose:
        print(f" {level6_sig} significant")

    # Compute expected false positives
    expected_by_chance = total_tests * 0.001  # at p<0.001 threshold

    # Signal detection
    n_sig = len(significant_approximations)

    # Multi-bit approximations are more interesting than single-bit
    multi_bit_sig = [a for a in significant_approximations
                     if a["input_weight"] > 1 or a["output_weight"] > 1]
    single_bit_sig = [a for a in significant_approximations
                      if a["input_weight"] == 1 and a["output_weight"] == 1]

    # Noise floor for max_bias: at N samples, random fluctuation ~1/sqrt(N)
    # Max over millions of tests: expect max bias ~3/sqrt(N) under the null
    # (sqrt(2 ln M) / (2 sqrt N) with M ~ 1e7), so 10/sqrt(N) is conservative
    bias_noise_floor = 4.0 / math.sqrt(n_samples)

    # Signal: significantly more approximations than expected by chance,
    # OR any approximation with bias well above the noise floor
    has_signal = (n_sig > max(expected_by_chance * 5, 10) or
                  max_bias > bias_noise_floor * 2.5 or
                  len(multi_bit_sig) > max(expected_by_chance * 3, 10))

    signal_strength = 0.0
    if has_signal:
        if max_bias > bias_noise_floor * 2.5:
            signal_strength = min(1.0, (max_bias - bias_noise_floor) / 0.2)
        elif expected_by_chance > 0:
            signal_strength = min(1.0, (n_sig / expected_by_chance - 1) / 20)
    signal_strength = max(0.0, signal_strength)

    # Categorize by level for reporting
    level_summary = {
        "1×1": {"tests": level1_tests, "significant": level1_sig},
        "2×1": {"tests": len(input_pairs) * n_output_bits, "significant": level2_sig},
        "1×2": {"tests": n_input_bits * len(output_pairs), "significant": level3_sig},
        "2×2": {"tests": n_level4, "significant": level4_sig},
        "3×1": {"tests": n_triples * len(out_bits_multi), "significant": level5_sig},
        "byte_parity": {"tests": (n_in_bytes + n_in_bytes * (n_in_bytes - 1) // 2) * n_out_bytes,
                        "significant": level6_sig},
    }

    result = {
        "test": "linear_approximation",
        "n_samples": n_samples,
        "n_input_bits": n_input_bits,
        "n_output_bits": n_output_bits,
        "total_tests": total_tests,
        "n_significant": n_sig,
        "n_significant_multi_bit": len(multi_bit_sig),
        "n_significant_single_bit": len(single_bit_sig),
        "expected_by_chance": round(expected_by_chance, 1),
        "max_bias": round(max_bias, 6),
        "level_summary": level_summary,
        "signal": has_signal,
        "signal_strength": round(signal_strength, 4),
    }

    if significant_approximations:
        # Sort by bias descending, keep top 20
        significant_approximations.sort(key=lambda x: -x["bias"])
        result["top_approximations"] = significant_approximations[:20]

    return result


def print_report(name: str, results: dict):
    """Print human-readable report."""
    print(f"\n  {'='*65}")
    print(f"  LINEAR APPROXIMATION — {name}")
    print(f"  {'='*65}")

    signal = "SIGNAL" if results.get("signal") else "clean"
    print(f"\n  Status: {signal} (strength: {results.get('signal_strength', 0):.4f})")
    print(f"  Total tests: {results.get('total_tests', 0):,}")
    print(f"  Max bias: {results.get('max_bias', 0):.6f}")
    print(f"  Significant: {results.get('n_significant', 0)} "
          f"(expected by chance: {results.get('expected_by_chance', 0):.1f})")
    print(f"    Single-bit: {results.get('n_significant_single_bit', 0)}")
    print(f"    Multi-bit:  {results.get('n_significant_multi_bit', 0)}")

    ls = results.get("level_summary", {})
    print(f"\n  By level:")
    for level, info in ls.items():
        sig = info.get("significant", 0)
        tests = info.get("tests", "")
        tests_str = f" ({tests} tests)" if tests else ""
        print(f"    {level:>12}: {sig} significant{tests_str}")

    top = results.get("top_approximations", [])
    if top:
        print(f"\n  Top approximations:")
        for a in top[:8]:
            in_w = a["input_weight"]
            out_w = a["output_weight"]
            print(f"    in{a['input_mask']} ⊕ out{a['output_mask']}  "
                  f"bias={a['bias']:.6f}  chi2={a['chi_squared']:.1f}  ({in_w}×{out_w})")


# --- Main ---

def main():
    parser = argparse.ArgumentParser(
        description="Linear approximation testing for hash functions."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    sweep_parser = subparsers.add_parser("sweep",
        help="Run linear approximation analysis on specified algorithms")
    sweep_parser.add_argument("--algorithms", type=str, default=None,
                              help="Comma-separated algorithms (default: all)")
    sweep_parser.add_argument("--size", type=int, default=10000,
                              help="Samples per test (default: 10000)")
    sweep_parser.add_argument("--output-dir", default="data/linear_sweep/")

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

        print(f"Linear approximation sweep: {len(all_algos)} algorithms, {args.size} samples")
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

            t0 = time.time()
            results = linear_approximation_analysis(
                hash_fn,
                n_samples=args.size,
                verbose=True,
            )
            elapsed = time.time() - t0
            all_results[algo] = results
            print_report(algo, results)
            print(f"  Time: {elapsed:.1f}s\n")

        # Save results
        results_path = os.path.join(args.output_dir, "linear_results.json")
        with open(results_path, "w") as f:
            json.dump(all_results, f, indent=2, default=str)

        # Summary table
        print(f"\n{'='*90}")
        print(f"  LINEAR APPROXIMATION SWEEP SUMMARY")
        print(f"{'='*90}")
        print(f"\n  {'Algorithm':<20} {'MaxBias':>8} {'Sig':>6} {'Multi':>6} {'Exp':>6} {'Verdict':>10}")
        print(f"  {'-'*65}")

        for algo in all_algos:
            r = all_results.get(algo, {})
            mb = r.get("max_bias", 0)
            sig = r.get("n_significant", 0)
            multi = r.get("n_significant_multi_bit", 0)
            exp = r.get("expected_by_chance", 0)
            verdict = "SIGNAL" if r.get("signal") else "clean"
            print(f"  {algo:<20} {mb:>7.4f} {sig:>6} {multi:>6} {exp:>5.0f} {verdict:>10}")

        print(f"\n  Results saved to: {results_path}")


if __name__ == "__main__":
    main()
