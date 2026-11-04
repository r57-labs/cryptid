#!/usr/bin/env python3
"""
Detection-matrix sweep: run the complete cryptid pipeline (statistical
suite + meta-learner, differential profile, extended analysis, linear
approximation) over every built-in algorithm and its matched random-oracle
control, and print the matrix the whitepaper's Table 1 is built from.

Inputs are the toolkit's standard mixed text distribution for the
record-based statistical suite and raw random bytes for the chosen-input
tiers (see input_handler.generate_plaintexts and generate_dataset.as_bytes).

Usage:
  python experiments/full_sweep.py --samples 10000 --output results/sweep_10k.json
  python experiments/full_sweep.py --samples 10000 --algorithms sha256,jenkins,crc32
"""

import argparse
import json
import os
import random
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "src"))
sys.path.insert(0, os.path.join(_HERE, "..", "cryptid"))

from generate_dataset import HASH_FUNCTIONS, RANDOM_ORACLES, ORACLE_FOR_ALGO  # noqa: E402
from engine import run_audit  # noqa: E402
from input_handler import generate_plaintexts  # noqa: E402

CATEGORY = {
    **{k: "hash" for k in ["sha256", "sha512", "sha1", "sha224", "sha512_256", "sha3_256", "sha3_512",
                           "blake2b", "blake2s", "md5", "sm3"]},
    **{k: "cipher" for k in ["aes128", "chacha20", "sm4", "camellia128"]},
    **{k: "checksum" for k in ["crc32", "adler32"]},
    **{k: "non-crypto" for k in ["fnv1a_32", "fnv1a_64", "murmur3_32", "djb2", "jenkins", "pearson64"]},
    "siphash24": "PRF",
}


LETTER = {"single_bit": "S", "byte_diff": "Y", "hamming": "H", "bit_independence": "I",
          "near_collision": "N", "sequence": "Q", "cycle": "C"}


def tier_mark(summary: dict) -> str:
    """'-' if no test in the tier fired, else one letter per fired test (see LETTER)."""
    if not summary:
        return "n/a"
    fired = [LETTER.get(k, k[0].upper()) for k, v in summary.items() if v.get("detected")]
    return "".join(fired) if fired else "-"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--samples", type=int, default=10000)
    ap.add_argument("--level", default="full", choices=["quick", "standard", "full"])
    ap.add_argument("--algorithms", default=None, help="comma-separated subset (default: all + oracles)")
    ap.add_argument("--no-oracles", action="store_true")
    ap.add_argument("--output", default=None)
    args = ap.parse_args()

    if args.algorithms:
        names = [a.strip() for a in args.algorithms.split(",")]
    else:
        names = list(HASH_FUNCTIONS.keys())
    if not args.no_oracles:
        for a in list(names):
            o = ORACLE_FOR_ALGO.get(a)
            if o and o not in names:
                names.append(o)

    print(f"Sweep: {len(names)} functions, level={args.level}, {args.samples} samples each\n")
    results = {}
    for name in names:
        fn = HASH_FUNCTIONS.get(name) or RANDOM_ORACLES.get(name)
        if fn is None:
            print(f"  unknown: {name}")
            continue
        rng = random.Random(42)
        try:
            records = [{"plaintext": pt, "hash": fn(pt)} for pt in generate_plaintexts(args.samples, rng)]
        except Exception as e:  # e.g. optional dependency missing
            print(f"  {name:<18} skipped ({e})")
            continue
        t0 = time.time()
        r = run_audit(records=records, hash_fn=fn, name=name, level=args.level,
                      n_samples=args.samples, verbose=False)
        d = r.to_dict()
        d["wall_seconds"] = round(time.time() - t0, 1)
        d["category"] = CATEGORY.get(name, "control")
        results[name] = d
        if args.output:  # save incrementally so a crash keeps what finished
            os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
            with open(args.output, "w") as f:
                json.dump({"args": vars(args), "results": results}, f, indent=2, default=str)
        ml = d.get("meta_learner") or {}
        p = ml.get("probability")
        print(f"  {name:<18} {d['verdict']:<6} P={p:.3f}  diff={tier_mark(d['differential_summary']):<5} "
              f"ext={tier_mark(d['extended_summary']):<4} lin={'S' if (d['linear_summary'] or {}).get('detected') else '-'}  "
              f"({d['wall_seconds']:.0f}s)", flush=True)

    # Matrix
    print(f"\n{'=' * 96}")
    print(f"  DETECTION MATRIX — level={args.level}, n={args.samples}")
    print(f"{'=' * 96}")
    print(f"  {'Algorithm':<18} {'Type':<11} {'Bits':>5} {'Meta P':>7} {'Diff':>6} {'Ext':>5} {'Lin':>4} {'Verdict':>8} {'Time':>7}")
    print(f"  {'-' * 90}")
    for name, d in results.items():
        ml = d.get("meta_learner") or {}
        p = ml.get("probability")
        print(f"  {name:<18} {d['category']:<11} {d['output_bits']:>5} {p:>7.3f} "
              f"{tier_mark(d['differential_summary']):>6} {tier_mark(d['extended_summary']):>5} "
              f"{'S' if (d['linear_summary'] or {}).get('detected') else '-':>4} {d['verdict']:>8} {d['wall_seconds']:>6.0f}s")
    print("\n  Diff: S=single-bit, Y=byte, H=Hamming profile, I=bit independence; "
          "Ext: N=near-collision, Q=sequence correlation, C=cycles. '-' = clean.")

    if args.output:
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w") as f:
            json.dump({"args": vars(args), "results": results}, f, indent=2, default=str)
        print(f"\nResults saved to {args.output}")


if __name__ == "__main__":
    main()
