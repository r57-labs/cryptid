#!/usr/bin/env python3
"""
Out-of-family generalization test.

The statistical suite and meta-learner were calibrated on four synthetic
weakness families that share the suite's own feature vocabulary. This script
runs the complete pipeline (statistical suite + meta-learner, differential
profile, extended analysis, linear approximation) against weaknesses that
were written AFTER the detectors were frozen and deliberately target things
the detectors were not designed to look for (see
synthetic_weakness.OUT_OF_FAMILY), plus a clean control, and prints the
catch matrix exactly as it comes out.

Optionally it also runs two "unfaithful implementation" variants of SHA-256
(a one-bit typo in a round constant, and a round-reduced version) to show
what the black-box battery cannot see: a well-mixed function that is simply
not the standard one.

Usage:
  python experiments/out_of_family_eval.py --samples 5000 --output results/out_of_family.json
  python experiments/out_of_family_eval.py --samples 5000 --implementation-variants --impl-samples 2000
  python experiments/out_of_family_eval.py --impl-only --impl-level full --merge-into results/out_of_family.json

--impl-only runs just the unfaithful-SHA-256 variants (pure Python: about half
an hour per variant at the full level); --merge-into replaces that section of
an existing results file and records the run. v0.2's file held a standard-level
run of these while the paper said "entire battery"; v0.3 re-ran them at full.
"""

import argparse
import json
import os
import struct
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "src"))
sys.path.insert(0, os.path.join(_HERE, "..", "cryptid"))

from synthetic_weakness import OUT_OF_FAMILY, _SeededSha256  # noqa: E402
from engine import run_audit  # noqa: E402
from input_handler import generate_plaintexts  # noqa: E402
import random  # noqa: E402


# --- Unfaithful-implementation variants of SHA-256 (pure Python) ---

_K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]


def _rr(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF


def make_sha256_variant(n_rounds: int = 64, corrupt_k: int = None):
    """SHA-256 with a reduced round count and/or one corrupted round constant."""
    K = list(_K)
    if corrupt_k is not None:
        K[corrupt_k] ^= 0x00010000  # a single-bit typo in one constant

    def h(message) -> str:
        data = message if isinstance(message, (bytes, bytearray)) else str(message).encode("utf-8")
        msg = bytearray(data)
        L = len(msg)
        msg.append(0x80)
        while len(msg) % 64 != 56:
            msg.append(0)
        msg += struct.pack(">Q", L * 8)
        H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
             0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
        for bs in range(0, len(msg), 64):
            w = list(struct.unpack(">16I", msg[bs:bs + 64]))
            for i in range(16, 64):
                s0 = _rr(w[i - 15], 7) ^ _rr(w[i - 15], 18) ^ (w[i - 15] >> 3)
                s1 = _rr(w[i - 2], 17) ^ _rr(w[i - 2], 19) ^ (w[i - 2] >> 10)
                w.append((w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFF)
            a, b, c, d, e, f, g, hh = H
            for i in range(n_rounds):
                S1 = _rr(e, 6) ^ _rr(e, 11) ^ _rr(e, 25)
                ch = (e & f) ^ (~e & g)
                t1 = (hh + S1 + ch + K[i] + w[i]) & 0xFFFFFFFF
                S0 = _rr(a, 2) ^ _rr(a, 13) ^ _rr(a, 22)
                maj = (a & b) ^ (a & c) ^ (b & c)
                t2 = (S0 + maj) & 0xFFFFFFFF
                hh, g, f, e, d, c, b, a = g, f, e, (d + t1) & 0xFFFFFFFF, c, b, a, (t1 + t2) & 0xFFFFFFFF
            H = [(x + y) & 0xFFFFFFFF for x, y in zip(H, [a, b, c, d, e, f, g, hh])]
        return struct.pack(">8I", *H).hex()

    return h


# --- Runner ---

def _flags(summary: dict) -> str:
    """Compact 'name:S/-' string for a tier summary."""
    if not summary:
        return "n/a"
    return " ".join(f"{k}:{'S' if v.get('detected') else '-'}" for k, v in summary.items())


def audit(name, fn, n_samples, level, model_path=None, verbose=False):
    rng = random.Random(42)
    records = [{"plaintext": pt, "hash": fn(pt)} for pt in generate_plaintexts(n_samples, rng)]
    t0 = time.time()
    result = run_audit(records=records, hash_fn=fn, name=name, level=level,
                       n_samples=n_samples, model_path=model_path, verbose=verbose)
    d = result.to_dict()
    d["wall_seconds"] = round(time.time() - t0, 1)
    return d


def print_matrix(rows: list[dict], title: str):
    print(f"\n{'=' * 100}")
    print(f"  {title}")
    print(f"{'=' * 100}")
    print(f"  {'variant':<24} {'verdict':<7} {'meta P':>7}  {'differential':<40} {'extended':<32} {'linear':<8}")
    print(f"  {'-' * 96}")
    for d in rows:
        ml = d.get("meta_learner") or {}
        p = ml.get("probability")
        p_str = f"{p:.3f}" if isinstance(p, (int, float)) else "skip"
        lin = d.get("linear_summary") or {}
        lin_str = ("S" if lin.get("detected") else "-") if lin else "n/a"
        print(f"  {d['name']:<24} {d['verdict']:<7} {p_str:>7}  "
              f"{_flags(d.get('differential_summary')):<40} {_flags(d.get('extended_summary')):<32} {lin_str:<8}")
    print()
    print("  S = that test reported a signal; - = clean; meta P = meta-learner P(weakened), threshold 0.40.")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--samples", type=int, default=5000)
    ap.add_argument("--level", default="full", choices=["quick", "standard", "full"])
    ap.add_argument("--seed", default="out-of-family-2026", help="per-variant seed string")
    ap.add_argument("--implementation-variants", action="store_true",
                    help="also run the (slow, pure-Python) unfaithful SHA-256 variants")
    ap.add_argument("--impl-samples", type=int, default=2000)
    ap.add_argument("--impl-level", default="standard", choices=["quick", "standard", "full"])
    ap.add_argument("--impl-only", action="store_true",
                    help="run only the implementation variants (implies --implementation-variants)")
    ap.add_argument("--merge-into", default=None,
                    help="existing results JSON whose implementation_variants section is replaced")
    ap.add_argument("--output", default=None, help="write all results as JSON")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    seed = args.seed.encode()

    class CleanControl(_SeededSha256):
        """Seeded SHA-256 with nothing planted (accepts text or bytes)."""
        def __call__(self, message):
            data = message if isinstance(message, (bytes, bytearray)) else str(message).encode("utf-8")
            return self._strong(data).hex()

    variants = [("clean control (sha256)", CleanControl(seed + b"-clean"))]
    for key, cls in OUT_OF_FAMILY.items():
        variants.append((key, cls(seed + b"-" + key.encode())))

    rows = []
    if not args.impl_only:
        print(f"Out-of-family evaluation: {len(variants)} variants x level={args.level} x {args.samples} samples")
        for name, fn in variants:
            print(f"  running {name} ...", end="", flush=True)
            d = audit(name, fn, args.samples, args.level, verbose=args.verbose)
            print(f" {d['verdict']} ({d['wall_seconds']}s)")
            rows.append(d)
        print_matrix(rows, f"Out-of-family planted weaknesses — level={args.level}, n={args.samples}")

    impl_rows = []
    if args.implementation_variants or args.impl_only:
        impl = [
            ("sha256 correct (pure py)", make_sha256_variant()),
            ("sha256 K[20] 1-bit typo", make_sha256_variant(corrupt_k=20)),
            ("sha256 24 of 64 rounds", make_sha256_variant(n_rounds=24)),
            ("sha256 12 of 64 rounds", make_sha256_variant(n_rounds=12)),
        ]
        print(f"\nUnfaithful-implementation variants: level={args.impl_level}, {args.impl_samples} samples (pure Python, slow)")
        for name, fn in impl:
            print(f"  running {name} ...", end="", flush=True)
            d = audit(name, fn, args.impl_samples, args.impl_level, verbose=args.verbose)
            print(f" {d['verdict']} ({d['wall_seconds']}s)")
            impl_rows.append(d)
        print_matrix(impl_rows, f"Unfaithful SHA-256 implementations — level={args.impl_level}, n={args.impl_samples}")
        print("  These are well-mixed functions that are not SHA-256; use `cryptid kat` / `compare` for faithfulness.")

    if args.output:
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w") as f:
            json.dump({"args": vars(args), "out_of_family": rows, "implementation_variants": impl_rows},
                      f, indent=2, default=str)
        print(f"\nResults saved to {args.output}")

    if args.merge_into and impl_rows:
        with open(args.merge_into) as f:
            existing = json.load(f)
        existing["implementation_variants"] = impl_rows
        existing["args"]["impl_level"] = args.impl_level
        existing["args"]["impl_samples"] = args.impl_samples
        existing["args"]["implementation_variants"] = True
        existing.setdefault("reruns", []).append({
            "date": time.strftime("%Y-%m-%d"), "section": "implementation_variants",
            "level": args.impl_level, "samples": args.impl_samples, "reason": "see docs/REVIEW-2.md",
        })
        with open(args.merge_into, "w") as f:
            json.dump(existing, f, indent=2, default=str)
        print(f"Replaced implementation_variants in {args.merge_into}")


if __name__ == "__main__":
    main()
