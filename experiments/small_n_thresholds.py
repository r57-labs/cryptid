#!/usr/bin/env python3
"""
Calibration and power of the small-N entropy thresholds (tier 1, output
entropy test), with recorded seeds.

Three measurements, written to one JSON file:

  null      the distribution of a column's plug-in byte entropy and bit
            entropy for N uniform random bytes, per N: mean, sd, minimum over
            all simulated columns, and the headroom between that minimum and
            the shipped threshold (statistical_analysis.entropy_thresholds).
            The (mean, sd) table embedded in statistical_analysis.py was
            produced by this step with the default seed.
  power     fraction of runs in which the entropy test (thresholds plus the
            v0.3.1 coverage / chi-square support checks) flags a planted
            output-support defect (one digest byte restricted to S of 256
            values, bit-balanced), per N and S. v0.3's thresholds alone
            caught S = 192 in no run at any N; the coverage check sees it
            from N = 500.
  clean     fraction of runs in which *any* tier-1 test flags a correct
            function at small N (the spurious-WARN rate when the classifier
            is skipped), over several real functions and seeds.

Usage:
  python experiments/small_n_thresholds.py --out results/small_n_thresholds.json
  python experiments/small_n_thresholds.py --skip-clean      # null + power only (~2 min)

The second cross-model review (docs/REVIEW-2.md, round two) pointed out that
v0.3's thresholds rested on a hand-set margin and that the quoted spurious-WARN
rates had no script or seeds behind them. This is that script.
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

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "src"))
sys.path.insert(0, os.path.join(_HERE, "..", "cryptid"))

from statistical_analysis import entropy_analysis, entropy_thresholds, run_full_analysis, _BYTE_NULL  # noqa: E402
from input_handler import generate_plaintexts  # noqa: E402
from generate_dataset import HASH_FUNCTIONS  # noqa: E402

N_GRID = [100, 150, 200, 300, 500, 750, 1000, 1500, 2000]
POWER_N_GRID = N_GRID + [3000, 4000, 5000]
SUPPORTS = [254, 240, 224, 192, 160, 128]
CLEAN_FUNCTIONS = ["sha256", "sha3_256", "siphash24", "md5", "sha512"]


def _ent(counts: Counter, n: int) -> float:
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def null_distribution(seed: int, columns: int = 64) -> dict:
    rng = random.Random(seed)
    out = {}
    for n in N_GRID:
        trials = 150 if n <= 500 else 60
        byte_vals, bit_min = [], 1.0
        for _ in range(trials):
            for _ in range(columns):
                data = rng.randbytes(n)
                byte_vals.append(_ent(Counter(data), n))
                for b in range(8):
                    p = sum((x >> b) & 1 for x in data) / n
                    h = 0.0 if p in (0.0, 1.0) else -(p * math.log2(p) + (1 - p) * math.log2(1 - p))
                    bit_min = min(bit_min, h)
        mean = sum(byte_vals) / len(byte_vals)
        sd = (sum((v - mean) ** 2 for v in byte_vals) / len(byte_vals)) ** 0.5
        bit_thr, byte_thr = entropy_thresholds(n)
        out[str(n)] = {
            "columns": len(byte_vals),
            "byte_mean": round(mean, 4), "byte_sd": round(sd, 4), "byte_min": round(min(byte_vals), 4),
            "byte_threshold": byte_thr, "byte_headroom": round(min(byte_vals) - byte_thr, 4),
            "bit_min": round(bit_min, 4), "bit_threshold": bit_thr, "bit_headroom": round(bit_min - bit_thr, 4),
        }
        print(f"  null N={n:5d}: byte mean {mean:.3f} sd {sd:.4f} min {min(byte_vals):.3f} thr {byte_thr:.3f} "
              f"(headroom {min(byte_vals) - byte_thr:+.3f}) | bit min {bit_min:.4f} thr {bit_thr:.4f}", flush=True)
    return out


def _support_fn(support: int, table_seed: int):
    """SHA-256 with its first digest byte mapped (near-)uniformly onto a random
    `support`-value subset.

    The index is taken from sixteen digest bits, so every value of the subset
    is equiprobable to within 1 part in 341 (65536 mod 192 = 64). v0.3.1 used
    `h[0] % support`, which for a support that does not divide 256 gives
    256 - support of the values twice the probability of the rest; that skew
    let the byte-entropy threshold fire at N = 300 for the 192-value defect
    and made the table overstate the coverage check (third cross-model
    review pass). The subset is random, so the bits stay balanced.
    """
    table = random.Random(table_seed).sample(range(256), support)

    def fn(message):
        data = message if isinstance(message, bytes) else str(message).encode("utf-8")
        h = bytearray(hashlib.sha256(data).digest())
        h[0] = table[((h[0] << 8) | h[1]) % support]
        return bytes(h).hex()
    return fn


def power(seeds: int) -> dict:
    """Fraction of runs caught, and by which part of the test: the entropy
    thresholds (bit/byte) or the support checks (coverage / chi-square)."""
    out = {}
    for n in POWER_N_GRID:
        row = {}
        for s in SUPPORTS:
            caught = by_threshold = by_support = 0
            for seed in range(seeds):
                fn = _support_fn(s, 1000 + seed)
                recs = [{"plaintext": pt, "hash": fn(pt)} for pt in generate_plaintexts(n, random.Random(seed))]
                r = entropy_analysis(recs)
                caught += bool(r["signal"])
                by_support += bool(r["support_signal"])
                by_threshold += bool(r["min_bit_entropy"] < r["bit_threshold"] or r["min_byte_entropy"] < r["byte_threshold"])
            row[str(s)] = {"caught": round(caught / seeds, 3), "by_threshold": round(by_threshold / seeds, 3),
                           "by_support_check": round(by_support / seeds, 3)}
        out[str(n)] = row
        print(f"  power N={n:5d}: " + "  ".join(f"S={s}: {row[str(s)]['caught']:.2f}"
                                               f"(t{row[str(s)]['by_threshold']:.2f}/s{row[str(s)]['by_support_check']:.2f})"
                                               for s in SUPPORTS), flush=True)
    return out


def clean_rate(seeds: int, n_values=(200, 500, 1000)) -> dict:
    out = {}
    for n in n_values:
        runs = flagged = 0
        by_test = Counter()
        for algo in CLEAN_FUNCTIONS:
            fn = HASH_FUNCTIONS[algo]
            for seed in range(100, 100 + seeds):
                recs = [{"plaintext": pt, "hash": fn(pt)} for pt in generate_plaintexts(n, random.Random(seed))]
                st = run_full_analysis(recs, verbose=False)
                hits = [k for k, r in st.items() if isinstance(r, dict) and r.get("signal_strength", 0) > 0.1]
                marginal = [k for k, r in st.items() if isinstance(r, dict) and r.get("signal")
                            and r.get("signal_strength", 0) <= 0.1]
                runs += 1
                flagged += bool(hits)
                for k in hits:
                    by_test["SIGNAL:" + k] += 1
                for k in marginal:
                    by_test["marginal:" + k] += 1
        out[str(n)] = {"runs": runs, "would_warn": flagged, "rate": round(flagged / runs, 4),
                       "by_test": dict(by_test), "functions": CLEAN_FUNCTIONS, "seeds": f"100..{100 + seeds - 1}"}
        print(f"  clean N={n:5d}: {flagged}/{runs} runs would WARN; {dict(by_test)}", flush=True)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=20261105)
    ap.add_argument("--power-seeds", type=int, default=20)
    ap.add_argument("--clean-seeds", type=int, default=20, help="per function; 20 x 5 functions = 100 runs per N")
    ap.add_argument("--skip-clean", action="store_true")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    t0 = time.time()
    result = {"seed": args.seed, "embedded_table": _BYTE_NULL, "z": {"byte": 6.0, "bit": 5.0}}
    print("Null distribution of per-column entropy (uniform bytes)")
    result["null"] = null_distribution(args.seed)
    print("Detection power: one digest byte restricted to S of 256 values (entropy test alone)")
    result["power"] = power(args.power_seeds)
    if not args.skip_clean:
        print("Spurious tier-1 flags on correct functions (classifier skipped below 2,000)")
        result["clean"] = clean_rate(args.clean_seeds)
    result["seconds"] = round(time.time() - t0, 1)

    worst = min(v["byte_headroom"] for v in result["null"].values())
    print(f"\nSmallest byte-threshold headroom over the null: {worst:+.3f} bits "
          f"({'ok' if worst > 0 else 'THRESHOLD TOO TIGHT'}); {result['seconds']}s")
    if args.out:
        os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
        with open(args.out, "w") as f:
            json.dump(result, f, indent=2)
        print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
