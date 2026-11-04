#!/usr/bin/env python3
"""
Measure wall-clock time per test level for the configurations quoted in the
README and whitepaper, and write results/timings.json.

Usage:
  python experiments/timing.py --output results/timings.json
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

from generate_dataset import HASH_FUNCTIONS  # noqa: E402
from engine import run_audit  # noqa: E402
from input_handler import generate_plaintexts  # noqa: E402

CONFIGS = [("jenkins", 5000), ("sha256", 5000), ("sha256", 10000)]
LEVELS = ["quick", "standard", "full"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", default=os.path.join(_HERE, "..", "results", "timings.json"))
    args = ap.parse_args()

    out = {lvl: {} for lvl in LEVELS}
    for name, n in CONFIGS:
        fn = HASH_FUNCTIONS[name]
        for lvl in LEVELS:
            rng = random.Random(42)
            t0 = time.time()
            records = [{"plaintext": pt, "hash": fn(pt)} for pt in generate_plaintexts(n, rng)]
            run_audit(records=records, hash_fn=fn, name=name, level=lvl, n_samples=n, verbose=False)
            dt = time.time() - t0
            out[lvl][f"{name}_{n}"] = round(dt, 1)
            print(f"  {name:<8} n={n:<6} {lvl:<9} {dt:6.1f}s", flush=True)

    out["note"] = ("Wall-clock seconds including input generation, measured on a 2-vCPU Linux container; "
                   "an Apple-silicon laptop is roughly 1.5x faster.")
    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(out, f, indent=2)
    print(f"wrote {args.output}")


if __name__ == "__main__":
    main()
