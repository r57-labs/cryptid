#!/usr/bin/env python3
"""
Full sweep: run the complete detection pipeline across all algorithms,
all input distributions, at high sample count.

Pipeline per dataset:
  1. Generate dataset (if not already present)
  2. Run statistical analysis suite (6 tests)
  3. Classify via meta-learner
  4. Run targeted probe on anything borderline or flagged (requires PyTorch)

Usage:
  # Full sweep with all defaults (100K samples, all algos, all distributions)
  python src/run_full_sweep.py --output-dir data/sweep_round1/

  # Quick test run (1K samples, specific targets)
  python src/run_full_sweep.py --size 1000 \
    --targets sha256,sm3 --distributions random \
    --output-dir data/sweep_test/

  # Skip targeted probe (no PyTorch needed)
  python src/run_full_sweep.py --skip-probe --output-dir data/sweep_round1/
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(__file__))
from generate_dataset import HASH_FUNCTIONS, RANDOM_ORACLES, ORACLE_FOR_ALGO, DISTRIBUTIONS
from generate_dataset import generate_dataset, write_jsonl
from statistical_analysis import run_full_analysis, load_records
from meta_learner import extract_features_from_stats, predict_logistic, FEATURE_NAMES


def run_sweep(
    targets: list[str],
    distributions: list[str],
    size: int,
    model_path: str,
    output_dir: str,
    skip_probe: bool = False,
    verbose: bool = True,
):
    """Run the full detection pipeline sweep."""

    # Load meta-learner model
    if verbose:
        print(f"Loading meta-learner: {model_path}")
    with open(model_path) as f:
        model = json.load(f)

    # Determine all algorithms to test (targets + their oracle controls)
    algorithms = list(targets)
    oracle_set = set()
    for algo in targets:
        oracle = ORACLE_FOR_ALGO.get(algo)
        if oracle:
            oracle_set.add(oracle)
    algorithms += sorted(oracle_set)

    total_jobs = len(algorithms) * len(distributions)
    if verbose:
        print(f"\nSweep configuration:")
        print(f"  Algorithms:    {len(algorithms)} ({len(targets)} targets + {len(oracle_set)} oracle controls)")
        print(f"  Distributions: {distributions}")
        print(f"  Sample size:   {size:,}")
        print(f"  Total jobs:    {total_jobs}")
        print(f"  Output:        {output_dir}")
        print()

    # Create output directories
    data_dir = os.path.join(output_dir, "datasets")
    stats_dir = os.path.join(output_dir, "stats")
    results_dir = os.path.join(output_dir, "results")
    for d in [data_dir, stats_dir, results_dir]:
        os.makedirs(d, exist_ok=True)

    all_results = []
    job_num = 0
    sweep_start = time.time()

    for algo in algorithms:
        for dist in distributions:
            job_num += 1
            name = f"{algo}_{dist}"

            if verbose:
                print(f"\n[{job_num}/{total_jobs}] {name}")
                print(f"  {'—' * 50}")

            # Step 1: Generate dataset
            dataset_path = os.path.join(data_dir, f"{name}.jsonl")
            if os.path.exists(dataset_path):
                if verbose:
                    print(f"  Dataset exists, loading...")
                records = load_records(dataset_path)
            else:
                if verbose:
                    print(f"  Generating {size:,} samples...", end="", flush=True)
                t0 = time.time()

                # Get hash function
                if algo in HASH_FUNCTIONS:
                    hash_fn = HASH_FUNCTIONS[algo]
                elif algo in RANDOM_ORACLES:
                    hash_fn = RANDOM_ORACLES[algo]
                else:
                    print(f"  SKIP — unknown algorithm: {algo}")
                    continue

                raw_records = generate_dataset(algo, dist, size)
                records = raw_records

                # Save dataset
                with open(dataset_path, "w") as f:
                    for r in raw_records:
                        f.write(json.dumps(r) + "\n")

                if verbose:
                    print(f" done ({time.time()-t0:.1f}s)")

            # Step 2: Run statistical analysis
            if verbose:
                print(f"  Running statistical analysis...", end="", flush=True)
            t0 = time.time()
            stats = run_full_analysis(records, verbose=False)
            stats_time = time.time() - t0

            # Save stats
            stats_path = os.path.join(stats_dir, f"{name}_stats.json")
            with open(stats_path, "w") as f:
                json.dump(stats, f, indent=2, default=str)

            if verbose:
                print(f" done ({stats_time:.1f}s)")

            # Step 3: Meta-learner classification
            features = extract_features_from_stats(stats)
            prediction = predict_logistic(model, features)

            if verbose:
                prob = prediction['probability']
                verdict = prediction['verdict']
                print(f"  Meta-learner:  prob={prob:.4f}  → {verdict}")

            result = {
                "name": name,
                "algorithm": algo,
                "distribution": dist,
                "n_samples": len(records),
                "stats_file": stats_path,
                "features": features,
                "prediction": prediction,
                "stats_time_s": round(stats_time, 1),
            }

            # Step 4: Targeted probe (if not skipped and PyTorch available)
            if not skip_probe and prediction['probability'] > 0.15:
                try:
                    import torch
                    from targeted_probe import probe_dataset
                    if verbose:
                        print(f"  Running targeted probe...", end="", flush=True)
                    t0 = time.time()
                    probe_results = probe_dataset(records, stats, verbose=False)
                    probe_time = time.time() - t0
                    result["probe"] = probe_results
                    result["probe_time_s"] = round(probe_time, 1)
                    n_confirmed = probe_results.get("n_confirmed", 0)
                    n_candidates = probe_results.get("n_candidates", 0)
                    if verbose:
                        print(f" done ({probe_time:.1f}s) — {n_confirmed}/{n_candidates} confirmed")
                except ImportError:
                    if verbose:
                        print(f"  Targeted probe skipped (PyTorch not available)")
                except Exception as e:
                    if verbose:
                        print(f"  Targeted probe error: {e}")
                    result["probe_error"] = str(e)

            all_results.append(result)

    sweep_time = time.time() - sweep_start

    # Save full results
    results_path = os.path.join(results_dir, "sweep_results.json")
    with open(results_path, "w") as f:
        json.dump(all_results, f, indent=2, default=str)

    # Print summary table
    print(f"\n\n{'='*105}")
    print(f"  FULL SWEEP RESULTS — {len(all_results)} datasets, {size:,} samples each")
    print(f"{'='*105}")
    print(f"\n  {'Algorithm':<16} {'Dist':<12} {'Prob':>7} {'Conf':>7} {'Probe':>10} {'Verdict'}")
    print(f"  {'-'*95}")

    flagged = []
    for r in sorted(all_results, key=lambda x: -x['prediction']['probability']):
        pred = r['prediction']
        probe_str = ""
        if 'probe' in r:
            p = r['probe']
            probe_str = f"{p.get('n_confirmed',0)}/{p.get('n_candidates',0)}"
        elif 'probe_error' in r:
            probe_str = "error"

        line = (f"  {r['algorithm']:<16} {r['distribution']:<12} "
                f"{pred['probability']:>6.4f} {pred['confidence']:>6.2f} "
                f"{probe_str:>10}  {pred['verdict']}")
        print(line)

        if pred['predicted_label'] == 1:
            flagged.append(r)

    # Algorithm-level summary (aggregate across distributions)
    print(f"\n  {'—'*95}")
    print(f"\n  ALGORITHM SUMMARY (max probability across distributions):")
    print(f"  {'Algorithm':<16} {'Max Prob':>9} {'Status'}")
    print(f"  {'-'*45}")

    algo_max = {}
    for r in all_results:
        algo = r['algorithm']
        prob = r['prediction']['probability']
        if algo not in algo_max or prob > algo_max[algo]:
            algo_max[algo] = prob

    for algo, max_prob in sorted(algo_max.items(), key=lambda x: -x[1]):
        status = "FLAGGED" if max_prob >= model.get('threshold', 0.35) else "clean"
        print(f"  {algo:<16} {max_prob:>8.4f}  {status}")

    print(f"\n  Total flagged: {len(flagged)}/{len(all_results)}")
    print(f"  Sweep time: {sweep_time:.0f}s ({sweep_time/60:.1f} min)")
    print(f"\n  Results saved to: {results_path}")

    if flagged:
        print(f"\n  *** ATTENTION: {len(flagged)} dataset(s) flagged as potentially weakened! ***")
        for r in flagged:
            print(f"    → {r['name']}: prob={r['prediction']['probability']:.4f}")
        print(f"\n  Recommended: run targeted probe on flagged datasets for independent confirmation.")

    return all_results


def main():
    parser = argparse.ArgumentParser(
        description="Full detection pipeline sweep across all algorithms and distributions."
    )
    parser.add_argument("--targets", type=str, default=None,
                        help="Comma-separated target algorithms (default: all)")
    parser.add_argument("--distributions", type=str, default="random,words,sequential",
                        help="Comma-separated distributions (default: random,words,sequential)")
    parser.add_argument("--size", type=int, default=100000,
                        help="Samples per dataset (default: 100000)")
    parser.add_argument("--model", type=str, default="models/meta_learner_multiwidth_10k.json",
                        help="Path to trained meta-learner model")
    parser.add_argument("--output-dir", type=str, default="data/sweep_round1/",
                        help="Output directory for all results")
    parser.add_argument("--skip-probe", action="store_true",
                        help="Skip targeted probe (no PyTorch needed)")

    args = parser.parse_args()

    if args.targets:
        targets = [t.strip() for t in args.targets.split(",")]
        for t in targets:
            if t not in HASH_FUNCTIONS:
                parser.error(f"Unknown algorithm: {t}. Available: {', '.join(sorted(HASH_FUNCTIONS.keys()))}")
    else:
        targets = sorted(HASH_FUNCTIONS.keys())

    distributions = [d.strip() for d in args.distributions.split(",")]

    run_sweep(
        targets=targets,
        distributions=distributions,
        size=args.size,
        model_path=args.model,
        output_dir=args.output_dir,
        skip_probe=args.skip_probe,
    )


if __name__ == "__main__":
    main()
