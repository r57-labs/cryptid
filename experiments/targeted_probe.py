#!/usr/bin/env python3
"""
Targeted bit predictor: statistical suite narrows, NN confirms.

Pipeline:
  1. Run statistical analysis to identify candidate relationships
     (e.g., "byte_parity(5) may correlate with output_bit(20)")
  2. For each candidate, train a small focused NN to predict the
     specific input feature from output bits
  3. Compare prediction accuracy to a shuffled baseline
  4. Report which candidates are confirmed vs spurious

This provides an independent second opinion on statistical findings
using a fundamentally different methodology (learned prediction vs
chi-squared testing).

Usage:
  # Probe a single dataset using statistical analysis to find candidates
  python targeted_probe.py probe \
    --data data/calibration/datasets/vale-prism.jsonl \
    --output results/targeted_vale-prism.json

  # Probe all datasets in a directory
  python targeted_probe.py batch \
    --data-dir data/calibration/datasets/ \
    --output results/targeted_batch.json

  # Probe with pre-computed stats results
  python targeted_probe.py probe-with-stats \
    --data data/calibration/datasets/vale-prism.jsonl \
    --stats results/stats_results.json \
    --variant-name vale-prism \
    --output results/targeted_vale-prism.json

Requirements:
  pip install torch
"""

import argparse
import json
import math
import os
import random
import sys
from pathlib import Path

import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, Dataset, random_split


# --- Data Handling ---

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
    """Convert hex string to list of bits."""
    bits = []
    for ch in hex_str:
        val = int(ch, 16)
        bits.extend([(val >> i) & 1 for i in range(3, -1, -1)])
    return bits


def text_to_bytes(text: str, max_len: int = 10) -> list[int]:
    """Convert text to list of byte values, zero-padded."""
    byte_vals = list(text.encode("utf-8"))[:max_len]
    byte_vals += [0] * (max_len - len(byte_vals))
    return byte_vals


# --- Candidate Extraction from Statistical Results ---

def extract_candidates(stats_results: dict, max_candidates: int = 20) -> list[dict]:
    """
    Extract testable candidate relationships from statistical analysis results.

    Each candidate is a (input_feature_fn, output_bit_or_byte, description) tuple
    that the NN will try to confirm.
    """
    candidates = []

    # From bit correlation: top significant (input_bit, output_bit) pairs
    bc = stats_results.get("bit_correlation", {})
    for pair in bc.get("significant_pairs", [])[:10]:
        candidates.append({
            "type": "bit_to_bit",
            "source": "bit_correlation",
            "input_bit": pair["input_bit"],
            "output_bit": pair["output_bit"],
            "chi_squared": pair["chi_squared"],
            "description": f"input_bit({pair['input_bit']}) → output_bit({pair['output_bit']})",
        })

    # From frequency analysis: features with significant bytes
    freq = stats_results.get("frequency", {})
    for feat_name, feat_results in freq.get("results_by_feature", {}).items():
        if feat_results.get("n_significant_bytes", 0) > 0:
            # Find the most significant byte
            chi2s = feat_results.get("byte_chi_squareds", [])
            if chi2s:
                best_byte = max(range(len(chi2s)), key=lambda i: chi2s[i])
                candidates.append({
                    "type": "feature_to_byte",
                    "source": "frequency",
                    "feature_name": feat_name,
                    "output_byte": best_byte,
                    "chi_squared": chi2s[best_byte],
                    "description": f"{feat_name} → output_byte({best_byte})",
                })

    # From interaction analysis: top strong hits
    inter = stats_results.get("interaction", {})
    for hit in inter.get("top_hits", [])[:10]:
        candidates.append({
            "type": "interaction_to_bit",
            "source": "interaction",
            "feature_name": hit["feature"],
            "output_bit": hit["output_bit"],
            "chi_squared": hit["chi_squared"],
            "description": f"{hit['feature']} → output_bit({hit['output_bit']})",
        })

    # Sort by chi-squared (strongest candidates first) and limit
    candidates.sort(key=lambda c: -c.get("chi_squared", 0))
    return candidates[:max_candidates]


# --- Feature Computation for Candidates ---

def compute_candidate_target(
    records: list[dict],
    candidate: dict,
    max_input_bytes: int = 10,
) -> list[int]:
    """
    Compute the target binary label for each record based on the candidate.
    Returns a list of 0/1 values.
    """
    targets = []

    if candidate["type"] == "bit_to_bit":
        input_bit = candidate["input_bit"]
        byte_idx = input_bit // 8
        bit_within_byte = 7 - (input_bit % 8)  # MSB first
        for r in records:
            pt_bytes = text_to_bytes(r["plaintext"], max_input_bytes)
            if byte_idx < len(pt_bytes):
                targets.append((pt_bytes[byte_idx] >> bit_within_byte) & 1)
            else:
                targets.append(0)

    elif candidate["type"] == "feature_to_byte":
        feat_name = candidate["feature_name"]
        for r in records:
            if feat_name == "input_length_parity":
                targets.append(len(r["plaintext"]) % 2)
            elif feat_name == "first_char_high_bit":
                targets.append((ord(r["plaintext"][0]) >> 6) & 1 if r["plaintext"] else 0)
            elif feat_name == "ascii_sum_parity":
                targets.append(sum(ord(c) for c in r["plaintext"]) % 2)
            else:
                targets.append(0)

    elif candidate["type"] == "interaction_to_bit":
        feat_name = candidate["feature_name"]
        for r in records:
            pt_bytes = text_to_bytes(r["plaintext"], max_input_bytes)
            target = _compute_interaction_feature(feat_name, pt_bytes)
            targets.append(target)

    return targets


def _compute_interaction_feature(feature_name: str, input_bytes: list[int]) -> int:
    """Compute an interaction feature value from its name."""
    # Parse feature names like "byte_parity(5)", "xor_pair(3,7)_lsb", "xor_triple(1,2,4)_msb"
    if feature_name.startswith("byte_parity("):
        idx = int(feature_name.split("(")[1].split(")")[0])
        return bin(input_bytes[idx]).count("1") % 2 if idx < len(input_bytes) else 0

    elif feature_name.startswith("byte_high("):
        idx = int(feature_name.split("(")[1].split(")")[0])
        return (input_bytes[idx] >> 7) & 1 if idx < len(input_bytes) else 0

    elif feature_name.startswith("byte_low("):
        idx = int(feature_name.split("(")[1].split(")")[0])
        return input_bytes[idx] & 1 if idx < len(input_bytes) else 0

    elif feature_name.startswith("xor_pair("):
        inner = feature_name.split("(")[1].split(")")[0]
        i, j = map(int, inner.split(","))
        xor_val = input_bytes[i] ^ input_bytes[j] if max(i, j) < len(input_bytes) else 0
        if "_lsb" in feature_name:
            return xor_val & 1
        elif "_msb" in feature_name:
            return (xor_val >> 7) & 1
        return xor_val & 1

    elif feature_name.startswith("sum_pair("):
        inner = feature_name.split("(")[1].split(")")[0]
        i, j = map(int, inner.split(","))
        sum_val = (input_bytes[i] + input_bytes[j]) if max(i, j) < len(input_bytes) else 0
        return sum_val & 1

    elif feature_name.startswith("xor_triple("):
        inner = feature_name.split("(")[1].split(")")[0]
        indices = list(map(int, inner.split(",")))
        xor_val = 0
        for idx in indices:
            if idx < len(input_bytes):
                xor_val ^= input_bytes[idx]
        if "_lsb" in feature_name:
            return xor_val & 1
        elif "_msb" in feature_name:
            return (xor_val >> 7) & 1
        return xor_val & 1

    return 0


# --- NN Probe ---

class ProbeDataset(Dataset):
    """Dataset for a single candidate probe: output bits → binary target."""

    def __init__(self, output_bits_list: list[list[int]], targets: list[int]):
        self.samples = list(zip(output_bits_list, targets))

    def __len__(self):
        return len(self.samples)

    def __getitem__(self, idx):
        bits, target = self.samples[idx]
        return (
            torch.tensor(bits, dtype=torch.float32),
            torch.tensor(target, dtype=torch.float32),
        )


class BitProbe(nn.Module):
    """Small MLP for binary prediction from output bits."""

    def __init__(self, input_dim: int, hidden_dims: list[int] = None):
        super().__init__()
        if hidden_dims is None:
            hidden_dims = [64, 32]

        layers = []
        prev = input_dim
        for h in hidden_dims:
            layers.extend([
                nn.Linear(prev, h),
                nn.ReLU(),
                nn.Dropout(0.1),
            ])
            prev = h
        layers.append(nn.Linear(prev, 1))
        layers.append(nn.Sigmoid())
        self.net = nn.Sequential(*layers)

    def forward(self, x):
        return self.net(x).squeeze(-1)


def train_probe(
    output_bits_list: list[list[int]],
    targets: list[int],
    epochs: int = 40,
    batch_size: int = 128,
    lr: float = 1e-3,
) -> dict:
    """
    Train a probe to predict a binary target from output bits.
    Returns accuracy metrics.
    """
    dataset = ProbeDataset(output_bits_list, targets)

    # Majority baseline
    n_pos = sum(targets)
    n_neg = len(targets) - n_pos
    majority_baseline = max(n_pos, n_neg) / len(targets)

    # Split 80/20
    train_size = int(0.8 * len(dataset))
    test_size = len(dataset) - train_size
    train_ds, test_ds = random_split(
        dataset, [train_size, test_size],
        generator=torch.Generator().manual_seed(42),
    )

    train_loader = DataLoader(train_ds, batch_size=batch_size, shuffle=True)
    test_loader = DataLoader(test_ds, batch_size=batch_size)

    input_dim = len(output_bits_list[0])
    model = BitProbe(input_dim)
    optimizer = optim.Adam(model.parameters(), lr=lr)
    criterion = nn.BCELoss()

    # Train
    for epoch in range(epochs):
        model.train()
        for inputs, labels in train_loader:
            optimizer.zero_grad()
            outputs = model(inputs)
            loss = criterion(outputs, labels)
            loss.backward()
            optimizer.step()

    # Evaluate
    model.eval()
    correct = 0
    total = 0
    with torch.no_grad():
        for inputs, labels in test_loader:
            outputs = model(inputs)
            predicted = (outputs > 0.5).float()
            correct += (predicted == labels).sum().item()
            total += labels.size(0)

    accuracy = correct / total if total > 0 else 0.0
    signal = accuracy > majority_baseline + 0.02  # 2% above majority baseline

    return {
        "accuracy": accuracy,
        "majority_baseline": majority_baseline,
        "signal_above_baseline": accuracy - majority_baseline,
        "n_test_samples": total,
        "signal": signal,
    }


def train_shuffled_probe(
    output_bits_list: list[list[int]],
    targets: list[int],
    epochs: int = 40,
    batch_size: int = 128,
    lr: float = 1e-3,
) -> dict:
    """
    Train a probe on SHUFFLED targets as a control.
    If the real probe beats this, the relationship is genuine.
    """
    rng = random.Random(42)
    shuffled_targets = targets.copy()
    rng.shuffle(shuffled_targets)
    return train_probe(output_bits_list, shuffled_targets, epochs, batch_size, lr)


# --- Full Pipeline ---

def probe_dataset(
    records: list[dict],
    stats_results: dict = None,
    max_candidates: int = 10,
    epochs: int = 40,
    verbose: bool = True,
) -> dict:
    """
    Full pipeline: extract candidates from stats, train probes, report.
    """
    # Run statistical analysis if not provided
    if stats_results is None:
        sys.path.insert(0, os.path.dirname(__file__))
        from statistical_analysis import run_full_analysis
        if verbose:
            print("  Running statistical analysis...")
        stats_results = run_full_analysis(records, verbose=False)

    # Extract candidates
    candidates = extract_candidates(stats_results, max_candidates)

    if not candidates:
        if verbose:
            print("  No candidates found — dataset appears clean")
        return {
            "n_candidates": 0,
            "n_confirmed": 0,
            "candidates": [],
            "confirmed": [],
            "verdict": "CLEAN — no statistical candidates to probe",
        }

    if verbose:
        print(f"  Found {len(candidates)} candidates to probe")

    # Precompute output bits for all records
    output_bits_list = [hex_to_bits(r["hash"]) for r in records]

    # Probe each candidate
    probe_results = []
    for cand in candidates:
        if verbose:
            print(f"    Probing: {cand['description']}...", end="", flush=True)

        targets = compute_candidate_target(records, cand)

        # Real probe
        real_result = train_probe(output_bits_list, targets, epochs=epochs)

        # Shuffled control
        control_result = train_shuffled_probe(output_bits_list, targets, epochs=epochs)

        # Confirmation: real must beat shuffled by >2% AND be above majority baseline
        confirmed = (
            real_result["signal"]
            and real_result["accuracy"] > control_result["accuracy"] + 0.02
        )

        result = {
            "candidate": cand,
            "real_accuracy": real_result["accuracy"],
            "control_accuracy": control_result["accuracy"],
            "majority_baseline": real_result["majority_baseline"],
            "accuracy_delta": real_result["accuracy"] - control_result["accuracy"],
            "confirmed": confirmed,
        }
        probe_results.append(result)

        if verbose:
            status = "CONFIRMED" if confirmed else "not confirmed"
            print(f" {real_result['accuracy']:.4f} vs control {control_result['accuracy']:.4f} → {status}")

    confirmed_results = [r for r in probe_results if r["confirmed"]]

    if confirmed_results:
        verdict = f"SIGNAL — {len(confirmed_results)}/{len(probe_results)} candidates confirmed by NN"
    else:
        verdict = "CLEAN — no candidates confirmed by NN probe"

    return {
        "n_candidates": len(candidates),
        "n_confirmed": len(confirmed_results),
        "candidates": probe_results,
        "confirmed": confirmed_results,
        "verdict": verdict,
    }


# --- Reporting ---

def print_probe_report(results: dict, label: str = ""):
    """Print human-readable probe report."""
    if label:
        print(f"\n  {'='*56}")
        print(f"    {label}")
        print(f"  {'='*56}")

    print(f"    Candidates tested:  {results['n_candidates']}")
    print(f"    Confirmed by NN:    {results['n_confirmed']}")
    print(f"    Verdict:            {results['verdict']}")

    if results["confirmed"]:
        print(f"\n    Confirmed relationships:")
        for r in results["confirmed"]:
            cand = r["candidate"]
            print(f"      {cand['description']}")
            print(f"        Real accuracy: {r['real_accuracy']:.4f}  "
                  f"Control: {r['control_accuracy']:.4f}  "
                  f"Delta: {r['accuracy_delta']:+.4f}  "
                  f"Chi2: {cand.get('chi_squared', 0):.1f}")


def print_batch_summary(all_results: dict):
    """Print summary table for batch analysis."""
    print(f"\n{'='*80}")
    print("  TARGETED PROBE — BATCH SUMMARY")
    print(f"{'='*80}")
    print(f"\n  {'Variant':<22} {'Cands':>6} {'Confirmed':>10} {'Best Δ':>8} {'Verdict'}")
    print(f"  {'-'*70}")

    for name, results in sorted(
        all_results.items(),
        key=lambda x: -x[1].get("n_confirmed", 0),
    ):
        n_cand = results.get("n_candidates", 0)
        n_conf = results.get("n_confirmed", 0)
        best_delta = 0.0
        if results.get("confirmed"):
            best_delta = max(r["accuracy_delta"] for r in results["confirmed"])
        delta_str = f"{best_delta:+.4f}" if best_delta != 0 else "—"
        verdict_short = "SIGNAL" if n_conf > 0 else "clean"
        print(f"  {name:<22} {n_cand:>6} {n_conf:>10} {delta_str:>8}  {verdict_short}")

    n_signal = sum(1 for r in all_results.values() if r.get("n_confirmed", 0) > 0)
    print(f"\n  Variants with confirmed signal: {n_signal}/{len(all_results)}")


# --- Main ---

def main():
    parser = argparse.ArgumentParser(
        description="Targeted bit predictor: stats narrows, NN confirms."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Single dataset probe
    probe_parser = subparsers.add_parser("probe", help="Probe a single dataset")
    probe_parser.add_argument("--data", required=True, help="Path to JSONL dataset")
    probe_parser.add_argument("--output", default="results/targeted_probe.json")
    probe_parser.add_argument("--max-candidates", type=int, default=10)
    probe_parser.add_argument("--epochs", type=int, default=40)

    # Batch mode
    batch_parser = subparsers.add_parser("batch", help="Probe all datasets in a directory")
    batch_parser.add_argument("--data-dir", required=True, help="Directory of JSONL files")
    batch_parser.add_argument("--output", default="results/targeted_batch.json")
    batch_parser.add_argument("--max-candidates", type=int, default=10)
    batch_parser.add_argument("--epochs", type=int, default=40)

    # Probe with pre-computed stats
    stats_parser = subparsers.add_parser("probe-with-stats", help="Probe using pre-computed stats")
    stats_parser.add_argument("--data", required=True, help="Path to JSONL dataset")
    stats_parser.add_argument("--stats", required=True, help="Stats results JSON")
    stats_parser.add_argument("--variant-name", help="Variant name key in stats JSON")
    stats_parser.add_argument("--output", default="results/targeted_probe.json")
    stats_parser.add_argument("--max-candidates", type=int, default=10)
    stats_parser.add_argument("--epochs", type=int, default=40)

    args = parser.parse_args()

    if args.command == "probe":
        print(f"Loading: {args.data}")
        records = load_records(args.data)
        print(f"Probing {len(records)} records...")
        results = probe_dataset(records, max_candidates=args.max_candidates, epochs=args.epochs)
        print_probe_report(results, Path(args.data).stem)

        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\nResults saved to {args.output}")

    elif args.command == "batch":
        jsonl_files = sorted(Path(args.data_dir).glob("*.jsonl"))
        if not jsonl_files:
            print(f"No JSONL files found in {args.data_dir}")
            return

        print(f"Found {len(jsonl_files)} datasets to probe\n")

        all_results = {}
        for filepath in jsonl_files:
            name = filepath.stem
            print(f"Probing: {name}")
            records = load_records(str(filepath))
            results = probe_dataset(
                records, max_candidates=args.max_candidates, epochs=args.epochs
            )
            all_results[name] = results
            print_probe_report(results, name)

        print_batch_summary(all_results)

        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w") as f:
            json.dump(all_results, f, indent=2, default=str)
        print(f"\nAll results saved to {args.output}")

    elif args.command == "probe-with-stats":
        print(f"Loading: {args.data}")
        records = load_records(args.data)

        print(f"Loading stats: {args.stats}")
        with open(args.stats) as f:
            stats_data = json.load(f)

        # Extract the right variant's stats
        if args.variant_name and args.variant_name in stats_data:
            stats_results = stats_data[args.variant_name]
        elif "bit_correlation" in stats_data:
            stats_results = stats_data
        else:
            print("Error: could not find stats results. Use --variant-name.")
            return

        results = probe_dataset(
            records, stats_results=stats_results,
            max_candidates=args.max_candidates, epochs=args.epochs,
        )
        print_probe_report(results, Path(args.data).stem)

        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\nResults saved to {args.output}")


if __name__ == "__main__":
    main()
