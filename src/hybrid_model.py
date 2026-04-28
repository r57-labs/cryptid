#!/usr/bin/env python3
"""
Feature-enhanced hybrid neural network for hash function weakness detection.

Method 3 in the multi-method detection approach. Combines the raw bit-level
analysis of the neural network probes (Method 1) with pre-computed statistical
features (Method 2) to allow the network to exploit synergies between both.

The key insight: statistical analysis can identify *which* relationships might
exist (e.g., "byte 5 parity correlates with output bit 20"), and the neural
network can then learn to exploit those relationships with greater sensitivity
than threshold-based detection.

Architecture:
  - Feature engineering: per-sample features including byte parities, pair/triple
    XOR interactions, cross-correlation features between input and output bytes
  - Two-branch network: raw bits branch + engineered features branch, merged
    via concatenation before shared classification layers
  - Task: discriminator (real vs shuffled pairs) — the same task as byte_model.py
    but with dramatically richer input representation

Usage:
  # Run on a single dataset
  python hybrid_model.py single \
    --data data/calibration/datasets/vale-prism.jsonl \
    --output results/hybrid_single.json

  # Run on all datasets in a directory (calibration batch mode)
  python hybrid_model.py batch \
    --data-dir data/calibration/datasets/ \
    --output results/hybrid_batch.json

  # Compare target vs control
  python hybrid_model.py compare \
    --target data/calibration/datasets/vale-prism.jsonl \
    --control data/calibration/datasets/coral-raven.jsonl \
    --output results/hybrid_compare.json

Requirements:
  pip install torch numpy
"""

import argparse
import json
import math
import os
import random
import sys
from collections import Counter
from itertools import combinations
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


def text_to_bytes(text: str, max_len: int) -> list[int]:
    """Convert text to list of byte values, zero-padded."""
    byte_vals = list(text.encode("utf-8"))[:max_len]
    byte_vals += [0] * (max_len - len(byte_vals))
    return byte_vals


def bytes_to_bits(byte_vals: list[int]) -> list[int]:
    """Convert byte values to list of bits."""
    bits = []
    for b in byte_vals:
        bits.extend([(b >> i) & 1 for i in range(7, -1, -1)])
    return bits


# --- Feature Engineering ---

def compute_features(
    input_bytes: list[int],
    output_bytes: list[int],
    n_input: int = 10,
    n_output: int = 8,
    max_pair_bytes: int = 10,
    max_triple_bytes: int = 6,
) -> list[float]:
    """
    Compute per-sample engineered features from input and output bytes.

    Features computed:
      1. Input byte parities (n_input features)
      2. Input byte pair XOR parities (C(max_pair_bytes, 2) features)
      3. Input byte triple XOR parities (C(max_triple_bytes, 3) features)
      4. Output byte parities (n_output features)
      5. Cross-features: XOR parity of each input byte with each output byte
         (n_input × n_output features)
      6. Input byte high bits (n_input features)
      7. Output byte high bits (n_output features)
      8. Input byte low bits (n_input features)

    Returns a flat list of float features.
    """
    features = []

    # Pad to expected lengths
    inp = list(input_bytes[:n_input]) + [0] * max(0, n_input - len(input_bytes))
    out = list(output_bytes[:n_output]) + [0] * max(0, n_output - len(output_bytes))

    # 1. Input byte parities
    for b in inp:
        features.append(float(bin(b).count("1") % 2))

    # 2. Input byte pair XOR parities
    pair_indices = list(range(min(len(inp), max_pair_bytes)))
    for i, j in combinations(pair_indices, 2):
        features.append(float(bin(inp[i] ^ inp[j]).count("1") % 2))

    # 3. Input byte triple XOR parities
    triple_indices = list(range(min(len(inp), max_triple_bytes)))
    for i, j, k in combinations(triple_indices, 3):
        features.append(float(bin(inp[i] ^ inp[j] ^ inp[k]).count("1") % 2))

    # 4. Output byte parities
    for b in out:
        features.append(float(bin(b).count("1") % 2))

    # 5. Cross-features: XOR parity of each input byte × each output byte
    for ib in inp:
        for ob in out:
            features.append(float(bin(ib ^ ob).count("1") % 2))

    # 6. Input byte high bits
    for b in inp:
        features.append(float((b >> 7) & 1))

    # 7. Output byte high bits
    for b in out:
        features.append(float((b >> 7) & 1))

    # 8. Input byte low bits
    for b in inp:
        features.append(float(b & 1))

    return features


def count_features(
    n_input: int = 10,
    n_output: int = 8,
    max_pair_bytes: int = 10,
    max_triple_bytes: int = 6,
) -> int:
    """Count the total number of engineered features."""
    n_pair = len(list(combinations(range(min(n_input, max_pair_bytes)), 2)))
    n_triple = len(list(combinations(range(min(n_input, max_triple_bytes)), 3)))
    return (
        n_input              # input byte parities
        + n_pair             # pair XOR parities
        + n_triple           # triple XOR parities
        + n_output           # output byte parities
        + n_input * n_output # cross-features
        + n_input            # input high bits
        + n_output           # output high bits
        + n_input            # input low bits
    )


# --- Dataset ---

class HybridDiscriminatorDataset(Dataset):
    """
    Dataset for the hybrid discriminator.

    Each sample provides:
      - raw_bits: concatenated (hash_bits, plaintext_bits)
      - features: engineered statistical features
      - label: 1 for real pair, 0 for shuffled pair

    The model receives both raw bits and features, allowing it to
    exploit both raw patterns and pre-digested statistical relationships.
    """

    def __init__(
        self,
        records: list[dict],
        max_plaintext_bytes: int = 10,
        n_output_bytes: int = 8,
    ):
        self.samples = []
        self.n_features = count_features(max_plaintext_bytes, n_output_bytes)

        # Precompute all samples
        all_hashes = [r["hash"] for r in records]
        all_plaintexts = [r["plaintext"] for r in records]

        # Real pairs (label=1)
        for r in records:
            h_bits = hex_to_bits(r["hash"])
            pt_bytes = text_to_bytes(r["plaintext"], max_plaintext_bytes)
            pt_bits = bytes_to_bits(pt_bytes)
            out_bytes = list(bytes.fromhex(r["hash"]))[:n_output_bytes]
            features = compute_features(pt_bytes, out_bytes, max_plaintext_bytes, n_output_bytes)
            self.samples.append((h_bits + pt_bits, features, 1))

        # Shuffled pairs (label=0)
        rng = random.Random(99)
        shuffled_hashes = all_hashes.copy()
        rng.shuffle(shuffled_hashes)
        # Ensure no pair stays matched
        for i in range(len(shuffled_hashes)):
            if shuffled_hashes[i] == all_hashes[i]:
                j = (i + 1) % len(shuffled_hashes)
                shuffled_hashes[i], shuffled_hashes[j] = (
                    shuffled_hashes[j], shuffled_hashes[i]
                )

        for pt_str, h_hex in zip(all_plaintexts, shuffled_hashes):
            h_bits = hex_to_bits(h_hex)
            pt_bytes = text_to_bytes(pt_str, max_plaintext_bytes)
            pt_bits = bytes_to_bits(pt_bytes)
            out_bytes = list(bytes.fromhex(h_hex))[:n_output_bytes]
            features = compute_features(pt_bytes, out_bytes, max_plaintext_bytes, n_output_bytes)
            self.samples.append((h_bits + pt_bits, features, 0))

    def __len__(self):
        return len(self.samples)

    def __getitem__(self, idx):
        raw_bits, features, label = self.samples[idx]
        return (
            torch.tensor(raw_bits, dtype=torch.float32),
            torch.tensor(features, dtype=torch.float32),
            torch.tensor(label, dtype=torch.float32),
        )


# --- Model ---

class HybridDiscriminator(nn.Module):
    """
    Two-branch discriminator that processes raw bits and engineered features
    through separate pathways, then merges for classification.

    Branch 1 (raw bits): processes concatenated (hash_bits, plaintext_bits)
      through an MLP, learning raw bit-level patterns.

    Branch 2 (features): processes engineered statistical features through
      a separate MLP, learning higher-level relationships.

    Merge: concatenate branch outputs, pass through shared classification
      layers. This allows the network to combine raw pattern detection with
      pre-computed statistical relationships.
    """

    def __init__(
        self,
        raw_dim: int,
        feature_dim: int,
        raw_hidden: list[int] = None,
        feat_hidden: list[int] = None,
        merge_hidden: list[int] = None,
        dropout: float = 0.15,
    ):
        super().__init__()

        if raw_hidden is None:
            raw_hidden = [256, 128]
        if feat_hidden is None:
            feat_hidden = [128, 64]
        if merge_hidden is None:
            merge_hidden = [128, 64]

        # Branch 1: raw bits
        raw_layers = []
        prev = raw_dim
        for h in raw_hidden:
            raw_layers.extend([
                nn.Linear(prev, h),
                nn.BatchNorm1d(h),
                nn.ReLU(),
                nn.Dropout(dropout),
            ])
            prev = h
        self.raw_branch = nn.Sequential(*raw_layers)
        raw_out_dim = raw_hidden[-1]

        # Branch 2: engineered features
        feat_layers = []
        prev = feature_dim
        for h in feat_hidden:
            feat_layers.extend([
                nn.Linear(prev, h),
                nn.BatchNorm1d(h),
                nn.ReLU(),
                nn.Dropout(dropout),
            ])
            prev = h
        self.feat_branch = nn.Sequential(*feat_layers)
        feat_out_dim = feat_hidden[-1]

        # Merge layers
        merge_layers = []
        prev = raw_out_dim + feat_out_dim
        for h in merge_hidden:
            merge_layers.extend([
                nn.Linear(prev, h),
                nn.BatchNorm1d(h),
                nn.ReLU(),
                nn.Dropout(dropout),
            ])
            prev = h
        merge_layers.append(nn.Linear(prev, 1))
        merge_layers.append(nn.Sigmoid())
        self.merge = nn.Sequential(*merge_layers)

    def forward(self, raw_bits, features):
        raw_out = self.raw_branch(raw_bits)
        feat_out = self.feat_branch(features)
        merged = torch.cat([raw_out, feat_out], dim=1)
        return self.merge(merged).squeeze(-1)


# --- Training ---

def train_hybrid(
    records: list[dict],
    max_plaintext_bytes: int = 10,
    n_output_bytes: int = 8,
    epochs: int = 60,
    batch_size: int = 128,
    lr: float = 1e-3,
    verbose: bool = True,
) -> dict:
    """Train the hybrid discriminator and return evaluation metrics."""

    dataset = HybridDiscriminatorDataset(records, max_plaintext_bytes, n_output_bytes)

    # Split 80/20
    train_size = int(0.8 * len(dataset))
    test_size = len(dataset) - train_size
    train_ds, test_ds = random_split(
        dataset, [train_size, test_size],
        generator=torch.Generator().manual_seed(42),
    )

    train_loader = DataLoader(train_ds, batch_size=batch_size, shuffle=True)
    test_loader = DataLoader(test_ds, batch_size=batch_size)

    # Infer dimensions
    sample_raw, sample_feat, _ = dataset[0]
    raw_dim = sample_raw.shape[0]
    feat_dim = sample_feat.shape[0]

    if verbose:
        print(f"    Raw bits dimension: {raw_dim}")
        print(f"    Feature dimension:  {feat_dim}")
        print(f"    Total samples:      {len(dataset)} ({train_size} train, {test_size} test)")

    model = HybridDiscriminator(raw_dim, feat_dim)
    optimizer = optim.Adam(model.parameters(), lr=lr, weight_decay=1e-5)
    criterion = nn.BCELoss()

    # Learning rate scheduler — reduce on plateau
    scheduler = optim.lr_scheduler.ReduceLROnPlateau(
        optimizer, mode="min", factor=0.5, patience=8, min_lr=1e-5
    )

    # Training loop
    train_losses = []
    best_val_loss = float("inf")
    best_state = None

    for epoch in range(epochs):
        model.train()
        epoch_loss = 0.0
        n_batches = 0

        for raw, feat, labels in train_loader:
            optimizer.zero_grad()
            outputs = model(raw, feat)
            loss = criterion(outputs, labels)
            loss.backward()
            optimizer.step()
            epoch_loss += loss.item()
            n_batches += 1

        avg_loss = epoch_loss / n_batches
        train_losses.append(avg_loss)
        scheduler.step(avg_loss)

        if verbose and (epoch + 1) % 15 == 0:
            print(f"    Epoch {epoch + 1}/{epochs} — Loss: {avg_loss:.4f}")

        # Track best model
        if avg_loss < best_val_loss:
            best_val_loss = avg_loss
            best_state = {k: v.clone() for k, v in model.state_dict().items()}

    # Restore best model
    if best_state is not None:
        model.load_state_dict(best_state)

    # Evaluation
    model.eval()
    correct = 0
    total = 0
    real_correct = 0
    real_total = 0
    fake_correct = 0
    fake_total = 0
    all_preds = []
    all_labels = []
    total_loss = 0.0
    n_eval_batches = 0

    with torch.no_grad():
        for raw, feat, labels in test_loader:
            outputs = model(raw, feat)
            loss = criterion(outputs, labels)
            total_loss += loss.item()
            n_eval_batches += 1

            predicted = (outputs > 0.5).float()
            correct += (predicted == labels).sum().item()
            total += labels.size(0)

            real_mask = labels == 1
            fake_mask = labels == 0
            real_correct += (predicted[real_mask] == labels[real_mask]).sum().item()
            real_total += real_mask.sum().item()
            fake_correct += (predicted[fake_mask] == labels[fake_mask]).sum().item()
            fake_total += fake_mask.sum().item()

            all_preds.extend(outputs.tolist())
            all_labels.extend(labels.tolist())

    accuracy = correct / total if total > 0 else 0.0
    real_acc = real_correct / real_total if real_total > 0 else 0.0
    fake_acc = fake_correct / fake_total if fake_total > 0 else 0.0
    eval_loss = total_loss / n_eval_batches if n_eval_batches > 0 else 0.0

    # Confidence separation: how well-separated are real and fake predictions?
    real_preds = [p for p, l in zip(all_preds, all_labels) if l == 1]
    fake_preds = [p for p, l in zip(all_preds, all_labels) if l == 0]
    mean_real_pred = sum(real_preds) / len(real_preds) if real_preds else 0.5
    mean_fake_pred = sum(fake_preds) / len(fake_preds) if fake_preds else 0.5
    prediction_separation = mean_real_pred - mean_fake_pred

    # Signal detection: require accuracy > 0.52 (2% above chance)
    signal = accuracy > 0.52
    signal_strength = min(1.0, max(0.0, (accuracy - 0.50) / 0.20))  # 0 at 50%, 1.0 at 70%

    return {
        "model": "hybrid_discriminator",
        "n_records": len(records),
        "total_test_samples": total,
        "raw_dim": raw_dim,
        "feature_dim": feat_dim,
        "accuracy": accuracy,
        "real_pair_accuracy": real_acc,
        "fake_pair_accuracy": fake_acc,
        "baseline_accuracy": 0.5,
        "signal_above_baseline": accuracy - 0.5,
        "prediction_separation": prediction_separation,
        "mean_real_prediction": mean_real_pred,
        "mean_fake_prediction": mean_fake_pred,
        "eval_loss": eval_loss,
        "final_train_loss": train_losses[-1] if train_losses else None,
        "best_train_loss": best_val_loss,
        "signal": signal,
        "signal_strength": signal_strength,
        "interpretation": (
            f"Accuracy: {accuracy:.4f} (baseline 0.50, separation: {prediction_separation:.4f}). "
            + (
                f"SIGNAL: Model distinguishes real from shuffled pairs "
                f"({signal_strength:.0%} strength)."
                if signal
                else "No signal: accuracy within noise of random guessing."
            )
        ),
    }


# --- Reporting ---

def print_results(results: dict, label: str = ""):
    """Print human-readable results."""
    if label:
        print(f"\n  {'='*56}")
        print(f"    {label}")
        print(f"  {'='*56}")

    print(f"    Records:              {results['n_records']}")
    print(f"    Test samples:         {results['total_test_samples']}")
    print(f"    Input dims:           {results['raw_dim']} raw + {results['feature_dim']} features")
    print(f"    Accuracy:             {results['accuracy']:.4f}  (baseline: 0.50)")
    print(f"    Real pair accuracy:   {results['real_pair_accuracy']:.4f}")
    print(f"    Fake pair accuracy:   {results['fake_pair_accuracy']:.4f}")
    print(f"    Prediction sep:       {results['prediction_separation']:.4f}")
    print(f"    Train loss (final):   {results['final_train_loss']:.4f}")
    print(f"    Eval loss:            {results['eval_loss']:.4f}")
    if results["signal"]:
        print(f"    >> SIGNAL DETECTED (strength: {results['signal_strength']:.2f})")
    else:
        print(f"    >> No signal")


def print_batch_summary(all_results: dict):
    """Print summary table for batch analysis."""
    print(f"\n{'='*80}")
    print("  HYBRID NN — BATCH SUMMARY")
    print(f"{'='*80}")
    print(f"\n  {'Variant':<22} {'Accuracy':>9} {'Signal':>8} {'Strength':>9} {'PredSep':>9} {'EvalLoss':>9}")
    print(f"  {'-'*70}")

    for name, results in sorted(
        all_results.items(),
        key=lambda x: -x[1]["accuracy"],
    ):
        sig_str = "YES" if results["signal"] else "—"
        strength_str = f"{results['signal_strength']:.2f}" if results["signal"] else "—"
        print(
            f"  {name:<22} {results['accuracy']:>8.4f} {sig_str:>8} "
            f"{strength_str:>9} {results['prediction_separation']:>+8.4f} "
            f"{results['eval_loss']:>8.4f}"
        )

    print(f"\n  Signal threshold: accuracy > 0.52")
    n_signal = sum(1 for r in all_results.values() if r["signal"])
    n_total = len(all_results)
    print(f"  Variants with signal: {n_signal}/{n_total}")


# --- Main ---

def main():
    parser = argparse.ArgumentParser(
        description="Feature-enhanced hybrid NN for hash function weakness detection."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Single dataset
    single_parser = subparsers.add_parser("single", help="Analyze a single dataset")
    single_parser.add_argument("--data", required=True, help="Path to JSONL dataset")
    single_parser.add_argument("--output", default="results/hybrid_single.json")
    single_parser.add_argument("--epochs", type=int, default=60)
    single_parser.add_argument("--batch-size", type=int, default=128)
    single_parser.add_argument("--lr", type=float, default=1e-3)

    # Batch mode (directory of datasets)
    batch_parser = subparsers.add_parser("batch", help="Analyze all datasets in a directory")
    batch_parser.add_argument("--data-dir", required=True, help="Directory of JSONL files")
    batch_parser.add_argument("--output", default="results/hybrid_batch.json")
    batch_parser.add_argument("--epochs", type=int, default=60)
    batch_parser.add_argument("--batch-size", type=int, default=128)
    batch_parser.add_argument("--lr", type=float, default=1e-3)

    # Compare target vs control
    compare_parser = subparsers.add_parser("compare", help="Compare target vs control")
    compare_parser.add_argument("--target", required=True, help="Target dataset")
    compare_parser.add_argument("--control", required=True, help="Control dataset")
    compare_parser.add_argument("--output", default="results/hybrid_compare.json")
    compare_parser.add_argument("--epochs", type=int, default=60)
    compare_parser.add_argument("--batch-size", type=int, default=128)
    compare_parser.add_argument("--lr", type=float, default=1e-3)

    args = parser.parse_args()

    if args.command == "single":
        print(f"Loading: {args.data}")
        records = load_records(args.data)
        print(f"Training hybrid discriminator on {len(records)} records...")
        results = train_hybrid(records, epochs=args.epochs, batch_size=args.batch_size, lr=args.lr)
        print_results(results, Path(args.data).stem)

        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\nResults saved to {args.output}")

    elif args.command == "batch":
        jsonl_files = sorted(Path(args.data_dir).glob("*.jsonl"))
        if not jsonl_files:
            print(f"No JSONL files found in {args.data_dir}")
            return

        print(f"Found {len(jsonl_files)} datasets to analyze\n")

        all_results = {}
        for filepath in jsonl_files:
            name = filepath.stem
            print(f"Analyzing: {name}")
            records = load_records(str(filepath))
            results = train_hybrid(
                records, epochs=args.epochs, batch_size=args.batch_size, lr=args.lr
            )
            all_results[name] = results
            print_results(results, name)

        print_batch_summary(all_results)

        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w") as f:
            json.dump(all_results, f, indent=2)
        print(f"\nAll results saved to {args.output}")

    elif args.command == "compare":
        all_results = {}
        for label, filepath in [("target", args.target), ("control", args.control)]:
            print(f"\n{'#'*60}")
            print(f"  {label.upper()}: {filepath}")
            print(f"{'#'*60}")

            records = load_records(filepath)
            results = train_hybrid(
                records, epochs=args.epochs, batch_size=args.batch_size, lr=args.lr
            )
            all_results[label] = results
            print_results(results, f"{label.upper()} — {Path(filepath).stem}")

        # Comparison
        t = all_results["target"]
        c = all_results["control"]
        print(f"\n{'='*60}")
        print("  COMPARISON")
        print(f"{'='*60}")
        print(f"  Target accuracy:   {t['accuracy']:.4f}  (signal: {t['signal_above_baseline']:+.4f})")
        print(f"  Control accuracy:  {c['accuracy']:.4f}  (signal: {c['signal_above_baseline']:+.4f})")
        print(f"  Delta:             {t['accuracy'] - c['accuracy']:+.4f}")
        print(f"  Target pred sep:   {t['prediction_separation']:+.4f}")
        print(f"  Control pred sep:  {c['prediction_separation']:+.4f}")

        target_signal = t["accuracy"] > 0.52 and t["accuracy"] > c["accuracy"] + 0.02
        print(f"\n  VERDICT: {'SIGNAL — target shows structure beyond control' if target_signal else 'No significant difference'}")

        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w") as f:
            json.dump(all_results, f, indent=2)
        print(f"\nResults saved to {args.output}")


if __name__ == "__main__":
    main()
