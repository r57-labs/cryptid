#!/usr/bin/env python3
"""
Byte-level neural network for hash function structure detection.

Unlike the LLM LoRA approach, this works directly on raw bytes/bits,
avoiding tokenization artifacts that obscure bit-level patterns.

Two model architectures:

1. Discriminator: Given a (hash, plaintext) pair, classify as real or shuffled.
   Tests whether any statistical relationship exists between input and output.
   (Equivalent to Tier 3, but with a purpose-built architecture.)

2. Predictor: Given a hash, predict the plaintext bytes.
   Tests whether the hash→plaintext mapping is learnable.
   (Equivalent to Tiers 1 and 2, but at byte level.)

Usage:
  # Train discriminator on CRC32 + random strings
  python byte_model.py discriminator \
    --data data/raw/crc32_random.jsonl \
    --output results/byte_crc32_random_discriminator.json

  # Train predictor on CRC32 + random strings
  python byte_model.py predictor \
    --data data/raw/crc32_random.jsonl \
    --output results/byte_crc32_random_predictor.json

  # Run full experiment (both models, both algos, with control)
  python byte_model.py full \
    --target data/raw/crc32_random.jsonl \
    --control data/raw/random_oracle_32_random.jsonl \
    --output results/byte_full_results.json

Requirements:
  pip install torch  (CPU is fine — these models are tiny)
"""

import argparse
import json
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


def text_to_bytes(text: str, max_len: int) -> list[int]:
    """Convert text to list of byte values, zero-padded to max_len."""
    byte_vals = [b for b in text.encode("utf-8")][:max_len]
    byte_vals += [0] * (max_len - len(byte_vals))
    return byte_vals


def bytes_to_bits(byte_vals: list[int]) -> list[int]:
    """Convert byte values to list of bits."""
    bits = []
    for b in byte_vals:
        bits.extend([(b >> i) & 1 for i in range(7, -1, -1)])
    return bits


class DiscriminatorDataset(Dataset):
    """
    Dataset for the discriminator model.
    Each sample: (hash_bits, plaintext_bits, label)
    label=1 for real pairs, label=0 for shuffled pairs.
    """

    def __init__(self, records: list[dict], max_plaintext_len: int = 16):
        self.samples = []
        self.max_pt_len = max_plaintext_len

        # Create real pairs (label=1)
        for r in records:
            h_bits = hex_to_bits(r["hash"])
            pt_bytes = text_to_bytes(r["plaintext"], max_plaintext_len)
            pt_bits = bytes_to_bits(pt_bytes)
            self.samples.append((h_bits, pt_bits, 1))

        # Create shuffled pairs (label=0)
        rng = random.Random(99)
        plaintexts = [r["plaintext"] for r in records]
        hashes = [r["hash"] for r in records]
        shuffled_hashes = hashes.copy()
        rng.shuffle(shuffled_hashes)

        # Ensure no pair stays matched
        for i in range(len(shuffled_hashes)):
            if shuffled_hashes[i] == hashes[i]:
                j = (i + 1) % len(shuffled_hashes)
                shuffled_hashes[i], shuffled_hashes[j] = (
                    shuffled_hashes[j],
                    shuffled_hashes[i],
                )

        for pt_str, h_hex in zip(plaintexts, shuffled_hashes):
            h_bits = hex_to_bits(h_hex)
            pt_bytes = text_to_bytes(pt_str, max_plaintext_len)
            pt_bits = bytes_to_bits(pt_bytes)
            self.samples.append((h_bits, pt_bits, 0))

    def __len__(self):
        return len(self.samples)

    def __getitem__(self, idx):
        h_bits, pt_bits, label = self.samples[idx]
        # Concatenate hash and plaintext bits as input
        combined = h_bits + pt_bits
        return (
            torch.tensor(combined, dtype=torch.float32),
            torch.tensor(label, dtype=torch.float32),
        )


class PredictorDataset(Dataset):
    """
    Dataset for the predictor model.
    Each sample: (hash_bits, plaintext_bytes)
    The model predicts plaintext byte values from hash bits.
    """

    def __init__(self, records: list[dict], max_plaintext_len: int = 16):
        self.samples = []
        for r in records:
            h_bits = hex_to_bits(r["hash"])
            pt_bytes = text_to_bytes(r["plaintext"], max_plaintext_len)
            self.samples.append((h_bits, pt_bytes))

    def __len__(self):
        return len(self.samples)

    def __getitem__(self, idx):
        h_bits, pt_bytes = self.samples[idx]
        return (
            torch.tensor(h_bits, dtype=torch.float32),
            torch.tensor(pt_bytes, dtype=torch.float32),
        )


# --- Models ---

class Discriminator(nn.Module):
    """
    Binary classifier: does this (hash, plaintext) pair look real?
    Input: concatenated bit vectors of hash + plaintext.
    Output: probability of being a real pair.
    """

    def __init__(self, input_dim: int, hidden_dims: list[int] = None):
        super().__init__()
        if hidden_dims is None:
            hidden_dims = [256, 128, 64]

        layers = []
        prev_dim = input_dim
        for h_dim in hidden_dims:
            layers.extend([
                nn.Linear(prev_dim, h_dim),
                nn.BatchNorm1d(h_dim),
                nn.ReLU(),
                nn.Dropout(0.1),
            ])
            prev_dim = h_dim
        layers.append(nn.Linear(prev_dim, 1))
        layers.append(nn.Sigmoid())

        self.network = nn.Sequential(*layers)

    def forward(self, x):
        return self.network(x).squeeze(-1)


class Predictor(nn.Module):
    """
    Regression model: predict plaintext bytes from hash bits.
    Input: bit vector of hash.
    Output: predicted byte values for each plaintext position.
    """

    def __init__(self, input_dim: int, output_dim: int, hidden_dims: list[int] = None):
        super().__init__()
        if hidden_dims is None:
            hidden_dims = [512, 256, 128]

        layers = []
        prev_dim = input_dim
        for h_dim in hidden_dims:
            layers.extend([
                nn.Linear(prev_dim, h_dim),
                nn.BatchNorm1d(h_dim),
                nn.ReLU(),
                nn.Dropout(0.1),
            ])
            prev_dim = h_dim
        layers.append(nn.Linear(prev_dim, output_dim))

        self.network = nn.Sequential(*layers)

    def forward(self, x):
        return self.network(x)


# --- Training ---

def train_discriminator(
    records: list[dict],
    max_plaintext_len: int = 16,
    epochs: int = 50,
    batch_size: int = 64,
    lr: float = 1e-3,
    verbose: bool = True,
) -> dict:
    """Train the discriminator and return evaluation metrics."""

    dataset = DiscriminatorDataset(records, max_plaintext_len)

    # Split 80/20
    train_size = int(0.8 * len(dataset))
    test_size = len(dataset) - train_size
    train_ds, test_ds = random_split(
        dataset, [train_size, test_size],
        generator=torch.Generator().manual_seed(42),
    )

    train_loader = DataLoader(train_ds, batch_size=batch_size, shuffle=True)
    test_loader = DataLoader(test_ds, batch_size=batch_size)

    # Infer input dimension from first sample
    sample_input, _ = dataset[0]
    input_dim = sample_input.shape[0]

    model = Discriminator(input_dim)
    optimizer = optim.Adam(model.parameters(), lr=lr)
    criterion = nn.BCELoss()

    # Training loop
    train_losses = []
    for epoch in range(epochs):
        model.train()
        epoch_loss = 0.0
        n_batches = 0

        for inputs, labels in train_loader:
            optimizer.zero_grad()
            outputs = model(inputs)
            loss = criterion(outputs, labels)
            loss.backward()
            optimizer.step()
            epoch_loss += loss.item()
            n_batches += 1

        avg_loss = epoch_loss / n_batches
        train_losses.append(avg_loss)

        if verbose and (epoch + 1) % 10 == 0:
            print(f"  Epoch {epoch + 1}/{epochs} — Loss: {avg_loss:.4f}")

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

    with torch.no_grad():
        for inputs, labels in test_loader:
            outputs = model(inputs)
            predicted = (outputs > 0.5).float()
            correct += (predicted == labels).sum().item()
            total += labels.size(0)

            # Per-class accuracy
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

    return {
        "model": "discriminator",
        "total_test_samples": total,
        "accuracy": accuracy,
        "real_pair_accuracy": real_acc,
        "fake_pair_accuracy": fake_acc,
        "baseline_accuracy": 0.5,  # Random guessing
        "signal_above_baseline": accuracy - 0.5,
        "final_train_loss": train_losses[-1] if train_losses else None,
        "train_loss_curve": train_losses,
        "interpretation": (
            f"Model achieves {accuracy:.4f} accuracy (baseline 0.50). "
            + (
                "SIGNAL: Model distinguishes real from shuffled pairs above chance."
                if accuracy > 0.52  # ~2% above chance as threshold
                else "No signal: accuracy is within noise of random guessing."
            )
        ),
    }


def train_predictor(
    records: list[dict],
    max_plaintext_len: int = 16,
    epochs: int = 50,
    batch_size: int = 64,
    lr: float = 1e-3,
    verbose: bool = True,
) -> dict:
    """Train the predictor and return evaluation metrics."""

    dataset = PredictorDataset(records, max_plaintext_len)

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
    sample_input, sample_target = dataset[0]
    input_dim = sample_input.shape[0]
    output_dim = sample_target.shape[0]

    model = Predictor(input_dim, output_dim)
    optimizer = optim.Adam(model.parameters(), lr=lr)
    criterion = nn.MSELoss()

    # Also track a "random baseline" — MSE of predicting the training mean
    all_targets = []
    for _, target in train_ds:
        all_targets.append(target)
    mean_target = torch.stack(all_targets).mean(dim=0)

    # Training loop
    train_losses = []
    for epoch in range(epochs):
        model.train()
        epoch_loss = 0.0
        n_batches = 0

        for inputs, targets in train_loader:
            optimizer.zero_grad()
            outputs = model(inputs)
            loss = criterion(outputs, targets)
            loss.backward()
            optimizer.step()
            epoch_loss += loss.item()
            n_batches += 1

        avg_loss = epoch_loss / n_batches
        train_losses.append(avg_loss)

        if verbose and (epoch + 1) % 10 == 0:
            print(f"  Epoch {epoch + 1}/{epochs} — Loss: {avg_loss:.4f}")

    # Evaluation
    model.eval()
    total_mse = 0.0
    baseline_mse = 0.0
    byte_correct = 0
    byte_total = 0
    exact_matches = 0
    n_samples = 0

    with torch.no_grad():
        for inputs, targets in test_loader:
            outputs = model(inputs)

            # MSE
            total_mse += criterion(outputs, targets).item() * inputs.size(0)

            # Baseline MSE (always predict training mean)
            baseline_pred = mean_target.unsqueeze(0).expand_as(targets)
            baseline_mse += criterion(baseline_pred, targets).item() * inputs.size(0)

            # Per-byte accuracy (round to nearest int, compare)
            pred_bytes = outputs.round().long()
            true_bytes = targets.long()
            byte_correct += (pred_bytes == true_bytes).sum().item()
            byte_total += true_bytes.numel()

            # Exact sequence matches
            exact_matches += (
                (pred_bytes == true_bytes).all(dim=1).sum().item()
            )
            n_samples += inputs.size(0)

    avg_mse = total_mse / n_samples if n_samples > 0 else 0.0
    avg_baseline_mse = baseline_mse / n_samples if n_samples > 0 else 0.0
    byte_accuracy = byte_correct / byte_total if byte_total > 0 else 0.0

    return {
        "model": "predictor",
        "total_test_samples": n_samples,
        "mse": avg_mse,
        "baseline_mse": avg_baseline_mse,
        "mse_improvement_over_baseline": avg_baseline_mse - avg_mse,
        "byte_accuracy": byte_accuracy,
        "exact_sequence_matches": exact_matches,
        "exact_match_rate": exact_matches / n_samples if n_samples > 0 else 0.0,
        "final_train_loss": train_losses[-1] if train_losses else None,
        "train_loss_curve": train_losses,
        "interpretation": (
            f"Model MSE: {avg_mse:.4f}, Baseline MSE: {avg_baseline_mse:.4f}. "
            + (
                "SIGNAL: Model predicts byte values better than the constant-mean baseline."
                if avg_mse < avg_baseline_mse * 0.95  # 5% improvement threshold
                else "No signal: model performs similarly to always-predict-mean baseline."
            )
        ),
    }


# --- Reporting ---

def print_results(results: dict, label: str = ""):
    """Print human-readable results."""
    if label:
        print(f"\n{'='*60}")
        print(f"  {label}")
        print(f"{'='*60}")

    if results["model"] == "discriminator":
        print(f"  Test samples:         {results['total_test_samples']}")
        print(f"  Accuracy:             {results['accuracy']:.4f}")
        print(f"  Real pair accuracy:   {results['real_pair_accuracy']:.4f}")
        print(f"  Fake pair accuracy:   {results['fake_pair_accuracy']:.4f}")
        print(f"  Baseline (random):    {results['baseline_accuracy']:.4f}")
        print(f"  Signal above base:    {results['signal_above_baseline']:.4f}")
        print(f"  Final train loss:     {results['final_train_loss']:.4f}")
        print(f"  >> {results['interpretation']}")

    elif results["model"] == "predictor":
        print(f"  Test samples:         {results['total_test_samples']}")
        print(f"  MSE:                  {results['mse']:.4f}")
        print(f"  Baseline MSE:         {results['baseline_mse']:.4f}")
        print(f"  MSE improvement:      {results['mse_improvement_over_baseline']:.4f}")
        print(f"  Byte accuracy:        {results['byte_accuracy']:.4f}")
        print(f"  Exact matches:        {results['exact_sequence_matches']}/{results['total_test_samples']}")
        print(f"  Final train loss:     {results['final_train_loss']:.4f}")
        print(f"  >> {results['interpretation']}")


# --- Main ---

def main():
    parser = argparse.ArgumentParser(
        description="Byte-level neural network for hash structure detection."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Discriminator command
    disc_parser = subparsers.add_parser("discriminator", help="Train discriminator model")
    disc_parser.add_argument("--data", required=True, help="Path to raw JSONL dataset")
    disc_parser.add_argument("--output", default="results/byte_discriminator.json")
    disc_parser.add_argument("--epochs", type=int, default=50)
    disc_parser.add_argument("--batch-size", type=int, default=64)
    disc_parser.add_argument("--lr", type=float, default=1e-3)
    disc_parser.add_argument("--max-plaintext-len", type=int, default=16)

    # Predictor command
    pred_parser = subparsers.add_parser("predictor", help="Train predictor model")
    pred_parser.add_argument("--data", required=True, help="Path to raw JSONL dataset")
    pred_parser.add_argument("--output", default="results/byte_predictor.json")
    pred_parser.add_argument("--epochs", type=int, default=50)
    pred_parser.add_argument("--batch-size", type=int, default=64)
    pred_parser.add_argument("--lr", type=float, default=1e-3)
    pred_parser.add_argument("--max-plaintext-len", type=int, default=16)

    # Full experiment command
    full_parser = subparsers.add_parser("full", help="Run full experiment with target and control")
    full_parser.add_argument("--target", required=True, help="Target algorithm dataset (e.g., CRC32)")
    full_parser.add_argument("--control", required=True, help="Control dataset (random oracle)")
    full_parser.add_argument("--output", default="results/byte_full_results.json")
    full_parser.add_argument("--epochs", type=int, default=50)
    full_parser.add_argument("--batch-size", type=int, default=64)
    full_parser.add_argument("--lr", type=float, default=1e-3)
    full_parser.add_argument("--max-plaintext-len", type=int, default=16)

    args = parser.parse_args()

    if args.command == "discriminator":
        print(f"Loading data: {args.data}")
        records = load_records(args.data)
        print(f"Training discriminator on {len(records)} records...")
        results = train_discriminator(
            records, args.max_plaintext_len, args.epochs, args.batch_size, args.lr,
        )
        print_results(results, "Discriminator Results")

        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\nResults saved to {args.output}")

    elif args.command == "predictor":
        print(f"Loading data: {args.data}")
        records = load_records(args.data)
        print(f"Training predictor on {len(records)} records...")
        results = train_predictor(
            records, args.max_plaintext_len, args.epochs, args.batch_size, args.lr,
        )
        print_results(results, "Predictor Results")

        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\nResults saved to {args.output}")

    elif args.command == "full":
        all_results = {}

        for label, filepath in [("target", args.target), ("control", args.control)]:
            print(f"\n{'#'*60}")
            print(f"  {label.upper()}: {filepath}")
            print(f"{'#'*60}")

            records = load_records(filepath)
            print(f"Loaded {len(records)} records")

            # Discriminator
            print(f"\nTraining discriminator...")
            disc_results = train_discriminator(
                records, args.max_plaintext_len, args.epochs, args.batch_size, args.lr,
            )
            print_results(disc_results, f"{label.upper()} — Discriminator")

            # Predictor
            print(f"\nTraining predictor...")
            pred_results = train_predictor(
                records, args.max_plaintext_len, args.epochs, args.batch_size, args.lr,
            )
            print_results(pred_results, f"{label.upper()} — Predictor")

            all_results[label] = {
                "file": filepath,
                "discriminator": disc_results,
                "predictor": pred_results,
            }

        # Comparison summary
        print(f"\n{'='*60}")
        print("  COMPARISON SUMMARY")
        print(f"{'='*60}")

        t_disc = all_results["target"]["discriminator"]
        c_disc = all_results["control"]["discriminator"]
        t_pred = all_results["target"]["predictor"]
        c_pred = all_results["control"]["predictor"]

        print(f"\n  Discriminator accuracy:")
        print(f"    Target:   {t_disc['accuracy']:.4f}  (signal: {t_disc['signal_above_baseline']:+.4f})")
        print(f"    Control:  {c_disc['accuracy']:.4f}  (signal: {c_disc['signal_above_baseline']:+.4f})")
        print(f"    Delta:    {t_disc['accuracy'] - c_disc['accuracy']:+.4f}")

        print(f"\n  Predictor MSE (lower = better):")
        print(f"    Target:   {t_pred['mse']:.4f}  (baseline: {t_pred['baseline_mse']:.4f})")
        print(f"    Control:  {c_pred['mse']:.4f}  (baseline: {c_pred['baseline_mse']:.4f})")
        print(f"    Target improvement over baseline:  {t_pred['mse_improvement_over_baseline']:.4f}")
        print(f"    Control improvement over baseline: {c_pred['mse_improvement_over_baseline']:.4f}")

        # Signal requires BOTH: target above chance AND meaningfully better than control
        target_above_chance = t_disc["accuracy"] > 0.52
        target_beats_control = t_disc["accuracy"] - c_disc["accuracy"] > 0.02
        predictor_signal = (
            t_pred["mse_improvement_over_baseline"] > 0
            and t_pred["mse_improvement_over_baseline"]
            > c_pred["mse_improvement_over_baseline"] + 0.5
        )
        overall_signal = (target_above_chance and target_beats_control) or predictor_signal
        print(f"\n  OVERALL: {'SIGNAL DETECTED — target shows structure beyond control' if overall_signal else 'No significant difference between target and control'}")

        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w") as f:
            json.dump(all_results, f, indent=2)
        print(f"\nFull results saved to {args.output}")


if __name__ == "__main__":
    main()
