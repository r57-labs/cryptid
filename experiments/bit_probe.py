#!/usr/bin/env python3
"""
Bit-level probing for hash function structure detection.

Instead of predicting the full plaintext, this trains one binary classifier
per bit position: "given the hash output, predict whether bit N of the
plaintext is 0 or 1." If any bit is predictable above 50%, information
is leaking through the hash function.

Two model variants:
  1. Standard MLP (baseline)
  2. XOR-aware network with multiplicative interactions between input bits,
     designed to capture the kind of algebraic relationships CRC32 uses.

Probes every bit in the first N bytes of the plaintext (default: first 2
bytes = 16 bit positions).

Usage:
  # Probe CRC32 vs random oracle
  python bit_probe.py \
    --target data/raw/crc32_random.jsonl \
    --control data/raw/random_oracle_32_random.jsonl \
    --output results/bit_probe_crc32_results.json

  # Probe with more epochs and larger dataset
  python bit_probe.py \
    --target data/raw/crc32_random.jsonl \
    --control data/raw/random_oracle_32_random.jsonl \
    --epochs 100 --probe-bytes 4 \
    --output results/bit_probe_crc32_deep.json

Requirements:
  pip install torch
"""

import argparse
import json
import os
import statistics
import sys

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


def text_to_bits(text: str, n_bytes: int) -> list[int]:
    """Convert text to list of bits for the first n_bytes."""
    raw_bytes = list(text.encode("utf-8"))[:n_bytes]
    raw_bytes += [0] * (n_bytes - len(raw_bytes))
    bits = []
    for b in raw_bytes:
        bits.extend([(b >> i) & 1 for i in range(7, -1, -1)])
    return bits


class BitProbeDataset(Dataset):
    """
    Dataset for single-bit prediction.
    Each sample: (hash_bits, target_bit_value)
    """

    def __init__(self, records: list[dict], target_bit_index: int, probe_bytes: int = 2):
        self.samples = []
        for r in records:
            h_bits = hex_to_bits(r["hash"])
            pt_bits = text_to_bits(r["plaintext"], probe_bytes)
            if target_bit_index < len(pt_bits):
                self.samples.append((h_bits, pt_bits[target_bit_index]))

    def __len__(self):
        return len(self.samples)

    def __getitem__(self, idx):
        h_bits, target = self.samples[idx]
        return (
            torch.tensor(h_bits, dtype=torch.float32),
            torch.tensor(target, dtype=torch.float32),
        )


# --- Models ---

class BitProbeMLP(nn.Module):
    """
    Standard MLP for single-bit prediction.
    Input: hash bit vector.
    Output: probability that target bit is 1.
    """

    def __init__(self, input_dim: int, hidden_dims: list[int] = None):
        super().__init__()
        if hidden_dims is None:
            hidden_dims = [128, 64, 32]

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


class BitProbeXOR(nn.Module):
    """
    XOR-aware network for single-bit prediction.

    Key insight: CRC32 uses XOR as its fundamental operation. Standard MLPs
    with ReLU struggle to learn XOR-like relationships because ReLU is
    piecewise linear. This network adds explicit pairwise multiplicative
    interactions between input bits (x_i * x_j), which can directly represent
    XOR-like logic (since XOR(a,b) = a + b - 2*a*b in {0,1}).

    Architecture:
      1. Original bits (linear terms)
      2. Pairwise products of randomly sampled bit pairs (interaction terms)
      3. Standard MLP on the combined features
    """

    def __init__(
        self,
        input_dim: int,
        n_interactions: int = 256,
        hidden_dims: list[int] = None,
        seed: int = 42,
    ):
        super().__init__()
        if hidden_dims is None:
            hidden_dims = [128, 64, 32]

        # Pre-compute random pairs for interaction terms
        rng = torch.Generator().manual_seed(seed)
        self.register_buffer(
            "pair_i",
            torch.randint(0, input_dim, (n_interactions,), generator=rng),
        )
        self.register_buffer(
            "pair_j",
            torch.randint(0, input_dim, (n_interactions,), generator=rng),
        )

        # Combined features: original bits + interaction terms
        combined_dim = input_dim + n_interactions

        layers = []
        prev_dim = combined_dim
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
        # Compute pairwise products: x[i] * x[j] for sampled pairs
        interactions = x[:, self.pair_i] * x[:, self.pair_j]
        # Concatenate original features with interaction terms
        combined = torch.cat([x, interactions], dim=1)
        return self.network(combined).squeeze(-1)


# --- Training ---

def train_bit_probe(
    records: list[dict],
    target_bit: int,
    model_type: str = "mlp",
    probe_bytes: int = 2,
    epochs: int = 50,
    batch_size: int = 64,
    lr: float = 1e-3,
) -> dict:
    """Train a single-bit probe and return accuracy."""

    dataset = BitProbeDataset(records, target_bit, probe_bytes)

    if len(dataset) == 0:
        return {"bit": target_bit, "model": model_type, "error": "No samples"}

    # Check class balance
    targets = [dataset[i][1].item() for i in range(len(dataset))]
    n_ones = sum(targets)
    n_zeros = len(targets) - n_ones
    class_balance = n_ones / len(targets)

    # Split 80/20
    train_size = int(0.8 * len(dataset))
    test_size = len(dataset) - train_size
    train_ds, test_ds = random_split(
        dataset, [train_size, test_size],
        generator=torch.Generator().manual_seed(42),
    )

    train_loader = DataLoader(train_ds, batch_size=batch_size, shuffle=True)
    test_loader = DataLoader(test_ds, batch_size=batch_size)

    # Infer input dim
    sample_input, _ = dataset[0]
    input_dim = sample_input.shape[0]

    # Create model
    if model_type == "xor":
        model = BitProbeXOR(input_dim)
    else:
        model = BitProbeMLP(input_dim)

    optimizer = optim.Adam(model.parameters(), lr=lr)
    criterion = nn.BCELoss()

    # Training
    for epoch in range(epochs):
        model.train()
        for inputs, labels in train_loader:
            optimizer.zero_grad()
            outputs = model(inputs)
            loss = criterion(outputs, labels)
            loss.backward()
            optimizer.step()

    # Evaluation
    model.eval()
    correct = 0
    total = 0
    predictions_sum = 0.0

    with torch.no_grad():
        for inputs, labels in test_loader:
            outputs = model(inputs)
            predicted = (outputs > 0.5).float()
            correct += (predicted == labels).sum().item()
            total += labels.size(0)
            predictions_sum += outputs.sum().item()

    accuracy = correct / total if total > 0 else 0.0
    mean_prediction = predictions_sum / total if total > 0 else 0.5

    # The meaningful baseline is the majority class rate
    # (if 60% of targets are 1, always guessing 1 gives 60%)
    majority_baseline = max(class_balance, 1 - class_balance)

    return {
        "bit_index": target_bit,
        "byte_index": target_bit // 8,
        "bit_in_byte": target_bit % 8,
        "model_type": model_type,
        "accuracy": accuracy,
        "majority_baseline": majority_baseline,
        "signal_above_majority": accuracy - majority_baseline,
        "class_balance": class_balance,
        "mean_prediction": mean_prediction,
        "test_samples": total,
    }


def run_full_probe(
    records: list[dict],
    probe_bytes: int = 2,
    epochs: int = 50,
    batch_size: int = 64,
    lr: float = 1e-3,
    verbose: bool = True,
) -> list[dict]:
    """Run both MLP and XOR probes across all bit positions."""
    n_bits = probe_bytes * 8
    results = []

    for bit_idx in range(n_bits):
        for model_type in ["mlp", "xor"]:
            result = train_bit_probe(
                records, bit_idx, model_type, probe_bytes, epochs, batch_size, lr,
            )
            results.append(result)

            if verbose:
                acc = result["accuracy"]
                base = result["majority_baseline"]
                sig = result["signal_above_majority"]
                flag = " <<<" if sig > 0.02 else ""
                print(
                    f"  Bit {bit_idx:2d} ({model_type:3s}): "
                    f"acc={acc:.4f}  base={base:.4f}  signal={sig:+.4f}{flag}"
                )

    return results


# --- Reporting ---

def print_summary(target_results: list[dict], control_results: list[dict]):
    """Print comparison summary."""

    print(f"\n{'='*70}")
    print("  BIT PROBE COMPARISON SUMMARY")
    print(f"{'='*70}")

    # Group by model type
    for model_type in ["mlp", "xor"]:
        t_results = [r for r in target_results if r["model_type"] == model_type]
        c_results = [r for r in control_results if r["model_type"] == model_type]

        t_accs = [r["accuracy"] for r in t_results]
        c_accs = [r["accuracy"] for r in c_results]
        t_sigs = [r["signal_above_majority"] for r in t_results]
        c_sigs = [r["signal_above_majority"] for r in c_results]

        print(f"\n  --- {model_type.upper()} Model ---")
        print(f"  {'Metric':<30} {'Target':>10} {'Control':>10} {'Delta':>10}")
        print(f"  {'-'*60}")
        print(f"  {'Mean accuracy':<30} {statistics.mean(t_accs):>10.4f} {statistics.mean(c_accs):>10.4f} {statistics.mean(t_accs)-statistics.mean(c_accs):>+10.4f}")
        print(f"  {'Max accuracy':<30} {max(t_accs):>10.4f} {max(c_accs):>10.4f} {max(t_accs)-max(c_accs):>+10.4f}")
        print(f"  {'Mean signal above majority':<30} {statistics.mean(t_sigs):>10.4f} {statistics.mean(c_sigs):>10.4f} {statistics.mean(t_sigs)-statistics.mean(c_sigs):>+10.4f}")
        print(f"  {'Max signal above majority':<30} {max(t_sigs):>10.4f} {max(c_sigs):>10.4f} {max(t_sigs)-max(c_sigs):>+10.4f}")

        # Count bits with significant signal (>2% above majority baseline)
        t_sig_bits = sum(1 for s in t_sigs if s > 0.02)
        c_sig_bits = sum(1 for s in c_sigs if s > 0.02)
        print(f"  {'Bits with signal >2%':<30} {t_sig_bits:>10d} {c_sig_bits:>10d} {t_sig_bits-c_sig_bits:>+10d}")

    # Overall verdict
    target_mlp_max = max(r["signal_above_majority"] for r in target_results if r["model_type"] == "mlp")
    control_mlp_max = max(r["signal_above_majority"] for r in control_results if r["model_type"] == "mlp")
    target_xor_max = max(r["signal_above_majority"] for r in target_results if r["model_type"] == "xor")
    control_xor_max = max(r["signal_above_majority"] for r in control_results if r["model_type"] == "xor")

    # Signal = target has bits above 2% that control doesn't, OR target max significantly exceeds control max
    has_signal = (
        (target_mlp_max > 0.03 and target_mlp_max > control_mlp_max + 0.02)
        or (target_xor_max > 0.03 and target_xor_max > control_xor_max + 0.02)
    )

    print(f"\n  {'='*60}")
    if has_signal:
        print("  SIGNAL DETECTED: Target hash shows predictable bit structure")
        print("  beyond what's seen in the random oracle control.")
    else:
        print("  NO SIGNAL: Target hash shows no more predictable structure")
        print("  than the random oracle control.")
    print(f"  {'='*60}")


# --- Main ---

def main():
    parser = argparse.ArgumentParser(
        description="Bit-level probing for hash function structure detection."
    )
    parser.add_argument("--target", required=True, help="Target algorithm dataset (e.g., CRC32)")
    parser.add_argument("--control", required=True, help="Control dataset (random oracle)")
    parser.add_argument("--output", default="results/bit_probe_results.json")
    parser.add_argument("--epochs", type=int, default=50)
    parser.add_argument("--batch-size", type=int, default=64)
    parser.add_argument("--lr", type=float, default=1e-3)
    parser.add_argument("--probe-bytes", type=int, default=2,
                        help="Number of plaintext bytes to probe (default: 2 = 16 bits)")

    args = parser.parse_args()

    all_results = {}

    for label, filepath in [("target", args.target), ("control", args.control)]:
        print(f"\n{'#'*70}")
        print(f"  {label.upper()}: {filepath}")
        print(f"{'#'*70}")

        records = load_records(filepath)
        print(f"Loaded {len(records)} records\n")

        results = run_full_probe(
            records, args.probe_bytes, args.epochs, args.batch_size, args.lr,
        )
        all_results[label] = results

    # Summary
    print_summary(all_results["target"], all_results["control"])

    # Save
    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(all_results, f, indent=2)
    print(f"\nFull results saved to {args.output}")


if __name__ == "__main__":
    main()
