#!/usr/bin/env python3
"""
Meta-learner: replaces hand-tuned composite scoring with a learned classifier.

Takes the statistical analysis suite's output (signal strengths + raw statistics)
as features and learns the optimal decision boundary between clean and weakened
hash functions. This replaces the manually tuned weights and thresholds in
compute_composite_score().

Two classifier options:
  1. Logistic regression (default): simple, interpretable, shows which features
     matter most via learned weights. No external dependencies.
  2. Random forest (if sklearn available): handles nonlinear interactions better.

Training workflow:
  1. Generate many calibration variants (synthetic_weakness.py)
  2. Run statistical analysis on each
  3. Train meta-learner on (features, label) pairs
  4. Save trained model for use in production analysis

Production workflow:
  1. Run statistical analysis on unknown dataset
  2. Feed results through trained meta-learner
  3. Get probability of weakness + confidence

Usage:
  # Train on generated training data
  python meta_learner.py train \
    --training-data data/meta_training/training_data.json \
    --output models/meta_learner.json

  # Generate training data + train in one step
  python meta_learner.py generate-and-train \
    --n-batches 10 --variants-per-batch 12 \
    --output models/meta_learner.json

  # Classify a single dataset's statistical results
  python meta_learner.py classify \
    --model models/meta_learner.json \
    --stats-results results/stats_results.json

  # Classify a batch of datasets
  python meta_learner.py classify-batch \
    --model models/meta_learner.json \
    --data-dir data/calibration/datasets/

Requirements:
  None beyond Python stdlib (logistic regression implemented from scratch)
  Optional: scikit-learn (for random forest option)
"""

import argparse
import json
import math
import os
import random
import sys
from pathlib import Path


# --- Feature Extraction ---

FEATURE_NAMES = [
    # Signal strengths (6 features) — already scale-independent
    "bit_correlation",
    "entropy",
    "avalanche",
    "frequency",
    "mutual_information",
    "interaction",
    # Sample-size-normalized statistics (12 features)
    "bit_corr_max_chi2_norm",    # max_chi2 / n_samples (chi2 scales with N)
    "bit_corr_max_phi",          # phi coefficient (already sqrt(N)-normalized)
    "bit_corr_n_sig_frac",       # n_significant / total_pairs
    "entropy_min_bit",           # 0-1, doesn't scale with N
    "entropy_min_byte",          # 0-8, doesn't scale with N
    "avalanche_deviation",       # proportion, doesn't scale with N
    "avalanche_stdev_ratio",     # ratio, doesn't scale with N
    "freq_max_chi2_norm",        # max_chi2 / n_samples
    "mi_real_norm",              # MI / log2(n_samples) (MI grows with N)
    "mi_threshold_norm",         # threshold / log2(n_samples)
    "interaction_n_strong_frac", # n_strong / n_total_tests
    "interaction_n_hits_frac",   # n_hits / n_total_tests
    # Width + scale context (5 features)
    "output_bits",               # raw width (64, 128, 160, 256, 512)
    "log_n_samples",             # log2(n_samples) — lets model know the scale
    "bit_corr_n_sig_width_norm", # n_significant / (n_input_bits * n_output_bits)
    "interaction_n_strong_norm", # same as frac above, kept for back-compat naming
    "interaction_n_hits_norm",   # same as frac above, kept for back-compat naming
]


def extract_features_from_stats(stats_results: dict) -> list[float]:
    """
    Extract the feature vector from statistical analysis results.

    All features are normalized to be scale-independent:
    - Chi-squared values divided by n_samples (chi2 scales linearly with N)
    - Count-based features divided by total tests
    - MI divided by log2(n_samples) (MI grows logarithmically)
    - Phi coefficient, entropy, avalanche deviation already scale-independent

    This ensures the meta-learner works correctly regardless of sample size
    (2K, 10K, 100K, etc.) without retraining.
    """
    import math
    features = []

    # Detect sample size from any test that reports it
    n_samples = 10000  # default fallback
    for test_name in ["bit_correlation", "entropy", "frequency", "interaction"]:
        test = stats_results.get(test_name, {})
        if "n_samples" in test:
            n_samples = test["n_samples"]
            break

    log_n = math.log2(max(n_samples, 2))

    # Signal strengths (6 features) — already scale-independent
    for test_name in ["bit_correlation", "entropy", "avalanche", "frequency",
                       "mutual_information", "interaction"]:
        test = stats_results.get(test_name, {})
        features.append(test.get("signal_strength", 0.0))

    # Sample-size-normalized statistics (12 features)
    bc = stats_results.get("bit_correlation", {})
    features.append(bc.get("max_chi_squared", 0.0) / max(n_samples, 1))  # chi2/N
    features.append(bc.get("max_abs_correlation", 0.0))  # phi, already normalized

    # n_significant as fraction of total pairs
    n_output_bits = 64
    n_input_bits = 80
    for test_name in ["bit_correlation", "entropy", "avalanche", "interaction"]:
        test = stats_results.get(test_name, {})
        if "n_output_bits" in test:
            n_output_bits = test["n_output_bits"]
            break
    if "n_input_bits" in bc:
        n_input_bits = bc["n_input_bits"]
    n_total_pairs = n_input_bits * n_output_bits
    n_sig = float(bc.get("n_significant_pairs_p001", 0))
    features.append(n_sig / max(n_total_pairs, 1))

    ent = stats_results.get("entropy", {})
    features.append(ent.get("min_bit_entropy", 1.0))
    features.append(ent.get("min_byte_entropy", 8.0))

    av = stats_results.get("avalanche", {})
    features.append(av.get("deviation_from_expected", 0.0))
    features.append(av.get("stdev_ratio", 1.0))

    freq = stats_results.get("frequency", {})
    features.append(freq.get("max_chi_squared_overall", 0.0) / max(n_samples, 1))  # chi2/N

    mi = stats_results.get("mutual_information", {})
    features.append(mi.get("mutual_information_bits", 0.0) / max(log_n, 1))  # MI/log(N)
    features.append(mi.get("permutation_threshold", 0.0) / max(log_n, 1))

    inter = stats_results.get("interaction", {})
    n_strong = float(inter.get("n_strong_hits", 0))
    n_hits = float(inter.get("n_hits_p001", 0))
    n_total_interaction = float(inter.get("n_total_tests", 1))
    if n_total_interaction < 1:
        n_total_interaction = 1.0
    features.append(n_strong / n_total_interaction)
    features.append(n_hits / n_total_interaction)

    # Width + scale context (5 features)
    features.append(float(n_output_bits))
    features.append(log_n)
    features.append(n_sig / max(n_total_pairs, 1))  # duplicate of above, kept for compat
    features.append(n_strong / n_total_interaction)  # duplicate, kept for compat
    features.append(n_hits / n_total_interaction)     # duplicate, kept for compat

    return features


# --- Logistic Regression (from scratch) ---

def sigmoid(z: float) -> float:
    """Numerically stable sigmoid."""
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-z))
    else:
        ez = math.exp(z)
        return ez / (1.0 + ez)


def normalize_features(
    X: list[list[float]],
    means: list[float] = None,
    stds: list[float] = None,
) -> tuple[list[list[float]], list[float], list[float]]:
    """Z-score normalization. Returns normalized X, means, stds."""
    n = len(X)
    d = len(X[0]) if X else 0

    if means is None:
        means = [sum(X[i][j] for i in range(n)) / n for j in range(d)]
    if stds is None:
        stds = []
        for j in range(d):
            variance = sum((X[i][j] - means[j]) ** 2 for i in range(n)) / max(n - 1, 1)
            stds.append(math.sqrt(variance) if variance > 0 else 1.0)

    X_norm = []
    for i in range(n):
        row = [(X[i][j] - means[j]) / stds[j] if stds[j] > 0 else 0.0 for j in range(d)]
        X_norm.append(row)

    return X_norm, means, stds


def train_logistic_regression(
    X: list[list[float]],
    y: list[int],
    lr: float = 0.1,
    epochs: int = 500,
    l2_lambda: float = 0.01,
    verbose: bool = True,
) -> dict:
    """
    Train L2-regularized logistic regression via gradient descent.

    Returns model dict with weights, bias, normalization params, and metrics.
    """
    n = len(X)
    d = len(X[0])

    # Normalize features
    X_norm, means, stds = normalize_features(X)

    # Initialize weights
    rng = random.Random(42)
    weights = [rng.gauss(0, 0.01) for _ in range(d)]
    bias = 0.0

    # Training loop
    losses = []
    for epoch in range(epochs):
        # Forward pass + compute loss
        total_loss = 0.0
        grad_w = [0.0] * d
        grad_b = 0.0

        for i in range(n):
            z = sum(weights[j] * X_norm[i][j] for j in range(d)) + bias
            pred = sigmoid(z)

            # Binary cross-entropy
            eps = 1e-12
            loss = -(y[i] * math.log(pred + eps) + (1 - y[i]) * math.log(1 - pred + eps))
            total_loss += loss

            # Gradients
            error = pred - y[i]
            for j in range(d):
                grad_w[j] += error * X_norm[i][j]
            grad_b += error

        # Average gradients + L2 regularization
        for j in range(d):
            grad_w[j] = grad_w[j] / n + l2_lambda * weights[j]
        grad_b /= n

        # Update
        for j in range(d):
            weights[j] -= lr * grad_w[j]
        bias -= lr * grad_b

        avg_loss = total_loss / n
        losses.append(avg_loss)

        if verbose and (epoch + 1) % 100 == 0:
            print(f"  Epoch {epoch + 1}/{epochs} — Loss: {avg_loss:.4f}")

    # Compute training accuracy and optimal threshold via F1
    all_probs = []
    for i in range(n):
        z = sum(weights[j] * X_norm[i][j] for j in range(d)) + bias
        all_probs.append(sigmoid(z))

    # Try thresholds from 0.1 to 0.9 to find best F1
    best_threshold = 0.5
    best_f1 = 0.0
    for t_int in range(10, 91, 5):
        t = t_int / 100.0
        tp = sum(1 for p, yi in zip(all_probs, y) if p >= t and yi == 1)
        fp = sum(1 for p, yi in zip(all_probs, y) if p >= t and yi == 0)
        fn = sum(1 for p, yi in zip(all_probs, y) if p < t and yi == 1)
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        if f1 > best_f1:
            best_f1 = f1
            best_threshold = t

    # Final metrics at best threshold
    correct = sum(
        1 for p, yi in zip(all_probs, y)
        if (p >= best_threshold) == (yi == 1)
    )
    accuracy = correct / n

    # Feature importance: absolute weight values (normalized features)
    feature_importance = sorted(
        zip(FEATURE_NAMES, weights),
        key=lambda x: -abs(x[1]),
    )

    return {
        "weights": weights,
        "bias": bias,
        "means": means,
        "stds": stds,
        "threshold": best_threshold,
        "training_accuracy": accuracy,
        "training_f1": best_f1,
        "training_loss": losses[-1],
        "feature_importance": [
            {"feature": name, "weight": w} for name, w in feature_importance
        ],
        "n_training_examples": n,
        "n_features": d,
    }


def predict_logistic(model: dict, features: list[float]) -> dict:
    """
    Predict weakness probability for a single feature vector.
    Returns probability, predicted label, and confidence.
    """
    weights = model["weights"]
    bias = model["bias"]
    means = model["means"]
    stds = model["stds"]
    threshold = model["threshold"]

    # Handle model/feature dimension mismatch (backward compat)
    d = len(weights)
    if len(features) > d:
        # New features with old model: truncate to model's expected size
        features = features[:d]
    elif len(features) < d:
        # Old features with new model: pad with zeros (normalized = neutral)
        features = features + [0.0] * (d - len(features))

    # Normalize
    x_norm = [
        (features[j] - means[j]) / stds[j] if stds[j] > 0 else 0.0
        for j in range(d)
    ]

    # Predict
    z = sum(weights[j] * x_norm[j] for j in range(d)) + bias
    prob = sigmoid(z)
    predicted = 1 if prob >= threshold else 0

    # Confidence: how far from the decision boundary
    confidence = abs(prob - threshold) / max(threshold, 1 - threshold)

    # Interpret
    if predicted == 1:
        if confidence > 0.7:
            verdict = "STRONG — almost certainly weakened"
        elif confidence > 0.3:
            verdict = "MODERATE — likely weakened"
        else:
            verdict = "WEAK — possible anomaly"
    else:
        if confidence > 0.5:
            verdict = "CLEAN — no anomaly detected"
        else:
            verdict = "BORDERLINE — close to decision boundary"

    return {
        "probability": prob,
        "predicted_label": predicted,
        "confidence": confidence,
        "verdict": verdict,
    }


# --- Generate Training Data ---

def generate_training_data(
    n_batches: int = 10,
    variants_per_batch: int = 12,
    samples_per_variant: int = 2000,
    severity_range: tuple = (0.50, 0.95),
    output_bits_list: list[int] = None,
    sample_sizes: list[int] = None,
    verbose: bool = True,
) -> list[dict]:
    """
    Generate labeled training data for the meta-learner.

    Creates many calibration variants at multiple output widths and sample
    sizes, runs the statistical suite on each, and returns (features, label)
    pairs. Varying sample sizes teaches the model to handle normalized
    features correctly across scales (2K, 10K, 50K, etc.).

    Args:
      output_bits_list: List of output widths to train across (e.g. [64, 128, 256]).
        Default [64] for backward compatibility.
      sample_sizes: List of sample sizes to cycle through (e.g. [2000, 10000, 50000]).
        Default [samples_per_variant] for backward compatibility.
    """
    # Import here to avoid circular dependency if called from other scripts
    sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
    from synthetic_weakness import generate_variants, generate_input_strings
    from statistical_analysis import run_full_analysis

    if output_bits_list is None:
        output_bits_list = [64]

    if sample_sizes is None:
        sample_sizes = [samples_per_variant]

    # Build a combined cycle of (width, sample_size) pairs
    # This ensures we get training data across all combinations
    configs = []
    for i in range(n_batches):
        w = output_bits_list[i % len(output_bits_list)]
        s = sample_sizes[i % len(sample_sizes)]
        configs.append((w, s))

    all_examples = []

    for batch_idx in range(n_batches):
        seed = 100000 + batch_idx * 7919
        rng = random.Random(seed)
        n_clean = rng.randint(4, 6)

        output_bits, batch_samples = configs[batch_idx]

        if verbose:
            print(f"  Batch {batch_idx + 1}/{n_batches}: "
                  f"{n_clean} clean, {variants_per_batch - n_clean} weakened, "
                  f"{output_bits}-bit output, {batch_samples} samples")

        manifest, variants = generate_variants(
            n_variants=variants_per_batch,
            n_clean=n_clean,
            master_seed=seed,
            difficulty_range=severity_range,
            output_bits=output_bits,
        )

        input_rng = random.Random(seed + 1)
        inputs = generate_input_strings(batch_samples, input_rng)

        for codename, hash_fn in variants:
            records = [
                {"plaintext": pt, "hash": hash_fn(pt)}
                for pt in inputs
            ]

            results = run_full_analysis(records, verbose=False)
            features = extract_features_from_stats(results)

            weakness_info = manifest["variants"][codename]
            label = 0 if weakness_info["type"] == "clean" else 1

            all_examples.append({
                "codename": codename,
                "batch": batch_idx,
                "output_bits": output_bits,
                "n_samples": batch_samples,
                "label": label,
                "weakness_type": weakness_info["type"],
                "features": features,
                "weakness_info": weakness_info,
            })

    return all_examples


# --- Reporting ---

def print_model_summary(model: dict):
    """Print human-readable model summary."""
    print(f"\n  {'='*56}")
    print(f"    META-LEARNER MODEL SUMMARY")
    print(f"  {'='*56}")
    print(f"    Training examples:    {model['n_training_examples']}")
    print(f"    Features:             {model['n_features']}")
    print(f"    Training accuracy:    {model['training_accuracy']:.4f}")
    print(f"    Training F1:          {model['training_f1']:.4f}")
    print(f"    Decision threshold:   {model['threshold']:.2f}")
    print(f"    Final loss:           {model['training_loss']:.4f}")
    print(f"\n    Feature importance (top 10):")
    for item in model["feature_importance"][:10]:
        direction = "+" if item["weight"] > 0 else "−"
        print(f"      {direction} {item['feature']:<25} weight: {abs(item['weight']):.4f}")


def print_classification_table(results: list[dict]):
    """Print batch classification results as a table."""
    print(f"\n{'='*80}")
    print("  META-LEARNER — CLASSIFICATION RESULTS")
    print(f"{'='*80}")
    print(f"\n  {'Variant':<22} {'Prob':>7} {'Conf':>7} {'Verdict'}")
    print(f"  {'-'*70}")

    for r in sorted(results, key=lambda x: -x["prediction"]["probability"]):
        pred = r["prediction"]
        print(f"  {r['name']:<22} {pred['probability']:>6.3f} {pred['confidence']:>6.2f}  {pred['verdict']}")

    n_flagged = sum(1 for r in results if r["prediction"]["predicted_label"] == 1)
    print(f"\n  Flagged as weakened: {n_flagged}/{len(results)}")


# --- Main ---

def main():
    parser = argparse.ArgumentParser(
        description="Meta-learner for hash function weakness classification."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Train from existing training data
    train_parser = subparsers.add_parser("train", help="Train from existing training data file")
    train_parser.add_argument("--training-data", required=True, help="Path to training_data.json")
    train_parser.add_argument("--output", default="models/meta_learner.json")
    train_parser.add_argument("--lr", type=float, default=0.1)
    train_parser.add_argument("--epochs", type=int, default=500)

    # Generate data + train in one step
    gen_parser = subparsers.add_parser("generate-and-train", help="Generate training data and train")
    gen_parser.add_argument("--n-batches", type=int, default=10)
    gen_parser.add_argument("--variants-per-batch", type=int, default=12)
    gen_parser.add_argument("--samples-per-variant", type=int, default=2000)
    gen_parser.add_argument("--output", default="models/meta_learner.json")
    gen_parser.add_argument("--save-training-data", default=None, help="Also save training data")
    gen_parser.add_argument("--output-bits", type=str, default="64",
                            help="Comma-separated output widths to train across (e.g. '64,128,256')")
    gen_parser.add_argument("--sample-sizes", type=str, default=None,
                            help="Comma-separated sample sizes to cycle through (e.g. '2000,10000,50000'). "
                                 "Default: use --samples-per-variant only.")
    gen_parser.add_argument("--lr", type=float, default=0.1)
    gen_parser.add_argument("--epochs", type=int, default=500)

    # Classify a batch of datasets
    batch_parser = subparsers.add_parser("classify-batch", help="Classify all datasets in a directory")
    batch_parser.add_argument("--model", required=True, help="Path to trained model JSON")
    batch_parser.add_argument("--data-dir", required=True, help="Directory of JSONL files")
    batch_parser.add_argument("--output", default="results/meta_classification.json")

    # Classify from existing stats results
    stats_parser = subparsers.add_parser("classify-stats", help="Classify from stats results JSON")
    stats_parser.add_argument("--model", required=True, help="Path to trained model JSON")
    stats_parser.add_argument("--stats-results", required=True, help="Stats results JSON (from statistical_analysis.py)")
    stats_parser.add_argument("--output", default="results/meta_classification.json")

    args = parser.parse_args()

    if args.command == "train":
        print(f"Loading training data: {args.training_data}")
        with open(args.training_data) as f:
            data = json.load(f)

        X = [x["features"] if isinstance(x["features"], list) else
             [x["extended_features"][k] for k in FEATURE_NAMES]
             for x in data]
        y = [x["label"] for x in data]

        # Pad old training data (18 features) to current feature count if needed
        expected_d = len(FEATURE_NAMES)
        if X and len(X[0]) < expected_d:
            print(f"  Note: padding features from {len(X[0])} to {expected_d} (width features = 0)")
            X = [row + [0.0] * (expected_d - len(row)) for row in X]

        print(f"Training on {len(X)} examples ({sum(y)} weakened, {len(y) - sum(y)} clean)")
        print(f"Training logistic regression...")

        model = train_logistic_regression(X, y, lr=args.lr, epochs=args.epochs)
        print_model_summary(model)

        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w") as f:
            json.dump(model, f, indent=2)
        print(f"\nModel saved to {args.output}")

    elif args.command == "generate-and-train":
        output_bits_list = [int(x.strip()) for x in args.output_bits.split(",")]
        sample_sizes = None
        if args.sample_sizes:
            sample_sizes = [int(x.strip()) for x in args.sample_sizes.split(",")]
        print(f"Generating training data: {args.n_batches} batches × {args.variants_per_batch} variants")
        print(f"Output widths: {output_bits_list}")
        if sample_sizes:
            print(f"Sample sizes: {sample_sizes}")
        examples = generate_training_data(
            n_batches=args.n_batches,
            variants_per_batch=args.variants_per_batch,
            samples_per_variant=args.samples_per_variant,
            output_bits_list=output_bits_list,
            sample_sizes=sample_sizes,
        )

        if args.save_training_data:
            os.makedirs(os.path.dirname(args.save_training_data) or ".", exist_ok=True)
            with open(args.save_training_data, "w") as f:
                json.dump(examples, f, indent=2)
            print(f"Training data saved to {args.save_training_data}")

        X = [x["features"] for x in examples]
        y = [x["label"] for x in examples]

        print(f"\nTraining on {len(X)} examples ({sum(y)} weakened, {len(y) - sum(y)} clean)")
        model = train_logistic_regression(X, y, lr=args.lr, epochs=args.epochs)
        print_model_summary(model)

        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w") as f:
            json.dump(model, f, indent=2)
        print(f"\nModel saved to {args.output}")

    elif args.command == "classify-batch":
        print(f"Loading model: {args.model}")
        with open(args.model) as f:
            model = json.load(f)

        # Import statistical analysis
        sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
        from statistical_analysis import run_full_analysis, load_records

        jsonl_files = sorted(Path(args.data_dir).glob("*.jsonl"))
        if not jsonl_files:
            print(f"No JSONL files found in {args.data_dir}")
            return

        print(f"Analyzing {len(jsonl_files)} datasets...\n")

        all_results = []
        for filepath in jsonl_files:
            name = filepath.stem
            print(f"  {name}: running stats...", end="", flush=True)
            records = load_records(str(filepath))
            stats = run_full_analysis(records, verbose=False)
            features = extract_features_from_stats(stats)
            prediction = predict_logistic(model, features)
            all_results.append({
                "name": name,
                "features": features,
                "prediction": prediction,
            })
            print(f" → {prediction['verdict']}")

        print_classification_table(all_results)

        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w") as f:
            json.dump(all_results, f, indent=2)
        print(f"\nResults saved to {args.output}")

    elif args.command == "classify-stats":
        print(f"Loading model: {args.model}")
        with open(args.model) as f:
            model = json.load(f)

        print(f"Loading stats: {args.stats_results}")
        with open(args.stats_results) as f:
            stats_data = json.load(f)

        # Handle both single-dataset and multi-dataset results
        all_results = []

        if "bit_correlation" in stats_data:
            # Single dataset
            features = extract_features_from_stats(stats_data)
            prediction = predict_logistic(model, features)
            all_results.append({"name": "dataset", "prediction": prediction})
        else:
            # Multi-dataset (keyed by variant name)
            for name, stats in stats_data.items():
                if "bit_correlation" in stats:
                    features = extract_features_from_stats(stats)
                    prediction = predict_logistic(model, features)
                    all_results.append({"name": name, "prediction": prediction})

        print_classification_table(all_results)

        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w") as f:
            json.dump(all_results, f, indent=2)
        print(f"\nResults saved to {args.output}")


if __name__ == "__main__":
    main()
