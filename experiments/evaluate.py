#!/usr/bin/env python3
"""
Evaluation framework for hash collision testing experiment.

Evaluates fine-tuned models across three tiers:
  Tier 1: Exact plaintext recovery
  Tier 2: Partial input prediction (character accuracy, length prediction)
  Tier 3: Statistical distinguishing (real pairs vs shuffled pairs)

Usage:
  # Full evaluation against a trained adapter
  python evaluate.py --model mlx-community/Qwen2.5-7B-Instruct-4bit \
                     --adapter adapters/crc32_words \
                     --eval-data data/eval/crc32_words_eval.jsonl \
                     --output results/crc32_words_results.json

  # Tier 3 only (statistical distinguishing — doesn't require generation)
  python evaluate.py --tier3-only \
                     --model mlx-community/Qwen2.5-7B-Instruct-4bit \
                     --adapter adapters/crc32_words \
                     --eval-data data/eval/crc32_words_eval.jsonl

  # Offline evaluation (if you already have model predictions saved)
  python evaluate.py --predictions results/predictions.jsonl \
                     --eval-data data/eval/crc32_words_eval.jsonl
"""

import argparse
import json
import os
import random
import statistics
import sys
from pathlib import Path

# Add parent dir to path for utils
sys.path.insert(0, os.path.dirname(__file__))
from utils import (
    compute_character_accuracy,
    create_shuffled_pairs,
    expected_random_char_accuracy,
    load_jsonl,
    parse_training_text,
    save_jsonl,
)


# --- Model Inference ---

def generate_predictions(
    model_path: str,
    adapter_path: str | None,
    eval_records: list[dict],
    max_tokens: int = 64,
) -> list[dict]:
    """
    Run the fine-tuned model to generate plaintext predictions from hashes.
    Returns list of dicts with: hash, predicted_plaintext, actual_plaintext.

    Requires mlx_lm to be installed.
    """
    try:
        from mlx_lm import generate, load
    except ImportError:
        print("Error: mlx_lm is required for model inference.", file=sys.stderr)
        print("Install with: pip install mlx-lm", file=sys.stderr)
        sys.exit(1)

    print(f"Loading model: {model_path}")
    if adapter_path:
        print(f"Loading adapter: {adapter_path}")

    model, tokenizer = load(model_path, adapter_path=adapter_path)

    predictions = []
    total = len(eval_records)

    for i, record in enumerate(eval_records):
        hash_value = record["hash"]
        actual = record["plaintext"]

        # Prompt format matches training format
        prompt = f"hash: {hash_value} → plaintext:"

        response = generate(
            model,
            tokenizer,
            prompt=prompt,
            max_tokens=max_tokens,
            verbose=False,
        )

        # Clean up the response — extract just the predicted plaintext
        predicted = response.strip()
        # Remove any trailing content after first whitespace/newline
        predicted = predicted.split("\n")[0].strip()
        predicted = predicted.split(" ")[0].strip()

        predictions.append({
            "hash": hash_value,
            "predicted_plaintext": predicted,
            "actual_plaintext": actual,
        })

        if (i + 1) % 20 == 0 or (i + 1) == total:
            print(f"  Generated {i + 1}/{total} predictions")

    return predictions


# --- Tier 1: Exact Recovery ---

def evaluate_tier1(predictions: list[dict]) -> dict:
    """
    Tier 1: Exact plaintext recovery.
    What fraction of hashes did the model recover the exact plaintext for?
    """
    total = len(predictions)
    exact_matches = sum(
        1
        for p in predictions
        if p["predicted_plaintext"].lower() == p["actual_plaintext"].lower()
    )
    case_sensitive_matches = sum(
        1 for p in predictions if p["predicted_plaintext"] == p["actual_plaintext"]
    )

    return {
        "tier": 1,
        "name": "Exact Plaintext Recovery",
        "total_samples": total,
        "exact_matches_case_insensitive": exact_matches,
        "exact_matches_case_sensitive": case_sensitive_matches,
        "accuracy_case_insensitive": exact_matches / total if total > 0 else 0.0,
        "accuracy_case_sensitive": case_sensitive_matches / total if total > 0 else 0.0,
        "expected_random_accuracy": 0.0,  # Effectively zero for any reasonable vocabulary
    }


# --- Tier 2: Partial Prediction ---

def evaluate_tier2(predictions: list[dict]) -> dict:
    """
    Tier 2: Partial input prediction.
    Can the model predict some characters/properties better than chance?
    """
    char_accuracies = []
    length_correct = 0
    prefix_lengths = []
    first_char_correct = 0
    total = len(predictions)

    for p in predictions:
        pred = p["predicted_plaintext"].lower()
        actual = p["actual_plaintext"].lower()

        metrics = compute_character_accuracy(pred, actual)
        char_accuracies.append(metrics["char_accuracy"])
        prefix_lengths.append(metrics["prefix_match_len"])

        if metrics["length_match"]:
            length_correct += 1

        if pred and actual and pred[0] == actual[0]:
            first_char_correct += 1

    random_baseline = expected_random_char_accuracy(charset_size=26)

    mean_char_acc = statistics.mean(char_accuracies) if char_accuracies else 0.0
    mean_prefix = statistics.mean(prefix_lengths) if prefix_lengths else 0.0

    return {
        "tier": 2,
        "name": "Partial Input Prediction",
        "total_samples": total,
        "mean_character_accuracy": mean_char_acc,
        "median_character_accuracy": statistics.median(char_accuracies) if char_accuracies else 0.0,
        "stdev_character_accuracy": statistics.stdev(char_accuracies) if len(char_accuracies) > 1 else 0.0,
        "length_prediction_accuracy": length_correct / total if total > 0 else 0.0,
        "first_character_accuracy": first_char_correct / total if total > 0 else 0.0,
        "mean_prefix_match_length": mean_prefix,
        "random_baseline_char_accuracy": random_baseline,
        "signal_above_baseline": mean_char_acc - random_baseline,
    }


# --- Tier 3: Statistical Distinguishing ---

def evaluate_tier3(
    model_path: str,
    adapter_path: str | None,
    eval_records: list[dict],
) -> dict:
    """
    Tier 3: Statistical distinguishing.
    Can the model distinguish real plaintext→hash pairs from shuffled ones?

    Approach: compute perplexity/loss on real pairs vs mismatched pairs.
    If the model assigns lower loss to real pairs, it has learned structure.
    """
    try:
        from mlx_lm import load
        import mlx.core as mx
        import mlx.nn as nn
    except ImportError:
        print("Error: mlx_lm and mlx are required for Tier 3 evaluation.", file=sys.stderr)
        return {"tier": 3, "error": "mlx_lm not available"}

    print("Loading model for Tier 3 evaluation...")
    model, tokenizer = load(model_path, adapter_path=adapter_path)

    # Prepare real pairs and shuffled pairs
    shuffled_records = create_shuffled_pairs(eval_records)

    def compute_avg_loss(records: list[dict], label: str) -> float:
        """Compute average per-token loss over a set of records."""
        losses = []
        for i, r in enumerate(records):
            text = f"hash: {r['hash']} → plaintext: {r['plaintext']}"
            tokens = tokenizer.encode(text)

            if len(tokens) < 2:
                continue

            token_ids = mx.array([tokens])
            logits = model(token_ids)

            # Compute cross-entropy loss
            # Shift logits and targets for next-token prediction
            shift_logits = logits[:, :-1, :]
            shift_targets = token_ids[:, 1:]

            loss = nn.losses.cross_entropy(
                shift_logits.reshape(-1, shift_logits.shape[-1]),
                shift_targets.reshape(-1),
            )
            avg_loss = loss.mean().item()
            losses.append(avg_loss)

            if (i + 1) % 50 == 0:
                print(f"  [{label}] Processed {i + 1}/{len(records)}")

        return statistics.mean(losses) if losses else float("inf")

    real_loss = compute_avg_loss(eval_records, "Real pairs")
    shuffled_loss = compute_avg_loss(shuffled_records, "Shuffled pairs")

    # If the model learned structure, real pairs should have lower loss
    loss_difference = shuffled_loss - real_loss
    # Positive = model prefers real pairs (evidence of learned structure)

    return {
        "tier": 3,
        "name": "Statistical Distinguishing",
        "total_samples": len(eval_records),
        "real_pairs_avg_loss": real_loss,
        "shuffled_pairs_avg_loss": shuffled_loss,
        "loss_difference": loss_difference,
        "model_prefers_real_pairs": loss_difference > 0,
        "interpretation": (
            "Model assigns lower loss to real pairs — evidence of learned structure"
            if loss_difference > 0
            else "Model does not distinguish real from shuffled pairs — no detectable structure"
        ),
    }


# --- Reporting ---

def print_report(results: dict):
    """Print a human-readable evaluation report."""
    print("\n" + "=" * 70)
    print("EVALUATION REPORT")
    print("=" * 70)

    meta = results.get("metadata", {})
    if meta:
        print(f"\nAlgorithm:    {meta.get('algorithm', 'N/A')}")
        print(f"Distribution: {meta.get('distribution', 'N/A')}")
        print(f"Model:        {meta.get('model', 'N/A')}")
        print(f"Adapter:      {meta.get('adapter', 'N/A')}")

    # Tier 1
    t1 = results.get("tier1", {})
    if t1 and "error" not in t1:
        print(f"\n--- Tier 1: Exact Plaintext Recovery ---")
        print(f"  Samples:              {t1['total_samples']}")
        print(f"  Exact matches:        {t1['exact_matches_case_insensitive']} / {t1['total_samples']}")
        print(f"  Accuracy:             {t1['accuracy_case_insensitive']:.4f}")
        print(f"  Random baseline:      ~0.0000")
        verdict = "SIGNAL DETECTED" if t1['accuracy_case_insensitive'] > 0 else "No signal"
        print(f"  Verdict:              {verdict}")

    # Tier 2
    t2 = results.get("tier2", {})
    if t2 and "error" not in t2:
        print(f"\n--- Tier 2: Partial Input Prediction ---")
        print(f"  Samples:              {t2['total_samples']}")
        print(f"  Mean char accuracy:   {t2['mean_character_accuracy']:.4f}")
        print(f"  Random baseline:      {t2['random_baseline_char_accuracy']:.4f}")
        print(f"  Signal above random:  {t2['signal_above_baseline']:.4f}")
        print(f"  Length prediction:     {t2['length_prediction_accuracy']:.4f}")
        print(f"  First char accuracy:  {t2['first_character_accuracy']:.4f}")
        print(f"  Mean prefix match:    {t2['mean_prefix_match_length']:.2f} chars")
        verdict = "SIGNAL DETECTED" if t2['signal_above_baseline'] > 0.01 else "No signal"
        print(f"  Verdict:              {verdict}")

    # Tier 3
    t3 = results.get("tier3", {})
    if t3 and "error" not in t3:
        print(f"\n--- Tier 3: Statistical Distinguishing ---")
        print(f"  Samples:              {t3['total_samples']}")
        print(f"  Real pairs avg loss:  {t3['real_pairs_avg_loss']:.4f}")
        print(f"  Shuffled avg loss:    {t3['shuffled_pairs_avg_loss']:.4f}")
        print(f"  Difference:           {t3['loss_difference']:.4f}")
        print(f"  Prefers real pairs:   {t3['model_prefers_real_pairs']}")
        print(f"  Verdict:              {t3['interpretation']}")

    print("\n" + "=" * 70)


# --- Main ---

def main():
    parser = argparse.ArgumentParser(
        description="Evaluate fine-tuned model on hash collision testing."
    )
    parser.add_argument(
        "--model",
        default="mlx-community/Qwen2.5-7B-Instruct-4bit",
        help="Base model path or HuggingFace ID.",
    )
    parser.add_argument(
        "--adapter",
        help="Path to LoRA adapter directory.",
    )
    parser.add_argument(
        "--eval-data",
        required=True,
        help="Path to evaluation JSONL (with plaintext and hash fields).",
    )
    parser.add_argument(
        "--predictions",
        help="Path to pre-computed predictions JSONL (skip inference).",
    )
    parser.add_argument(
        "--output",
        default="results/eval_results.json",
        help="Output path for results JSON.",
    )
    parser.add_argument(
        "--tier3-only",
        action="store_true",
        help="Only run Tier 3 (statistical distinguishing). Skips generation.",
    )
    parser.add_argument(
        "--max-tokens",
        type=int,
        default=64,
        help="Max tokens for generation (Tier 1/2).",
    )

    args = parser.parse_args()

    # Load evaluation data
    print(f"Loading eval data: {args.eval_data}")
    eval_records = load_jsonl(args.eval_data)
    print(f"  {len(eval_records)} records loaded")

    # Infer metadata from filename
    filename = Path(args.eval_data).stem.replace("_eval", "")
    parts = filename.split("_", 1)
    algo = parts[0] if parts else "unknown"
    dist = parts[1] if len(parts) > 1 else "unknown"

    results = {
        "metadata": {
            "algorithm": algo,
            "distribution": dist,
            "model": args.model,
            "adapter": args.adapter or "none",
            "eval_data": args.eval_data,
            "total_eval_samples": len(eval_records),
        }
    }

    if args.tier3_only:
        # Tier 3 only — no generation needed
        print("\nRunning Tier 3 evaluation only...")
        results["tier3"] = evaluate_tier3(args.model, args.adapter, eval_records)
    else:
        # Get or load predictions
        if args.predictions:
            print(f"\nLoading predictions: {args.predictions}")
            predictions = load_jsonl(args.predictions)
        else:
            print("\nGenerating predictions...")
            predictions = generate_predictions(
                args.model, args.adapter, eval_records, args.max_tokens
            )
            # Save predictions for reuse
            pred_path = args.output.replace(".json", "_predictions.jsonl")
            save_jsonl(predictions, pred_path)
            print(f"  Saved predictions to {pred_path}")

        # Run Tier 1 and 2
        print("\nRunning Tier 1 evaluation (Exact Recovery)...")
        results["tier1"] = evaluate_tier1(predictions)

        print("Running Tier 2 evaluation (Partial Prediction)...")
        results["tier2"] = evaluate_tier2(predictions)

        # Run Tier 3
        print("\nRunning Tier 3 evaluation (Statistical Distinguishing)...")
        results["tier3"] = evaluate_tier3(args.model, args.adapter, eval_records)

    # Save results
    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nResults saved to {args.output}")

    # Print report
    print_report(results)


if __name__ == "__main__":
    main()
