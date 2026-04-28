#!/usr/bin/env python3
"""
Shared utilities for the hash collision testing experiment.
"""

import json
import os
import random
from typing import Optional


def load_jsonl(filepath: str) -> list[dict]:
    """Load records from a JSONL file."""
    records = []
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def save_jsonl(records: list[dict], filepath: str):
    """Save records to a JSONL file."""
    os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
    with open(filepath, "w") as f:
        for record in records:
            f.write(json.dumps(record) + "\n")


def parse_training_text(text: str) -> tuple[Optional[str], Optional[str]]:
    """
    Parse a training-format string back into (hash_value, plaintext).
    Expected format: "hash: <hex> → plaintext: <word>"
    Returns (None, None) if parsing fails.
    """
    try:
        # Split on the arrow separator
        parts = text.split(" → plaintext: ")
        if len(parts) != 2:
            return None, None
        hash_part = parts[0]
        plaintext = parts[1].strip()
        hash_value = hash_part.replace("hash: ", "").strip()
        return hash_value, plaintext
    except Exception:
        return None, None


def create_shuffled_pairs(records: list[dict], seed: int = 99) -> list[dict]:
    """
    Create shuffled (mismatched) pairs from a dataset.
    Each record gets a different record's hash, breaking the real mapping.
    Used for statistical distinguishing evaluation (Tier 3).
    """
    rng = random.Random(seed)
    shuffled = records.copy()

    # Shuffle hashes independently of plaintexts
    hashes = [r["hash"] for r in shuffled]
    plaintexts = [r["plaintext"] for r in shuffled]

    rng.shuffle(hashes)

    # Make sure no hash stays paired with its original plaintext
    for i in range(len(hashes)):
        if hashes[i] == records[i]["hash"]:
            # Swap with next position (wrap around)
            j = (i + 1) % len(hashes)
            hashes[i], hashes[j] = hashes[j], hashes[i]

    result = []
    for pt, h in zip(plaintexts, hashes):
        result.append({
            "plaintext": pt,
            "hash": h,
            "matched": False,  # These are intentionally mismatched
        })
    return result


def compute_character_accuracy(predicted: str, actual: str) -> dict:
    """
    Compute per-character accuracy between predicted and actual strings.
    Returns dict with metrics for Tier 2 evaluation.
    """
    if not predicted or not actual:
        return {
            "char_accuracy": 0.0,
            "length_match": predicted is not None and actual is not None and len(predicted) == len(actual),
            "length_predicted": len(predicted) if predicted else 0,
            "length_actual": len(actual) if actual else 0,
            "prefix_match_len": 0,
        }

    # Character-by-character accuracy (up to min length)
    min_len = min(len(predicted), len(actual))
    matches = sum(1 for a, b in zip(predicted[:min_len], actual[:min_len]) if a == b)
    max_len = max(len(predicted), len(actual))
    char_accuracy = matches / max_len if max_len > 0 else 0.0

    # Longest matching prefix
    prefix_len = 0
    for a, b in zip(predicted, actual):
        if a == b:
            prefix_len += 1
        else:
            break

    return {
        "char_accuracy": char_accuracy,
        "length_match": len(predicted) == len(actual),
        "length_predicted": len(predicted),
        "length_actual": len(actual),
        "prefix_match_len": prefix_len,
    }


def expected_random_char_accuracy(charset_size: int = 26, avg_length: int = 7) -> float:
    """
    Compute expected per-character accuracy for random guessing.
    For lowercase English letters, this is 1/26 ≈ 3.85%.
    """
    return 1.0 / charset_size
