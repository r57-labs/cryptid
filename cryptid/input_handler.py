"""
Input handling for cryptid.

Supports three input modes:
  1. JSONL file: each line has {"plaintext": "...", "hash": "..."}
  2. Binary file: raw input/output pairs (fixed-width, user specifies sizes)
  3. Command mode: cryptid invokes a shell command with random inputs
     and captures outputs
"""

import json
import os
import random
import string
import subprocess
import sys
from typing import Callable, Optional


def load_jsonl(filepath: str) -> list[dict]:
    """Load input/output pairs from a JSONL file.

    Accepts records with fields:
      - plaintext/input + hash/output/digest
    Normalizes to {"plaintext": str, "hash": str} format.
    """
    records = []
    with open(filepath) as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError as e:
                print(f"Warning: skipping malformed line {lineno}: {e}", file=sys.stderr)
                continue

            # Normalize field names
            plaintext = rec.get("plaintext") or rec.get("input") or rec.get("message", "")
            hash_val = rec.get("hash") or rec.get("output") or rec.get("digest", "")

            if not hash_val:
                print(f"Warning: skipping line {lineno}: no hash/output field", file=sys.stderr)
                continue

            records.append({"plaintext": str(plaintext), "hash": str(hash_val)})

    return records


def load_hex_pairs(filepath: str) -> list[dict]:
    """Load from a simple two-column hex file (one pair per line, space-separated)."""
    records = []
    with open(filepath) as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) < 2:
                print(f"Warning: skipping line {lineno}: need two hex values", file=sys.stderr)
                continue
            records.append({"plaintext": parts[0], "hash": parts[1]})
    return records


def generate_from_command(
    command: str,
    n_samples: int = 10000,
    input_bytes: int = 10,
    verbose: bool = True,
) -> list[dict]:
    """Generate test data by invoking a shell command.

    The command receives hex-encoded random input on stdin (one per line)
    and should output the corresponding hex-encoded hash (one per line).

    Example command: "openssl dgst -sha256 -hex"
    """
    rng = random.Random(42)
    inputs = []
    for _ in range(n_samples):
        data = bytes(rng.randint(0, 255) for _ in range(input_bytes))
        inputs.append(data.hex())

    if verbose:
        print(f"  Generating {n_samples} samples via command: {command}")

    input_text = "\n".join(inputs) + "\n"

    try:
        result = subprocess.run(
            command,
            shell=True,
            input=input_text,
            capture_output=True,
            text=True,
            timeout=300,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"Command timed out after 300s: {command}")

    if result.returncode != 0:
        raise RuntimeError(f"Command failed (exit {result.returncode}): {result.stderr[:500]}")

    outputs = [line.strip() for line in result.stdout.strip().split("\n") if line.strip()]

    if len(outputs) != len(inputs):
        raise RuntimeError(
            f"Command produced {len(outputs)} outputs for {len(inputs)} inputs. "
            f"Expected 1:1 correspondence."
        )

    records = []
    for inp, out in zip(inputs, outputs):
        # Handle common output formats like "(stdin)= abc123..."
        if "=" in out:
            out = out.split("=")[-1].strip()
        records.append({"plaintext": inp, "hash": out})

    return records


def make_hash_fn_from_records(records: list[dict]) -> Callable:
    """Create a hash function (str -> hex str) from pre-computed records.

    Used for analysis modules that expect a callable hash_fn.
    Falls back to random oracle behavior for unseen inputs.
    """
    lookup = {}
    for rec in records:
        lookup[rec["plaintext"]] = rec["hash"]

    # Infer output length from first record
    output_hex_len = len(records[0]["hash"]) if records else 16

    def hash_fn(plaintext: str) -> str:
        if plaintext in lookup:
            return lookup[plaintext]
        # For unseen inputs, we can't produce a real hash
        # This signals that the caller should use record-based analysis instead
        raise KeyError(f"Input not in pre-computed dataset: {plaintext[:50]}...")

    hash_fn._output_hex_len = output_hex_len
    hash_fn._n_records = len(records)
    hash_fn._is_precomputed = True

    return hash_fn


def make_hash_fn_from_command(command: str) -> Callable:
    """Create a hash function from a shell command.

    The command receives plaintext on stdin and outputs hex hash on stdout.
    Much slower than in-process hashing, but works with any external implementation.
    """
    def hash_fn(plaintext: str) -> str:
        result = subprocess.run(
            command,
            shell=True,
            input=plaintext,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            raise RuntimeError(f"Hash command failed: {result.stderr[:200]}")
        out = result.stdout.strip()
        if "=" in out:
            out = out.split("=")[-1].strip()
        return out

    hash_fn._is_precomputed = False

    return hash_fn


def detect_output_width(records: list[dict]) -> int:
    """Detect hash output width in bits from sample records."""
    if not records:
        raise ValueError("No records to detect output width from")

    # Sample a few records to check consistency
    sample = records[:min(100, len(records))]
    lengths = set()
    for rec in sample:
        hex_str = rec["hash"].lower().replace("0x", "")
        lengths.add(len(hex_str))

    if len(lengths) > 1:
        print(f"Warning: inconsistent hash lengths detected: {lengths}", file=sys.stderr)

    hex_len = max(lengths)  # Use longest observed
    return hex_len * 4  # 4 bits per hex character


def detect_input_format(filepath: str) -> str:
    """Auto-detect input file format.

    Returns: "jsonl", "hex_pairs", or "unknown"
    """
    with open(filepath) as f:
        first_line = f.readline().strip()

    if not first_line:
        return "unknown"

    # Try JSONL
    try:
        rec = json.loads(first_line)
        if isinstance(rec, dict):
            return "jsonl"
    except (json.JSONDecodeError, ValueError):
        pass

    # Try hex pairs (two space-separated hex strings)
    parts = first_line.split()
    if len(parts) >= 2:
        try:
            int(parts[0], 16)
            int(parts[1], 16)
            return "hex_pairs"
        except ValueError:
            pass

    return "unknown"


def load_input(filepath: str, format: Optional[str] = None) -> list[dict]:
    """Load input data from file, auto-detecting format if needed."""
    if format is None:
        format = detect_input_format(filepath)

    if format == "jsonl":
        return load_jsonl(filepath)
    elif format == "hex_pairs":
        return load_hex_pairs(filepath)
    else:
        # Try JSONL first, fall back to hex pairs
        try:
            records = load_jsonl(filepath)
            if records:
                return records
        except Exception:
            pass

        try:
            records = load_hex_pairs(filepath)
            if records:
                return records
        except Exception:
            pass

        raise ValueError(
            f"Could not parse {filepath}. Expected JSONL (with plaintext/hash fields) "
            f"or space-separated hex pairs."
        )
