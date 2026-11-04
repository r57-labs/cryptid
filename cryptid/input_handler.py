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
import re
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


_HEX_TOKEN = re.compile(r"[0-9a-fA-F]{8,}")


def _parse_hash_output(raw: str) -> str:
    """Normalize a single hash output line to a bare lowercase hex digest.

    Handles the common tool formats:
      "abc123..."                      (bare digest)
      "SHA2-256(stdin)= abc123..."     (openssl dgst)
      "abc123...  -"                   (sha256sum / shasum)
      "0xabc123..."
    The digest is taken to be the longest run of 8+ hex characters.
    """
    out = raw.strip()
    if "=" in out:
        out = out.split("=")[-1].strip()
    tokens = _HEX_TOKEN.findall(out)
    if tokens:
        return max(tokens, key=len).lower()
    return out.lower()


def generate_plaintexts(n_samples: int, rng: random.Random, input_bytes: int = 10) -> list[str]:
    """The toolkit's standard mixed input distribution for record-based tests.

    50% hex strings of input_bytes random bytes, 30% lowercase pseudo-words
    of 3-15 letters, 20% zero-padded counters. The statistical suite's
    features (length parity, first character, byte sums) are defined on
    this text; the message a hash function sees is its UTF-8 encoding.
    """
    plaintexts = []
    for i in range(n_samples):
        r = rng.random()
        if r < 0.5:
            plaintexts.append(bytes(rng.randint(0, 255) for _ in range(input_bytes)).hex())
        elif r < 0.8:
            length = rng.randint(3, 15)
            plaintexts.append("".join(rng.choice(string.ascii_lowercase) for _ in range(length)))
        else:
            plaintexts.append(f"counter_{i:010d}")
    return plaintexts


def _message_bytes(message) -> bytes:
    """Text is hashed as UTF-8; bytes are hashed as-is."""
    if isinstance(message, (bytes, bytearray, memoryview)):
        return bytes(message)
    return str(message).encode("utf-8")


def generate_from_command(
    command: str,
    n_samples: int = 10000,
    input_bytes: int = 10,
    verbose: bool = True,
) -> list[dict]:
    """Generate test data by invoking a shell command.

    The command receives each message on stdin and should print its hex
    digest on stdout. Messages are the toolkit's standard text inputs (see
    generate_plaintexts); the command sees their UTF-8 bytes with no
    trailing newline -- the same bytes the built-in algorithms hash, and
    the same convention make_hash_fn_from_command uses for the
    chosen-input tiers, so every phase of an audit tests one function.

    Batch mode (all messages at once, newline-separated) is tried first
    for line-oriented tools; tools that hash all of stdin as one message
    (openssl dgst, sha256sum, ...) fall back to one invocation per message.

    Example commands:
      "openssl dgst -sha256 -hex"
      "./my_hash_tool"
    """
    rng = random.Random(42)
    inputs = generate_plaintexts(n_samples, rng, input_bytes)

    if verbose:
        print(f"  Generating {n_samples:,} samples via command: {command}")

    records = _try_batch_command(command, inputs)
    if records is not None:
        if verbose:
            print(f"  Batch mode succeeded ({n_samples:,} samples)")
        return records

    if verbose:
        print(f"  Batch mode failed, falling back to per-input invocation...")

    records = []
    for i, inp in enumerate(inputs):
        if verbose and (i + 1) % 1000 == 0:
            print(f"    {i + 1:,}/{n_samples:,}...")

        try:
            result = subprocess.run(
                command,
                shell=True,
                input=_message_bytes(inp),
                capture_output=True,
                timeout=10,
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"Command timed out on input {i + 1}: {command}")

        if result.returncode != 0:
            raise RuntimeError(
                f"Command failed on input {i + 1} (exit {result.returncode}): "
                f"{result.stderr.decode(errors='replace')[:200]}"
            )

        out = _parse_hash_output(result.stdout.decode(errors="replace"))
        if not out:
            raise RuntimeError(f"Command produced empty output for input {i + 1}")

        records.append({"plaintext": inp, "hash": out})

    return records


def _try_batch_command(command: str, inputs: list[str]) -> Optional[list[dict]]:
    """Try sending all inputs at once. Returns records or None if it fails."""
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
        return None

    if result.returncode != 0:
        return None

    outputs = [line.strip() for line in result.stdout.strip().split("\n") if line.strip()]

    if len(outputs) != len(inputs):
        return None

    records = []
    for inp, raw_out in zip(inputs, outputs):
        out = _parse_hash_output(raw_out)
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

    The returned callable accepts text (sent as UTF-8) or raw bytes (sent
    as-is), writes the message to the command's stdin with no trailing
    newline, and returns the hex digest parsed from stdout. One process per
    call, so this is much slower than in-process hashing.
    """
    def hash_fn(message) -> str:
        result = subprocess.run(
            command,
            shell=True,
            input=_message_bytes(message),
            capture_output=True,
            timeout=10,
        )
        if result.returncode != 0:
            raise RuntimeError(f"Hash command failed: {result.stderr.decode(errors='replace')[:200]}")
        out = _parse_hash_output(result.stdout.decode(errors="replace"))
        if not out:
            raise RuntimeError("Hash command produced empty output")
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


class InputFormatError(ValueError):
    """Raised when an input file cannot be used as-is."""


def validate_records(records: list[dict], source: str = "input") -> list[dict]:
    """Normalize digests and reject files the analysis cannot interpret.

    Digests are lower-cased and any 0x prefix removed. Every digest must be
    hex and all digests must have the same length: an output width is
    inferred from the records, and a file mixing lengths is almost always a
    wrapper that forgot to zero-pad (format(x, "x") instead of "064x").
    Such a file used to run anyway and produced a spurious WARN, because
    the truncated digests distort the inter-record distance and entropy
    features.
    """
    if not records:
        raise InputFormatError(f"{source}: no usable records")

    lengths = {}
    for rec in records:
        h = rec["hash"].strip().lower()
        if h.startswith("0x"):
            h = h[2:]
        try:
            int(h, 16)
        except ValueError:
            raise InputFormatError(
                f"{source}: digest is not hex: {rec['hash'][:40]!r}"
            )
        if len(h) % 2:
            raise InputFormatError(
                f"{source}: digest has an odd number of hex characters ({len(h)}): {h[:40]!r}"
            )
        rec["hash"] = h
        lengths[len(h)] = lengths.get(len(h), 0) + 1

    if len(lengths) > 1:
        detail = ", ".join(f"{n} records x {l} hex chars" for l, n in sorted(lengths.items(), reverse=True))
        raise InputFormatError(
            f"{source}: inconsistent digest lengths ({detail}). "
            f"Zero-pad every digest to the hash's full width "
            f"(e.g. format(value, '064x') for 256 bits) and re-run."
        )

    return records


def load_input(filepath: str, format: Optional[str] = None) -> list[dict]:
    """Load input data from file, auto-detecting format if needed.

    Raises InputFormatError (a ValueError) if the file cannot be parsed or
    its digests are inconsistent -- see validate_records.
    """
    if format is None:
        format = detect_input_format(filepath)

    if format == "jsonl":
        records = load_jsonl(filepath)
    elif format == "hex_pairs":
        records = load_hex_pairs(filepath)
    else:
        # Try JSONL first, fall back to hex pairs
        records = []
        try:
            records = load_jsonl(filepath)
        except Exception:
            pass
        if not records:
            try:
                records = load_hex_pairs(filepath)
            except Exception:
                pass
        if not records:
            raise InputFormatError(
                f"Could not parse {filepath}. Expected JSONL (with plaintext/hash fields) "
                f"or space-separated hex pairs."
            )

    return validate_records(records, source=os.path.basename(filepath))
