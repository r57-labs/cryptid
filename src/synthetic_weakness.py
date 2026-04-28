#!/usr/bin/env python3
"""
Double-blind synthetic weakness calibration framework.

Generates N hash function variants — some with planted statistical biases
of varying types and severity, some completely clean. Each variant is
assigned a random codename. The mapping between codenames and weakness
types is sealed in a manifest (SHA-256 hashed, revealed only after
detection analysis is complete).

Weakness types:
  1. Bit correlation: specific output bits are correlated with specific
     input bits at a controllable rate above 50%.
  2. Frequency bias: certain output byte values appear more or less
     frequently than expected for certain input patterns.
  3. Differential leak: similar inputs (differing by 1 bit) produce
     outputs that share more bits than expected (weakened avalanche).
  4. Subset leak: the output preserves some function of a subset of
     input bytes (e.g., parity, sum mod N).

Usage:
  # Generate variants and sealed manifest
  python synthetic_weakness.py generate \
    --n-variants 12 --n-clean 4 \
    --output-dir data/calibration/

  # Generate datasets for all variants
  python synthetic_weakness.py make-datasets \
    --config data/calibration/variants_config.json \
    --size 10000 --output-dir data/calibration/datasets/

  # Unseal the manifest (after detection analysis is done)
  python synthetic_weakness.py unseal \
    --manifest data/calibration/manifest_sealed.json
"""

import argparse
import hashlib
import json
import os
import random
import secrets
import string
import struct
import sys
from pathlib import Path


# --- Codename Generator ---

ADJECTIVES = [
    "amber", "azure", "brass", "cedar", "coral", "dusk", "ember", "flint",
    "ghost", "haze", "iron", "jade", "knot", "larch", "moss", "night",
    "onyx", "pearl", "quartz", "rust", "slate", "thorn", "umbra", "vale",
    "wren", "zinc",
]

NOUNS = [
    "anvil", "beacon", "cipher", "delta", "echo", "falcon", "glacier",
    "harbor", "iris", "juniper", "kestrel", "lantern", "mirror", "nexus",
    "orbit", "prism", "quarry", "raven", "summit", "tide", "vault",
    "whisper", "zenith",
]


def generate_codename(rng: random.Random, used: set) -> str:
    """Generate a unique two-word codename."""
    while True:
        name = f"{rng.choice(ADJECTIVES)}-{rng.choice(NOUNS)}"
        if name not in used:
            used.add(name)
            return name


# --- Weakness Implementations ---

class CleanHash:
    """
    Clean hash function — wraps SHA-256 with a per-variant seed.
    Should produce no detectable bias.
    """

    def __init__(self, seed: bytes, output_bytes: int = 8):
        self.seed = seed
        self.output_bytes = output_bytes
        self.weakness_type = "clean"
        self.weakness_params = {}

    def __call__(self, plaintext: str) -> str:
        data = self.seed + plaintext.encode("utf-8")
        return hashlib.sha256(data).hexdigest()[:self.output_bytes * 2]

    def describe(self) -> dict:
        return {"type": "clean", "params": {}}


class BitCorrelationHash:
    """
    Planted weakness: specific output bits are correlated with specific
    input bits at a controllable rate.

    Parameters:
      - input_bit: which bit of the input to leak
      - output_bit: which bit of the output carries the leak
      - correlation: probability that output_bit matches input_bit
        (0.5 = no leak, 1.0 = perfect leak)
    """

    def __init__(self, seed: bytes, input_bit: int, output_bit: int, correlation: float,
                 output_bytes: int = 8):
        self.seed = seed
        self.input_bit = input_bit
        self.output_bit = output_bit
        self.correlation = correlation
        self.output_bytes = output_bytes
        self.weakness_type = "bit_correlation"

    def __call__(self, plaintext: str) -> str:
        data = self.seed + plaintext.encode("utf-8")
        h = hashlib.sha256(data).hexdigest()[:self.output_bytes * 2]
        h_bytes = bytearray.fromhex(h)

        # Get the target input bit
        pt_bytes = plaintext.encode("utf-8")
        input_byte_idx = self.input_bit // 8
        input_bit_pos = self.input_bit % 8
        if input_byte_idx < len(pt_bytes):
            input_val = (pt_bytes[input_byte_idx] >> (7 - input_bit_pos)) & 1
        else:
            input_val = 0

        # Decide whether to leak
        # Use deterministic randomness based on the hash so it's consistent
        leak_rng = random.Random(int.from_bytes(hashlib.sha256(
            self.seed + b"leak" + plaintext.encode()
        ).digest()[:8], "big"))

        if leak_rng.random() < self.correlation:
            # Set output bit to match input bit
            out_byte_idx = self.output_bit // 8
            out_bit_pos = self.output_bit % 8
            if out_byte_idx < len(h_bytes):
                if input_val:
                    h_bytes[out_byte_idx] |= (1 << (7 - out_bit_pos))
                else:
                    h_bytes[out_byte_idx] &= ~(1 << (7 - out_bit_pos))

        return h_bytes.hex()

    def describe(self) -> dict:
        return {
            "type": "bit_correlation",
            "params": {
                "input_bit": self.input_bit,
                "output_bit": self.output_bit,
                "correlation": self.correlation,
            },
        }


class FrequencyBiasHash:
    """
    Planted weakness: certain output byte values are biased based on
    input characteristics.

    Parameters:
      - input_feature: "length_parity" | "first_char_high_bit" | "ascii_sum_mod"
      - output_byte: which output byte is affected
      - bias_strength: how much to bias (0.0 = no bias, 1.0 = deterministic)
    """

    def __init__(self, seed: bytes, input_feature: str, output_byte: int, bias_strength: float,
                 output_bytes: int = 8):
        self.seed = seed
        self.input_feature = input_feature
        self.output_byte = output_byte
        self.bias_strength = bias_strength
        self.output_bytes = output_bytes
        self.weakness_type = "frequency_bias"

    def _extract_feature(self, plaintext: str) -> int:
        """Extract a binary feature from the plaintext."""
        if self.input_feature == "length_parity":
            return len(plaintext) % 2
        elif self.input_feature == "first_char_high_bit":
            return (ord(plaintext[0]) >> 6) & 1 if plaintext else 0
        elif self.input_feature == "ascii_sum_mod":
            return sum(ord(c) for c in plaintext) % 2
        return 0

    def __call__(self, plaintext: str) -> str:
        data = self.seed + plaintext.encode("utf-8")
        h = hashlib.sha256(data).hexdigest()[:self.output_bytes * 2]
        h_bytes = bytearray.fromhex(h)

        feature = self._extract_feature(plaintext)

        # Deterministic decision on whether to apply bias
        bias_rng = random.Random(int.from_bytes(hashlib.sha256(
            self.seed + b"freq" + plaintext.encode()
        ).digest()[:8], "big"))

        if bias_rng.random() < self.bias_strength:
            if feature == 1:
                # Bias this byte toward high values
                h_bytes[self.output_byte] = (h_bytes[self.output_byte] | 0x80)
            else:
                # Bias this byte toward low values
                h_bytes[self.output_byte] = (h_bytes[self.output_byte] & 0x7F)

        return h_bytes.hex()

    def describe(self) -> dict:
        return {
            "type": "frequency_bias",
            "params": {
                "input_feature": self.input_feature,
                "output_byte": self.output_byte,
                "bias_strength": self.bias_strength,
            },
        }


class WeakAvalancheHash:
    """
    Planted weakness: the avalanche property is weakened — similar inputs
    produce outputs sharing more bits than expected.

    Parameters:
      - preserved_bytes: how many leading output bytes are derived from
        a weaker hash of the input (preserving more structure)
      - weakness_strength: interpolation factor (0.0 = full SHA-256,
        1.0 = fully weakened for preserved bytes)
    """

    def __init__(self, seed: bytes, preserved_bytes: int, weakness_strength: float,
                 output_bytes: int = 8):
        self.seed = seed
        self.preserved_bytes = preserved_bytes
        self.weakness_strength = weakness_strength
        self.output_bytes = output_bytes
        self.weakness_type = "weak_avalanche"

    def _weak_hash(self, plaintext: str) -> bytes:
        """A deliberately weak hash — simple byte mixing without proper diffusion."""
        pt = plaintext.encode("utf-8")
        # Pad seed to at least output_bytes for wider hashes
        seed_padded = (self.seed * ((self.output_bytes // len(self.seed)) + 1))[:self.output_bytes]
        state = list(seed_padded)
        for b in pt:
            for i in range(len(state)):
                state[i] = (state[i] + b + i) & 0xFF
        return bytes(state)

    def __call__(self, plaintext: str) -> str:
        data = self.seed + plaintext.encode("utf-8")
        strong = bytearray.fromhex(hashlib.sha256(data).hexdigest()[:self.output_bytes * 2])
        weak = bytearray(self._weak_hash(plaintext))

        # Interpolate: mix weak hash into the first N bytes
        bias_rng = random.Random(int.from_bytes(hashlib.sha256(
            self.seed + b"aval" + plaintext.encode()
        ).digest()[:8], "big"))

        for i in range(min(self.preserved_bytes, len(strong), len(weak))):
            if bias_rng.random() < self.weakness_strength:
                strong[i] = weak[i]

        return strong.hex()

    def describe(self) -> dict:
        return {
            "type": "weak_avalanche",
            "params": {
                "preserved_bytes": self.preserved_bytes,
                "weakness_strength": self.weakness_strength,
            },
        }


class SubsetLeakHash:
    """
    Planted weakness: the output preserves some function of a subset
    of input bytes.

    Parameters:
      - input_bytes: list of input byte indices to leak from
      - leak_function: "xor" | "sum_mod" | "parity"
      - output_bit: which output bit carries the leaked value
      - leak_rate: probability of the leak being active (1.0 = always)
    """

    def __init__(self, seed: bytes, input_bytes: list, leak_function: str,
                 output_bit: int, leak_rate: float, output_bytes: int = 8):
        self.seed = seed
        self.input_bytes = input_bytes
        self.leak_function = leak_function
        self.output_bit = output_bit
        self.leak_rate = leak_rate
        self.output_bytes = output_bytes
        self.weakness_type = "subset_leak"

    def _compute_leak(self, plaintext: str) -> int:
        """Compute the leaked value from input bytes."""
        pt = plaintext.encode("utf-8")
        values = [pt[i] if i < len(pt) else 0 for i in self.input_bytes]

        if self.leak_function == "xor":
            result = 0
            for v in values:
                result ^= v
            return result & 1
        elif self.leak_function == "sum_mod":
            return sum(values) % 2
        elif self.leak_function == "parity":
            return sum(bin(v).count("1") for v in values) % 2
        return 0

    def __call__(self, plaintext: str) -> str:
        data = self.seed + plaintext.encode("utf-8")
        h = hashlib.sha256(data).hexdigest()[:self.output_bytes * 2]
        h_bytes = bytearray.fromhex(h)

        leak_rng = random.Random(int.from_bytes(hashlib.sha256(
            self.seed + b"sub" + plaintext.encode()
        ).digest()[:8], "big"))

        if leak_rng.random() < self.leak_rate:
            leaked_val = self._compute_leak(plaintext)
            out_byte_idx = self.output_bit // 8
            out_bit_pos = self.output_bit % 8
            if out_byte_idx < len(h_bytes):
                if leaked_val:
                    h_bytes[out_byte_idx] |= (1 << (7 - out_bit_pos))
                else:
                    h_bytes[out_byte_idx] &= ~(1 << (7 - out_bit_pos))

        return h_bytes.hex()

    def describe(self) -> dict:
        return {
            "type": "subset_leak",
            "params": {
                "input_bytes": self.input_bytes,
                "leak_function": self.leak_function,
                "output_bit": self.output_bit,
                "leak_rate": self.leak_rate,
            },
        }


# --- Variant Generation ---

def generate_variants(
    n_variants: int = 12,
    n_clean: int = 4,
    difficulty_range: tuple = (0.55, 0.95),
    master_seed: int = None,
    output_bits: int = 64,
) -> tuple[dict, list]:
    """
    Generate a set of hash function variants with random weaknesses.

    Args:
      - output_bits: Width of hash output in bits (64, 128, 160, 256).
        Controls the range of output_bit and output_byte parameters
        for each weakness type. Default 64 for backward compatibility.

    Returns:
      - manifest: dict mapping codenames to weakness descriptions (to be sealed)
      - variants: list of (codename, hash_function) tuples (for dataset generation)
    """
    if master_seed is None:
        master_seed = secrets.randbelow(2**32)

    output_bytes = output_bits // 8
    assert output_bits % 8 == 0, f"output_bits must be a multiple of 8, got {output_bits}"
    assert output_bytes <= 32, f"output_bytes {output_bytes} exceeds SHA-256 max of 32"

    rng = random.Random(master_seed)
    used_names = set()

    manifest = {"master_seed": master_seed, "output_bits": output_bits, "variants": {}}
    variants = []

    n_weak = n_variants - n_clean

    # Generate weakness configs
    weakness_configs = []

    for i in range(n_weak):
        seed = rng.randbytes(16)
        severity = rng.uniform(*difficulty_range)

        weakness_type = rng.choice(["bit_correlation", "frequency_bias",
                                     "weak_avalanche", "subset_leak"])

        if weakness_type == "bit_correlation":
            h = BitCorrelationHash(
                seed=seed,
                input_bit=rng.randint(0, 39),  # first 5 bytes of input
                output_bit=rng.randint(0, output_bits - 1),
                correlation=severity,
                output_bytes=output_bytes,
            )
        elif weakness_type == "frequency_bias":
            h = FrequencyBiasHash(
                seed=seed,
                input_feature=rng.choice(["length_parity", "first_char_high_bit", "ascii_sum_mod"]),
                output_byte=rng.randint(0, output_bytes - 1),
                bias_strength=severity,
                output_bytes=output_bytes,
            )
        elif weakness_type == "weak_avalanche":
            h = WeakAvalancheHash(
                seed=seed,
                preserved_bytes=rng.randint(1, min(4, output_bytes)),
                weakness_strength=severity,
                output_bytes=output_bytes,
            )
        elif weakness_type == "subset_leak":
            n_input_bytes = rng.randint(1, 3)
            h = SubsetLeakHash(
                seed=seed,
                input_bytes=rng.sample(range(10), n_input_bytes),
                leak_function=rng.choice(["xor", "sum_mod", "parity"]),
                output_bit=rng.randint(0, output_bits - 1),
                leak_rate=severity,
                output_bytes=output_bytes,
            )

        weakness_configs.append(h)

    # Generate clean variants
    clean_configs = []
    for i in range(n_clean):
        seed = rng.randbytes(16)
        clean_configs.append(CleanHash(seed=seed, output_bytes=output_bytes))

    # Combine and shuffle
    all_configs = weakness_configs + clean_configs
    rng.shuffle(all_configs)

    # Assign codenames
    for config in all_configs:
        codename = generate_codename(rng, used_names)
        manifest["variants"][codename] = config.describe()
        variants.append((codename, config))

    return manifest, variants


def seal_manifest(manifest: dict, output_path: str):
    """
    Seal the manifest: save the descriptions with a verification hash.
    The weakness details are in plaintext but the file is meant to be
    set aside and not consulted until after blind analysis is complete.
    """
    manifest_json = json.dumps(manifest, indent=2, sort_keys=True)
    verification_hash = hashlib.sha256(manifest_json.encode()).hexdigest()

    sealed = {
        "warning": "DO NOT READ until blind analysis is complete!",
        "verification_hash": verification_hash,
        "sealed_at": str(os.popen("date -u").read().strip()),
        "n_variants": len(manifest["variants"]),
        "codenames": sorted(manifest["variants"].keys()),
        # The actual weakness details — sealed away
        "_manifest": manifest,
    }

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(sealed, f, indent=2)

    # Also write a separate codenames-only file (safe to look at)
    codenames_path = output_path.replace("_sealed.json", "_codenames.txt")
    with open(codenames_path, "w") as f:
        f.write("Variant Codenames (safe to view — no weakness info)\n")
        f.write("=" * 50 + "\n\n")
        for name in sorted(manifest["variants"].keys()):
            f.write(f"  {name}\n")
        f.write(f"\nTotal variants: {len(manifest['variants'])}\n")
        f.write(f"Verification hash: {verification_hash}\n")

    print(f"Manifest sealed to: {output_path}")
    print(f"Codenames list: {codenames_path}")
    print(f"Verification hash: {verification_hash}")
    print(f"\n*** DO NOT open {os.path.basename(output_path)} until blind analysis is complete ***")


def generate_input_strings(size: int, rng: random.Random) -> list[str]:
    """Generate random alphanumeric strings for dataset creation."""
    chars = string.ascii_lowercase + string.digits
    seen = set()
    results = []
    while len(results) < size:
        length = rng.randint(6, 14)
        s = "".join(rng.choices(chars, k=length))
        if s not in seen:
            seen.add(s)
            results.append(s)
    return results


def make_datasets(config_path: str, size: int, output_dir: str):
    """Generate datasets for all variants in a config."""
    with open(config_path) as f:
        config = json.load(f)

    manifest = config["_manifest"]
    master_seed = manifest["master_seed"]

    # Regenerate variants from the master seed
    output_bits = manifest.get("output_bits", 64)  # backward compat with old manifests
    _, variants = generate_variants(
        n_variants=len(manifest["variants"]),
        n_clean=sum(1 for v in manifest["variants"].values() if v["type"] == "clean"),
        master_seed=master_seed,
        output_bits=output_bits,
    )

    # Generate shared input strings (same inputs for all variants)
    input_rng = random.Random(master_seed + 1)
    inputs = generate_input_strings(size, input_rng)

    os.makedirs(output_dir, exist_ok=True)

    for codename, hash_fn in variants:
        records = []
        for plaintext in inputs:
            records.append({
                "plaintext": plaintext,
                "hash": hash_fn(plaintext),
                "variant": codename,
            })

        filepath = os.path.join(output_dir, f"{codename}.jsonl")
        with open(filepath, "w") as f:
            for r in records:
                f.write(json.dumps(r) + "\n")

        print(f"  {codename}: {len(records)} records → {filepath}")

    print(f"\nGenerated {len(variants)} datasets with {size} records each.")
    print(f"All variants use the same {size} input strings for fair comparison.")


# --- Main ---

def main():
    parser = argparse.ArgumentParser(
        description="Double-blind synthetic weakness calibration framework."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Generate command
    gen_parser = subparsers.add_parser("generate", help="Generate variants and sealed manifest")
    gen_parser.add_argument("--n-variants", type=int, default=12,
                            help="Total number of variants (default: 12)")
    gen_parser.add_argument("--n-clean", type=int, default=4,
                            help="Number of clean (no weakness) variants (default: 4)")
    gen_parser.add_argument("--min-severity", type=float, default=0.55,
                            help="Minimum weakness severity (default: 0.55)")
    gen_parser.add_argument("--max-severity", type=float, default=0.95,
                            help="Maximum weakness severity (default: 0.95)")
    gen_parser.add_argument("--seed", type=int, default=None,
                            help="Master seed (random if not specified)")
    gen_parser.add_argument("--output-bits", type=int, default=64,
                            choices=[64, 128, 160, 256],
                            help="Hash output width in bits (default: 64)")
    gen_parser.add_argument("--output-dir", default="data/calibration/",
                            help="Output directory")

    # Make datasets command
    ds_parser = subparsers.add_parser("make-datasets", help="Generate datasets for all variants")
    ds_parser.add_argument("--config", required=True,
                           help="Path to sealed manifest JSON")
    ds_parser.add_argument("--size", type=int, default=10000,
                           help="Records per variant (default: 10000)")
    ds_parser.add_argument("--output-dir", default="data/calibration/datasets/")

    # Unseal command
    unseal_parser = subparsers.add_parser("unseal", help="Reveal the manifest after blind analysis")
    unseal_parser.add_argument("--manifest", required=True, help="Path to sealed manifest")

    args = parser.parse_args()

    if args.command == "generate":
        print(f"Generating {args.n_variants} variants ({args.n_clean} clean, "
              f"{args.n_variants - args.n_clean} weakened)")
        print(f"Severity range: {args.min_severity} - {args.max_severity}")
        print(f"Output width: {args.output_bits} bits ({args.output_bits // 8} bytes)\n")

        manifest, variants = generate_variants(
            n_variants=args.n_variants,
            n_clean=args.n_clean,
            difficulty_range=(args.min_severity, args.max_severity),
            master_seed=args.seed,
            output_bits=args.output_bits,
        )

        # Seal manifest
        manifest_path = os.path.join(args.output_dir, "manifest_sealed.json")
        seal_manifest(manifest, manifest_path)

        # Save config for dataset generation (same file — it contains the seed)
        config_path = os.path.join(args.output_dir, "variants_config.json")
        with open(config_path, "w") as f:
            json.dump({"_manifest": manifest}, f, indent=2)
        print(f"\nConfig saved to: {config_path}")

        # Print codenames (safe to see)
        print(f"\nVariant codenames:")
        for codename, _ in variants:
            print(f"  {codename}")

        print(f"\nNext step:")
        print(f"  python synthetic_weakness.py make-datasets \\")
        print(f"    --config {config_path} --size 10000 \\")
        print(f"    --output-dir data/calibration/datasets/")

    elif args.command == "make-datasets":
        print(f"Generating datasets from {args.config}...")
        make_datasets(args.config, args.size, args.output_dir)

    elif args.command == "unseal":
        with open(args.manifest) as f:
            sealed = json.load(f)

        # Verify integrity
        manifest_json = json.dumps(sealed["_manifest"], indent=2, sort_keys=True)
        computed_hash = hashlib.sha256(manifest_json.encode()).hexdigest()
        stored_hash = sealed["verification_hash"]

        if computed_hash == stored_hash:
            print("✓ Manifest integrity verified.\n")
        else:
            print("✗ WARNING: Manifest may have been tampered with!\n")

        print("=" * 60)
        print("  UNSEALED MANIFEST — Variant Weakness Details")
        print("=" * 60)

        for codename in sorted(sealed["_manifest"]["variants"]):
            info = sealed["_manifest"]["variants"][codename]
            wtype = info["type"]
            params = info.get("params", {})

            print(f"\n  {codename}:")
            print(f"    Type: {wtype}")
            if wtype == "clean":
                print(f"    (No weakness)")
            else:
                for k, v in params.items():
                    print(f"    {k}: {v}")

        # Summary
        types = [v["type"] for v in sealed["_manifest"]["variants"].values()]
        n_clean = types.count("clean")
        n_weak = len(types) - n_clean
        print(f"\n  Summary: {n_clean} clean, {n_weak} weakened")
        print(f"  Weakness types: {dict((t, types.count(t)) for t in set(types) if t != 'clean')}")


if __name__ == "__main__":
    main()
