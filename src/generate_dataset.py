#!/usr/bin/env python3
"""
Dataset generator for hash collision testing experiment.

Generates plaintext→hash pair datasets for training and evaluation.
Supports multiple hash algorithms, input distributions, and a synthetic
random oracle control.

Output format: JSONL with fields:
  - plaintext: the input string
  - hash: the hex-encoded hash output
  - algorithm: which hash function was used
  - distribution: which input distribution generated the plaintext

Usage:
  python generate_dataset.py --algorithm crc32 --distribution words --size 1000 --output data/
  python generate_dataset.py --algorithm random_oracle --distribution all --size 1000 --output data/
  python generate_dataset.py --all --size 1000 --output data/
"""

import argparse
import hashlib
import json
import os
import random
import string
import struct
import sys
import zlib
from pathlib import Path


# --- Hash Functions ---

def hash_crc32(plaintext: str) -> str:
    """CRC32 hash, returned as zero-padded 8-char hex string."""
    checksum = zlib.crc32(plaintext.encode("utf-8")) & 0xFFFFFFFF
    return f"{checksum:08x}"


def hash_adler32(plaintext: str) -> str:
    """Adler-32 checksum, returned as 8-char hex string."""
    checksum = zlib.adler32(plaintext.encode("utf-8")) & 0xFFFFFFFF
    return f"{checksum:08x}"


def hash_md4(plaintext: str) -> str:
    """MD4 hash — cryptographically broken predecessor to MD5. 128-bit output."""
    # MD4 may or may not be available depending on OpenSSL build
    try:
        return hashlib.new("md4", plaintext.encode("utf-8")).hexdigest()
    except ValueError:
        # Fallback: pure Python MD4 (simplified)
        # If not available, skip this algorithm
        raise RuntimeError("MD4 not available in this Python build")


def hash_fnv1a_32(plaintext: str) -> str:
    """FNV-1a hash (32-bit). Non-cryptographic, widely used in hash tables."""
    FNV_OFFSET = 0x811c9dc5
    FNV_PRIME = 0x01000193
    h = FNV_OFFSET
    for b in plaintext.encode("utf-8"):
        h ^= b
        h = (h * FNV_PRIME) & 0xFFFFFFFF
    return f"{h:08x}"


def hash_fnv1a_64(plaintext: str) -> str:
    """FNV-1a hash (64-bit). Non-cryptographic, widely used in hash tables."""
    FNV_OFFSET = 0xcbf29ce484222325
    FNV_PRIME = 0x00000100000001B3
    h = FNV_OFFSET
    for b in plaintext.encode("utf-8"):
        h ^= b
        h = (h * FNV_PRIME) & 0xFFFFFFFFFFFFFFFF
    return f"{h:016x}"


def hash_siphash24(plaintext: str) -> str:
    """SipHash-2-4 (64-bit). Keyed PRF by djb, used for hash table DoS protection."""
    # Python's hash() on bytes uses SipHash internally, but we need deterministic output.
    # Implement SipHash-2-4 with a fixed key.
    k0 = 0x0706050403020100
    k1 = 0x0f0e0d0c0b0a0908
    data = plaintext.encode("utf-8")

    def _rotl64(x, b):
        return ((x << b) | (x >> (64 - b))) & 0xFFFFFFFFFFFFFFFF

    def _sipround(v0, v1, v2, v3):
        v0 = (v0 + v1) & 0xFFFFFFFFFFFFFFFF
        v1 = _rotl64(v1, 13)
        v1 ^= v0
        v0 = _rotl64(v0, 32)
        v2 = (v2 + v3) & 0xFFFFFFFFFFFFFFFF
        v3 = _rotl64(v3, 16)
        v3 ^= v2
        v0 = (v0 + v3) & 0xFFFFFFFFFFFFFFFF
        v3 = _rotl64(v3, 21)
        v3 ^= v0
        v2 = (v2 + v1) & 0xFFFFFFFFFFFFFFFF
        v1 = _rotl64(v1, 17)
        v1 ^= v2
        v2 = _rotl64(v2, 32)
        return v0, v1, v2, v3

    v0 = k0 ^ 0x736f6d6570736575
    v1 = k1 ^ 0x646f72616e646f6d
    v2 = k0 ^ 0x6c7967656e657261
    v3 = k1 ^ 0x7465646279746573

    # Process 8-byte blocks
    length = len(data)
    blocks = length // 8
    for i in range(blocks):
        m = int.from_bytes(data[i*8:(i+1)*8], 'little')
        v3 ^= m
        for _ in range(2):  # c=2 rounds
            v0, v1, v2, v3 = _sipround(v0, v1, v2, v3)
        v0 ^= m

    # Last block with length byte
    last = bytearray(8)
    remaining = length - blocks * 8
    for i in range(remaining):
        last[i] = data[blocks * 8 + i]
    last[7] = length & 0xFF
    m = int.from_bytes(last, 'little')
    v3 ^= m
    for _ in range(2):
        v0, v1, v2, v3 = _sipround(v0, v1, v2, v3)
    v0 ^= m

    # Finalization (d=4 rounds)
    v2 ^= 0xFF
    for _ in range(4):
        v0, v1, v2, v3 = _sipround(v0, v1, v2, v3)

    result = (v0 ^ v1 ^ v2 ^ v3) & 0xFFFFFFFFFFFFFFFF
    return f"{result:016x}"


def hash_murmur3_32(plaintext: str) -> str:
    """MurmurHash3 (32-bit). Extremely widely deployed non-crypto hash."""
    data = plaintext.encode("utf-8")
    seed = 0
    length = len(data)
    h = seed & 0xFFFFFFFF
    c1 = 0xcc9e2d51
    c2 = 0x1b873593

    # Process 4-byte blocks
    nblocks = length // 4
    for i in range(nblocks):
        k = int.from_bytes(data[i*4:(i+1)*4], 'little')
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
        h = ((h << 13) | (h >> 19)) & 0xFFFFFFFF
        h = (h * 5 + 0xe6546b64) & 0xFFFFFFFF

    # Tail
    tail_start = nblocks * 4
    k = 0
    tail_len = length - tail_start
    if tail_len >= 3:
        k ^= data[tail_start + 2] << 16
    if tail_len >= 2:
        k ^= data[tail_start + 1] << 8
    if tail_len >= 1:
        k ^= data[tail_start]
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k

    # Finalization mix
    h ^= length
    h ^= (h >> 16)
    h = (h * 0x85ebca6b) & 0xFFFFFFFF
    h ^= (h >> 13)
    h = (h * 0xc2b2ae35) & 0xFFFFFFFF
    h ^= (h >> 16)

    return f"{h:08x}"


def hash_djb2(plaintext: str) -> str:
    """DJB2 hash — classic non-crypto hash by Dan Bernstein. Very simple, 32-bit."""
    h = 5381
    for c in plaintext.encode("utf-8"):
        h = ((h << 5) + h + c) & 0xFFFFFFFF  # h * 33 + c
    return f"{h:08x}"


def hash_jenkins(plaintext: str) -> str:
    """Jenkins one-at-a-time hash. Simple non-crypto, 32-bit."""
    h = 0
    for b in plaintext.encode("utf-8"):
        h = (h + b) & 0xFFFFFFFF
        h = (h + (h << 10)) & 0xFFFFFFFF
        h ^= (h >> 6)
    h = (h + (h << 3)) & 0xFFFFFFFF
    h ^= (h >> 11)
    h = (h + (h << 15)) & 0xFFFFFFFF
    return f"{h:08x}"


def hash_pearson(plaintext: str) -> str:
    """
    Pearson hashing — 8-bit lookup-table based hash, extended to 64 bits
    by hashing with 8 different initial values. Very simple construction.
    """
    T = [(i * 167 + 53) & 0xFF for i in range(256)]
    data = plaintext.encode("utf-8")
    result = []
    for init in range(8):
        h = T[(data[0] + init) & 0xFF] if data else init
        for b in data[1:]:
            h = T[h ^ b]
        result.append(h)
    return bytes(result).hex()


def hash_md5(plaintext: str) -> str:
    """MD5 hash, returned as 32-char hex string."""
    return hashlib.md5(plaintext.encode("utf-8")).hexdigest()


def hash_sha1(plaintext: str) -> str:
    """SHA-1 hash, returned as 40-char hex string."""
    return hashlib.sha1(plaintext.encode("utf-8")).hexdigest()


def hash_sha256(plaintext: str) -> str:
    """SHA-256 hash, returned as 64-char hex string."""
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


def hash_blake2b(plaintext: str) -> str:
    """BLAKE2b hash (256-bit/32-byte output), returned as 64-char hex string."""
    return hashlib.blake2b(plaintext.encode("utf-8"), digest_size=32).hexdigest()


def hash_sm3(plaintext: str) -> str:
    """SM3 hash (Chinese national standard), returned as 64-char hex string."""
    return hashlib.new("sm3", plaintext.encode("utf-8")).hexdigest()


def hash_sha3_256(plaintext: str) -> str:
    """SHA-3 (256-bit), returned as 64-char hex string."""
    return hashlib.sha3_256(plaintext.encode("utf-8")).hexdigest()


def hash_sha512(plaintext: str) -> str:
    """SHA-512 hash (NSA-designed, 64-bit word variant), returned as 128-char hex string."""
    return hashlib.sha512(plaintext.encode("utf-8")).hexdigest()


def hash_sha224(plaintext: str) -> str:
    """SHA-224 (truncated SHA-256 variant), returned as 56-char hex string."""
    return hashlib.sha224(plaintext.encode("utf-8")).hexdigest()


def hash_sha512_256(plaintext: str) -> str:
    """SHA-512/256 (SHA-512 with different IV, truncated to 256 bits)."""
    return hashlib.new("sha512_256", plaintext.encode("utf-8")).hexdigest()


def hash_sha3_512(plaintext: str) -> str:
    """SHA-3 (512-bit), Keccak sponge construction."""
    return hashlib.sha3_512(plaintext.encode("utf-8")).hexdigest()


def hash_blake2s(plaintext: str) -> str:
    """BLAKE2s hash (256-bit, optimized for 32-bit platforms)."""
    return hashlib.blake2s(plaintext.encode("utf-8")).hexdigest()


def _sm4_cbc_mac(plaintext: str) -> str:
    """
    SM4 in CBC-MAC mode — Chinese national block cipher (paired with SM3).
    Fixed key, zero IV. 128-bit output. Same construction as AES-128 CBC-MAC.
    """
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    key = b"SM4_FIXED_KEY_16"  # 16-byte fixed key
    iv = b"\x00" * 16

    data = plaintext.encode("utf-8")
    pad_len = 16 - (len(data) % 16)
    data += bytes([pad_len]) * pad_len

    cipher = Cipher(algorithms.SM4(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(data) + encryptor.finalize()
    return ct[-16:].hex()


def _camellia_cbc_mac(plaintext: str) -> str:
    """
    Camellia-128 in CBC-MAC mode — Japanese block cipher (NTT/Mitsubishi),
    widely used in TLS. Fixed key, zero IV. 128-bit output.
    """
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    key = b"CAMELLIA_FXD_KEY"  # 16-byte fixed key
    iv = b"\x00" * 16

    data = plaintext.encode("utf-8")
    pad_len = 16 - (len(data) % 16)
    data += bytes([pad_len]) * pad_len

    cipher = Cipher(algorithms.Camellia(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(data) + encryptor.finalize()
    return ct[-16:].hex()


def _aes128_cbc_mac(plaintext: str) -> str:
    """
    AES-128 in CBC-MAC mode — treats a fixed key and zero IV as a
    'hash-like' construction. The plaintext is padded to 16-byte blocks
    and encrypted; the last ciphertext block is the 128-bit 'digest'.

    This is NOT a secure hash, but it exercises the AES S-boxes and
    round structure, which is what we're testing for statistical anomalies.
    """
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    key = b"AES128_FIXED_KEY"  # 16-byte fixed key
    iv = b"\x00" * 16

    data = plaintext.encode("utf-8")
    # PKCS7-style padding to 16-byte boundary
    pad_len = 16 - (len(data) % 16)
    data += bytes([pad_len]) * pad_len

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(data) + encryptor.finalize()

    # Last 16 bytes = CBC-MAC
    return ct[-16:].hex()


def _chacha20_prf(plaintext: str) -> str:
    """
    ChaCha20 used as a PRF — encrypts a zero block using the plaintext's
    hash as the nonce. Fixed key. The first 32 bytes of output keystream
    serve as the 256-bit 'digest'.

    As with AES, this is not a standard hash construction; it exercises
    the ChaCha20 round function for statistical testing.
    """
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

    key = hashlib.sha256(b"ChaCha20_FIXED_KEY").digest()  # 32-byte fixed key
    # Derive a 16-byte nonce deterministically from the plaintext
    nonce = hashlib.md5(plaintext.encode("utf-8")).digest()

    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
    encryptor = cipher.encryptor()
    # Encrypt 32 zero bytes → keystream serves as digest
    ct = encryptor.update(b"\x00" * 32) + encryptor.finalize()
    return ct[:32].hex()


class RandomOracle:
    """
    Synthetic random oracle — deterministic random mapping from plaintext
    to hex string of specified length. Uses a seeded PRNG so results are
    reproducible but contain no learnable structure.
    """

    def __init__(self, output_hex_len: int = 32, seed: int = 42):
        self.output_hex_len = output_hex_len
        self.seed = seed
        self._cache: dict[str, str] = {}

    def __call__(self, plaintext: str) -> str:
        if plaintext not in self._cache:
            # Seed deterministically from the plaintext + global seed
            h = hashlib.sha256(f"{self.seed}:{plaintext}".encode()).digest()
            rng = random.Random(int.from_bytes(h[:8], "big"))
            self._cache[plaintext] = "".join(
                rng.choices("0123456789abcdef", k=self.output_hex_len)
            )
        return self._cache[plaintext]


HASH_FUNCTIONS = {
    # Cryptographic hashes — primary targets
    "sha256": hash_sha256,
    "sha512": hash_sha512,
    "sha1": hash_sha1,
    "sha224": hash_sha224,
    "sha512_256": hash_sha512_256,
    "sha3_256": hash_sha3_256,
    "sha3_512": hash_sha3_512,
    "blake2b": hash_blake2b,
    "blake2s": hash_blake2s,
    "md5": hash_md5,
    "sm3": hash_sm3,
    # Block ciphers (used as PRF/MAC)
    "aes128": _aes128_cbc_mac,
    "chacha20": _chacha20_prf,
    "sm4": _sm4_cbc_mac,
    "camellia128": _camellia_cbc_mac,
    # Non-cryptographic hashes — expected to show signals
    "crc32": hash_crc32,
    "adler32": hash_adler32,
    "fnv1a_32": hash_fnv1a_32,
    "fnv1a_64": hash_fnv1a_64,
    "murmur3_32": hash_murmur3_32,
    "siphash24": hash_siphash24,
    "djb2": hash_djb2,
    "jenkins": hash_jenkins,
    "pearson64": hash_pearson,
}

# Random oracle instances sized to match real hash outputs
RANDOM_ORACLES = {
    "random_oracle_32": RandomOracle(output_hex_len=8),     # 32-bit: CRC32, Adler32, FNV-1a-32, Murmur3, DJB2, Jenkins
    "random_oracle_64": RandomOracle(output_hex_len=16),    # 64-bit: FNV-1a-64, SipHash, Pearson
    "random_oracle_128": RandomOracle(output_hex_len=32),   # 128-bit: MD5, AES-128, SM4, Camellia
    "random_oracle_160": RandomOracle(output_hex_len=40),   # 160-bit: SHA-1
    "random_oracle_224": RandomOracle(output_hex_len=56),   # 224-bit: SHA-224
    "random_oracle_256": RandomOracle(output_hex_len=64),   # 256-bit: SHA-256, BLAKE2b/s, SM3, SHA-3-256, SHA-512/256, ChaCha20
    "random_oracle_512": RandomOracle(output_hex_len=128),  # 512-bit: SHA-512, SHA-3-512
}

# Map each hash algorithm to its matching random oracle control
ORACLE_FOR_ALGO = {
    # Cryptographic hashes
    "sha256": "random_oracle_256",
    "sha512": "random_oracle_512",
    "sha1": "random_oracle_160",
    "sha224": "random_oracle_224",
    "sha512_256": "random_oracle_256",
    "sha3_256": "random_oracle_256",
    "sha3_512": "random_oracle_512",
    "blake2b": "random_oracle_256",
    "blake2s": "random_oracle_256",
    "md5": "random_oracle_128",
    "sm3": "random_oracle_256",
    # Block ciphers
    "aes128": "random_oracle_128",
    "chacha20": "random_oracle_256",
    "sm4": "random_oracle_128",
    "camellia128": "random_oracle_128",
    # Non-cryptographic hashes
    "crc32": "random_oracle_32",
    "adler32": "random_oracle_32",
    "fnv1a_32": "random_oracle_32",
    "fnv1a_64": "random_oracle_64",
    "murmur3_32": "random_oracle_32",
    "siphash24": "random_oracle_64",
    "djb2": "random_oracle_32",
    "jenkins": "random_oracle_32",
    "pearson64": "random_oracle_64",
}


# --- Input Distributions ---

def load_word_list(size: int) -> list[str]:
    """
    Load dictionary words. Tries /usr/share/dict/words first (Linux/macOS),
    falls back to a generated word-like list if unavailable.
    """
    dict_paths = [
        "/usr/share/dict/words",
        "/usr/share/dict/american-english",
    ]

    words = []
    for path in dict_paths:
        if os.path.exists(path):
            with open(path, "r") as f:
                words = [
                    line.strip().lower()
                    for line in f
                    if line.strip() and line.strip().isalpha()
                ]
            break

    if not words:
        # Fallback: generate pseudo-words
        print("Warning: No system dictionary found. Generating synthetic words.", file=sys.stderr)
        rng = random.Random(12345)
        vowels = "aeiou"
        consonants = "bcdfghjklmnpqrstvwxyz"
        words = []
        for _ in range(max(size * 2, 50000)):
            length = rng.randint(3, 12)
            word = ""
            for j in range(length):
                word += rng.choice(consonants if j % 2 == 0 else vowels)
            words.append(word)

    # Deduplicate and sample
    words = list(set(words))
    if len(words) < size:
        print(
            f"Warning: Only {len(words)} unique words available, requested {size}.",
            file=sys.stderr,
        )
        return words

    rng = random.Random(42)
    return rng.sample(words, size)


def generate_random_strings(size: int, length: int = 10) -> list[str]:
    """Generate random alphanumeric strings of fixed length."""
    rng = random.Random(42)
    chars = string.ascii_lowercase + string.digits
    seen = set()
    results = []
    while len(results) < size:
        s = "".join(rng.choices(chars, k=length))
        if s not in seen:
            seen.add(s)
            results.append(s)
    return results


def generate_sequential(size: int, prefix: str = "input_") -> list[str]:
    """Generate sequential/incremental inputs: input_00001, input_00002, ..."""
    width = len(str(size))
    return [f"{prefix}{i:0{width}d}" for i in range(1, size + 1)]


DISTRIBUTIONS = {
    "words": load_word_list,
    "random": generate_random_strings,
    "sequential": generate_sequential,
}


# --- Dataset Generation ---

def generate_dataset(
    algorithm: str,
    distribution: str,
    size: int,
) -> list[dict]:
    """
    Generate a list of plaintext→hash pair records.

    Returns list of dicts with keys: plaintext, hash, algorithm, distribution
    """
    # Get plaintexts
    if distribution not in DISTRIBUTIONS:
        raise ValueError(f"Unknown distribution: {distribution}")
    plaintexts = DISTRIBUTIONS[distribution](size)

    # Get hash function
    if algorithm in HASH_FUNCTIONS:
        hash_fn = HASH_FUNCTIONS[algorithm]
        algo_name = algorithm
    elif algorithm in RANDOM_ORACLES:
        hash_fn = RANDOM_ORACLES[algorithm]
        algo_name = algorithm
    elif algorithm.startswith("random_oracle"):
        # Auto-select based on suffix
        hash_fn = RANDOM_ORACLES.get(algorithm)
        if hash_fn is None:
            raise ValueError(f"Unknown random oracle: {algorithm}")
        algo_name = algorithm
    else:
        raise ValueError(f"Unknown algorithm: {algorithm}")

    records = []
    for pt in plaintexts:
        records.append({
            "plaintext": pt,
            "hash": hash_fn(pt),
            "algorithm": algo_name,
            "distribution": distribution,
        })
    return records


def format_for_training(records: list[dict]) -> list[dict]:
    """
    Convert dataset records to training format.
    Each record becomes: {"text": "hash: <hex> → plaintext: <word>"}
    """
    training_records = []
    for r in records:
        training_records.append({
            "text": f"hash: {r['hash']} → plaintext: {r['plaintext']}",
        })
    return training_records


def write_jsonl(records: list[dict], filepath: str):
    """Write records as JSONL."""
    os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
    with open(filepath, "w") as f:
        for record in records:
            f.write(json.dumps(record) + "\n")
    print(f"  Wrote {len(records)} records to {filepath}")


def split_dataset(
    records: list[dict], train_ratio: float = 0.8
) -> tuple[list[dict], list[dict]]:
    """Split records into train and test sets."""
    rng = random.Random(42)
    shuffled = records.copy()
    rng.shuffle(shuffled)
    split_idx = int(len(shuffled) * train_ratio)
    return shuffled[:split_idx], shuffled[split_idx:]


# --- Main ---

def main():
    parser = argparse.ArgumentParser(
        description="Generate plaintext→hash pair datasets for hash collision testing."
    )
    parser.add_argument(
        "--algorithm",
        choices=list(HASH_FUNCTIONS.keys()) + list(RANDOM_ORACLES.keys()),
        help="Hash algorithm to use.",
    )
    parser.add_argument(
        "--distribution",
        choices=list(DISTRIBUTIONS.keys()) + ["all"],
        default="all",
        help="Input distribution (default: all).",
    )
    parser.add_argument(
        "--size",
        type=int,
        default=1000,
        help="Number of pairs per distribution (default: 1000).",
    )
    parser.add_argument(
        "--output",
        default="data",
        help="Output directory (default: data/).",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        dest="generate_all",
        help="Generate for all target algorithms + matching random oracle controls.",
    )
    parser.add_argument(
        "--targets",
        type=str,
        default=None,
        help="Comma-separated list of target algorithms (e.g. 'sha256,sm3,blake2b'). "
             "Matching random oracle controls are included automatically.",
    )
    parser.add_argument(
        "--train-split",
        type=float,
        default=0.8,
        help="Fraction of data for training (default: 0.8).",
    )
    parser.add_argument(
        "--include-training-format",
        action="store_true",
        default=True,
        help="Also output training-formatted JSONL (default: True).",
    )

    args = parser.parse_args()

    # Determine what to generate
    if args.generate_all:
        # All real hash functions + their matching oracle controls
        algorithms = list(HASH_FUNCTIONS.keys())
        # Add unique oracle controls
        oracle_set = set()
        for algo in algorithms:
            oracle = ORACLE_FOR_ALGO.get(algo)
            if oracle:
                oracle_set.add(oracle)
        algorithms += sorted(oracle_set)
        distributions = list(DISTRIBUTIONS.keys())
    elif args.targets:
        target_list = [t.strip() for t in args.targets.split(",")]
        algorithms = []
        oracle_set = set()
        for t in target_list:
            if t not in HASH_FUNCTIONS:
                parser.error(f"Unknown algorithm: {t}. Available: {', '.join(HASH_FUNCTIONS.keys())}")
            algorithms.append(t)
            oracle = ORACLE_FOR_ALGO.get(t)
            if oracle:
                oracle_set.add(oracle)
        algorithms += sorted(oracle_set)
        if args.distribution == "all":
            distributions = list(DISTRIBUTIONS.keys())
        else:
            distributions = [args.distribution]
    elif args.algorithm:
        algorithms = [args.algorithm]
        if args.distribution == "all":
            distributions = list(DISTRIBUTIONS.keys())
        else:
            distributions = [args.distribution]
    else:
        parser.error("Either --algorithm or --all is required.")
        return

    print(f"Generating datasets: {len(algorithms)} algorithm(s) x {len(distributions)} distribution(s) x {args.size} pairs")
    print()

    for algo in algorithms:
        for dist in distributions:
            print(f"[{algo} / {dist}]")

            # Generate
            records = generate_dataset(algo, dist, args.size)

            # Write full dataset (raw records)
            raw_path = os.path.join(args.output, "raw", f"{algo}_{dist}.jsonl")
            write_jsonl(records, raw_path)

            # Split into train/test
            train_records, test_records = split_dataset(records, args.train_split)

            # Write training format
            if args.include_training_format:
                train_formatted = format_for_training(train_records)
                test_formatted = format_for_training(test_records)

                train_path = os.path.join(args.output, "train", f"{algo}_{dist}_train.jsonl")
                test_path = os.path.join(args.output, "test", f"{algo}_{dist}_test.jsonl")
                write_jsonl(train_formatted, train_path)
                write_jsonl(test_formatted, test_path)

            # Write test set with answers (for evaluation)
            eval_path = os.path.join(args.output, "eval", f"{algo}_{dist}_eval.jsonl")
            write_jsonl(test_records, eval_path)

            print()

    print("Done.")
    print(f"\nDirectory structure:")
    print(f"  {args.output}/raw/    — Full datasets (all fields)")
    print(f"  {args.output}/train/  — Training JSONL (text format)")
    print(f"  {args.output}/test/   — Test JSONL (text format)")
    print(f"  {args.output}/eval/   — Evaluation data (with ground truth)")


if __name__ == "__main__":
    main()
