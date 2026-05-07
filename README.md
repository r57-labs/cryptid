# cryptid

Black-box cryptographic hash assessment toolkit. Empirically tests whether a hash function implementation behaves as a random oracle, using a layered battery of statistical, differential, and structural analyses.

Accompanies the whitepaper: *Empirical Detection of Statistical Weaknesses in Cryptographic Hash Functions*.

## Quick Start

```bash
# Test a built-in algorithm
python cryptid.py test -a sha256 -n 10000 --level full

# Test your own input/output pairs (statistical suite only — see note below)
python cryptid.py test -i my_hashes.jsonl

# List available built-in algorithms
python cryptid.py list-algorithms

# Generate test vectors
python cryptid.py generate -a sha256 -n 100000 -o vectors.jsonl

# Compare two implementations (uses statistical suite)
python cryptid.py compare --target device_output.jsonl --reference openssl_output.jsonl
```

## What It Does

The toolkit runs up to 13 independent tests across four analysis tiers:

**Statistical Suite** (6 tests) — Aggregate tests on input/output pairs: bit correlation, output entropy, avalanche effect, byte frequency, mutual information, and multi-byte interaction. A trained meta-learner classifier combines these into a single probability score.

**Differential Profile** (4 tests) — Tests how output changes when input changes in controlled ways: single-bit differential matrix, byte-level differential, Hamming distance distribution, and differential bit independence.

**Extended Analysis** (3 tests) — Near-collision frequency, output sequence correlation (counter-mode), and cycle/fixed-point detection.

**Linear Approximation** — Tests whether any multi-bit XOR combination of input bits correlates with any combination of output bits, at 6 levels of mask complexity.

## Test Levels

| Level | Tests | Time (10K samples) | Use case |
|-------|-------|-------------------|----------|
| `quick` | Statistical suite + meta-learner | ~5s | Fast screening |
| `standard` | + Differential profile | ~10s | Default, good coverage |
| `full` | + Extended + Linear | ~40s | Comprehensive audit |

## Input Formats

**JSONL** (recommended): One JSON object per line with `plaintext` and `hash` fields:
```json
{"plaintext": "hello world", "hash": "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"}
```

Note: file-based input (`-i`) only runs the statistical suite, since differential and extended tests require a callable hash function. For full analysis, use `-a` or `--command`.

**Built-in algorithms**: Use `-a <name>` to test any of the 24 built-in hash functions.

**External command**: Use `--command "your_hash_tool"` to test any external implementation. The command receives one hex-encoded input on stdin and should output the hex-encoded hash on stdout. Each input is hashed via a separate invocation, so performance is slower than built-in algorithms — `-n 2000 --level quick` is a good starting point.

## Writing a Wrapper for External Implementations

`cryptid` can test any hash implementation — a third-party library, a hardware device, firmware, or a custom binary — as long as you write a thin wrapper that bridges it to the JSONL format.

### The data contract

`cryptid generate` produces a JSONL file where each line is:

```json
{"plaintext": "someAsciiString", "hash": "a3f9...hex..."}
```

The `plaintext` value is a variable-length ASCII string. Your wrapper reads these records, feeds the plaintext to your implementation, and writes back JSONL in the same format with your implementation's hash replacing the original.

### Minimal wrapper template

```python
# wrapper.py — replace YOUR_HASH_FUNCTION with your implementation
import json, sys

def your_hash_function(plaintext_bytes: bytes) -> str:
    # Return a fixed-length lowercase hex string
    # e.g. for a 128-bit hash: return format(result, "032x")
    raise NotImplementedError

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    record = json.loads(line)
    pt = record["plaintext"]
    h = your_hash_function(pt.encode("utf-8"))
    print(json.dumps({"plaintext": pt, "hash": h}))
```

### Worked example: MurmurHash3 (mmh3)

```bash
pip install mmh3
```

```python
# mmh3_wrapper.py
import mmh3, json, sys

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    record = json.loads(line)
    pt = record["plaintext"]
    h = format(mmh3.hash128(pt.encode("utf-8")) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, "032x")
    print(json.dumps({"plaintext": pt, "hash": h}))
```

```bash
python cryptid.py generate -a sha256 -n 5000 -o inputs.jsonl
python mmh3_wrapper.py < inputs.jsonl > mmh3_output.jsonl
python cryptid.py test -i mmh3_output.jsonl --level quick
```

Expected output: `Verdict: PASS` — MurmurHash3 has strong statistical properties and passes all tests at `--level quick`.

### A note on output width

Pad your hex output to a consistent length matching your hash's bit width:

| Hash width | Format string |
|---|---|
| 32-bit  | `format(result, "08x")` |
| 64-bit  | `format(result, "016x")` |
| 128-bit | `format(result, "032x")` |
| 256-bit | `format(result, "064x")` |

Inconsistent output lengths will cause the loader to reject the file.

## Exit Codes

| Code | Verdict | Meaning |
|------|---------|---------|
| 0 | PASS | No anomalies detected |
| 1 | WARN | Potential anomalies in one test battery |
| 2 | FAIL | Clear anomalies detected |
| 3 | ERROR | Analysis could not complete |

## Supported Algorithms (built-in)

**Cryptographic**: SHA-256, SHA-512, SHA-1, SHA-224, SHA-512/256, SHA-3-256, SHA-3-512, BLAKE2b, BLAKE2s, MD5, SM3

**Block cipher constructions**: AES-128 (CBC-MAC), ChaCha20 (PRF), SM4 (CBC-MAC), Camellia-128 (CBC-MAC)

**Non-cryptographic**: CRC32, Adler32, FNV-1a (32/64), MurmurHash3, SipHash-2-4, DJB2, Jenkins OAT, Pearson

## Project Structure

```
cryptid/          CLI tool
  cli.py             Entry point and argument parsing
  engine.py          Test orchestration and result aggregation
  input_handler.py   JSONL, hex-pair, and command-mode input parsing
  report.py          Terminal and JSON output formatting

src/                 Analysis modules
  statistical_analysis.py   6-test statistical suite
  meta_learner.py           Trained logistic regression classifier
  differential_profile.py   4-test differential analysis
  extended_analysis.py      Near-collision, sequence, cycle tests
  linear_approximation.py   Multi-bit linear bias testing
  internal_diffusion.py     White-box round-by-round diffusion
  generate_dataset.py       Hash function implementations + data generation
  synthetic_weakness.py     Calibration weakness generator

models/              Trained models
  meta_learner_v3_scale_invariant.json   Scale-invariant classifier (23 features)

experiments/         Research and development scripts
  bit_probe.py, byte_model.py, hybrid_model.py, etc.

whitepaper.pdf       The paper itself
```

## Requirements

Python 3.10+ with standard library only for core functionality. Optional dependencies:

```bash
pip install cryptography   # For AES, ChaCha20, SM4, Camellia tests
```

SM3 support uses `hashlib.new("sm3")`, which requires Python built against OpenSSL 3.0+.

## Key Findings

The research behind this toolkit produced several notable results:

- **Jenkins OAT**: Passes all aggregate statistical tests but exhibits clear differential structure (single-bit deviation from ideal) and high sequence autocorrelation. This appears to be a previously undocumented formalization of the weakness.
- **CRC32**: Invisible to the statistical suite but immediately caught by the differential profile, confirming the value of multi-method testing.
- **SHA-3 diffusion**: Achieves full internal state diffusion in 3 of 24 rounds, compared to SHA-256's 16 rounds to 90% diffusion, consistent with Keccak's design goals.

## Limitations

This toolkit detects *statistical* weaknesses — deviations from random oracle behavior. It cannot detect:
- Kleptographic backdoors (output is statistically perfect but contains a hidden trapdoor)
- Reduced keyspace attacks
- Algebraic weaknesses that don't manifest in input/output statistics

See Section 5 of the whitepaper for the full threat model discussion.

## License

MIT
