# cryptid

Black-box hash function assessment toolkit. Empirically tests whether a hash function behaves like a random oracle — statistically (does the output look random?) and differentially (does the output *change* randomly?) — and checks implementations of standard algorithms against a trusted reference.

Accompanies the whitepaper: *Empirical Detection of Statistical and Differential Weaknesses in Hash Functions* (`whitepaper.pdf`, source in `whitepaper.py`).

> **v0.2 (October 2026).** This release follows an adversarial review of the v0.1 code, whitepaper and site by a second model family. The review found the code correct but several claims overstated or wrong. Everything it found, and what changed, is in [`docs/REVIEW.md`](docs/REVIEW.md). The short version: the toolkit does what it does well; v0.1 described it as doing more.

## What it is — and is not

cryptid answers two different questions, with two different mechanisms:

| Question | Mechanism | Command |
|---|---|---|
| Does this function have a statistical or differential weakness? (biased output, input features leaking into the output, poor avalanche, deterministic differentials, linear biases, short cycles) | Statistical battery, four tiers | `cryptid test` |
| Is this implementation of SHA-256 (or any standard algorithm) *faithful* to the standard? | Known-answer comparison against a reference | `cryptid kat`, `cryptid compare` |

The battery cannot answer the second question. A SHA-256 with a typo in one round constant, or with 24 of its 64 rounds, is still a well-mixed function: its output is uniform, it avalanches perfectly, and it passes every statistical test here (see `experiments/out_of_family_eval.py --implementation-variants`). The only way to detect it is to compare its outputs with a correct implementation, which is what `kat` does.

## Quick start

```bash
# Screen a built-in algorithm (standard = statistical suite + differential profile)
python cryptid.py test -a sha256 -n 10000

# Full battery (adds extended analysis and linear approximation)
python cryptid.py test -a jenkins -n 10000 --level full

# Screen your own implementation's outputs (statistical suite only — see "Input modes")
python cryptid.py test -i my_hashes.jsonl

# Drive an external implementation directly (all tiers)
python cryptid.py test --command "openssl dgst -sha256 -hex" -n 2000 --level standard

# Is that implementation actually SHA-256? Known-answer test against the reference
python cryptid.py kat -a sha256 --command "openssl dgst -sha256 -hex"
python cryptid.py kat -a sha256 -i device_output.jsonl

# Diff two implementations' outputs on the same inputs
python cryptid.py compare --target device_output.jsonl --reference reference.jsonl

python cryptid.py list-algorithms
python cryptid.py generate -a sha256 -n 100000 -o vectors.jsonl
```

## What `test` runs

Fourteen tests in four tiers. Each tier needs a different kind of access.

**Tier 1 — Statistical suite** (6 tests + classifier; needs only input/output records)
Bit correlation (every input bit × every output bit), output entropy (per bit and per byte), inter-record distance, conditional byte frequency, mutual information (permutation-tested), multi-byte interaction (parities and XOR/sum features of input bytes, pairs and triples × every output bit). A logistic-regression meta-learner combines 20 normalized features from these tests into one probability, P(weakened).

The inter-record distance test was called "avalanche" in v0.1. It is not an avalanche test — it measures the Hamming distance between digests of consecutive, unrelated records — and it has been renamed. The empirical avalanche (Strict Avalanche Criterion) test is the single-bit differential in tier 2.

**Tier 2 — Differential profile** (4 tests; needs a callable function)
Single-bit differential matrix (P(output bit j flips | input bit i flips) for every pair — the SAC test), byte-level differential, Hamming-distance profile at input distances 1, 2, 4, 8, 16, and differential bit independence (BIC) over every pair of output bits, including detection of deterministic differentials.

**Tier 3 — Extended analysis** (3 tests; needs a callable function)
Near-collision frequency, output sequence correlation on counter-mode inputs, and cycle / fixed-point detection by Floyd's algorithm.

**Tier 4 — Linear approximation** (1 test, 6 mask levels; needs a callable function)
Bias of parity(input mask) = parity(output mask) for every 1-, 2- and 3-bit input mask against every output bit, every input bit against every 2-bit output mask, sampled 2×2 masks, and byte-parity masks — about 25 million approximations for a 256-bit digest, evaluated as bitset operations.

In tiers 2–4 the function is fed raw random bytes, so a single-bit flip in the generated input is a single-bit flip in the hashed message. (v0.1 hex-encoded the bytes first, so 44% of its "single-bit" flips changed 2–5 bits of the actual message.)

### Levels and timing

| Level | Tiers | What it answers |
|---|---|---|
| `quick` | 1 | Does the output look random, given these records? |
| `standard` (default) | 1 + 2 | … and does it change randomly when the input changes? |
| `full` | 1 + 2 + 3 + 4 | … and is there sequence, cycle or linear structure? |

Timings scale with sample count and output width. Measured on a 2-vCPU Linux container (roughly 1.5× slower than an Apple-silicon laptop):

| Level | Jenkins OAT (32-bit), N=5,000 | SHA-256, N=5,000 | SHA-256, N=10,000 |
|---|---|---|---|
| `quick` | 1 s | 2 s | 4 s |
| `standard` | 3 s | 7 s | 14 s |
| `full` | 42 s | 49 s | 85 s |

`full` is dominated by cycle detection (up to 30 million hash calls) and the exhaustive linear search; `--command` mode adds one process spawn per hash call.

### Verdicts and exit codes

| Code | Verdict | Meaning |
|------|---------|---------|
| 0 | PASS | Every requested test ran; none found anything |
| 1 | WARN | One test battery reported an anomaly |
| 2 | FAIL | Two or more batteries, or a strong single signal (`compare`/`kat`: outputs disagree) |
| 3 | ERROR | A test could not run (bad input file, missing model, implementation error) — never reported as PASS |

The meta-learner's threshold is 0.40. When P(weakened) is near or over it, the report names the features that drove the score, so a WARN is explainable even when every individual test row reads "clean".

## Input modes

**`-a <name>`** — one of the 24 built-in functions (`list-algorithms`). All tiers.

**`--command "<shell command>"`** — any external implementation that reads a message on stdin and prints a hex digest. All tiers. Each message is one invocation (batch mode is tried first for line-oriented tools); the command receives the **raw message bytes with no trailing newline**. `openssl dgst -<alg> -hex`, `sha256sum`, `shasum -a 256` and tools printing a bare digest all work. Standard and full levels spawn one process per hash and are slow: start with `-n 2000 --level standard`.

**`-i <file>`** — JSONL records, one per line, with `plaintext` (or `input`/`message`) and `hash` (or `output`/`digest`):

```json
{"plaintext": "hello world", "hash": "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"}
```

Only tier 1 can run from a file, because the other tiers must choose their own inputs. The plaintext is a string; the message the hash function saw is its UTF-8 encoding. Every digest must be zero-padded to the hash's full width — a file mixing digest lengths is rejected with an explanation (v0.1 ran it anyway and produced a spurious WARN).

## Writing a wrapper for an external implementation

The data contract: read the records `cryptid generate` wrote, hash the UTF-8 bytes of each `plaintext`, write the same record back with your digest.

```python
# wrapper.py — replace your_hash_function with your implementation
import json, sys

def your_hash_function(message: bytes) -> str:
    # Return a fixed-width lowercase hex string, e.g. format(value, "032x") for 128 bits
    raise NotImplementedError

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    record = json.loads(line)
    pt = record["plaintext"]
    print(json.dumps({"plaintext": pt, "hash": your_hash_function(pt.encode("utf-8"))}))
```

```bash
python cryptid.py generate -a sha256 -n 5000 -o inputs.jsonl      # reference vectors + inputs
python wrapper.py < inputs.jsonl > device_output.jsonl              # your implementation
python cryptid.py kat -a sha256 -i device_output.jsonl              # faithful to SHA-256?
python cryptid.py test -i device_output.jsonl --level quick         # statistically sound?
```

For an HSM, the body of `your_hash_function` is a PKCS#11 digest call; for a serial device, write the bytes out and read the digest back. If your implementation can also be invoked as a command, `--command` gives you the differential tiers as well.

Worked example with MurmurHash3 (`pip install mmh3`):

```python
# mmh3_wrapper.py
import mmh3, json, sys
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    record = json.loads(line)
    pt = record["plaintext"]
    h = format(mmh3.hash128(pt.encode("utf-8")) & (2**128 - 1), "032x")
    print(json.dumps({"plaintext": pt, "hash": h}))
```

Expected: `Verdict: PASS` at `--level quick` — MurmurHash3's output statistics are clean. (Its *differential* behaviour would need `--command`.)

| Hash width | Format string |
|---|---|
| 32-bit  | `format(result, "08x")` |
| 64-bit  | `format(result, "016x")` |
| 128-bit | `format(result, "032x")` |
| 256-bit | `format(result, "064x")` |

## Built-in algorithms

**Cryptographic hashes:** SHA-256, SHA-512, SHA-1, SHA-224, SHA-512/256, SHA-3-256, SHA-3-512, BLAKE2b (256), BLAKE2s, MD5, SM3

**Block-cipher constructions** (require `pip install cryptography`): AES-128 CBC-MAC (fixed key, zero IV), SM4 CBC-MAC, Camellia-128 CBC-MAC, ChaCha20 as a PRF of the input (the padded message is the 256-bit key; v0.1 used nonce = MD5(message), which tested MD5's diffusion rather than ChaCha20's)

**Non-cryptographic:** CRC32, Adler-32, FNV-1a (32/64), MurmurHash3 (x86_32), SipHash-2-4 (fixed key), DJB2, Jenkins one-at-a-time, Pearson-64 (8 chained 8-bit Pearson hashes with a seeded random table; v0.1 used an affine table)

Every hand-rolled implementation is checked against published test vectors by `cryptid kat -a <name>`.

## Results

Every number below is read from a file in `results/`, produced by the scripts named; the whitepaper is built from the same files.

### Detection matrix — 24 built-ins + 7 oracle controls, full level, N = 10,000

`python experiments/full_sweep.py --samples 10000` → `results/sweep_10k.json`

| Function | Type | Bits | P(weakened) | Differential | Extended | Linear | Verdict |
|---|---|---|---|---|---|---|---|
| sha256 | hash | 256 | 0.06 | — | — | — | PASS |
| sha512 | hash | 512 | 0.10 | — | — | — | PASS |
| sha1 | hash | 160 | 0.05 | — | — | — | PASS |
| sha224 | hash | 224 | 0.07 | — | — | — | PASS |
| sha512_256 | hash | 256 | 0.07 | — | — | — | PASS |
| sha3_256 | hash | 256 | 0.06 | — | — | — | PASS |
| sha3_512 | hash | 512 | 0.10 | — | — | — | PASS |
| blake2b | hash | 256 | 0.07 | — | — | — | PASS |
| blake2s | hash | 256 | 0.07 | — | — | — | PASS |
| md5 | hash | 128 | 0.05 | — | — | — | PASS |
| sm3 | hash | 256 | 0.08 | — | — | — | PASS |
| aes128 | cipher | 128 | 0.05 | — | — | — | PASS |
| chacha20 | cipher | 256 | 0.06 | — | — | — | PASS |
| sm4 | cipher | 128 | 0.04 | — | — | — | PASS |
| camellia128 | cipher | 128 | 0.05 | — | — | — | PASS |
| crc32 | checksum | 32 | 0.04 | SYHI | NQ | — | FAIL |
| adler32 | checksum | 32 | 1.00 | SYHI | NQC | S | FAIL |
| fnv1a_32 | non-crypto | 32 | 1.00 | SYHI | NQ | — | FAIL |
| fnv1a_64 | non-crypto | 64 | 1.00 | SYHI | NQ | — | FAIL |
| murmur3_32 | non-crypto | 32 | 0.06 | — | — | — | PASS |
| siphash24 | PRF | 64 | 0.05 | — | — | — | PASS |
| djb2 | non-crypto | 32 | 1.00 | SYHI | NQC | — | FAIL |
| jenkins | non-crypto | 32 | 0.05 | SI | Q | — | FAIL |
| pearson64 | non-crypto | 64 | 0.06 | S | — | — | WARN |
| random_oracle_32 | control | 32 | 0.03 | — | — | — | PASS |
| random_oracle_64 | control | 64 | 0.04 | — | — | — | PASS |
| random_oracle_128 | control | 128 | 0.04 | — | — | — | PASS |
| random_oracle_160 | control | 160 | 0.04 | — | — | — | PASS |
| random_oracle_224 | control | 224 | 0.05 | — | — | — | PASS |
| random_oracle_256 | control | 256 | 0.05 | — | — | — | PASS |
| random_oracle_512 | control | 512 | 0.09 | — | — | — | PASS |

Differential letters: S single-bit, Y byte, H Hamming profile, I bit independence. Extended: N near-collision, Q sequence correlation, C cycles. The block-cipher rows are constructions (CBC-MAC / key-input PRF), not the raw primitives.

All 15 cryptographic functions pass every test, with P(weakened) 0.04–0.10 against 0.03–0.09 for the random-oracle controls. 7 of the 7 non-cryptographic hashes designed without regard to avalanche or linearity are flagged (crc32, adler32, fnv1a_32, fnv1a_64, djb2, jenkins, pearson64); 4 of them by the statistical suite alone (adler32, fnv1a_32, fnv1a_64, djb2), the rest only by the differential and structural tiers. MurmurHash3 and SipHash-2-4 pass. This is a null result on the primitives, stated at the size it is: at N = 10,000 and these tests' sensitivity, nothing is detectable — not a certificate of anything.

**Jenkins OAT** is the positive control: it passes the aggregate suite (P = 0.05) and fails the differential profile, because a difference in the last message byte passes through only one per-byte mix and a three-step finalizer before output. This is documented behaviour (Wikipedia; SMHasher lists OAT as failing its avalanche and BIC tests), not a finding of ours — v0.1 said otherwise. **CRC32** is uniform in distribution (P = 0.04) and deterministic in its differentials (every flip column constant), so only the differential and structural tiers see it.

### Classifier: held-out evaluation

`python src/meta_learner.py evaluate --model models/meta_learner_v4.json --seed-base 1700000` → `results/meta_evaluation_v4_test.json`

The classifier is trained on 288 synthetic variants of the four calibration families. A *development* set of 96 unseen variants was used to find detector gaps (the v0.1 model scored 90.6% on it; every missed bit-correlation variant had its input bit outside the 32-bit window the old test scanned, and the widened model's remaining misses were parity-of-XOR leaks the interaction features did not include). After those fixes, a *test* set of 96 variants from a fresh seed range, used for no decision: accuracy 100.0%, 0 false positives, 0 misses; clean variants score 0.04–0.15, weakened 0.47–1.00, threshold 0.40. Treat this as a calibration result — the families and the detectors share a vocabulary — which is why the next experiment exists.

### Out-of-family weaknesses

`python experiments/out_of_family_eval.py --samples 5000 --implementation-variants` → `results/out_of_family.json`

Five weaknesses written after the detectors were frozen, chosen to be things they were *not* built to look for:

| Planted weakness | P(weakened) | Differential | Extended | Linear | Verdict |
|---|---|---|---|---|---|
| clean control (sha256) | 0.08 | — | — | — | PASS |
| dead input byte | 0.08 | SYHI | N | — | FAIL |
| tail copy | 1.00 | SYHI | Q | S | FAIL |
| output redundancy | 0.07 | I | — | — | WARN |
| permutation invariant | 0.33 | — | — | — | PASS |
| linear mask leak | 1.00 | S | — | S | FAIL |

4 of 5 are caught. The dead input byte and the output-byte copy are invisible to the statistical suite and caught by the differential tier (the latter only because bit independence now covers every output-bit pair). The 3-bit linear leak is found by the single-bit differential and reported exactly by the exhaustive linear search. The permutation-invariant hash — sort the bytes, then hash — passes everything: uniform output, perfect avalanche, trivial second preimages. That is the boundary of black-box statistical testing.

### What the battery cannot see: unfaithful implementations

| Implementation | P(weakened) | Differential | Verdict |
|---|---|---|---|
| sha256 correct (pure py) | 0.15 | — | PASS |
| sha256 K[20] 1-bit typo | 0.15 | — | PASS |
| sha256 24 of 64 rounds | 0.15 | — | PASS |
| sha256 12 of 64 rounds | 0.18 | — | PASS |

(standard level, N = 2,000; pure-Python SHA-256 variants.) All pass. 24-step SHA-256 is below the best published practical collision attack (31 steps). `cryptid kat -a sha256 --command …` fails all three immediately.

### Internal diffusion (white-box), aligned on word injection

`python src/internal_diffusion.py compare --algorithms sha3_256,sm3,sha256,sha512,md5,sha1 --size 2000` → `results/diffusion_comparison.json`

| Algorithm | Absolute rounds to 90% | Rounds after injection to 50% / 90% | Diffusion at +3 / +5 |
|---|---|---|---|
| sha3_256 | 3 | 3 / 3 | 100% / 100% |
| sm3 | 12 | 4 / 6 | 31% / 77% |
| sha256 | 16 | 4 / 5 | 43% / 90% |
| sha512 | 16 | 4 / 6 | 29% / 76% |
| md5 | 18 | 5 / 8 | 19% / 52% |
| sha1 | 20 | 7 / 11 | 9% / 26% |

"Absolute" counts from the start of the compression function and depends on when the flipped message word is absorbed (one word per round in Merkle–Damgård; the whole block at once in the sponge) — the comparison v0.1 made. "After injection" counts from the round the flipped word enters the state and is the only column that compares mixing speed. SHA-3 reaches full diffusion 3 rounds after absorption; SHA-256 reaches 90% 5 rounds after injection, MD5 8, SHA-1 11. SM3's apparent lead over SHA-256 in absolute terms is its message expansion injecting each word four rounds early; aligned, it mixes slightly slower than SHA-256. Diffusion rate describes a design; it does not rank security.

Figures: `python experiments/make_figures.py` → `figures/`.

## Limitations

cryptid detects *statistical and differential* departures from random-oracle behaviour. It cannot detect:

- **Unfaithful but well-mixed implementations** — a wrong constant, a reduced round count, a non-standard IV. Use `kat`/`compare`.
- **Kleptographic backdoors** (Dual EC DRBG style) — output is statistically perfect; the trapdoor is in the parameters.
- **Reduced keyspace** — a security property, not an output property.
- **Structural weaknesses with no statistical signature** — e.g. a hash that sorts its input bytes first collides on every permutation of a message and passes every test here (`permutation_invariant` in the out-of-family experiment).
- **Anything cryptanalytic.** No statistical test certifies collision or preimage resistance; a round-reduced SHA-256 that is practically collision-broken passes clean.

Sensitivity is bounded by the sample count: a bias too small to reach the chi-squared thresholds at the chosen `-n` is invisible. Running at larger `-n` is the remedy, and the thresholds are deliberately conservative to keep the false-positive rate at zero on real primitives.

Related tools: [SMHasher](https://github.com/rurban/smhasher) is the standard quality suite for non-cryptographic hashes and includes avalanche, BIC and differential tests; it requires compiling the function in as C/C++. cryptid trades its depth for black-box access — anything that returns a digest can be tested — and adds the record-based statistical screening and known-answer workflow for implementations. NIST SP 800-22 and similar batteries test the randomness of a bit stream, not the input→output relationship.

## Project structure

```
cryptid/                 CLI
  cli.py                   subcommands: test, generate, compare, kat, list-algorithms
  engine.py                tier orchestration and verdicts
  input_handler.py         JSONL / hex-pair loading and validation, command mode, input generation
  report.py                terminal and JSON output

src/                     analysis modules
  statistical_analysis.py  tier 1 (6 tests)
  meta_learner.py          feature extraction, logistic-regression classifier, training + held-out evaluation
  differential_profile.py  tier 2 (4 tests)
  extended_analysis.py     tier 3 (3 tests)
  linear_approximation.py  tier 4
  internal_diffusion.py    white-box round-by-round diffusion (instrumented MD5/SHA-1/SHA-256/SHA-512/SM3/SHA-3)
  generate_dataset.py      built-in hash functions, oracle controls, known-answer vectors
  synthetic_weakness.py    planted-weakness generators (calibration families + out-of-family set)

models/
  meta_learner_v4.json     shipped classifier (20 distinct features, 288 synthetic training variants)
  meta_learner_v3_scale_invariant.json   v0.1 classifier, kept for reference

experiments/
  full_sweep.py            detection matrix over all built-ins + oracle controls
  out_of_family_eval.py    generalization test on weaknesses the detectors were not designed for
  run_full_sweep.py, targeted_probe.py, bit_probe.py, byte_model.py, hybrid_model.py, evaluate.py
                           research scripts from the project's earlier phases (some need PyTorch)

results/                 JSON output of the experiments quoted in the whitepaper
docs/REVIEW.md           the v0.1 review and the v0.2 change list
whitepaper.py            builds whitepaper.pdf (ReportLab)
```

## Requirements

Python 3.10+, standard library only for everything except the four block-cipher constructions (`pip install cryptography`). SM3 needs a Python built against OpenSSL 3.0+ (`hashlib.new("sm3")`). PyTorch is only needed for the neural-probe research scripts in `experiments/`.

## License

MIT — see `LICENSE`.
