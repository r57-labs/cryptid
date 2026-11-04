# The v0.1 review, and what changed in v0.2

cryptid v0.1 (April 2026) was built by a non-cryptographer working with one AI model family. Before announcing it, the code, whitepaper and site were handed to a *different* model family with one instruction: find what is wrong. The reviewer read every source file, reproduced the headline numbers, verified every hand-rolled hash against published test vectors, and ran targeted experiments where a claim looked shaky.

This document is that review, lightly edited, followed by what was done about each item. It is kept in the repository because the project exists to test a way of working — AI-assisted development in a domain outside the author's expertise — and the honest result of that test is "the code was right, several claims were not, and a second independent pass was what caught it."

## Summary

**What checked out.** All 24 built-in functions were correct (SipHash-2-4, MurmurHash3, FNV-1a, Jenkins OAT, DJB2 and CRC32 against published vectors; the instrumented MD5/SHA-1/SHA-256/SHA-512/SM3/SHA-3 against `hashlib`). The hero example reproduced exactly. The detection pattern for Jenkins, CRC32, MurmurHash3 and SipHash reproduced. The diffusion table reproduced. The shipped model matched the numbers quoted for it. No secrets, local paths or tool droppings in the repo.

**What did not.** Six claims a cryptographer would reject on sight, several methodology descriptions the code did not match, a missing LICENSE, two broken wrapper examples on the site, and a handful of bugs.

## A. Claims that were wrong or overstated

### A1. Jenkins OAT: "hidden", "previously uncharacterized", "no final mixing pass"
Jenkins one-at-a-time *has* a final mixing pass (the three operations after the byte loop — present in cryptid's own implementation). Its weak avalanche in the final input byte is documented on Wikipedia ("only a few bits in the last byte of the input key are weakly mixed to a minority of bits in the output hash", with the same heatmap the site reproduced) and in SMHasher, which lists `JenkinsOOAT … 53.5% bias, fails all tests`. The whitepaper even cited the Wikipedia diagram two paragraphs after calling the weakness uncharacterized.

*v0.2:* The novelty claim is withdrawn. Jenkins OAT is now presented as what it is: a *known* weakness that aggregate statistics miss and the differential tier catches — a positive control, like CRC32. The mechanism is described correctly. SMHasher is cited.

### A2. The white-box diffusion comparison was confounded
"SHA-3 reaches full diffusion in 3 rounds; SHA-1 needs 20 of 80 to reach 90%; SM3 achieves nearly double SHA-256's early-round diffusion — a deliberate design choice." In Merkle–Damgård compression functions, message word *k* first touches the state at round *k* (round *k−4* in SM3, via W′[j] = W[j] ⊕ W[j+4]); the sponge absorbs the whole block before round 1. The v0.1 curves flipped a random bit anywhere in a 55-byte message and averaged by absolute round number, so "diffusion at round 5" mostly measured *when the word was absorbed*. Restricting flips to word 0, SHA-256 was at 90% by round 5 and ~100% by round 8; SM3's lead was entirely the W′ four-round head start. "21-round security margin" misused the term (margin = rounds minus best attack; collision attacks reach 6 rounds of SHA-3).

*v0.2:* `internal_diffusion.py` aligns every sample on the round its flipped word enters the state and reports rounds-after-injection. The comparison is re-derived (§5 of the whitepaper); the SM3 claim reverses (aligned, SM3 mixes slightly *slower* than SHA-256); "security margin" is gone.

### A3. "Double-blind" calibration and the 93%
The four planted weakness families used exactly the features the detectors test, and the meta-learner trained on the same generator — a sanity calibration, not evidence of generalization. The "sealed" manifest was plaintext with an integrity hash. The "93.3% held-out" figure matched, to the digit, the *training* accuracy of an older model file; the shipped model reported 90.6%, and the paper's own description of the held-out scores (clean 0.10–0.24, weakened 0.92–1.00, threshold 0.40) implied 100%.

*v0.2:* Renamed "label-blind synthetic calibration" and described as such. A `meta_learner.py evaluate` command generates variants from unseen seeds and scores the shipped model on them; the number quoted is that one. An out-of-family experiment (`experiments/out_of_family_eval.py`) plants weaknesses the detectors were *not* designed for and reports the catch matrix as it comes out — including the misses.

### A4. "Neither MurmurHash3 nor SipHash claims cryptographic security"
SipHash is explicitly a cryptographic PRF/MAC. *v0.2:* corrected.

### A5. "How do you verify the implementation is faithful?"
Black-box statistics cannot. A SHA-256 with a one-bit typo in K[20], or with 24 of 64 rounds (below the best published practical collision at 31 steps), passed every cryptid test with P(weakened) ≈ 0.32–0.34. The right tool is a known-answer comparison.

*v0.2:* The framing is changed throughout; a `kat` subcommand does known-answer testing of a command or a JSONL file against the built-in reference, with published vectors and padding-boundary messages; the reduced-round result is a stated negative in Limitations.

### A6. "MIT licensed" with no LICENSE file
*v0.2:* `LICENSE` added.

## B. Methodology described inaccurately

- **B1.** The statistical suite's "avalanche" test compared digests of *consecutive unrelated records*; it cannot fail for any function with uniform output. *v0.2:* renamed `record_distance`; the SAC test is identified as the single-bit differential.
- **B2.** The chosen-input tiers hashed the ASCII-hex encoding of the generated bytes, so 44% of "single-bit" flips changed 2–5 bits of the actual message. *v0.2:* built-in functions and command mode accept raw bytes; the tiers feed bytes directly.
- **B3.** Coverage was narrower than described: bit correlation scanned input bits 0–31 (planted correlations used 0–39), interaction tested output bits 0–31, linear approximation covered 40 input × 64 output bits with sampled masks, and byte-parity masks covered 5 of 10 bytes. The held-out evaluation confirmed the consequence: every missed bit-correlation variant had its input bit in 36–39, and most missed subset leaks had their output bit above 31. *v0.2:* bit correlation and interaction cover every input and output bit; linear approximation is exhaustive for 1-, 2- and 3-bit input masks over all 80 input bits and all output bits (bitset arithmetic makes the ~25M tests cheap); the differential bit-independence test covers every output-bit pair and counts deterministic differentials. The meta-learner was retrained on the widened features (v4).
- **B4.** Method counts disagreed (six / seven / thirteen). *v0.2:* fourteen tests in four tiers, everywhere.
- **B5.** Numbers disagreed between page, paper and tables (SHA-256 diffusion 16.0% vs 17.1%; CRC32 P 0.11 vs 0.23; "7 oracle controls" with two shown). *v0.2:* every number quoted comes from a JSON file in `results/`.
- **B6.** "ChaCha20" was ChaCha20 with nonce = MD5(message); "Pearson-64" used an affine table. *v0.2:* ChaCha20 keys on the padded message; Pearson uses a seeded random permutation.
- **B7.** "Calibration data and raw results are available at …" — they were gitignored. *v0.2:* `results/` is committed.
- **B8.** Timings were quoted for 32-bit outputs as if general. *v0.2:* re-measured per level and width.

## C. Site problems

- Both hardware wrapper examples crashed on their first line (`bytes.fromhex` on a JSONL record) and recorded plaintexts the `compare` step could never match. *v0.2:* replaced with the working template.
- "Independent Verification" did not say who verified (an AI agent re-implementing the paper's own method), and its charts drew an "acceptable threshold" that SHA-256, MD5, SHA-1 and SHA-3 all exceeded. *v0.2:* section rewritten; the charts are regenerated from `results/`.
- Hero stats "7 detection methods", "93% detection accuracy", "<5s quick scan". *v0.2:* replaced with numbers that exist.

## D. Bugs

- A JSONL file with inconsistent digest lengths ran and produced a spurious WARN (P=0.585 on correct SHA-256 with 1-in-7 digests unpadded). *Fixed:* rejected with an explanation.
- `--command sha256sum` failed (the `  -` suffix was not parsed). *Fixed.*
- `--command` audits hashed different strings in phase 1 (with trailing newline) and phases 2–4 (without). *Fixed:* raw bytes, no newline, both phases.
- A phase that crashed could still yield PASS. *Fixed:* any error is an ERROR verdict.
- `compare --json` emitted non-JSON when outputs differed. *Fixed;* `compare` now exits 2 on mismatch.
- SHA-3 instrumented padding was wrong for messages of exactly 135 (mod 136) bytes — the length the diffusion analysis used. *Fixed* (`0x06|0x80` in one byte); curves were unaffected.
- The meta-learner's "23 features" included three duplicates. *Documented* (20 distinct).
- `byte_differential` re-hashed inside the output-byte loop (32× redundant work). *Fixed.*
- `experiments/` scripts could not import `src/` as documented. *Fixed.*
- Report cosmetics: predicted label never coloured; WARN with every row "clean" and no explanation. *Fixed:* three-state rows (clean / marginal / SIGNAL) and the meta-learner's driving features are printed.
- Several differential thresholds were fixed numbers tuned for N ≈ 10,000; at a few hundred samples the single-bit max-deviation criterion fired on SHA-256. *Fixed:* thresholds scale with N (noted in each test's output). The classifier still requires N ≥ 2,000.
- The random-oracle controls memoized every call in an unbounded dict and grew to gigabytes under cycle detection. *Fixed:* stateless SHA-256-derived oracle.

## What the review did not change

The statistical and differential machinery works as intended; the four non-cryptographic hashes it is meant to catch, it catches, and it has produced no false positive on a real cryptographic primitive at any sample size tried. The corrections above are to the *claims* and to coverage, not to the premise. The project's premise — that a layered, black-box battery separates functions with statistical or differential weaknesses from those without, with a conservative classifier on top — stands, and is now stated at the size it actually is.

## Methodology lesson

Every error above lives in the narrative layer, not the mechanical one: domain knowledge (SipHash, the Jenkins finalizer — contradicted by the project's own code), literature (Wikipedia and SMHasher already had the Jenkins result), interpretation (the diffusion confound), and marketing (the hero stats). The code that the first model wrote was correct; the story it told about the code was not checked against the code, the literature, or an adversary. The "independent verification" step in v0.1 re-ran the paper's numbers rather than attacking its claims.

The fix is a process one: generation and verification are different jobs. A claims-versus-code pass, a literature check before any "novel", and an adversarial review by a model that did not write the thing — asked to break it, not to confirm it — are now part of how this project is built. This file is the evidence that the loop ran.
