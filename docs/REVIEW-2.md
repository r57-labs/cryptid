# The v0.2 review, and what changed in v0.3

cryptid v0.2 (October 2026) was the result of the first adversarial review ([REVIEW.md](REVIEW.md)): Claude Fable 5.1 reviewing work built with Claude Opus. Those are different models from the same vendor, and v0.2 described the reviewer as "a different model family", which overstated its independence. So v0.2 — the public repository at commit `f05c986`, the v2.0 whitepaper and the live site — was handed to a model from a different vendor, OpenAI's Luna6 (Codex), with the same instruction: find what is wrong. The full conversation is in [REVIEW-2-transcript.md](REVIEW-2-transcript.md).

The review ran in three passes, each prompted by asking whether the previous one had actually covered everything. Luna6 confirmed the fourteen-test structure, recomputed the held-out classifier figures from the stored data, checked eighteen embedded vectors across thirteen algorithms and six instrumented implementations against `hashlib`, and spot-checked the sweep and out-of-family results against the README. It then found the items below. Every one was reproduced before being accepted; the reproduction and the fixes were done by Claude Fable 5.1 — the author of the v0.2 code that most of them are in — and the regression tests that now cover them run in CI.

**The headline.** The first review found narrative errors around correct code. This one found mechanical errors in code written *during* the first review. `kat` was added in v0.2 to replace a false claim ("the battery can verify an implementation is faithful") with a real check — and shipped with a verdict that could not be trusted. Nobody reviewed the fixes.

## A. Fail-open bugs in v0.2 code

### A1. `kat` reported PASS for an implementation that failed on every message — confirmed
The verdict was `ERROR` only if there were errors *and* zero checks had run, but the built-in reference's published-vector self-check ran first and counted as a check. `kat -a sha256 --command "python3 -c 'import sys; sys.exit(1)'"` returned PASS, exit 0, with 25 failures listed under `errors`. The same pooling let `kat -a sha256` with no `--command` or `-i` pass after checking only the reference.

*v0.3:* Reference checks and external checks are counted separately. Any failed invocation is ERROR (exit 3), and the mismatches found on the messages that did run are still reported. A target is required; `--self-check` is the explicit way to test only the built-in reference, and is what CI uses. Regression tests: `tests/test_cli.py::KatTests`.

### A2. `compare` exited 0 having compared nothing — confirmed, and worse than reported
Two files with no shared plaintexts gave `shared_inputs: 0, mismatches: 0`, exit 0. The terminal report also printed "✓ Implementations behave consistently (ΔP = 0.000)" above the note that nothing overlapped, because the consistency line compared two classifier probabilities that were both absent (the classifier had been skipped on both one-record files).

*v0.3:* No shared inputs is INCONCLUSIVE, exit 3, in both the report and the JSON. The consistency line is printed only when the classifier actually ran on both sides. Tests: `CompareTests`.

### A3. `test` could print PASS above a row marked SIGNAL — confirmed, with a second bug underneath
Below the classifier's 2,000-sample minimum the verdict ignored tier 1 entirely, so `test -a crc32 -n 200 --level quick` showed `Output entropy  SIGNAL` and `Verdict: PASS — No anomalies detected`.

Reproducing it exposed a second problem. The entropy SIGNAL on CRC32 was not a detection: the test's fixed 7.5-bit byte-entropy threshold flagged *every* function at N = 200, SHA-256 included, because 200 samples of a 256-symbol byte cannot show more than log2(200) = 7.64 bits. (CRC32's real weakness is differential, and the differential tier catches it at N = 300.)

*v0.3:* When the classifier is skipped, tier 1 decides on its own: any test at or above the report's SIGNAL threshold makes the verdict WARN, the verdict line says the tier is unclassified, and tests whose own flag fired below that threshold are listed as marginal in the notes. The entropy thresholds now follow the Miller–Madow small-sample bias below N ≈ 1,000 and are unchanged above it, so the classifier's inputs at N ≥ 2,000 are untouched. Measured spurious WARN rate on clean functions: 1 in 100 runs at N = 200 (the mutual-information permutation test's nominal 1%), 0 in 100 at N = 500. Tests: `TestVerdictTests`, `test_engine.py::EntropyThresholdTests`, `VerdictLogicTests`.

### A4. Unusable input lines were skipped silently — confirmed (predates v0.2)
Malformed JSON lines and records without a digest were dropped with a stderr warning; the verdict covered whatever loaded and said nothing about it.

*v0.3:* An error (exit 3) naming the lines, unless `--skip-malformed`, which runs on the usable records and puts the count in the report and the JSON. Tests: `InputHandlingTests`.

## B. Coverage and evidence

### B1. The linear tier covered only the first 256 output bits — confirmed
`linear_approximation_analysis` defaulted `max_output_bits` and `max_multi_output_bits` to 256 and the engine passed no override, so SHA-512, SHA-3-512 and the 512-bit oracle control had half their digest untested in tier 4 while README and paper said "every output bit". The v0.2 defaults and the v0.2 sentence were written by the same reviewer.

*v0.3:* Default is the full digest width (54M approximations for 512 bits, still affordable). The three affected rows of the sweep were re-run with `experiments/full_sweep.py --algorithms sha512,sha3_512 --merge-into results/sweep_10k.json`, which records the re-run in the file; all three still pass. Test: `LinearWidthTests`.

### B2. "Passes the entire battery" for the unfaithful SHA-256 variants — confirmed
The abstract said the reduced-round and corrupted-constant variants passed the entire battery; the saved run (`results/out_of_family.json`, `impl_level: standard`) covered tiers 1–2.

*v0.3:* The four variants were run at the full level (`--impl-level full`, 12–26 minutes per variant in pure Python on one container CPU) and `results/out_of_family.json` now holds that run. The sentence is true as written; Table 4 shows all four tiers.

### B3. "Best published practical collision attack: 31 steps" — confirmed, out of date
Li, Liu and Wang's 31-step practical collision (Eurocrypt 2024) was the state of the art when v0.1 was written. IACR ePrint 2026/1120 (Li, Zhang, Li, Liu, Qian, Zhu; June 2026) reports a 36-step SHA-256 collision at 2^57 with a published colliding message pair, and a 38-step attack at a theoretical 2^104.3. The reviewer's knowledge reached this; the first reviewer's did not.

*v0.3:* Restated with the dates and complexities. The point of the sentence — that a 24-round SHA-256 is well inside the practically broken range and the battery cannot tell — gets stronger.

## C. Descriptions that did not match the code

- **C1.** The tier-4 signal rule was stated with two conditions (max bias > 10/√N; p<0.001 count > 5× expectation). The code has a third: multi-bit p<0.001 count > 3× expectation (and > 10). *Restated.*
- **C2.** The interaction test was described as having XOR *and sum* features for byte pairs and triples. Sum-parity features exist for pairs only. *Restated.*
- **C3.** "SHA-3 reaches full diffusion 3 rounds after absorption." The measurement is 99.9% of the ideal distance. *Restated.*
- **C4.** "Every hand-rolled implementation is checked against published vectors." Pearson-64 is this project's own seeded-permutation construction and has none; and the paper's "on every run" was true only of `kat`. *Restated; the self-checks now also run in CI.*
- **C5.** "Standard library only" omitted matplotlib (`experiments/make_figures.py`) and ReportLab (`whitepaper.py`). *Restated.*
- **C6.** The site's tagline, "any function that returns a digest", needed the qualifier the README's Input modes section already carried: record files get tier 1; tiers 2–4 need something that can be called. *Restated on the site and in the paper's related-work section.*
- **C7.** The site's HSM wrapper example hard-coded a placeholder PIN. *Now reads it from the environment.*

## D. The reviewer's independence

"Reviewed by a different model family" (README, REVIEW.md, paper §8, site) described Claude Fable 5.1 reviewing Claude Opus's work. Luna6 pointed out, correctly, that this is the same family by any ordinary meaning of the word, and that the repository contained no transcript or log by which the review process itself could be checked.

*v0.3:* The history now reads: built with Claude Opus; v0.2 reviewed by Claude Fable 5.1, a more capable model from the same vendor; v0.3 reviewed by OpenAI's Luna6 (Codex), November 2026, scope and date as stated above. The transcript is published. None of this means the audit is complete, and Luna6 said so in its own words: "I can't honestly certify that no others exist."

## E. Legacy experiment scripts

Luna6 read the six neural-probe scripts from the project's earlier phases and found methodological flaws in each: `targeted_probe.py` selects candidates on the whole dataset and then probes a split of the same records; `byte_model.py` and `hybrid_model.py` split pairs rather than records, so sources are reused across train and test, and the hybrid script's `best_val_loss` is a training loss; `evaluate.py` reads an unpaired loss difference, computed over prompt tokens too, as evidence of structure; `run_full_sweep.py` reuses a dataset file without checking its size. All confirmed at the code level.

No number in the README, the paper or the site comes from any of them. *v0.3:* moved to `experiments/legacy/` with a README that lists the flaws, so that nobody mistakes their output for validation.

## What the review did not change

The fourteen-test structure, the detection matrix, the held-out classifier result, the out-of-family result and the diffusion measurements all reproduced. The three re-run 512-bit rows still pass. The machinery is where the first review left it; the verdict contract around it is now enforced by tests rather than by intent.

## Methodology lesson, second round

The first review's lesson was that generation and verification are different jobs and need different agents. This review adds two things. First, the fixes made in response to a review are new code and new claims, and they need the same adversarial pass as the original; the `kat` bug is the whole lesson in one function. Second, "independent" has to mean what the reader would assume it means: a second model from the same vendor is a useful check — it caught everything in REVIEW.md — but it is not an independent one, and describing it as one was itself the kind of overstatement the project exists to catch.

What now runs on every change: the regression tests for the verdict and exit-code contract, the built-in references against their published vectors, a correct function expected to pass, and two positive controls expected to fail.
