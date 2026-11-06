# The v0.2 review, and what changed in v0.3, v0.3.1 and v0.3.2

cryptid v0.2 (October 2026) was the result of the first adversarial review ([REVIEW.md](REVIEW.md)): Claude Fable 5.1 reviewing work built with Claude Opus. Those are different models from the same vendor, and v0.2 described the reviewer as "a different model family", which overstated its independence. So v0.2 — the public repository at commit `f05c986`, the v2.0 whitepaper and the live site — was handed to a model from a different vendor with the same instruction: find what is wrong. The product names the model "6 Luna"; the model describes itself as Codex on GPT-6; we use the product's name. The conversations — all three passes — are in [REVIEW-2-transcript.md](REVIEW-2-transcript.md), as recorded from the product, edited only to omit the README text pasted into the first prompt and to make file paths repository-relative. It is not an authenticated log and does not by itself establish which model ran. The prompts for the second and third passes were drafted by Claude Fable 5.1, the model that wrote the fixes under review, and sent by John with small wording changes; the transcript says so, and a reader should weigh it.

The review ran in three passes, each prompted by asking whether the previous one had actually covered everything. The reviewer confirmed the fourteen-test structure, recomputed the held-out classifier figures from the stored data, checked eighteen embedded vectors across thirteen algorithms and six instrumented implementations against `hashlib`, and spot-checked the sweep and out-of-family results against the README. It then found the items below (sections A–E). Every code finding was reproduced by running it before being accepted; the description findings (section C) were checked against the source and the documents. The reproduction and the fixes were done by Claude Fable 5.1 — the author of the v0.2 code that most of them are in — and the regression tests that now cover them run in CI. Section F is the reviewer's second pass, over v0.3, and what changed for v0.3.1; section G is its third pass, over v0.3.1, and what changed for v0.3.2.

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

"Reviewed by a different model family" (README, REVIEW.md, paper §8, site) described Claude Fable 5.1 reviewing Claude Opus's work. The reviewer pointed out, correctly, that this is the same family by any ordinary meaning of the word, and that the repository contained no transcript or log by which the review process itself could be checked.

*v0.3:* The history now reads: built with Claude Opus; v0.2 reviewed by Claude Fable 5.1, a more capable model from the same vendor; v0.3 reviewed by OpenAI's 6 Luna, November 2026, scope and date as stated above. The transcript is published. None of this means the audit is complete, and the reviewer said so in its own words: "I can't honestly certify that no others exist."

## E. Legacy experiment scripts

The reviewer read the neural-probe scripts from the project's earlier phases and found methodological flaws in five of the six: `targeted_probe.py` selects candidates on the whole dataset and then probes a split of the same records; `byte_model.py` and `hybrid_model.py` split pairs rather than records, so sources are reused across train and test, and the hybrid script's `best_val_loss` is a training loss; `evaluate.py` reads an unpaired loss difference, computed over prompt tokens too, as evidence of structure; `run_full_sweep.py` reuses a dataset file without checking its size. All confirmed at the code level. (v0.3 of this document said "six"; the sixth, `bit_probe.py`, was not examined until the second pass — see F.)

No number in the README, the paper or the site comes from any of them. *v0.3:* moved to `experiments/legacy/` with a README that lists the flaws, so that nobody mistakes their output for validation.

## What the review did not change

The fourteen-test structure, the detection matrix, the held-out classifier result, the out-of-family result and the diffusion measurements all reproduced. The three re-run 512-bit rows still pass. The machinery is where the first review left it; the verdict contract around it is now enforced by tests rather than by intent.

## Methodology lesson, second round

The first review's lesson was that generation and verification are different jobs and need different agents. This review adds two things. First, the fixes made in response to a review are new code and new claims, and they need the same adversarial pass as the original; the `kat` bug is the whole lesson in one function. Second, "independent" has to mean what the reader would assume it means: a second model from the same vendor is a useful check — it caught everything in REVIEW.md — but it is not an independent one, and describing it as one was itself the kind of overstatement the project exists to catch.

What now runs on every change: the regression tests for the verdict and exit-code contract, the built-in references against their published vectors, a correct function expected to pass, and two positive controls expected to fail.

## F. The second pass (v0.3 → v0.3.1)

v0.3 (tag `v0.3.0`, commit `d353ef1`) was handed back to the same reviewer with this document as the set of claims under test, a real git clone, and the instruction to attack the new code (the prompt and reply are the second part of the transcript). It confirmed A1, A2, A4, B1 (code), B3 and C1–C7 as fixed or accurately restated, confirmed the merged result rows as consistent, ran the test suite and the CI commands locally, and found the following. Everything below was reproduced before being accepted.

### F1. A3 was only partly fixed — confirmed
With the classifier skipped, a SIGNAL row now makes the verdict WARN; but with the classifier running, a tier-1 row can still read SIGNAL under a PASS, and the README's "none found anything" did not say so. The reviewer also found that the README's FAIL definition did not match the code (two flagged tests within one tier, or a linear signal alone, are FAIL).

*v0.3.1:* The override is the design — the six tests fire at their nominal rates and the calibrated classifier is the decision for the tier — so the verdict is unchanged; the report now marks such rows *overridden by classifier* and names them in a note under the verdict, and the README's verdict table is rewritten from the code.

### F2. Three more runs that tested nothing, or the wrong thing, and did not say so — confirmed
`test -n -1` reported PASS with zero samples (an empty record list skipped every phase and the verdict defaulted to PASS); `-n 0` silently became 10,000. `compare` kept the last row for a repeated input, so a reference file giving a wrong digest and then the right one for the same input passed. A one-record file produced a false inter-record-distance signal (zero pairs, mean 0 compared with 0.5).

*v0.3.1:* The sample count must be at least 1 (usage error otherwise), the statistical suite needs at least 100 records (ERROR otherwise, and `compare` skips the per-file summary below that instead of reporting a verdict on it), an input that appears with two different digests is a FAIL of that file, and the distance test returns no signal with fewer than two records. An empty audit with no function is ERROR in the engine itself (the third pass found that an empty audit *with* a function, and a count below the floor through the API, still passed — see G2). Tests: `SampleCountTests`, `CompareTests.test_conflicting_duplicate_rows_fail`, `test_one_record_distance_has_no_signal`.

### F3. The small-N entropy thresholds were uncalibrated — confirmed, and it led somewhere
The reviewer's points: the Miller–Madow term is a bias correction, not a bound on the minimum over many output columns; the margin was hand-set; the quoted spurious-WARN rates had no script or seeds; and a digest byte restricted to 160 of 256 values passed the N = 200 audit in five seeds.

On the last point, N = 200 is the limit rather than the threshold: with a bit-balanced 160-value byte the clean minimum byte entropy ranges 6.79–6.91 over 25 seeds (6.70 over 300 null trials) and the defect's 6.50–6.74, so no threshold separates them there without false alarms; at N = 300 the same defect is caught in every run. But following the probe to larger N exposed a real gap: the fixed 7.5-bit threshold corresponds to about 181 equiprobable values, so a byte restricted to 192 values (7.58 bits) passed the entropy test at every N, and the classifier scored it 0.35 at N = 5,000.

*v0.3.1:* The byte threshold is now six standard deviations below the simulated null (per-column plug-in entropy of N uniform bytes; the mean/sd table is embedded in `statistical_analysis.py`), the bit threshold is the entropy of a bit 5σ from one half; the Miller–Madow expansion is not used, because it fails for N near the alphabet size. The entropy test gained a coverage check — the number of values a column never takes, against a binomial approximation to the occupancy tail, p < 10⁻⁸ (called "exact" here in v0.3.1; it is not — see G3) — and, from N = 1,280, a chi-square frequency test. A z-score version of the coverage check was tried first and rejected: at N = 3,000 the occupancy count's sd is 0.045, so one missing value, which 0.2% of clean columns show, read as 22σ. `experiments/small_n_thresholds.py` reproduces the null, the thresholds' headroom (smallest +0.07 bits at N = 500), the power table in the README (as corrected in v0.3.2 — see G3 — 192 values caught from N = 500, 224 from 1,000, 240 from 1,500, 254 from 4,000) and the clean-run rate (0 of 100 at N = 200, 500 and 1,000; seeds recorded), writing `results/small_n_thresholds.json`. The classifier's inputs on clean data are unchanged (the new checks never fire there). Both held-out evaluations were re-run with the new test and the files in `results/` replaced: every clean variant's score is identical, seven weakened variants (two dev, five test) score higher, and accuracy is 100% on both as before.

### F4. The B1 regression test was incomplete — confirmed
It checked 1×1 coverage only; a cap reintroduced on the multi-bit output masks would have passed. *v0.3.1:* it asserts the 3×1 and 1×2 counts as well.

### F5. Errors in how v0.3 described the review — all confirmed
"Full conversation" / "complete transcript" contradicted the transcript's own header; the paper's "the first four are fail-open bugs in code the first review added" contradicted A4 (three of four); "every finding was reproduced" overstated the C items; "six scripts" listed five; the site's "two years out of date" should be "superseded by a June 2026 result"; the site's "32-bit outputs are several times faster" is true at quick and standard level (about 2×) and false at full level (42.5 vs 49.2 s), where cycle detection dominates. The model was named "Luna6" from memory; the product's name is "6 Luna". All restated. The reviewer also noted that the transcript is not an authenticated log and cannot establish model identity, which is now stated where the transcript is described.

### F6. `bit_probe.py` — new
Probes only the first two input bytes by default and declares a signal on the maximum over many bit/model comparisons with no correction for the number of comparisons. Added to `experiments/legacy/README.md`.

### What the second pass did not do
It did not re-run the four full-level implementation-variant audits (it checked the saved rows for consistency and plausibility against the stated run times), did not retrain or re-evaluate the classifier, and verified the CI commands locally rather than on a GitHub Actions run (the run itself is green on the repository). Its own closing line: "I would not describe this review as proving that no other issues remain." Neither would we.

## Methodology lesson, third round

Two of the three F2 bugs and the F3 gap were present in v0.2 and survived the first pass, which looked at the same files. Reviews sample; they do not enumerate. The practical consequences we have taken: boundary cases (empty, one, negative, duplicate) now have their own tests rather than waiting for a reviewer to try them; every threshold has a script that reproduces its calibration and a number for its power; and the account of a review is checked against the review as carefully as the code is.

## G. The third pass (v0.3.1 → v0.3.2)

v0.3.1 (tag `v0.3.1`, commit `75f98e0`) went back to the same reviewer at a higher effort setting (the third part of the transcript), with section F as the claims under test and a ranking: verdicts that can be wrong first, unsupported claims second, coverage gaps third, wording last. It verified F1, F4 and F6 as fixed, F2, F3 and F5 as partly fixed, re-ran both held-out evaluations and the calibration script and confirmed their stored outputs, checked the 36-step citation, and found the following. Everything below was reproduced before being accepted.

### G1. A file repeating one input could fail a correct function — confirmed
A JSONL file of one correct SHA-256 row repeated 100 times gave WARN; 2,000 times gave FAIL with P(weakened) = 1.0. The loader accepted the rows and the suite treated them as independent samples. A device log that answered the same query many times would do this.

*v0.3.2:* Rows that repeat an input with the same digest are collapsed to one, with the count reported in the output and the notes, and the 100-record floor applies to distinct inputs. An input that appears with two different digests is an error for `test` — the implementation is not a function of its input, or the file is corrupt — while `compare` keeps reporting such conflicts per input as a FAIL of that file. Tests: `RepeatedInputTests`.

### G2. Two ways around the record floor, and a PASS for a run that never happened — confirmed
`run_audit(records=[], hash_fn=…, level="quick")` returned PASS, and so did 99 records through the API: v0.3.1 put the floor in the command line and only the no-function branch in the engine, and this document said "an empty audit is ERROR in the engine itself", which was true of one branch. `compare`'s per-file JSON said `verdict: PASS` for sides whose statistical summary had been skipped; the test named for that case did not check the field.

*v0.3.2:* The floor and the empty-run check are in `run_audit`; a result in which no tier ran is `NOT RUN`, in the JSON and the report; the test checks it. Tests: `SampleCountTests.test_empty_run_is_error_in_engine`, `test_small_files_get_no_statistical_verdict`, `test_not_run_verdict_when_nothing_ran`.

### G3. The power table was construction-specific, and two statistical descriptions overstated — confirmed
The calibration script built its support defect with `h[0] % S`, which for S not dividing 256 gives 256 − S of the values twice the probability of the rest; the skew let the byte-entropy threshold fire early, so the v0.3.1 table said 0.80 for 192 values at N = 300 and credited the coverage check, when a near-uniform mapping gives 0.15 and the coverage check first fires at N = 500. "Exact binomial occupancy tail" was wrong: the missing-value events are negatively correlated, the binomial is an approximation, and the reviewer computed the exact tail and found the approximation conservative. "Six standard deviations" with "never" overstated a null simulated over ~10⁴ columns per N. The chi-square branch had no positive control, so its removal would have passed the suite; z = 5.6 is a tail of 1.01 × 10⁻⁸, not under 10⁻⁸. The reviewer also located the boundary for a byte missing two of its values: first caught at about N = 3,700.

*v0.3.2:* The script maps the defect uniformly (sixteen digest bits modulo S), records which part of the test fired, and includes 254 values and N up to 5,000; the README table is regenerated from it with those columns. The descriptions are corrected in the code comments, this document and the paper. The chi-square threshold is z = 5.7 (≈ 6 × 10⁻⁹) and has a full-support skew as a positive control. Tests: `test_chi_square_catches_full_support_skew`; the override label now has a rendered-output test as well.

### G4. Remaining errors in the account of the reviews — confirmed
The README said the first review found "four fail-open bugs in code it added" (three of four); README and paper called the three F2 bugs fail-opens (one was a false positive); the README said the detection machinery "has held up under every review" while this document lists two coverage gaps in it; paper §8.2 still attributed six legacy scripts to the first pass; the site's file-input description lacked the record floor and the distinct-input assumption; and the exit-code table did not say that argument errors also exit 2. All restated.

### What the third pass did not do
It did not re-run the full-level implementation-variant audits, re-audit the legacy scripts, verify the GitHub Actions run itself, or prove the statistical error rates; it checked the `d353ef1..75f98e0` diff, the requested modules, tests, workflow, documents, site and result files. Its closing line: "I found additional issues, so this pass does not establish that no others remain."

## Methodology lesson, fourth round

The findings got smaller each round — narrative errors, then fail-open verdicts, then input-handling and evidence errors — which is the curve one would hope for and not a guarantee of anything. Two things from this pass worth keeping. Asking the reviewer to rank by consequence, and defining what "done" means for the pass, produced a review that spent its effort on verification depth (re-running the evaluations, reproducing the calibration, computing the exact occupancy tail) rather than on breadth it had already covered. And the experiment behind a published table deserves the same review as the code behind a verdict: the skewed defect construction was the v0.1 class of error — the evidence layer — written in v0.3.1 by the same hand that had just finished listing that class of error.
