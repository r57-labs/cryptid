# The v0.2 review: transcripts of all three passes

These are the conversations in which an OpenAI model — "6 Luna" as the product
names it; it describes itself as Codex on GPT-6 — reviewed cryptid v0.2 (first
pass), then v0.3 (second pass) and v0.3.1 (third pass), in November 2026, with
John's prompts as he sent them. The text was taken from the product's "copy
conversation" output, so it is a record of the text exchanged, not an
authenticated run log: it does not preserve the reviewer's tool calls and
cannot by itself prove which model ran. `file:line` references are to the
commit named in each part's heading; in the first pass the reviewer worked from
a zip of the repository (no git metadata) and a text export of whitepaper
v2.0; in the second and third it had a git clone at the tag.

Edits, exactly two kinds: the reviewer's citations carried local filesystem
paths, which are made repository-relative (`whitepaper-text` stands for the
text export of the v2.0 paper); and the site and README text pasted into the
first prompt is omitted. Nothing else is changed.

Who wrote the prompts: the first pass's prompts are John's own. The second-
and third-pass prompts were drafted by Claude Fable 5.1 — the model that wrote
the fixes under review — and sent by John with small wording changes of his
own. A reader should weigh that: the reviewed party set the reviewer's agenda
for those passes, including the ranking of what to look for. Our verdict on
each finding and what changed are in [REVIEW-2.md](REVIEW-2.md) (sections A–E
for the first pass, F for the second, G for the third).

The prompting is deliberately plain. The instruction that produced the useful
answers in the first pass was not a clever one; it was asking, after a
confident first answer, whether the pass had actually covered everything —
and then supplying the material the reviewer said it could not see. The
later prompts added a ranking by consequence and a definition of "done".


---

## First pass — v0.2, commit `f05c986`


**John:**

hello, i'm hoping we can work together to cross-check work performed by another AI model to verify if the claims it made and code it wrote are all accurate and complete.  so i'm hoping you can dig in and find out if there's any mistakes or mis-statements :)

you should have a copy of the latest github code in the working directory cryptid_reivew_chatgpt/cryptid-main/

please let me know if i can provide anything to help with this task!

here are some of the claims:

*[the site's "The problem" section and the README at commit f05c986, pasted in full — omitted here]*


**Reviewer (6 Luna):**

### Findings

The headline structure is accurate: the code has **14 analysis tests across four tiers**—6 statistical, 4 differential, 3 extended, and 1 linear approximation—plus a meta-learner. The README also correctly says that JSONL input supports only Tier 1; the other tiers need a callable implementation or command. Those limits should stay beside any claim that the toolkit can test “anything that returns a digest.”

I found two **fail-open bugs** in the fidelity commands:

1. **`kat` can report PASS when the implementation fails every check.** Its verdict logic only returns ERROR when there are errors *and no checks were counted*. But the built-in reference’s self-check increments that count first. I ran `kat -a sha256` with a command that exits unsuccessfully on every input: it returned exit code 0 and `"verdict": "PASS"`, while listing the failures in `"errors"`. This contradicts the README’s claim that an implementation error is never reported as PASS. See `cryptid/cli.py:364` and `cryptid/cli.py:402`.

2. **`compare` can exit successfully without comparing a single shared input.** I gave it two valid one-record files with different plaintexts. It returned exit code 0 with `shared_inputs: 0` and `mismatches: 0`. The command only exits nonzero when it finds a mismatch, so zero overlap can look like success to automation. See `cryptid/cli.py:251` and `cryptid/cli.py:266`.

There’s also a **claim to qualify**: finite known-answer checks can show that an implementation matches a reference *on the messages checked*; they cannot prove universal conformance or security. For SHA-256, the command tests a finite set of messages against the built-in reference, which uses Python’s `hashlib`. See `cryptid/cli.py:314` and `src/generate_dataset.py:266`. I’d describe `kat` as a practical conformance check against a reference, and avoid saying it proves an implementation is faithful in every case. Likewise, `compare` only checks matching inputs in the two files; its reference is whatever file the user supplies.

I did **not** find an issue with the 14-test count or the stated input-mode limits in the README. I haven’t changed the code. The supplied checkout has no Git metadata, so I could review its contents but couldn’t confirm which upstream commit it represents.

The two command findings are directly reproducible. If you want me to check the checkout against a particular upstream revision, the commit hash or a Git checkout would help; otherwise, no further material is needed to act on these findings.


**John:**

alright, i appreciate the work!  just to confirm, have we done a deep dive on the entire code base as well as the claims, and are saying there are no additional overstatements or incorrect statements or assumptions other than those you've identified above?  if you want to do another pass just to verify that's no trouble :)


**Reviewer (6 Luna):**

**No—I can’t say there are no other issues.** My first answer was too broad for the work I’d done. This second pass covered the CLI and core analysis paths, checked the main stored results against the README, and traced more of the whitepaper’s methodology. It found additional problems. It still wasn’t a formal, line-by-line audit of every legacy experiment, and I couldn’t inspect the shipped PDF itself: this environment lacks PDF extraction and rendering tools.

### Additional findings

- **A quick statistical test can show a signal and still say PASS.** With `python3 cryptid.py test -a crc32 -n 200 --level quick --json`, the entropy result is flagged, but the overall verdict is PASS. Below 2,000 samples the meta-learner is skipped, and the verdict logic doesn’t use the individual statistical test signals. That conflicts with the README’s definition of PASS as “none found.” See `cryptid/engine.py:188` and `README.md:88`.

- **`kat` can PASS without testing an external implementation.** Running `python3 cryptid.py kat -a sha256 --json` returns PASS after checking only the built-in reference against its embedded vector. The parser doesn’t require either `--command` or `-i`. It can also PASS when the external command fails every message, because the reference self-check counts as a completed check. See `cryptid/cli.py:364` and `cryptid/cli.py:544`. The JSONL loader also skips malformed rows with warnings, so a KAT may pass on only the rows that loaded.

- **`compare` can exit successfully without comparing anything.** If the files have no shared plaintexts, it reports zero shared inputs and zero mismatches, then exits 0. A comparison needs to fail or be marked inconclusive when there’s no overlap. See `cryptid/cli.py:251`.

- **The linear tier checks only the first 256 digest bits.** The README says the masks cover every output bit, but the implementation caps single-bit and multi-bit output masks at 256. So SHA-512 and SHA3-512 receive linear analysis on only half their output. See `src/linear_approximation.py:70` and `README.md:61`.

- **The interaction-test description implies triple-sum features that aren’t implemented.** The paper describes pair/triple “XOR and sum features”; the code tests sums for pairs, but only XOR features for triples. See `whitepaper.py:216` and `src/statistical_analysis.py:670`.

- **The SHA-256 “31 steps” record statement needs a date or qualification.** The paper and README call 31 steps the best published practical collision attack. A later IACR ePrint paper reports a 36-step SHA-256 collision with complexity \(2^{57}\) and says it verified the attack with a colliding pair. Whether that counts as *practical* depends on the intended threshold, so the repository should define that term or update the statement. [IACR ePrint 2026/1120](https://eprint.iacr.org/2026/1120)

The README’s dependency statement also needs a narrower scope: the core CLI is mostly standard-library-only, but rebuilding the paper requires ReportLab and regenerating figures requires Matplotlib. And the claim that every hand-rolled implementation has published vectors is too broad: `pearson64` has no embedded known-answer vector.

### What checked out, and what remains unverified

The 14-test count is right. The main sweep and out-of-family figures I spot-checked match the stored JSON; I recomputed the held-out classifier metrics and got the stored 100% on 96 examples. I also checked 18 embedded vectors across 13 algorithms and compared six instrumented hash implementations with `hashlib` over boundary-length messages; those checks matched.

Those spot checks don’t prove the rest of the claims. The supplied directory has no Git metadata, so I can’t confirm its upstream commit. The repository also contains no independent review transcript or experiment logs that would let me verify the claimed second-model review process. I would treat the findings above as confirmed issues, and the rest of the project’s claims as **not yet exhaustively verified**, rather than conclude there are no others.


**John:**

alright, that's great stuff! i'm excited to use this info to improve everything, but first how about we see if there's a little more we can do here:
- i've created a text version of the whitepaper and dropped it into the working folder as "cryptid-whitepaper.txt", so please dive in there and let me know if there are errors, omissions, overstatements, etc
- when you say "It still wasn’t a formal, line-by-line audit of every legacy experiment", is that something we could dig into and complete? if yes, then i'm excited to hear what you find
- "The supplied directory has no Git metadata, so I can’t confirm its upstream commit." - i could be missing something, but i'm not sure that's something we need to do to verify the veracity of the tool and claims?  if i'm missing something please help me understand :)
- "The repository also contains no independent review transcript or experiment logs that would let me verify the claimed second-model review process" - ahh, this makes sense. we did the original work on Claude Opus and then a second review later with Claude Fable, which is the source of the original 'second-model review' claim, but decided since these models are in the same family it needed a more independent review, which is specifically what we're doing right now :) so i think this work you're doing will end up filling that claim
- to the point above, are there any commands or tests that i can run, or anything else i can do to empower you to do any more research or verification to improve this cross check?
- if you're able to access and review https://cryptid.r57labs.com , this is a github-pages based web site from the git repo that we're using to represent the tool. so if that's something you haven't reviewed and assessed from the repo copy you have in the working folder, maybe you could access the web site and review it's contents for errors, omissions, overstatements, etc?


**Reviewer (6 Luna):**

I reviewed the new whitepaper text and the live [cryptid site](https://cryptid.r57labs.com/), then extended the code review into the experiment scripts. I found more issues. I **can’t honestly certify that no others exist**: this is a substantial cross-check, not a formal proof or a guarantee that every possible edge case has been found.

### Whitepaper and site

The whitepaper is much more careful than the earlier claims, and most of its headline numbers match the saved results. These points still need correction or qualification:

- **The reduced-round SHA-256 result did not run the entire battery.** The abstract says it passed the entire battery, but the saved run used `impl_level: standard`, which covers only Tiers 1–2. The experiment script defaults to that level. The evidence supports “passed the statistical and differential tiers in this run,” not “passed every test.” See the [whitepaper text](`whitepaper-text:8`) and `results/out_of_family.json`.

- **“Every output bit” overstates the linear-search coverage for wider digests.** The linear search defaults to the first 256 digest bits. That leaves half the output of SHA-512 and SHA3-512 untested in that tier. The code documents this limit in `src/linear_approximation.py:70`.

- **The paper’s description of the Tier 4 signal rule is incomplete.** It gives two conditions, but the implementation has a third: a threshold on the count of significant multi-bit approximations. See the [paper’s method description](`whitepaper-text:124`) and `src/linear_approximation.py:276`.

- **“Full diffusion” is too strong for the SHA-3 measurement.** The table reports an empirical average of 99.9% of the ideal normalized distance at +3 rounds; that supports “near ideal on this measurement,” not full diffusion as a general or exact property. See the [paper’s diffusion section](`whitepaper-text:337`).

- **The review history says the reviewer came from a different model family.** You clarified that Opus and Fable were in the same family, so that claim on the site and in the paper is inaccurate. “Reviewed by a second model from the same family” would match what happened. This current Codex review is a separate model/provider review; describe it with its scope and date rather than claiming it proves the audit found everything. See the [revision-history text](`whitepaper-text:428`).

- **The “31-step best practical collision attack” reference needs an update and a definition of “practical.”** A 2026 IACR paper reports a 36-step SHA-256 collision attack with stated complexity of \(2^{57}\). That doesn’t establish a full-SHA-256 break, but it makes the unqualified “best … 31 steps” wording dated or ambiguous. [IACR ePrint 2026/1120](https://eprint.iacr.org/2026/1120).

The site’s broad “anything that returns a digest” framing also needs a mode qualifier: record files support Tier 1; Tiers 2–4 need a callable function or command that can hash chosen byte strings. The example HSM wrapper also hardcodes a placeholder PIN, which should be replaced with safer credential handling.

### Additional code issues

These are more consequential than wording changes:

- **`kat` can report PASS without testing an external implementation.** The command and input file are optional. It can also report PASS when every command invocation errors, because the built-in reference self-check increments the checked count. This conflicts with the `cryptid/cli.py:542` and `cryptid/cli.py:364`. I reproduced both cases in the earlier checks.

- **`compare` returns success when the files have no shared inputs.** It only exits with failure when there are mismatches; zero shared rows means zero mismatches. A comparison that checked nothing should be an error or nonzero result. See `cryptid/cli.py:251`.

- **At low sample counts, `test` can say PASS despite a raw test flag.** For example, the CRC32 quick run with 200 samples had a flagged entropy result but an overall PASS. The verdict logic does not use Tier 1 raw statistics when the meta-learner is skipped. That makes the README’s PASS definition unreliable for those runs; see `cryptid/engine.py:183`.

- **Malformed input rows are silently skipped.** A file with some bad rows can still produce a passing result on the rows that loaded, without a failing verdict. See `cryptid/input_handler.py:28`.

These mean the paper’s claim that a failed phase can no longer report PASS needs another review against the current code.

### Legacy experiments

I reviewed the experiment scripts’ methodology and data flow. Several are useful as exploratory tools, but their outputs should not be presented as independent validation:

- `targeted_probe.py` selects candidate leaks using statistics from the full dataset, then splits that same dataset into training and test subsets. The “held-out” probe examples therefore influenced which candidates were selected. It also tries only one shuffled-label control and uses a fixed 2% accuracy threshold without uncertainty estimates. See `experiments/targeted_probe.py:376`.

- `byte_model.py` and `hybrid_model.py` create real and shuffled pairs first, then randomly split those pairs. Records are reused across the split, so the reported test examples are not independent held-out source records. The hybrid script also calls the best training loss `best_val_loss`; it does not use a validation set. See `experiments/byte_model.py:100` and `experiments/hybrid_model.py:359`.

- `evaluate.py` interprets a single difference in average language-model loss as evidence of learned structure without a paired uncertainty test. Its loss includes the prompt tokens as well as the plaintext portion, so it is not a clean measure of whether the model learned the hash-to-plaintext relation. See `experiments/evaluate.py:190`.

- `run_full_sweep.py` reuses an existing dataset file without checking that its record count matches the requested sample size. A reused file can make the run label inaccurate. See `experiments/run_full_sweep.py:97`.

The repository doesn’t include the original datasets, model predictions, or run logs for most of these legacy experiments. I can assess what their code does, but I can’t reproduce or verify their historical outputs from this copy.

### Git metadata

You’re right that Git metadata is **not required** to assess whether this code behaves as claimed. I was too cautious in treating its absence as a limitation on the substantive audit. A commit hash would only help establish which exact revision was reviewed and whether it matches the deployed site. It doesn’t determine whether the findings above are valid.

You don’t need to run anything to support these findings. If you want to reproduce the `kat` issue locally, these commands exercise the two cases:

```sh
python3 cryptid.py kat -a sha256 --json
python3 cryptid.py kat -a sha256 --command "python3 -c 'import sys; sys.exit(1)'" --json
```

To pursue the legacy-model claims further, the most useful material would be the original datasets, saved predictions, model checkpoints, dependency versions, and run logs. That would let me separate code-level methodological problems from problems that actually affected reported results.


---

## Second pass — v0.3, tag `v0.3.0` (commit `d353ef1`)


**John:**

hi again, this is the second round on cryptid. last time you reviewed v0.2 from a zip with no git metadata; this time the working directory has a real git clone of github.com/r57-labs/cryptid checked out at tag v0.3.0 (commit d353ef1), with full history, so you can diff, run the tests, and confirm exactly what you're looking at.

what changed since you looked: everything you found was reproduced and fixed, and our response is in docs/REVIEW-2.md, which lists each of your findings, our verdict on it, the fix, and the test that is supposed to cover it. the transcript of your previous review is published as docs/REVIEW-2-transcript.md (local paths made repo-relative, nothing else changed). there is now a tests/ directory (python -m unittest discover -s tests -v) and a CI workflow in .github/workflows/ci.yml.

same instruction as before: find what's wrong. specifically, in this order:
1. treat docs/REVIEW-2.md as the set of claims under test. for each finding, verify the fix is real: read the code, re-run the command that reproduced the problem last time, run the test that claims to cover it, and tell me confirmed fixed / partly fixed / not fixed. if a test would pass trivially or doesn't test what its name says, say so.
2. attack the new code. the diff is git diff f05c986 d353ef1. last round the code written during the first review was the code with the bugs, so assume the same could be true of the code written in response to yours. the parts i most want pressure on: the verdict logic in cryptid/engine.py (classifier skipped vs ran, SIGNAL vs marginal); the N-aware entropy thresholds in src/statistical_analysis.py (is the 5-sigma bit threshold and the Miller-Madow byte margin justified, can a real weakness now hide under the relaxed small-N thresholds, and is it true that nothing changes at N >= 2000); the kat and compare rewrites in cryptid/cli.py; the loader changes in cryptid/input_handler.py; the linear tier default widening in src/linear_approximation.py; and the tests and workflow themselves (would CI actually go red if one of these regressions were reintroduced?).
3. the results files. results/sweep_10k.json has a "reruns" entry for three 512-bit rows that were re-run after the linear-tier fix, and results/out_of_family.json has one for the implementation variants re-run at the full level. check that the merged rows are consistent with the rest of each file and with what the README and whitepaper (whitepaper.py is the source; whitepaper.pdf is the build) say about them.
4. the claims we now make about the review process itself: the v0.3 note at the top of README.md, docs/REVIEW-2.md, section 8.2 of the whitepaper, and the live site at https://cryptid.r57labs.com. are they accurate and not overstated, including how we describe you and what your review did and didn't cover? the transcript should be faithful to the conversation you remember.
5. anything else you find, with the same standard as last time: don't tell me there are no other problems unless you looked, and say what you covered and what you didn't.
ground rules: don't modify the code or docs; reproduce before asserting; cite file:line against commit d353ef1. i'll take whatever you find and we'll do the next round.


**Reviewer (6 Luna):**

### Findings

**The checkout is the claimed commit:** tag `v0.3.0` resolves to `d353ef103daff4045b63ad56f92bd59cc7f066e0`, and the working tree is clean. I ran the 27-test suite, reproduced the listed CLI fixes, checked the results against the README and whitepaper source, and inspected the live site. The suite passes, but it misses several real edge cases below.

#### 1. Findings in `REVIEW-2.md`

| Finding | Assessment |
|---|---|
| **A1 — `kat` could pass when the command failed** | **Confirmed fixed.** The reproduced failing command now returns `ERROR`, and omitting a target is rejected. `KatTests` covers both cases. The implementation separates reference checks from implementation checks in `cryptid/cli.py:365`. |
| **A2 — `compare` could pass with no shared inputs** | **Confirmed fixed for the reported case.** The two-file reproduction now returns `INCONCLUSIVE`, exit 3, in JSON and terminal output. Tests cover no overlap and ordinary matching/mismatching rows. A separate duplicate-input flaw remains below. |
| **A3 — `test` could show PASS above a Tier 1 signal when the classifier was skipped** | **Partly fixed.** With the classifier skipped, a displayed signal now produces WARN; a marginal flag can remain PASS. The small-N CRC32 false alarm from the old fixed entropy threshold is also gone. But with the classifier running, it can still return PASS while the report prints a row as `SIGNAL`: the test explicitly codifies the classifier override in `tests/test_engine.py:60`, while `cryptid/report.py:151` labels rows independently of the classifier. The documentation’s broader “PASS means no requested test found anything” wording therefore needs qualification. The README’s FAIL definition also does not match the code: a single linear signal, or two signals within one differential battery, can produce FAIL (`cryptid/engine.py:217`, `README.md:91`). |
| **A4 — unusable input lines were silently skipped** | **Confirmed fixed.** Malformed lines error by default and are counted when `--skip-malformed` is used. The named tests cover both paths and inconsistent digest lengths (`cryptid/input_handler.py:342`, `tests/test_cli.py:185`). |
| **B1 — linear tier capped 512-bit outputs at 256 bits** | **Code fix confirmed; regression test is incomplete.** The default now covers the full digest, and the three saved 512-bit rows show 512 output bits and 54,293,600 tests. But `LinearWidthTests` checks 1×1 coverage only. It would not catch a cap reintroduced specifically for multi-bit output masks, which use `out_bits_multi` (`src/linear_approximation.py:209`, `tests/test_engine.py:109`). |
| **B2 — unfaithful SHA-256 variants passed the full battery** | **Saved evidence is consistent; I did not rerun all four expensive full-level audits.** All four saved variant rows say full-level, N=2,000, PASS, with no battery signals. The four runtimes are consistent with the stated 12–26 minutes each. This verifies the merged data and documentation agree, not that I independently reproduced the full runs (`results/out_of_family.json:992`, `docs/REVIEW-2.md:40`). |
| **B3 — collision-attack citation was out of date** | **Restatement appears accurate.** The June 2026 ePrint reports the 36-step result and a 38-step theoretical attack; see [IACR ePrint 2026/1120](https://eprint.iacr.org/2026/1120). |
| **C1–C7 — code and description mismatches** | **The restatements I checked align with the cited code or updated documentation:** the tier-4 rule, pair-only sum features, measured SHA-3 diffusion wording, Pearson-64’s lack of published vectors, non-standard-library figure/PDF dependencies, file-mode tier limitation, and environment-based HSM PIN. The site’s general tagline now includes the file-mode qualifier. |

The sweep rerun entries and rows are internally consistent: `sha512`, `sha3_512`, and `random_oracle_512` are all PASS at N=10,000 with full 512-bit linear coverage (`results/sweep_10k.json:130`, `results/sweep_10k.json:3771`). The paper source and built PDF agree on the corrected tables and explanations. I rendered the relevant PDF pages; they are legible with no visible clipping.

#### 2. New issues reproduced in v0.3

1. **Negative sample counts produce a false PASS.**  
   `python3 cryptid.py test -a sha256 -n -1 --level quick --json` exits 0 with `verdict: PASS`, `n_samples: 0`, and no test results. A negative count creates an empty record list; `run_audit` skips all phases and leaves the verdict at PASS. This contradicts the documented meaning of PASS and ERROR. There is no positive-count validation in `cryptid/cli.py:141`, and the empty-record path is visible in `cryptid/engine.py:384`. `-n 0` also silently falls back to the default because the CLI uses `args.samples or 10000`.

2. **`compare` can pass despite conflicting duplicate records.**  
   I gave the reference file two rows for the same plaintext: first a wrong digest, then the correct one. `compare` returned PASS, exit 0. `_check_output_divergence` stores reference rows in a dictionary, so the last duplicate overwrites earlier conflicting values (`cryptid/cli.py:288`). Existing tests cover ordinary unique rows but not duplicate conflicts.

3. **One record creates a false inter-record signal.**  
   A one-record JSONL file produces WARN with `record_distance` flagged at strength 1.0, even though there are zero pairs to measure. When `n == 0`, the code sets the mean flip rate to zero and compares it to 0.5 (`src/statistical_analysis.py:330`). This also makes one-record per-file summaries in `compare` misleading; the top-level comparison is correctly INCONCLUSIVE when there are no shared inputs.

#### 3. Small-N entropy thresholds

The threshold does become the fixed 0.95 bit / 7.5 byte values by N=2,000, so the narrow claim that these thresholds do not change at N≥2,000 is true. The tests verify that clamp, but do not establish the threshold’s detection power or false-alarm rate (`src/statistical_analysis.py:267`, `tests/test_engine.py:85`).

The Miller–Madow term is an asymptotic bias correction for a fixed alphabet, not a calibrated lower confidence bound for the minimum entropy across many output bytes. At N=200 with a 256-symbol alphabet, treating it as a reliable threshold needs additional evidence; see the original [entropy-estimation paper](https://sites.stat.columbia.edu/liam/research/pubs/info_est-nc.pdf).

I also tried a synthetic function whose first output byte is restricted to 160 of 256 possible values, while the remaining digest bytes come from SHA-256. That is a real output-support defect, but the N=200 quick audit passed in five seeds. This does not mean small-N testing should catch every weakness; it does mean the relaxed threshold can hide a meaningful distribution defect. The current positive-control test only checks a constant top byte, a much easier defect. The stated 1-in-100 / 0-in-100 clean-run rates were not contradicted by my 100-seed spot check, but the repository does not provide a reproducible experiment script and seed record for those rates.

#### 4. Tests and CI

`python3 -m unittest discover -s tests -v` passes all 27 tests. I also ran the suite in a fresh local virtual environment; it passed there too. The CI workflow’s self-check commands passed locally: all 13 built-in KAT self-checks, external `sha256sum`, SHA-256 expected PASS, and Jenkins/CRC32 expected FAIL (`.github/workflows/ci.yml:25`).

That is useful regression coverage, but it would **not** catch the three new cases above, the classifier/report PASS-versus-SIGNAL inconsistency, or a multi-output-only linear cap. I verified the workflow commands locally, not an actual GitHub Actions run.

#### 5. Review-process claims and the live site

The transcript’s own introduction says it omits the README text pasted into the first prompt and normalizes file paths (`docs/REVIEW-2-transcript.md:3`). Calling it the “full conversation” on the live site and in the whitepaper is therefore inaccurate; describe it as an edited transcript and name the omission. The prior assistant’s final answers in the transcript are broadly consistent with the review I remember, but the transcript is not an authenticated run log and does not establish model identity or preserve tool interactions.

There is also an internal inconsistency in the change log: the whitepaper says the “first four” findings were fail-open bugs in code added by the first review, while A4 says the input-skipping issue predates v0.2 (`whitepaper.py:607`, `docs/REVIEW-2.md:28`). The claim that every finding was “reproduced” is broader than the evidence described: several C items are source/document comparisons rather than executable reproductions (`docs/REVIEW-2.md:5`).

I can’t verify the historical “Luna6” model label from the repository or transcript metadata. The current environment identifies me as Codex based on GPT-6; that alone cannot prove which model ran the earlier review.

On the live site, I found two additional wording issues:

- It says 32-bit outputs are “several times faster” than 256-bit outputs. The repository’s full-level timing for Jenkins 32-bit versus SHA-256 at N=5,000 is 42.5 vs 49.2 seconds—about 1.16×, not several times (`results/timings.json:12`).
- It calls the collision citation “two years out of date.” The 31-step work dates to Eurocrypt 2024, but the newer 36-step result is from June 2026, only months before the October 2026 v0.2 release. Say it was superseded by the June 2026 result.

Finally, `docs/REVIEW-2.md:68` says six legacy neural-probe scripts were found flawed, but its named list describes five scripts. I also found a limitation in `bit_probe.py`: it probes only the first two input bytes by default and declares signal based on maxima across many bit/model comparisons without a statistical correction (`experiments/legacy/bit_probe.py:297`, `experiments/legacy/bit_probe.py:361`). The transcript does not document that specific finding, so the published account should either identify the sixth script and its flaw or correct the count.

This was a focused adversarial pass over the reported fixes, core verdict/entropy/compare/loader/KAT/linear paths, tests and CI, cited result rows, paper source/PDF, legacy-script claims, and the live site. I did not rerun the four long full-level implementation-variant experiments or independently retrain the classifier. The reproduced bugs and scope limits mean I would not describe this review as proving that no other issues remain.


---

## Third pass — v0.3.1, tag `v0.3.1` (commit `75f98e0`)


**John:**

thanks for that review & work :D 

and time for round three on cryptid, assuming you're game ;) the working directory has the same git clone, now pulled to tag v0.3.1 (commit 75f98e0). everything from your second pass was reproduced and fixed; section F of docs/REVIEW-2.md is our account of that pass and what changed, and it is the first set of claims under test this time.

what's new in v0.3.1, which is where i want most of your attention, since the code written in response to a review has been where the bugs were both times:
- src/statistical_analysis.py: the small-N entropy thresholds were rebuilt from a simulated null (the mean/sd table embedded near entropy_thresholds), and the entropy test gained two output-support checks: a coverage test on the values a digest byte never takes (exact binomial occupancy tail, p < 1e-8) and a chi-square frequency test from N = 1,280. experiments/small_n_thresholds.py is the calibration script and results/small_n_thresholds.json its output; the README has a power table from it. please attack the statistics: is the null simulation the right null, is the binomial approximation for the missing-value count sound given the negative correlation between values, is 6 sigma / p < 1e-8 the right trade, can a correct function trip these on any input distribution the toolkit accepts, and does the classifier's behaviour on clean data really stay unchanged (we re-ran both held-out sets and say so in F3; check that claim).
- cryptid/cli.py, engine.py, report.py: sample-count validation, the 100-record minimum, the compare duplicate handling, the classifier-override marking, and the rewritten verdict table in README.md, which should now match the code exactly.
- tests/: 37 tests. are any of the new ones tautological, and would CI go red if each fix were reverted?
then the rest, in this order of importance:
1. anything that lets a run report PASS or FAIL for a reason that isn't true (a verdict from nothing, from the wrong data, from a stale file).
2. any claim in README.md, docs/REVIEW-2.md, the whitepaper (whitepaper.py is the source; the PDF is the build) or the live site at https://cryptid.r57labs.com that the repository's own files don't support, including how we describe you and your two passes.
3. coverage gaps like the 192-of-256-value byte: a defect a reasonable user would expect the battery to see and it doesn't. if you find one, say at what N it becomes detectable in principle.
4. wording, counts and edge cases that don't change a verdict or a claim.
report everything you find, but rank it by that list and keep category 4 to a short separate section at the end, so the important things get the effort. "done" for this pass means: F1–F6 each marked confirmed / partly / not fixed with the command or test you used; the five files above read in full; the two held-out result files and results/sweep_10k.json checked for consistency with the README; and a closing scope statement of what you covered and what you didn't. same ground rules: don't modify the repo; reproduce before asserting; cite file:line against commit 75f98e0; and don't say there is nothing else unless you looked.


**Reviewer (6 Luna):**

### v0.3.1 audit — commit `75f98e0`

I reviewed the checkout at `75f98e06bf579dbe93c42767fc3ae8c17cac15e6`. The worktree is clean; I made no repository changes. All **37 tests pass** with `python -m unittest discover -s tests -v`. I also ran the listed CI self-checks locally: all 13 built-in KAT self-checks, external `sha256sum`, SHA-256 as a positive control, and Jenkins/CRC32 as negative controls.

### 1. Verdicts that can mislead

**Accepted repeated-input files can make correct SHA-256 report WARN or FAIL.** I created JSONL files with repeated copies of the same plaintext, each paired with its correct SHA-256 digest. `cryptid test -i … --level quick --json -q` returned **WARN at 100 rows** and **FAIL at 2,000 rows**, with classifier probability 1.0 in the latter case. Repeated queries to a correct deterministic hash are supposed to repeat their outputs; the statistical checks treat the rows as independent samples. The loader accepts duplicates, and `test` neither deduplicates nor rejects them. This reproduces the false verdict concern raised in your prompt. (`cryptid/input_handler.py:21`, `cryptid/input_handler.py:342`, `src/statistical_analysis.py:366`)

**The engine still has an empty-run PASS path, and it does not enforce the 100-record floor.** A direct call to `run_audit(records=[], hash_fn=lambda msg: "00", level="quick")` returned PASS with zero samples and no stats. A direct call with 99 distinct, correctly hashed SHA-256 records also returned PASS. The CLI does reject these sizes; the bypass is in the engine API, despite REVIEW-2 saying an empty audit is an engine error. The current empty-engine test covers only the *no records and no hash function* branch. (`cryptid/engine.py:403`, `cryptid/engine.py:412`, `cryptid/cli.py:79`, `docs/REVIEW-2.md:94`, `tests/test_cli.py:240`)

**`compare`’s top-level PASS is valid for matching outputs, but its per-file JSON verdicts are not.** With two matching 20-record files, the command returned top-level PASS for their shared outputs, while both `target.verdict` and `reference.verdict` also said PASS despite each statistical summary being `null`. The notes say the summaries were skipped, but a consumer reading the per-file verdict sees PASS. `test_small_files_get_no_statistical_verdict` passes without checking either per-file verdict; it only checks the missing summary and note. (`cryptid/cli.py:280`, `cryptid/cli.py:306`, `cryptid/engine.py:237`, `tests/test_cli.py:147`)

### 2. Entropy calibration, tests, and claims

The simulated byte null is the right *idealized* null for a random oracle queried on distinct inputs: each output byte is uniform. The script reproduces the table and power results, and its sample-size thresholds are unchanged by N = 2,000—indeed, they reach the fixed thresholds by about N = 750. The added support checks still run at larger N.

The statistical guarantee is weaker than the prose suggests. The byte threshold is set six simulated standard deviations below the mean, but the simulation has 9,600 columns at N ≤ 500 and 3,840 at larger N; it does not measure a six-sigma tail directly. The clean-rate experiment checks 100 runs per N only at N = 200, 500, and 1,000. Its 0/100 WARN result is useful evidence for those generated inputs, not evidence that a correct function “never” trips the checks. The comment that real primitives never trip them is contradicted by the repeated-input SHA-256 reproduction above. (`src/statistical_analysis.py:259`, `experiments/small_n_thresholds.py:61`, `experiments/small_n_thresholds.py:121`, `src/statistical_analysis.py:316`)

The missing-value calculation is **not an exact occupancy p-value**. A symbol is missing with the stated marginal probability, but missing-symbol indicators are dependent. The code calls the binomial model an approximation; I independently computed the exact occupancy tail over the tested rejection grid, and found the binomial tail conservative there. That supports using it as a cautious approximation, but “exact binomial occupancy tail” in REVIEW-2 and the paper is inaccurate. The N ≥ 1,280 chi-square branch has no full-support skew positive-control test: the current tests can still pass if that branch is removed. (`src/statistical_analysis.py:303`, `src/statistical_analysis.py:323`, `docs/REVIEW-2.md:101`, `whitepaper.py:671`, `tests/test_engine.py:131`)

The support-power table is construction-specific. `small_n_thresholds.py` uses `h[0] % support`, which gives unequal probabilities for supports that do not divide 256. For the 192-value defect at N = 300, the checked-in construction was caught in **16/20** runs; a near-uniform mapping onto the same 192-value subset was caught in **1/20**. In both cases the coverage test itself did not fire at N = 300; the byte-entropy threshold fired for the biased construction. At N = 500, both mappings were caught in 20/20 runs. So the N = 500 result is supported by this limited experiment; the N = 300 power figure and the claim that those detections are all the coverage check’s doing are not general. (`experiments/small_n_thresholds.py:89`, `experiments/small_n_thresholds.py:105`, `README.md:98`, `README.md:108`)

The held-out-evaluation claim **is confirmed**. I reran the development and test evaluation commands with seed bases 900000 and 1700000. Their evaluation objects match the saved outputs; compared with the parent commit, clean-variant scores are unchanged, seven weakened-variant scores increased, and both sets remain 96/96 accurate. The checked-in calibration script also reproduced the saved null, power, and clean results (apart from runtime). All 31 README sweep rows match `sweep_10k.json` at the displayed precision and verdict; the FNV-1a-64 rerun is recorded, with its changed entropy flag and unchanged P/verdict. (`results/meta_evaluation_v4_dev.json:14`, `results/meta_evaluation_v4_test.json:14`, `results/sweep_10k.json:3771`)

### 3. Review-history and site claims

Several remaining review-process statements need correction:

- README says the first review found **four** fail-open bugs in code it added; REVIEW-2 correctly says three of the first four were in that code, while the fourth predates it.
- README calls all three F2 issues “fail-opens,” and the whitepaper calls them three new fail-opens. One was a **false positive**: the one-record distance test signaled when there were no pairs. “Three verdict bugs, two fail-open and one false-positive” would be accurate.
- README says the detection machinery “has held up under every review,” despite the documented half-tested 512-bit linear tier and the 192-of-256 detection gap. Its own review history says both were found and fixed.
- Whitepaper §8.2 presents flaws in six legacy scripts as part of the first review’s findings; REVIEW-2 says that pass found flaws in five, and `bit_probe.py` was first inspected in the second pass.
- The live site’s file-input explanation omits the 100-record minimum and the distinct-input assumption. Its broad file-mode description therefore needs the same qualification as the CLI/docs.

These are inconsistent with the project’s own review account. (`README.md:9`, `docs/REVIEW-2.md:68`, `docs/REVIEW-2.md:91`, `whitepaper.py:639`)

The transcript’s model-name wording is appropriately qualified and its header says it is not authenticated; I found no material contradiction in its account of the prior exchange. It cannot establish model identity or preserve tool-call evidence. I also verified the cited 36-step SHA-256 collision claim against the [IACR ePrint 2026/1120](https://eprint.iacr.org/2026/1120). The PDF text matches `whitepaper.py`; I rendered and inspected the final pages as well. (`docs/REVIEW-2-transcript.md:3`, `whitepaper.py:603`, `whitepaper.pdf`)

### 4. Coverage limit found

A byte restricted to **254 of 256 values** (two values never occur) passed the entropy test at N = 3,000 in my reproduction: support p = 2.06e-6, chi-square z = 1.78. It still did not signal at N = 3,600; at N = 3,700, the support check crossed its threshold (p = 8.62e-9) and signaled. That gives a concrete sample-size boundary for this planted defect and input construction. It does not mean every 254-value mapping has identical power. (`src/statistical_analysis.py:369`, `src/statistical_analysis.py:389`)

### F1–F6 disposition

| Finding | Status | Verification |
|---|---|---|
| **F1 — classifier override and verdict table** | **Confirmed fixed** | Suite plus `VerdictLogicTests`; I also rendered a synthetic SIGNAL/PASS row and confirmed the “overridden by classifier” label. The tests check the engine property, but do not assert the rendered output. |
| **F2 — sample counts, duplicate compare rows, one-record distance** | **Partly fixed** | `SampleCountTests`, duplicate-row and one-record tests pass. CLI validation works, but the engine callable/under-100 PASS paths and skipped compare-side PASS remain. |
| **F3 — entropy thresholds and support checks** | **Partly fixed** | Reproduced `small_n_thresholds.py` and both held-out evaluations. The thresholds and main power claim are reproducible; the null-tail guarantee, generality of the power table, repeated-input behavior, and chi-square regression coverage remain limited as described above. |
| **F4 — linear-tier width test** | **Confirmed fixed** | `LinearWidthTests.test_linear_tier_covers_the_whole_digest` checks 1×1, 3×1, and 1×2 masks at 512 bits; a reintroduced cap would fail it. |
| **F5 — review-history descriptions** | **Partly fixed** | REVIEW-2 and the paper correct several prior inaccuracies, but README and whitepaper still contain the mismatches listed above. |
| **F6 — `bit_probe.py`** | **Confirmed as documented** | Its defaults and max-based signal rule match `experiments/legacy/README.md`; this is a source review finding, not a code regression covered by CI. |

The CI suite would catch most CLI fixes: KAT failure handling, no shared inputs, malformed files, negative/zero/minimum counts, conflicting compare duplicates, one-record distance, and linear-width caps. It would **not** catch the engine API bypasses, per-file compare PASS, removed chi-square detection, or a renderer regression in the override label. `test_small_files_get_no_statistical_verdict` is especially weak for its name: it passes while per-file verdicts say PASS.

### Minor precision issues

The chi-square z threshold of 5.6 corresponds to a chi-square tail of about 1.012e-8 for 255 degrees of freedom, slightly above the stated `<1e-8`. Also, argparse returns exit code 2 for invalid `-n 0`, while the README labels code 2 FAIL; clarify that the table describes assessment verdicts, not argument errors. (`src/statistical_analysis.py:316`, `cryptid/cli.py:67`, `README.md:89`)

### Scope

I reviewed the requested modules, tests, workflow, README, REVIEW-2 and transcript, whitepaper source and PDF, live site, and relevant result files. I also checked the `d353ef1..75f98e0` diff. I did **not** rerun the expensive full-level implementation-variant audits, re-audit all legacy research scripts, verify the upstream GitHub Actions run, or perform a formal proof of the statistical error rates. Local CI equivalents passed. I found additional issues, so this pass does not establish that no others remain.
