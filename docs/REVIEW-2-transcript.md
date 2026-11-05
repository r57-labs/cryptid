# The v0.2 review: transcript

This is the conversation in which OpenAI's Luna6 (Codex) reviewed cryptid v0.2
(commit `f05c986`, November 2026), reproduced here in full with John's prompts
as he typed them. Luna6 worked from a copy of the public repository, a text
export of whitepaper v2.0, and the live site; it had no git metadata and could
not render the PDF. `file:line` references are to commit `f05c986`.

The only edits: local filesystem paths in Luna6's citations are made
repository-relative, and the README text pasted into the first prompt is
omitted. Our verdict on each finding, and what changed, is in
[REVIEW-2.md](REVIEW-2.md).

The prompting is deliberately plain. The instruction that produced the useful
answers was not a clever one; it was asking, after a confident first pass,
whether the pass had actually covered everything — and then supplying the
material (the paper text, the site) that the reviewer said it could not see.

---

**John:**

hello, i'm hoping we can work together to cross-check work performed by another AI model to verify if the claims it made and code it wrote are all accurate and complete.  so i'm hoping you can dig in and find out if there's any mistakes or mis-statements :)

you should have a copy of the latest github code in the working directory cryptid_reivew_chatgpt/cryptid-main/

please let me know if i can provide anything to help with this task!

here are some of the claims:

*[the README's claims, pasted — omitted here; they are the README at commit f05c986]*


**Luna6:**

Findings
The headline structure is accurate: the code has 14 analysis tests across four tiers—6 statistical, 4 differential, 3 extended, and 1 linear approximation—plus a meta-learner. The README also correctly says that JSONL input supports only Tier 1; the other tiers need a callable implementation or command. Those limits should stay beside any claim that the toolkit can test “anything that returns a digest.”

I found two fail-open bugs in the fidelity commands:
1. kat can report PASS when the implementation fails every check. Its verdict logic only returns ERROR when there are errors and no checks were counted. But the built-in reference’s self-check increments that count first. I ran kat -a sha256 with a command that exits unsuccessfully on every input: it returned exit code 0 and "verdict": "PASS", while listing the failures in "errors". This contradicts the README’s claim that an implementation error is never reported as PASS. See `cryptid/cli.py:364` and `cryptid/cli.py:402`.
2. compare can exit successfully without comparing a single shared input. I gave it two valid one-record files with different plaintexts. It returned exit code 0 with shared_inputs: 0 and mismatches: 0. The command only exits nonzero when it finds a mismatch, so zero overlap can look like success to automation. See `cryptid/cli.py:251` and `cryptid/cli.py:266`.
There’s also a claim to qualify: finite known-answer checks can show that an implementation matches a reference on the messages checked; they cannot prove universal conformance or security. For SHA-256, the command tests a finite set of messages against the built-in reference, which uses Python’s hashlib. See `cryptid/cli.py:314` and `src/generate_dataset.py:266`. I’d describe kat as a practical conformance check against a reference, and avoid saying it proves an implementation is faithful in every case. Likewise, compare only checks matching inputs in the two files; its reference is whatever file the user supplies.

I did not find an issue with the 14-test count or the stated input-mode limits in the README. I haven’t changed the code. The supplied checkout has no Git metadata, so I could review its contents but couldn’t confirm which upstream commit it represents.

The two command findings are directly reproducible. If you want me to check the checkout against a particular upstream revision, the commit hash or a Git checkout would help; otherwise, no further material is needed to act on these findings.

**John:**
alright, i appreciate the work!  just to confirm, have we done a deep dive on the entire code base as well as the claims, and are saying there are no additional overstatements or incorrect statements or assumptions other than those you've identified above?  if you want to do another pass just to verify that's no trouble :)

**Luna6:**

No—I can’t say there are no other issues. My first answer was too broad for the work I’d done. This second pass covered the CLI and core analysis paths, checked the main stored results against the README, and traced more of the whitepaper’s methodology. It found additional problems. It still wasn’t a formal, line-by-line audit of every legacy experiment, and I couldn’t inspect the shipped PDF itself: this environment lacks PDF extraction and rendering tools.
Additional findings
- A quick statistical test can show a signal and still say PASS. With python3 cryptid.py test -a crc32 -n 200 --level quick --json, the entropy result is flagged, but the overall verdict is PASS. Below 2,000 samples the meta-learner is skipped, and the verdict logic doesn’t use the individual statistical test signals. That conflicts with the README’s definition of PASS as “none found.” See `cryptid/engine.py:188` and `README.md:88`.
- kat can PASS without testing an external implementation. Running python3 cryptid.py kat -a sha256 --json returns PASS after checking only the built-in reference against its embedded vector. The parser doesn’t require either --command or -i. It can also PASS when the external command fails every message, because the reference self-check counts as a completed check. See `cryptid/cli.py:364` and `cryptid/cli.py:544`. The JSONL loader also skips malformed rows with warnings, so a KAT may pass on only the rows that loaded.
- compare can exit successfully without comparing anything. If the files have no shared plaintexts, it reports zero shared inputs and zero mismatches, then exits 0. A comparison needs to fail or be marked inconclusive when there’s no overlap. See `cryptid/cli.py:251`.
- The linear tier checks only the first 256 digest bits. The README says the masks cover every output bit, but the implementation caps single-bit and multi-bit output masks at 256. So SHA-512 and SHA3-512 receive linear analysis on only half their output. See `src/linear_approximation.py:70` and `README.md:61`.
- The interaction-test description implies triple-sum features that aren’t implemented. The paper describes pair/triple “XOR and sum features”; the code tests sums for pairs, but only XOR features for triples. See `whitepaper.py:216` and `src/statistical_analysis.py:670`.
- The SHA-256 “31 steps” record statement needs a date or qualification. The paper and README call 31 steps the best published practical collision attack. A later IACR ePrint paper reports a 36-step SHA-256 collision with complexity 2^57 and says it verified the attack with a colliding pair. Whether that counts as practical depends on the intended threshold, so the repository should define that term or update the statement. IACR ePrint 2026/1120
The README’s dependency statement also needs a narrower scope: the core CLI is mostly standard-library-only, but rebuilding the paper requires ReportLab and regenerating figures requires Matplotlib. And the claim that every hand-rolled implementation has published vectors is too broad: pearson64 has no embedded known-answer vector.
What checked out, and what remains unverified
The 14-test count is right. The main sweep and out-of-family figures I spot-checked match the stored JSON; I recomputed the held-out classifier metrics and got the stored 100% on 96 examples. I also checked 18 embedded vectors across 13 algorithms and compared six instrumented hash implementations with hashlib over boundary-length messages; those checks matched.

Those spot checks don’t prove the rest of the claims. The supplied directory has no Git metadata, so I can’t confirm its upstream commit. The repository also contains no independent review transcript or experiment logs that would let me verify the claimed second-model review process. I would treat the findings above as confirmed issues, and the rest of the project’s claims as not yet exhaustively verified, rather than conclude there are no others.

**John:**

alright, that's great stuff! i'm excited to use this info to improve everything, but first how about we see if there's a little more we can do here:
- i've created a text version of the whitepaper and dropped it into the working folder as "cryptid-whitepaper.txt", so please dive in there and let me know if there are errors, omissions, overstatements, etc
- when you say "It still wasn’t a formal, line-by-line audit of every legacy experiment", is that something we could dig into and complete? if yes, then i'm excited to hear what you find
- "The supplied directory has no Git metadata, so I can’t confirm its upstream commit." - i could be missing something, but i'm not sure that's something we need to do to verify the veracity of the tool and claims?  if i'm missing something please help me understand :)
- "The repository also contains no independent review transcript or experiment logs that would let me verify the claimed second-model review process" - ahh, this makes sense. we did the original work on Claude Opus and then a second review later with Claude Fable, which is the source of the original 'second-model review' claim, but decided since these models are in the same family it needed a more independent review, which is specifically what we're doing right now :) so i think this work you're doing will end up filling that claim
- to the point above, are there any commands or tests that i can run, or anything else i can do to empower you to do any more research or verification to improve this cross check?
- if you're able to access and review https://cryptid.r57labs.com , this is a github-pages based web site from the git repo that we're using to represent the tool. so if that's something you haven't reviewed and assessed from the repo copy you have in the working folder, maybe you could access the web site and review it's contents for errors, omissions, overstatements, etc?


**Luna6:**

I reviewed the new whitepaper text and the live cryptid site, then extended the code review into the experiment scripts. I found more issues. I can’t honestly certify that no others exist: this is a substantial cross-check, not a formal proof or a guarantee that every possible edge case has been found.
Whitepaper and site
The whitepaper is much more careful than the earlier claims, and most of its headline numbers match the saved results. These points still need correction or qualification:
- The reduced-round SHA-256 result did not run the entire battery. The abstract says it passed the entire battery, but the saved run used impl_level: standard, which covers only Tiers 1–2. The experiment script defaults to that level. The evidence supports “passed the statistical and differential tiers in this run,” not “passed every test.” See the `whitepaper text:8` and `results/out_of_family.json`.
- “Every output bit” overstates the linear-search coverage for wider digests. The linear search defaults to the first 256 digest bits. That leaves half the output of SHA-512 and SHA3-512 untested in that tier. The code documents this limit in `src/linear_approximation.py:70`.
- The paper’s description of the Tier 4 signal rule is incomplete. It gives two conditions, but the implementation has a third: a threshold on the count of significant multi-bit approximations. See the `whitepaper text:124` and `src/linear_approximation.py:276`.
- “Full diffusion” is too strong for the SHA-3 measurement. The table reports an empirical average of 99.9% of the ideal normalized distance at +3 rounds; that supports “near ideal on this measurement,” not full diffusion as a general or exact property. See the `whitepaper text:337`.
- The review history says the reviewer came from a different model family. You clarified that Opus and Fable were in the same family, so that claim on the site and in the paper is inaccurate. “Reviewed by a second model from the same family” would match what happened. This current Codex review is a separate model/provider review; describe it with its scope and date rather than claiming it proves the audit found everything. See the `whitepaper text:428`.
- The “31-step best practical collision attack” reference needs an update and a definition of “practical.” A 2026 IACR paper reports a 36-step SHA-256 collision attack with stated complexity of 2^57. That doesn’t establish a full-SHA-256 break, but it makes the unqualified “best … 31 steps” wording dated or ambiguous. IACR ePrint 2026/1120.
The site’s broad “anything that returns a digest” framing also needs a mode qualifier: record files support Tier 1; Tiers 2–4 need a callable function or command that can hash chosen byte strings. The example HSM wrapper also hardcodes a placeholder PIN, which should be replaced with safer credential handling.
Additional code issues
These are more consequential than wording changes:
- kat can report PASS without testing an external implementation. The command and input file are optional. It can also report PASS when every command invocation errors, because the built-in reference self-check increments the checked count. This conflicts with the `cryptid/cli.py:542` and `cryptid/cli.py:364`. I reproduced both cases in the earlier checks.
- compare returns success when the files have no shared inputs. It only exits with failure when there are mismatches; zero shared rows means zero mismatches. A comparison that checked nothing should be an error or nonzero result. See `cryptid/cli.py:251`.
- At low sample counts, test can say PASS despite a raw test flag. For example, the CRC32 quick run with 200 samples had a flagged entropy result but an overall PASS. The verdict logic does not use Tier 1 raw statistics when the meta-learner is skipped. That makes the README’s PASS definition unreliable for those runs; see `cryptid/engine.py:183`.
- Malformed input rows are silently skipped. A file with some bad rows can still produce a passing result on the rows that loaded, without a failing verdict. See `cryptid/input_handler.py:28`.
These mean the paper’s claim that a failed phase can no longer report PASS needs another review against the current code.
Legacy experiments
I reviewed the experiment scripts’ methodology and data flow. Several are useful as exploratory tools, but their outputs should not be presented as independent validation:
- targeted_probe.py selects candidate leaks using statistics from the full dataset, then splits that same dataset into training and test subsets. The “held-out” probe examples therefore influenced which candidates were selected. It also tries only one shuffled-label control and uses a fixed 2% accuracy threshold without uncertainty estimates. See `experiments/targeted_probe.py:376`.
- byte_model.py and hybrid_model.py create real and shuffled pairs first, then randomly split those pairs. Records are reused across the split, so the reported test examples are not independent held-out source records. The hybrid script also calls the best training loss best_val_loss; it does not use a validation set. See `experiments/byte_model.py:100` and `experiments/hybrid_model.py:359`.
- evaluate.py interprets a single difference in average language-model loss as evidence of learned structure without a paired uncertainty test. Its loss includes the prompt tokens as well as the plaintext portion, so it is not a clean measure of whether the model learned the hash-to-plaintext relation. See `experiments/evaluate.py:190`.
- run_full_sweep.py reuses an existing dataset file without checking that its record count matches the requested sample size. A reused file can make the run label inaccurate. See `experiments/run_full_sweep.py:97`.
The repository doesn’t include the original datasets, model predictions, or run logs for most of these legacy experiments. I can assess what their code does, but I can’t reproduce or verify their historical outputs from this copy.
Git metadata
You’re right that Git metadata is not required to assess whether this code behaves as claimed. I was too cautious in treating its absence as a limitation on the substantive audit. A commit hash would only help establish which exact revision was reviewed and whether it matches the deployed site. It doesn’t determine whether the findings above are valid.

You don’t need to run anything to support these findings. If you want to reproduce the kat issue locally, these commands exercise the two cases:
python3 cryptid.py kat -a sha256 --json
python3 cryptid.py kat -a sha256 --command "python3 -c 'import sys; sys.exit(1)'" --json
To pursue the legacy-model claims further, the most useful material would be the original datasets, saved predictions, model checkpoints, dependency versions, and run logs. That would let me separate code-level methodological problems from problems that actually affected reported results.
