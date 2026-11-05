# Legacy research scripts

These six scripts are from the project's earlier phases (v0.1 and before), when
the question was whether a neural probe or a small language model could learn
input→output structure that the statistical tests missed. They are kept so the
project's history is visible, and because the data flow in them is instructive.

**No number in the README, the whitepaper or the project site comes from any of
these scripts.** Everything quoted there is produced by `experiments/full_sweep.py`,
`experiments/out_of_family_eval.py`, `src/meta_learner.py evaluate`,
`src/internal_diffusion.py` and `experiments/timing.py`, and is read from `results/`.

They were moved here in v0.3 after the second cross-model review
(`docs/REVIEW-2.md`) examined their methodology. Its findings, which are the
reasons their outputs should not be read as validation of anything:

| Script | Known problem |
|---|---|
| `targeted_probe.py` | Candidate leaks are selected from statistics computed on the *whole* dataset, and the probe is then trained and tested on a split of that same dataset, so the "held-out" probe examples influenced which candidates were chosen. One shuffled-label control, and a fixed 2% accuracy margin, with no uncertainty estimate. |
| `byte_model.py`, `hybrid_model.py` | Real and shuffled pairs are built first and the *pairs* are split, so source records are reused across train and test; the reported test examples are not independent held-out records. `hybrid_model.py` names its best training loss `best_val_loss` (the output key says `best_train_loss`; there is no validation set). |
| `evaluate.py` | Reads a single difference in average language-model loss between real and mismatched pairs as evidence of learned structure, with no paired uncertainty test, and the loss includes the prompt tokens, not only the plaintext being predicted. |
| `run_full_sweep.py` | Reuses an existing dataset file without checking that its record count matches the requested size, so a run's label can be wrong. |
| `bit_probe.py` | Same probe design as `targeted_probe.py`. |

Four of them need PyTorch. They import `src/` by relative path and run from the
repository root, e.g. `python experiments/legacy/evaluate.py --help`.
