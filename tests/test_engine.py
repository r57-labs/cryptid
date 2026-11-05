"""
Engine- and module-level regression tests (no subprocesses).

    python -m unittest discover -s tests -v
"""

import hashlib
import os
import random
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for sub in ("cryptid", "src"):
    path = os.path.join(ROOT, sub)
    if path not in sys.path:
        sys.path.insert(0, path)

from engine import AuditResult, run_audit  # noqa: E402
from input_handler import generate_plaintexts  # noqa: E402
from statistical_analysis import entropy_analysis  # noqa: E402
from linear_approximation import linear_approximation_analysis  # noqa: E402


def _records(fn, n, seed=0):
    rng = random.Random(seed)
    return [{"plaintext": pt, "hash": fn(pt)} for pt in generate_plaintexts(n, rng)]


def _sha256(msg):
    data = msg if isinstance(msg, bytes) else msg.encode()
    return hashlib.sha256(data).hexdigest()


def _sha512(msg):
    data = msg if isinstance(msg, bytes) else msg.encode()
    return hashlib.sha512(data).hexdigest()


class VerdictLogicTests(unittest.TestCase):

    def _result_with_stats(self, strength, flagged):
        r = AuditResult("t")
        r.stats = {"entropy": {"signal_strength": strength, "signal": flagged},
                   "bit_correlation": {"signal_strength": 0.0, "signal": False}}
        r.meta_learner = {"skipped": True, "reason": "test"}
        return r

    def test_signal_row_with_classifier_skipped_is_warn(self):
        r = self._result_with_stats(0.5, True)
        self.assertEqual(r.verdict, "WARN")
        self.assertEqual(r.signal_sources, ["statistical"])

    def test_marginal_row_with_classifier_skipped_is_pass(self):
        r = self._result_with_stats(0.02, True)
        self.assertEqual(r.verdict, "PASS")
        self.assertEqual(r.marginal_statistical_tests, ["entropy"])
        self.assertTrue(r.classifier_skipped)

    def test_classifier_decides_when_it_ran(self):
        r = self._result_with_stats(0.5, True)
        r.meta_learner = {"probability": 0.05, "threshold": 0.4}
        self.assertEqual(r.verdict, "PASS")   # the calibrated classifier overrides raw flags
        r.meta_learner = {"probability": 0.45, "threshold": 0.4}
        self.assertEqual(r.verdict, "WARN")
        r.meta_learner = {"probability": 0.9, "threshold": 0.4}
        self.assertEqual(r.verdict, "FAIL")

    def test_any_phase_error_is_error(self):
        r = self._result_with_stats(0.0, False)
        r.errors.append("Differential profile error: boom")
        self.assertEqual(r.verdict, "ERROR")

    def test_run_audit_with_raising_hash_fn_is_error(self):
        def bad(msg):
            if isinstance(msg, bytes):
                raise RuntimeError("device unplugged")
            return _sha256(msg)
        res = run_audit(records=_records(_sha256, 300), hash_fn=bad, level="standard",
                        n_samples=300, verbose=False)
        self.assertEqual(res.verdict, "ERROR")
        self.assertTrue(any("Differential" in e for e in res.errors))


class EntropyThresholdTests(unittest.TestCase):

    def test_small_n_threshold_relaxes_but_never_tightens(self):
        for n in (200, 500, 1000, 2000, 10000):
            recs = _records(_sha256, n, seed=1)
            r = entropy_analysis(recs)
            self.assertLessEqual(r["bit_threshold"], 0.95, n)
            self.assertLessEqual(r["byte_threshold"], 7.5, n)
            if n >= 2000:
                self.assertEqual((r["bit_threshold"], r["byte_threshold"]), (0.95, 7.5), n)

    def test_clean_function_not_flagged_at_small_n(self):
        for seed in range(5):
            r = entropy_analysis(_records(_sha256, 200, seed=seed))
            self.assertFalse(r["signal"], f"seed {seed}: {r['min_byte_entropy']:.3f} < {r['byte_threshold']}")

    def test_gross_entropy_defect_still_flagged_at_small_n(self):
        def low_entropy(msg):          # top output byte is constant
            return "00" + _sha256(msg)[2:]
        r = entropy_analysis(_records(low_entropy, 200))
        self.assertTrue(r["signal"])
        self.assertGreaterEqual(r["signal_strength"], 0.99)


class LinearWidthTests(unittest.TestCase):

    def test_linear_tier_covers_the_whole_digest(self):
        # v0.2 capped the output masks at 256 bits; a 512-bit digest was half tested.
        r = linear_approximation_analysis(_sha512, n_samples=200, input_bytes=2,
                                          rng=random.Random(0), verbose=False)
        self.assertEqual(r["n_output_bits"], 512)
        self.assertEqual(r["n_input_bits"], 16)
        self.assertEqual(r["level_summary"]["1×1"]["tests"], 16 * 512)
        self.assertFalse(r["signal"])

    def test_explicit_cap_still_honoured(self):
        r = linear_approximation_analysis(_sha512, n_samples=200, input_bytes=2, max_output_bits=64,
                                          max_multi_output_bits=64, rng=random.Random(0), verbose=False)
        self.assertEqual(r["n_output_bits"], 64)


if __name__ == "__main__":
    unittest.main()
