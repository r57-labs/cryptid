"""
Engine- and module-level regression tests (no subprocesses).

    python -m unittest discover -s tests -v
"""

import hashlib
import math
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

    def test_override_is_named_when_classifier_outscores_a_signal_row(self):
        # A tier-1 row at SIGNAL strength under a PASS is the classifier's
        # calibrated call, and the report must say so (second review).
        r = self._result_with_stats(0.5, True)
        r.meta_learner = {"probability": 0.12, "threshold": 0.4}
        self.assertEqual(r.verdict, "PASS")
        self.assertEqual(r.overridden_statistical_tests, ["entropy"])
        r.meta_learner = {"probability": 0.45, "threshold": 0.4}
        self.assertEqual(r.overridden_statistical_tests, [])     # not overridden: the classifier agreed

    def test_one_record_distance_has_no_signal(self):
        from statistical_analysis import record_distance_analysis
        r = record_distance_analysis(_records(_sha256, 1))
        self.assertFalse(r["signal"])
        self.assertEqual(r["n_pairs"], 0)

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
        from statistical_analysis import entropy_thresholds
        last = None
        for n in (100, 150, 200, 300, 500, 750, 1000, 2000, 10000):
            bit_t, byte_t = entropy_thresholds(n)
            self.assertLessEqual(bit_t, 0.95, n)
            self.assertLessEqual(byte_t, 7.5, n)
            if last is not None:
                self.assertGreaterEqual(bit_t, last[0], n)     # monotone in N
                self.assertGreaterEqual(byte_t, last[1], n)
            if n >= 750:
                self.assertEqual((bit_t, byte_t), (0.95, 7.5), n)
            last = (bit_t, byte_t)

    def test_byte_threshold_sits_below_the_simulated_null(self):
        # Six sd below the tabulated null mean; a quick fresh simulation must
        # stay above it (the full check is experiments/small_n_thresholds.py).
        import random as _r
        from collections import Counter
        from statistical_analysis import entropy_thresholds
        rng = _r.Random(99)
        for n in (100, 200, 500):
            _, byte_t = entropy_thresholds(n)
            lowest = min(-sum(c / n * math.log2(c / n) for c in Counter(rng.randbytes(n)).values())
                         for _ in range(400))
            self.assertGreater(lowest, byte_t, n)

    def test_support_defect_is_caught_and_clean_is_not(self):
        # A digest byte restricted to 192 of 256 values has 7.58 bits of
        # entropy and passed v0.3's thresholds at every N; the coverage check
        # sees it from N = 500. A byte that merely drops one value at N = 3000
        # (0.2% of clean columns do) must not fire.
        import random as _r
        table = _r.Random(7).sample(range(256), 192)

        def support192(msg):
            h = bytearray(hashlib.sha256(msg.encode()).digest())
            h[0] = table[h[0] % 192]
            return bytes(h).hex()
        for seed in range(3):
            self.assertTrue(entropy_analysis(_records(support192, 1000, seed=seed))["support_signal"], seed)
        for seed in range(3):
            r = entropy_analysis(_records(_sha256, 3000, seed=seed))
            self.assertFalse(r["signal"], seed)

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
        # the multi-bit output masks use their own list (a cap reintroduced
        # there alone would have passed the 1×1 check -- second review)
        self.assertEqual(r["level_summary"]["3×1"]["tests"], 560 * 512)          # C(16,3) x 512
        self.assertEqual(r["level_summary"]["1×2"]["tests"], 16 * (512 * 511 // 2))
        self.assertFalse(r["signal"])

    def test_explicit_cap_still_honoured(self):
        r = linear_approximation_analysis(_sha512, n_samples=200, input_bytes=2, max_output_bits=64,
                                          max_multi_output_bits=64, rng=random.Random(0), verbose=False)
        self.assertEqual(r["n_output_bits"], 64)
        self.assertEqual(r["level_summary"]["3×1"]["tests"], 560 * 64)


if __name__ == "__main__":
    unittest.main()
