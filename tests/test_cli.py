"""
Regression tests for the command-line surface: exit codes and verdicts.

Every test here corresponds to a fail-open found in the v0.3 cross-model
review (docs/REVIEW-2.md): `kat` reporting PASS for an implementation that
could not be run, `compare` exiting 0 with nothing compared, `test` printing
PASS above a SIGNAL row when the classifier was skipped, and unusable input
lines being dropped silently. Standard library only; run with

    python -m unittest discover -s tests -v
"""

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLI = os.path.join(ROOT, "cryptid.py")
PY = sys.executable

# A correct SHA-256 as an external command, a wrong one, and ones that fail.
SHA256_CMD = f'{PY} -c "import sys,hashlib; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())"'
SHA1_CMD = f'{PY} -c "import sys,hashlib; print(hashlib.sha1(sys.stdin.buffer.read()).hexdigest())"'
ALWAYS_FAILS_CMD = f'{PY} -c "import sys; sys.exit(1)"'
FAILS_ON_EMPTY_CMD = (f'{PY} -c "import sys,hashlib; d=sys.stdin.buffer.read(); '
                      f'sys.exit(1) if not d else print(hashlib.sha256(d).hexdigest())"')


def run(*args, timeout=600):
    """Run the CLI, return (exit code, stdout, stderr)."""
    p = subprocess.run([PY, CLI, *args], capture_output=True, text=True, timeout=timeout, cwd=ROOT)
    return p.returncode, p.stdout, p.stderr


def run_json(*args, timeout=600):
    code, out, err = run(*args, "--json", timeout=timeout)
    try:
        return code, json.loads(out), err
    except json.JSONDecodeError:
        raise AssertionError(f"--json output was not JSON (exit {code}):\n{out}\n{err}")


def write_jsonl(path, records):
    with open(path, "w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")


def sha256_records(messages):
    return [{"plaintext": m, "hash": hashlib.sha256(m.encode()).hexdigest()} for m in messages]


class KatTests(unittest.TestCase):
    """kat must never say PASS about an implementation it could not run."""

    def test_failing_command_is_error_not_pass(self):
        code, d, _ = run_json("kat", "-a", "sha256", "--command", ALWAYS_FAILS_CMD)
        self.assertEqual(d["verdict"], "ERROR")
        self.assertEqual(code, 3)
        self.assertEqual(d["checked"], 0)
        self.assertGreater(len(d["errors"]), 0)
        # the reference's own vector check must not be pooled with external checks
        self.assertGreaterEqual(d["reference_checks"], 1)

    def test_partial_failure_is_error(self):
        code, d, _ = run_json("kat", "-a", "sha256", "--command", FAILS_ON_EMPTY_CMD)
        self.assertEqual(d["verdict"], "ERROR")
        self.assertEqual(code, 3)
        self.assertEqual(len(d["errors"]), 1)
        self.assertEqual(d["mismatches"], [])

    def test_no_target_is_a_usage_error(self):
        code, out, err = run("kat", "-a", "sha256")
        self.assertEqual(code, 1)
        self.assertIn("--command", err)

    def test_self_check_is_explicit_and_labelled(self):
        code, d, _ = run_json("kat", "-a", "sha256", "--self-check")
        self.assertEqual(code, 0)
        self.assertEqual(d["mode"], "self-check")
        self.assertEqual(d["checked"], 0)
        self.assertIn("no external implementation", d["reason"])

    def test_self_check_without_vectors_is_error(self):
        code, d, _ = run_json("kat", "-a", "sha224", "--self-check")
        self.assertEqual(code, 3)
        self.assertEqual(d["verdict"], "ERROR")

    def test_correct_command_passes(self):
        code, d, _ = run_json("kat", "-a", "sha256", "--command", SHA256_CMD)
        self.assertEqual((code, d["verdict"]), (0, "PASS"))
        self.assertEqual(d["errors"], [])
        self.assertGreaterEqual(d["checked"], 20)

    def test_wrong_algorithm_fails(self):
        code, d, _ = run_json("kat", "-a", "sha256", "--command", SHA1_CMD)
        self.assertEqual((code, d["verdict"]), (2, "FAIL"))
        self.assertEqual(len(d["mismatches"]), d["checked"])

    def test_file_mode_detects_one_bad_record(self):
        with tempfile.TemporaryDirectory() as tmp:
            recs = sha256_records([f"msg{i}" for i in range(20)])
            recs[7]["hash"] = "0" * 64
            path = os.path.join(tmp, "out.jsonl")
            write_jsonl(path, recs)
            code, d, _ = run_json("kat", "-a", "sha256", "-i", path)
            self.assertEqual((code, d["verdict"]), (2, "FAIL"))
            self.assertEqual(len(d["mismatches"]), 1)
            self.assertEqual(d["checked"], 20)


class CompareTests(unittest.TestCase):
    """compare must not exit 0 when it compared nothing."""

    def test_no_shared_inputs_is_inconclusive(self):
        with tempfile.TemporaryDirectory() as tmp:
            a, b = os.path.join(tmp, "a.jsonl"), os.path.join(tmp, "b.jsonl")
            write_jsonl(a, sha256_records(["aa"]))
            write_jsonl(b, sha256_records(["bb"]))
            code, d, _ = run_json("compare", "--target", a, "--reference", b)
            self.assertEqual(d["verdict"], "INCONCLUSIVE")
            self.assertEqual(d["output_comparison"]["shared_inputs"], 0)
            self.assertEqual(code, 3)

    def test_identical_outputs_pass_and_mismatch_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            recs = sha256_records([f"m{i}" for i in range(50)])
            a, b, c = (os.path.join(tmp, n) for n in ("a.jsonl", "b.jsonl", "c.jsonl"))
            write_jsonl(a, recs)
            write_jsonl(b, recs)
            bad = [dict(r) for r in recs]
            bad[3]["hash"] = "f" * 64
            write_jsonl(c, bad)
            code, d, _ = run_json("compare", "--target", a, "--reference", b)
            self.assertEqual((code, d["verdict"]), (0, "PASS"))
            self.assertEqual(d["output_comparison"]["shared_inputs"], 50)
            code, d, _ = run_json("compare", "--target", c, "--reference", b)
            self.assertEqual((code, d["verdict"]), (2, "FAIL"))
            self.assertEqual(d["output_comparison"]["mismatches"], 1)


class TestVerdictTests(unittest.TestCase):
    """The verdict must agree with the rows under it."""

    def assert_verdict_consistent(self, d):
        detected = [k for k, v in (d.get("stats_summary") or {}).items() if v.get("detected")]
        if detected:
            self.assertNotEqual(d["verdict"], "PASS",
                                f"PASS printed above SIGNAL rows: {detected}")

    def test_small_n_signal_is_not_pass(self):
        # adler32's entropy and bit-correlation failures are gross enough to
        # show at 200 samples; with the classifier skipped they must still count.
        code, d, _ = run_json("test", "-a", "adler32", "-n", "200", "--level", "quick")
        self.assertTrue(d["classifier_skipped"])
        self.assertEqual(d["verdict"], "WARN")
        self.assertEqual(code, 1)
        self.assert_verdict_consistent(d)

    def test_small_n_clean_function_is_pass_with_note(self):
        code, d, _ = run_json("test", "-a", "sha256", "-n", "200", "--level", "quick")
        self.assertEqual(d["verdict"], "PASS")
        self.assertTrue(d["classifier_skipped"])
        self.assertTrue(any("unclassified" in n for n in d["notes"]))
        self.assert_verdict_consistent(d)

    def test_small_n_entropy_not_flagged_on_clean_function(self):
        # The fixed 7.5-bit byte-entropy threshold flagged every correct
        # function at N=200 (log2(200) = 7.64 is the most a byte can show).
        for algo in ("sha256", "sha3_256", "siphash24"):
            _, d, _ = run_json("test", "-a", algo, "-n", "200", "--level", "quick")
            self.assertFalse(d["stats_summary"]["entropy"]["flagged"], algo)

    def test_classifier_path_unchanged(self):
        code, d, _ = run_json("test", "-a", "sha256", "-n", "2000", "--level", "quick")
        self.assertEqual((code, d["verdict"]), (0, "PASS"))
        self.assertFalse(d["classifier_skipped"])
        self.assertLess(d["meta_learner"]["probability"], d["meta_learner"]["threshold"])


class InputHandlingTests(unittest.TestCase):
    """Unusable lines are an error unless the caller opts in, and are then reported."""

    def _file_with_bad_lines(self, tmp):
        path = os.path.join(tmp, "mixed.jsonl")
        with open(path, "w") as f:
            for r in sha256_records([f"m{i}" for i in range(30)]):
                f.write(json.dumps(r) + "\n")
            f.write('{"plaintext": "x", "nohash": 1}\n')
            f.write("this is not json\n")
        return path

    def test_malformed_lines_are_an_error_by_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, out, err = run("test", "-i", self._file_with_bad_lines(tmp), "--level", "quick", "-q")
            self.assertEqual(code, 3)
            self.assertIn("2 unusable line", err)
            self.assertIn("--skip-malformed", err)

    def test_skip_malformed_runs_and_reports(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, d, _ = run_json("test", "-i", self._file_with_bad_lines(tmp), "--level", "quick",
                                  "--skip-malformed")
            self.assertEqual(d["n_samples"], 30)
            self.assertTrue(any("2 unusable input line" in n for n in d["notes"]))

    def test_inconsistent_digest_lengths_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            recs = sha256_records([f"m{i}" for i in range(30)])
            recs[4]["hash"] = recs[4]["hash"][2:]  # an unpadded 31-byte digest
            path = os.path.join(tmp, "lengths.jsonl")
            write_jsonl(path, recs)
            code, out, err = run("test", "-i", path, "--level", "quick", "-q")
            self.assertEqual(code, 3)
            self.assertIn("inconsistent digest lengths", err)


if __name__ == "__main__":
    unittest.main()
