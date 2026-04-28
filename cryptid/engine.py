"""
Analysis engine — orchestrates the test battery and collects results.

Test levels:
  - quick:  Statistical suite + meta-learner only (~seconds)
  - standard: quick + differential profile (~minutes)
  - full:   standard + extended analysis + linear approximation (~10+ minutes)
"""

import json
import os
import sys
import time
import random
from pathlib import Path
from typing import Callable, Optional

# Add the src directory so we can import the analysis modules
_src_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "src")
if _src_dir not in sys.path:
    sys.path.insert(0, _src_dir)


def _load_meta_learner(model_path: str) -> dict:
    """Load the trained meta-learner model."""
    with open(model_path) as f:
        return json.load(f)


def _find_default_model() -> Optional[str]:
    """Find the default meta-learner model file."""
    candidates = [
        os.path.join(os.path.dirname(os.path.dirname(__file__)), "models", "meta_learner_v3_scale_invariant.json"),
        os.path.join(os.path.dirname(os.path.dirname(__file__)), "models", "meta_learner.json"),
    ]
    for path in candidates:
        if os.path.exists(path):
            return path
    return None


def run_statistical_suite(records: list[dict], verbose: bool = True) -> dict:
    """Run the 6-test statistical analysis suite on pre-computed records."""
    from statistical_analysis import run_full_analysis
    return run_full_analysis(records, verbose=verbose)


def run_meta_learner(stats_results: dict, model: dict, verbose: bool = True) -> dict:
    """Classify using the trained meta-learner."""
    from meta_learner import extract_features_from_stats, predict_logistic
    features = extract_features_from_stats(stats_results)
    prediction = predict_logistic(model, features)
    return prediction


def run_differential_profile(
    hash_fn: Callable,
    n_samples: int = 10000,
    input_bytes: int = 10,
    verbose: bool = True,
) -> dict:
    """Run the 4-test differential profile analysis."""
    from differential_profile import (
        single_bit_differential,
        byte_differential,
        hamming_distance_profile,
        differential_bit_independence,
    )

    rng = random.Random(42)
    results = {}

    if verbose:
        print("  Running single-bit differential...")
    results["single_bit"] = single_bit_differential(hash_fn, n_samples, input_bytes, rng=rng, verbose=verbose)

    if verbose:
        print("  Running byte differential...")
    results["byte_diff"] = byte_differential(hash_fn, n_samples, input_bytes, rng=rng, verbose=verbose)

    if verbose:
        print("  Running Hamming distance profile...")
    results["hamming"] = hamming_distance_profile(hash_fn, n_samples, input_bytes, rng=rng, verbose=verbose)

    if verbose:
        print("  Running differential bit independence...")
    results["bit_independence"] = differential_bit_independence(hash_fn, n_samples, input_bytes, rng=rng, verbose=verbose)

    # Aggregate signal — modules use "signal" or "signal_detected" for the boolean
    signals = []
    for key in ["single_bit", "byte_diff", "hamming", "bit_independence"]:
        if key in results:
            detected = results[key].get("signal_detected", results[key].get("signal", False))
            signals.append(detected)

    results["any_signal"] = any(signals)
    results["n_signals"] = sum(signals)

    return results


def run_extended_analysis(
    hash_fn: Callable,
    n_samples: int = 10000,
    input_bytes: int = 10,
    verbose: bool = True,
) -> dict:
    """Run extended analysis (near-collision, sequence correlation, cycle detection)."""
    from extended_analysis import (
        near_collision_analysis,
        sequence_correlation_analysis,
        cycle_detection,
    )

    rng = random.Random(42)
    results = {}

    if verbose:
        print("  Running near-collision analysis...")
    results["near_collision"] = near_collision_analysis(hash_fn, n_samples, input_bytes, rng=rng, verbose=verbose)

    if verbose:
        print("  Running sequence correlation analysis...")
    results["sequence"] = sequence_correlation_analysis(hash_fn, n_samples, input_bytes, rng=rng, verbose=verbose)

    if verbose:
        print("  Running cycle detection...")
    results["cycle"] = cycle_detection(hash_fn, n_starts=min(1000, n_samples // 10), verbose=verbose)

    # Aggregate — modules use "signal" for the boolean
    signals = []
    for key in ["near_collision", "sequence", "cycle"]:
        if key in results:
            detected = results[key].get("signal_detected", results[key].get("signal", False))
            signals.append(detected)

    results["any_signal"] = any(signals)
    results["n_signals"] = sum(signals)

    return results


def run_linear_approximation(
    hash_fn: Callable,
    n_samples: int = 10000,
    input_bytes: int = 10,
    verbose: bool = True,
) -> dict:
    """Run linear approximation testing."""
    from linear_approximation import linear_approximation_analysis
    rng = random.Random(42)
    return linear_approximation_analysis(hash_fn, n_samples, input_bytes, rng=rng, verbose=verbose)


class AuditResult:
    """Container for all analysis results with verdict computation."""

    def __init__(self, name: str):
        self.name = name
        self.output_bits: Optional[int] = None
        self.n_samples: int = 0
        self.stats: Optional[dict] = None
        self.meta_learner: Optional[dict] = None
        self.differential: Optional[dict] = None
        self.extended: Optional[dict] = None
        self.linear: Optional[dict] = None
        self.timings: dict = {}
        self.errors: list[str] = []

    @property
    def verdict(self) -> str:
        """Compute overall verdict: PASS, WARN, FAIL, or ERROR."""
        if self.errors and not any([self.stats, self.meta_learner]):
            return "ERROR"

        signals = []

        # Meta-learner is the primary classifier
        if self.meta_learner:
            prob = self.meta_learner.get("probability", 0)
            if prob >= 0.7:
                signals.append(("meta_learner", "FAIL", prob))
            elif prob >= 0.4:
                signals.append(("meta_learner", "WARN", prob))

        # Differential profile
        if self.differential and self.differential.get("any_signal"):
            n_sig = self.differential.get("n_signals", 0)
            if n_sig >= 2:
                signals.append(("differential", "FAIL", n_sig))
            else:
                signals.append(("differential", "WARN", n_sig))

        # Extended analysis
        if self.extended and self.extended.get("any_signal"):
            n_sig = self.extended.get("n_signals", 0)
            if n_sig >= 2:
                signals.append(("extended", "FAIL", n_sig))
            else:
                signals.append(("extended", "WARN", n_sig))

        # Linear approximation
        if self.linear and (self.linear.get("signal_detected") or self.linear.get("signal")):
            signals.append(("linear", "FAIL", self.linear.get("max_bias", 0)))

        if not signals:
            return "PASS"

        # Any FAIL → overall FAIL
        if any(s[1] == "FAIL" for s in signals):
            return "FAIL"

        return "WARN"

    @property
    def signal_sources(self) -> list[str]:
        """List which test batteries detected anomalies."""
        sources = []
        if self.meta_learner and self.meta_learner.get("probability", 0) >= 0.4:
            sources.append("statistical")
        if self.differential and self.differential.get("any_signal"):
            sources.append("differential")
        if self.extended and self.extended.get("any_signal"):
            sources.append("extended")
        if self.linear and (self.linear.get("signal_detected") or self.linear.get("signal")):
            sources.append("linear")
        return sources

    def to_dict(self) -> dict:
        """Serialize to dictionary."""
        return {
            "name": self.name,
            "verdict": self.verdict,
            "signal_sources": self.signal_sources,
            "output_bits": self.output_bits,
            "n_samples": self.n_samples,
            "meta_learner": self.meta_learner,
            "stats_summary": self._stats_summary(),
            "differential_summary": self._differential_summary(),
            "extended_summary": self._extended_summary(),
            "linear_summary": self._linear_summary(),
            "timings": self.timings,
            "errors": self.errors,
        }

    def _stats_summary(self) -> Optional[dict]:
        if not self.stats:
            return None
        summary = {}
        for test_name, test_result in self.stats.items():
            if isinstance(test_result, dict) and "signal_strength" in test_result:
                summary[test_name] = {
                    "signal": test_result["signal_strength"],
                    "detected": test_result.get("signal_detected", test_result["signal_strength"] > 0.1),
                }
        return summary

    def _differential_summary(self) -> Optional[dict]:
        if not self.differential:
            return None
        summary = {}
        for key in ["single_bit", "byte_diff", "hamming", "bit_independence"]:
            if key in self.differential:
                d = self.differential[key]
                summary[key] = {
                    "signal": d.get("signal_strength", 0),
                    "detected": d.get("signal_detected", d.get("signal", False)),
                }
        return summary

    def _extended_summary(self) -> Optional[dict]:
        if not self.extended:
            return None
        summary = {}
        for key in ["near_collision", "sequence", "cycle"]:
            if key in self.extended:
                d = self.extended[key]
                summary[key] = {
                    "signal": d.get("signal_strength", 0),
                    "detected": d.get("signal_detected", d.get("signal", False)),
                }
        return summary

    def _linear_summary(self) -> Optional[dict]:
        if not self.linear:
            return None
        return {
            "max_bias": self.linear.get("max_bias", 0),
            "detected": self.linear.get("signal_detected", self.linear.get("signal", False)),
            "n_significant": self.linear.get("n_significant", 0),
        }


def run_audit(
    records: list[dict] = None,
    hash_fn: Callable = None,
    name: str = "unknown",
    level: str = "standard",
    n_samples: int = 10000,
    input_bytes: int = 10,
    model_path: str = None,
    verbose: bool = True,
) -> AuditResult:
    """Run the full audit pipeline at the specified level.

    Args:
        records: Pre-computed input/output pairs (for statistical suite)
        hash_fn: Callable hash function str -> hex str (for differential/extended/linear)
        name: Human-readable name for this audit target
        level: "quick", "standard", or "full"
        n_samples: Number of samples for hash_fn-based tests
        input_bytes: Input size in bytes for generated test data
        model_path: Path to meta-learner model (auto-detected if None)
        verbose: Print progress
    """
    result = AuditResult(name)

    if records:
        result.n_samples = len(records)
        result.output_bits = len(records[0]["hash"]) * 4

    # --- Phase 1: Statistical suite + meta-learner (always runs) ---
    if records:
        if verbose:
            print(f"\n{'='*60}")
            print(f"  Phase 1: Statistical Suite")
            print(f"{'='*60}")

        t0 = time.time()
        try:
            result.stats = run_statistical_suite(records, verbose=verbose)
        except Exception as e:
            result.errors.append(f"Statistical suite error: {e}")
            if verbose:
                print(f"  ERROR: {e}", file=sys.stderr)
        result.timings["statistical"] = time.time() - t0

        # Meta-learner classification
        if result.stats:
            if model_path is None:
                model_path = _find_default_model()
            if model_path:
                try:
                    model = _load_meta_learner(model_path)
                    result.meta_learner = run_meta_learner(result.stats, model, verbose=verbose)
                    if verbose:
                        prob = result.meta_learner.get("probability", 0)
                        label = result.meta_learner.get("predicted_label", "?")
                        print(f"\n  Meta-learner: P(weakened) = {prob:.3f} → {label}")
                except Exception as e:
                    result.errors.append(f"Meta-learner error: {e}")
            else:
                result.errors.append("No meta-learner model found")

    if level == "quick":
        return result

    # --- Phase 2: Differential profile ---
    if hash_fn:
        if verbose:
            print(f"\n{'='*60}")
            print(f"  Phase 2: Differential Profile")
            print(f"{'='*60}")

        t0 = time.time()
        try:
            result.differential = run_differential_profile(
                hash_fn, n_samples, input_bytes, verbose=verbose
            )
        except Exception as e:
            result.errors.append(f"Differential profile error: {e}")
            if verbose:
                print(f"  ERROR: {e}", file=sys.stderr)
        result.timings["differential"] = time.time() - t0

    if level == "standard":
        return result

    # --- Phase 3: Extended analysis + linear approximation ---
    if hash_fn and level == "full":
        if verbose:
            print(f"\n{'='*60}")
            print(f"  Phase 3: Extended Analysis")
            print(f"{'='*60}")

        t0 = time.time()
        try:
            result.extended = run_extended_analysis(
                hash_fn, n_samples, input_bytes, verbose=verbose
            )
        except Exception as e:
            result.errors.append(f"Extended analysis error: {e}")
            if verbose:
                print(f"  ERROR: {e}", file=sys.stderr)
        result.timings["extended"] = time.time() - t0

        if verbose:
            print(f"\n{'='*60}")
            print(f"  Phase 4: Linear Approximation")
            print(f"{'='*60}")

        t0 = time.time()
        try:
            result.linear = run_linear_approximation(
                hash_fn, n_samples, input_bytes, verbose=verbose
            )
        except Exception as e:
            result.errors.append(f"Linear approximation error: {e}")
            if verbose:
                print(f"  ERROR: {e}", file=sys.stderr)
        result.timings["linear"] = time.time() - t0

    return result
