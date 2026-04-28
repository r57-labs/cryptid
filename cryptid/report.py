"""
Report formatting for cryptid results.

Supports:
  - Terminal output (colored, human-readable)
  - JSON output (machine-readable)
  - Comparison reports (two implementations side by side)
"""

import json
import sys
from typing import Optional


# --- ANSI Colors ---

class Colors:
    """ANSI color codes. Disabled if output is not a terminal."""
    _enabled = sys.stdout.isatty()

    @classmethod
    def enable(cls):
        cls._enabled = True

    @classmethod
    def disable(cls):
        cls._enabled = False

    @classmethod
    def _wrap(cls, code: str, text: str) -> str:
        if cls._enabled:
            return f"\033[{code}m{text}\033[0m"
        return text

    @classmethod
    def green(cls, text: str) -> str:
        return cls._wrap("32", text)

    @classmethod
    def yellow(cls, text: str) -> str:
        return cls._wrap("33", text)

    @classmethod
    def red(cls, text: str) -> str:
        return cls._wrap("31", text)

    @classmethod
    def bold(cls, text: str) -> str:
        return cls._wrap("1", text)

    @classmethod
    def dim(cls, text: str) -> str:
        return cls._wrap("2", text)

    @classmethod
    def cyan(cls, text: str) -> str:
        return cls._wrap("36", text)


def verdict_color(verdict: str) -> str:
    """Color a verdict string."""
    if verdict == "PASS":
        return Colors.green(verdict)
    elif verdict == "WARN":
        return Colors.yellow(verdict)
    elif verdict == "FAIL":
        return Colors.red(verdict)
    elif verdict == "ERROR":
        return Colors.red(verdict)
    return verdict


def signal_indicator(detected: bool) -> str:
    """Return a colored signal indicator."""
    if detected:
        return Colors.red("SIGNAL")
    return Colors.green("clean")


# --- Terminal Report ---

def print_header(name: str, n_samples: int, output_bits: Optional[int], level: str):
    """Print the report header."""
    print()
    print(Colors.bold(f"  cryptid report: {name}"))
    print(f"  {'─' * 56}")
    details = []
    if n_samples:
        details.append(f"{n_samples:,} samples")
    if output_bits:
        details.append(f"{output_bits}-bit output")
    details.append(f"level={level}")
    print(f"  {' | '.join(details)}")
    print()


def print_verdict(result) -> None:
    """Print the overall verdict banner."""
    verdict = result.verdict
    v_colored = verdict_color(verdict)

    if verdict == "PASS":
        msg = "No anomalies detected"
    elif verdict == "WARN":
        msg = f"Potential anomalies in: {', '.join(result.signal_sources)}"
    elif verdict == "FAIL":
        msg = f"Anomalies detected in: {', '.join(result.signal_sources)}"
    else:
        msg = "Analysis incomplete due to errors"

    box_width = 58
    print(f"  ┌{'─' * box_width}┐")
    inner = f"  Verdict: {verdict}  —  {msg}"
    # Can't easily measure ANSI-colored string width, so use uncolored for padding
    inner_plain = f"  Verdict: {verdict}  —  {msg}"
    pad = box_width - len(inner_plain)
    # Print with color
    print(f"  │  Verdict: {v_colored}  —  {msg}{' ' * max(0, pad)}│")
    print(f"  └{'─' * box_width}┘")
    print()


def print_statistical_results(result) -> None:
    """Print statistical suite results."""
    if not result.stats:
        return

    print(Colors.bold("  Statistical Suite"))
    print(f"  {'─' * 40}")

    test_names = {
        "bit_correlation": "Bit correlation",
        "entropy": "Output entropy",
        "avalanche": "Avalanche effect",
        "frequency": "Byte frequency",
        "mutual_information": "Mutual information",
        "interaction": "Multi-byte interaction",
    }

    for key, display in test_names.items():
        if key in result.stats:
            test = result.stats[key]
            sig = test.get("signal_strength", 0)
            detected = sig > 0.1

            indicator = signal_indicator(detected)
            sig_str = f"{sig:.3f}" if sig > 0 else "0.000"

            print(f"    {display:<25} {indicator:<14} (signal: {sig_str})")

    if result.meta_learner:
        prob = result.meta_learner.get("probability", 0)
        label = result.meta_learner.get("predicted_label", "?")
        threshold = result.meta_learner.get("threshold", 0.4)

        print()
        p_str = f"{prob:.3f}"
        if label == "weakened":
            p_colored = Colors.red(p_str)
        elif prob >= threshold * 0.8:
            p_colored = Colors.yellow(p_str)
        else:
            p_colored = Colors.green(p_str)

        print(f"    {'Meta-learner':<25} P(weakened) = {p_colored}")

    elapsed = result.timings.get("statistical", 0)
    if elapsed:
        print(f"    {Colors.dim(f'({elapsed:.1f}s)')}")
    print()


def print_differential_results(result) -> None:
    """Print differential profile results."""
    if not result.differential:
        return

    print(Colors.bold("  Differential Profile"))
    print(f"  {'─' * 40}")

    test_names = {
        "single_bit": "Single-bit differential",
        "byte_diff": "Byte differential",
        "hamming": "Hamming distance profile",
        "bit_independence": "Bit independence",
    }

    for key, display in test_names.items():
        if key in result.differential:
            test = result.differential[key]
            sig = test.get("signal_strength", 0)
            detected = test.get("signal_detected", test.get("signal", False))

            indicator = signal_indicator(detected)
            sig_str = f"{sig:.3f}" if sig > 0 else "0.000"

            print(f"    {display:<25} {indicator:<14} (signal: {sig_str})")

    elapsed = result.timings.get("differential", 0)
    if elapsed:
        print(f"    {Colors.dim(f'({elapsed:.1f}s)')}")
    print()


def print_extended_results(result) -> None:
    """Print extended analysis results."""
    if not result.extended:
        return

    print(Colors.bold("  Extended Analysis"))
    print(f"  {'─' * 40}")

    test_names = {
        "near_collision": "Near-collision frequency",
        "sequence": "Sequence correlation",
        "cycle": "Cycle detection",
    }

    for key, display in test_names.items():
        if key in result.extended:
            test = result.extended[key]
            sig = test.get("signal_strength", 0)
            detected = test.get("signal_detected", test.get("signal", False))

            indicator = signal_indicator(detected)
            sig_str = f"{sig:.3f}" if sig > 0 else "0.000"

            print(f"    {display:<25} {indicator:<14} (signal: {sig_str})")

    elapsed = result.timings.get("extended", 0)
    if elapsed:
        print(f"    {Colors.dim(f'({elapsed:.1f}s)')}")
    print()


def print_linear_results(result) -> None:
    """Print linear approximation results."""
    if not result.linear:
        return

    print(Colors.bold("  Linear Approximation"))
    print(f"  {'─' * 40}")

    detected = result.linear.get("signal_detected", result.linear.get("signal", False))
    max_bias = result.linear.get("max_bias", 0)
    n_sig = result.linear.get("n_significant", 0)
    n_tested = result.linear.get("n_tested", 0)

    indicator = signal_indicator(detected)
    print(f"    {'Overall':<25} {indicator:<14} (max bias: {max_bias:.4f})")

    if n_tested:
        print(f"    Masks tested: {n_tested:,}  |  Significant: {n_sig}")

    elapsed = result.timings.get("linear", 0)
    if elapsed:
        print(f"    {Colors.dim(f'({elapsed:.1f}s)')}")
    print()


def print_errors(result) -> None:
    """Print any errors encountered."""
    if not result.errors:
        return

    print(Colors.bold("  Errors"))
    print(f"  {'─' * 40}")
    for err in result.errors:
        print(f"    {Colors.red('!')} {err}")
    print()


def print_report(result, level: str = "standard") -> None:
    """Print the full terminal report."""
    print_header(result.name, result.n_samples, result.output_bits, level)
    print_verdict(result)
    print_statistical_results(result)
    print_differential_results(result)
    print_extended_results(result)
    print_linear_results(result)
    print_errors(result)

    # Total time
    total = sum(result.timings.values())
    if total:
        print(f"  {Colors.dim(f'Total time: {total:.1f}s')}")
    print()


def print_comparison_report(result_a, result_b, level: str = "standard") -> None:
    """Print a side-by-side comparison of two audit results."""
    print()
    print(Colors.bold(f"  cryptid comparison"))
    print(f"  {'─' * 56}")
    print(f"    A: {result_a.name}")
    print(f"    B: {result_b.name}")
    print()

    va = verdict_color(result_a.verdict)
    vb = verdict_color(result_b.verdict)
    print(f"    {'Verdict':<25}  A: {va:<14}  B: {vb}")
    print()

    # Compare statistical signals
    if result_a.stats and result_b.stats:
        print(Colors.bold("  Statistical Suite"))
        print(f"  {'─' * 56}")
        test_names = {
            "bit_correlation": "Bit correlation",
            "entropy": "Output entropy",
            "avalanche": "Avalanche effect",
            "frequency": "Byte frequency",
            "mutual_information": "Mutual information",
            "interaction": "Multi-byte interaction",
        }

        for key, display in test_names.items():
            sig_a = result_a.stats.get(key, {}).get("signal_strength", 0)
            sig_b = result_b.stats.get(key, {}).get("signal_strength", 0)
            diff = abs(sig_a - sig_b)
            diff_indicator = Colors.red(f" Δ={diff:.3f}") if diff > 0.05 else ""
            print(f"    {display:<22}  A: {sig_a:.3f}  B: {sig_b:.3f}{diff_indicator}")
        print()

    # Overall divergence assessment
    if result_a.meta_learner and result_b.meta_learner:
        pa = result_a.meta_learner.get("probability", 0)
        pb = result_b.meta_learner.get("probability", 0)
        diff = abs(pa - pb)
        if diff > 0.2:
            print(f"  {Colors.red('!')} Significant behavioral divergence detected (ΔP = {diff:.3f})")
        elif diff > 0.05:
            print(f"  {Colors.yellow('~')} Minor behavioral difference (ΔP = {diff:.3f})")
        else:
            print(f"  {Colors.green('✓')} Implementations behave consistently (ΔP = {diff:.3f})")
        print()


def to_json(result, indent: int = 2) -> str:
    """Serialize an AuditResult to JSON."""
    return json.dumps(result.to_dict(), indent=indent, default=str)
