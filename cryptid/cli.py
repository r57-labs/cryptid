#!/usr/bin/env python3
"""
cryptid — black-box cryptographic hash assessment toolkit.

Usage:
  cryptid test --input samples.jsonl [--level full]
  cryptid test --algorithm sha256 --samples 50000 [--level full]
  cryptid test --command "openssl dgst -sha256 -hex" --samples 10000
  cryptid generate --algorithm sha256 --samples 10000 --output samples.jsonl
  cryptid compare --target device.jsonl --reference openssl.jsonl
  cryptid list-algorithms

Examples:
  # Test a JSONL file of input/output pairs
  cryptid test -i my_hashes.jsonl

  # Test a built-in algorithm (useful for verification / demo)
  cryptid test -a sha256 -n 50000 --level full

  # Generate test vectors for later analysis
  cryptid generate -a sha256 -n 100000 -o sha256_vectors.jsonl

  # Compare two implementations
  cryptid compare --target hsm_output.jsonl --reference openssl_output.jsonl

  # JSON output for scripting
  cryptid test -i samples.jsonl --json
"""

import argparse
import json
import os
import sys
import time

# Ensure the package and src directories are importable
_pkg_dir = os.path.dirname(os.path.abspath(__file__))
_project_dir = os.path.dirname(_pkg_dir)
_src_dir = os.path.join(_project_dir, "src")

if _pkg_dir not in sys.path:
    sys.path.insert(0, _pkg_dir)
if _src_dir not in sys.path:
    sys.path.insert(0, _src_dir)

from input_handler import (
    InputFormatError,
    load_input,
    generate_from_command,
    generate_plaintexts,
    make_hash_fn_from_records,
    make_hash_fn_from_command,
    detect_output_width,
)
from engine import run_audit, AuditResult, MIN_RECORDS
from report import print_report, print_comparison_report, to_json, Colors


# The record floor lives in the engine (engine.MIN_RECORDS); the CLI checks
# it early only to give a cleaner message before generating anything.


def _positive_int(text: str) -> int:
    """argparse type for -n: v0.3 accepted -1 (an empty run reported PASS)
    and treated 0 as 'use the default' without saying so."""
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text!r} is not an integer")
    if value < 1:
        raise argparse.ArgumentTypeError(f"sample count must be at least 1, got {value}")
    return value


def _require_records(records, source: str, verbose: bool):
    """Exit 3 unless there are enough records for the statistical suite."""
    if len(records) < MIN_RECORDS:
        print(f"Error: {source}: {len(records):,} record(s); the statistical suite needs at least "
              f"{MIN_RECORDS:,} (the classifier 2,000). Nothing was tested.", file=sys.stderr)
        sys.exit(3)


def _resolve_model_path(args_model: str = None) -> str:
    """Find the meta-learner model."""
    if args_model:
        return args_model

    candidates = [
        os.path.join(_project_dir, "models", "meta_learner_v4.json"),
        os.path.join(_project_dir, "models", "meta_learner_v3_scale_invariant.json"),
    ]
    for path in candidates:
        if os.path.exists(path):
            return path

    print("Warning: no meta-learner model found. Statistical classification disabled.",
          file=sys.stderr)
    return None


def _get_builtin_hash_fn(algorithm: str):
    """Get a built-in hash function by name."""
    from generate_dataset import HASH_FUNCTIONS
    if algorithm not in HASH_FUNCTIONS:
        print(f"Error: unknown algorithm '{algorithm}'", file=sys.stderr)
        print(f"Available: {', '.join(sorted(HASH_FUNCTIONS.keys()))}", file=sys.stderr)
        sys.exit(1)
    return HASH_FUNCTIONS[algorithm]


def _generate_records(hash_fn, n_samples: int, input_bytes: int = 10, verbose: bool = True):
    """Generate input/output records using a hash function.

    Uses the toolkit's standard mixed text distribution (generate_plaintexts);
    the hash function sees each plaintext's UTF-8 bytes.
    """
    import random
    rng = random.Random(42)

    if verbose:
        print(f"  Generating {n_samples:,} test vectors...")

    plaintexts = generate_plaintexts(n_samples, rng, input_bytes)
    return [{"plaintext": pt, "hash": hash_fn(pt)} for pt in plaintexts]


# --- Subcommands ---

def cmd_test(args):
    """Run the test battery on a hash function or dataset."""
    verbose = not args.quiet
    json_output = args.json

    if json_output:
        verbose = False
        Colors.disable()

    model_path = _resolve_model_path(getattr(args, "model", None))

    records = None
    hash_fn = None
    name = "unknown"

    # Sample size guidance
    if args.samples and args.samples < 2000 and verbose:
        print(f"  Note: {args.samples} samples — meta-learner requires 2000+ and will be skipped.")

    # Determine input source
    load_report = {}
    if args.input:
        # Load from file
        if verbose:
            print(f"\n  Loading: {args.input}")
        try:
            records = load_input(args.input, skip_malformed=args.skip_malformed, report=load_report)
        except (InputFormatError, OSError) as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(3)
        name = os.path.splitext(os.path.basename(args.input))[0]
        if verbose:
            print(f"  Loaded {len(records):,} records ({detect_output_width(records)}-bit output)")
            if load_report.get("skipped"):
                print(f"  Skipped {load_report['skipped']:,} unusable line(s) (--skip-malformed)")
            if load_report.get("duplicates_removed"):
                print(f"  Collapsed {load_report['duplicates_removed']:,} repeated row(s) to one each")
        _require_records(records, os.path.basename(args.input), verbose)

    elif args.algorithm:
        # Use built-in algorithm
        name = args.algorithm
        hash_fn = _get_builtin_hash_fn(args.algorithm)
        n = args.samples if args.samples is not None else 10000
        _require_records(range(n), f"-n {n}", verbose)
        records = _generate_records(hash_fn, n, verbose=verbose)

    elif args.command:
        # Use external command
        name = args.command.split()[0] if args.command else "external"
        n = args.samples if args.samples is not None else 10000
        _require_records(range(n), f"-n {n}", verbose)
        records = generate_from_command(args.command, n, verbose=verbose)
        hash_fn = make_hash_fn_from_command(args.command)

    else:
        print("Error: specify --input, --algorithm, or --command", file=sys.stderr)
        sys.exit(1)

    # If we have records but no hash_fn, and level needs it, try to build one
    if records and not hash_fn and args.level != "quick":
        if args.algorithm:
            hash_fn = _get_builtin_hash_fn(args.algorithm)
        else:
            # For file-based input, we need a callable for differential tests
            # This only works if we can re-hash the inputs
            if verbose:
                print("  Note: differential/extended tests require a callable hash function.")
                print("  Use --algorithm or --command for full analysis. Running statistical suite only.")
            args.level = "quick"

    # Run the audit
    result = run_audit(
        records=records,
        hash_fn=hash_fn,
        name=name,
        level=args.level,
        n_samples=args.samples if args.samples is not None else len(records),
        model_path=model_path,
        verbose=verbose,
    )
    if load_report.get("skipped"):
        result.notes.append(f"{load_report['skipped']:,} unusable input line(s) were skipped at your request; "
                            f"the verdict covers the {load_report['records']:,} records that loaded")
    if load_report.get("duplicates_removed"):
        result.notes.append(f"{load_report['duplicates_removed']:,} repeated row(s) were collapsed: a repeated "
                            f"input is the same sample twice, not evidence about the function")

    # Output
    if json_output:
        print(to_json(result))
    else:
        print_report(result, level=args.level)

    # Exit code: 0=pass, 1=warn, 2=fail, 3=error
    exit_codes = {"PASS": 0, "WARN": 1, "FAIL": 2, "ERROR": 3}
    sys.exit(exit_codes.get(result.verdict, 3))


def cmd_generate(args):
    """Generate test vectors for later analysis."""
    verbose = not args.quiet

    hash_fn = _get_builtin_hash_fn(args.algorithm)
    n = args.samples

    records = _generate_records(hash_fn, n, verbose=verbose)

    output_path = args.output
    if verbose:
        print(f"  Writing {len(records):,} records to {output_path}")

    with open(output_path, "w") as f:
        for rec in records:
            f.write(json.dumps(rec) + "\n")

    if verbose:
        width = detect_output_width(records)
        print(f"  Done. {width}-bit output, {os.path.getsize(output_path):,} bytes.")


def cmd_compare(args):
    """Compare two hash implementations."""
    verbose = not args.quiet
    json_output = args.json

    if json_output:
        verbose = False
        Colors.disable()

    model_path = _resolve_model_path(getattr(args, "model", None))

    try:
        if verbose:
            print(f"\n  Loading target: {args.target}")
        records_a = load_input(args.target, allow_conflicts=True)
        name_a = os.path.splitext(os.path.basename(args.target))[0]

        if verbose:
            print(f"  Loading reference: {args.reference}")
        records_b = load_input(args.reference, allow_conflicts=True)
        name_b = os.path.splitext(os.path.basename(args.reference))[0]
    except (InputFormatError, OSError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(3)

    if verbose:
        print(f"  Target:    {len(records_a):,} records")
        print(f"  Reference: {len(records_b):,} records")

    # Per-file statistical summaries, only when there is enough data for
    # them to mean anything (v0.3 ran the suite on one-record files).
    def _audit(records, name):
        if len(records) < MIN_RECORDS:
            r = AuditResult(name)
            r.n_samples = len(records)
            r.output_bits = len(records[0]["hash"]) * 4 if records else None
            r.notes.append(f"statistical summary skipped: {len(records):,} records < {MIN_RECORDS:,}")
            return r
        return run_audit(records=records, name=name, level="quick", model_path=model_path, verbose=verbose)

    result_a = _audit(records_a, f"target ({name_a})")
    result_b = _audit(records_b, f"reference ({name_b})")

    # Direct output comparison on shared inputs (the faithfulness check)
    divergence = _check_output_divergence(records_a, records_b)
    if divergence["conflicts"]["target"] or divergence["conflicts"]["reference"]:
        # A file that gives one input two different digests is a failed
        # implementation (or a corrupt file) whatever the other file says.
        # v0.3 kept the last row and could report PASS (second review).
        divergence["verdict"] = "FAIL"
    elif divergence["shared_inputs"] == 0:
        divergence["verdict"] = "INCONCLUSIVE"
    elif divergence["mismatches"] > 0:
        divergence["verdict"] = "FAIL"
    else:
        divergence["verdict"] = "PASS"

    # Output
    if json_output:
        comparison = {
            "target": result_a.to_dict(),
            "reference": result_b.to_dict(),
            "output_comparison": divergence,
            "verdict": divergence["verdict"],
        }
        print(json.dumps(comparison, indent=2, default=str))
    else:
        print_comparison_report(result_a, result_b)
        _print_output_divergence(divergence, verbose)

    # Exit code: mismatching outputs on shared inputs is a failure (2); no
    # shared inputs means nothing was compared, which is an error (3), not a
    # pass. v0.2 exited 0 in that case (found in the v0.3 review).
    if divergence["verdict"] == "FAIL":
        sys.exit(2)
    if divergence["verdict"] == "INCONCLUSIVE":
        sys.exit(3)


def _digests_by_input(records: list) -> tuple[dict, list]:
    """Map plaintext -> set of digests; also return inputs with more than one digest."""
    table = {}
    for rec in records:
        table.setdefault(rec["plaintext"], set()).add(rec["hash"])
    conflicts = [pt for pt, hs in table.items() if len(hs) > 1]
    return table, conflicts


def _check_output_divergence(records_a: list, records_b: list) -> dict:
    """Compare outputs of the two datasets on the inputs they share.

    Repeated inputs with the same digest are one input; repeated inputs with
    different digests are reported as conflicts for that file, and any shared
    input with a conflict on either side counts as a mismatch.
    """
    table_a, conflicts_a = _digests_by_input(records_a)
    table_b, conflicts_b = _digests_by_input(records_b)

    mismatches = 0
    checked = 0
    examples = []
    for pt, digests_a in table_a.items():
        if pt in table_b:
            checked += 1
            digests_b = table_b[pt]
            if digests_a != digests_b or len(digests_a) > 1:
                mismatches += 1
                if len(examples) < 3:
                    examples.append({"plaintext": pt, "target": sorted(digests_a)[0],
                                     "reference": sorted(digests_b)[0]})

    return {
        "shared_inputs": checked,
        "mismatches": mismatches,
        "mismatch_pct": (mismatches / checked * 100) if checked else None,
        "examples": examples,
        "conflicts": {"target": len(conflicts_a), "reference": len(conflicts_b),
                      "examples": {"target": conflicts_a[:3], "reference": conflicts_b[:3]}},
    }


def _print_output_divergence(div: dict, verbose: bool):
    checked, mismatches = div["shared_inputs"], div["mismatches"]
    for side in ("target", "reference"):
        n_conf = div["conflicts"][side]
        if n_conf:
            ex = div["conflicts"]["examples"][side][0]
            print(f"\n  {Colors.red('!')} The {side} file gives {n_conf:,} input(s) more than one digest "
                  f"(e.g. {ex[:24]!r}); an implementation that is not a function of its input has failed, "
                  f"or the file is corrupt.")
    if checked == 0:
        print(f"  {Colors.red('INCONCLUSIVE')} — the two files share no inputs, so no outputs were compared.")
        print("  Hash the same inputs with both implementations (cryptid generate, then run each on the plaintexts).")
    elif mismatches > 0:
        print(f"\n  {Colors.red('!')} Output mismatch: {mismatches:,}/{checked:,} ({div['mismatch_pct']:.1f}%) of shared inputs differ")
        print(f"  This indicates the implementations are NOT equivalent.")
        for ex in div["examples"]:
            t, r = ex["target"], ex["reference"]
            first_diff = next((i for i, (a, b) in enumerate(zip(t, r)) if a != b), min(len(t), len(r)))
            print(f"    {ex['plaintext']!r}: digests first differ at hex position {first_diff} "
                  f"(target …{t[first_diff:first_diff+8]}, reference …{r[first_diff:first_diff+8]})")
    else:
        print(f"\n  {Colors.green('✓')} All {checked:,} shared inputs produce identical outputs.")


def _kat_messages(rng) -> list[tuple[str, bytes]]:
    """Messages for known-answer testing: classic strings plus random
    messages at padding-boundary lengths for 64- and 128-byte block hashes
    and the SHA-3-256 rate, where implementation bugs cluster."""
    msgs = [
        ("empty", b""),
        ("abc", b"abc"),
        ("nist-448-bit", b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
        ("nist-896-bit", b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
                         b"hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"),
        ("all-zero-64", bytes(64)),
        ("all-0xff-64", b"\xff" * 64),
    ]
    for L in (1, 31, 32, 55, 56, 63, 64, 65, 111, 112, 119, 127, 128, 129, 135, 136, 137, 1000, 10000):
        msgs.append((f"random-{L}B", bytes(rng.randint(0, 255) for _ in range(L))))
    return msgs


def cmd_kat(args):
    """Known-answer test: does an implementation agree with a trusted reference?

    This -- not the statistical battery -- is the check for "is this
    implementation of <algorithm> faithful?". A mis-constanted or
    round-reduced SHA-256 is still a well-mixed function and passes every
    statistical test; it only fails by disagreeing with the reference.
    """
    import random
    from generate_dataset import HASH_FUNCTIONS, KNOWN_ANSWERS

    verbose = not args.quiet
    if args.json:
        verbose = False
        Colors.disable()

    algorithm = args.algorithm
    if not (args.command or args.input or args.self_check):
        print("Error: kat needs an implementation to test: --command or -i/--input "
              "(or --self-check to test only the built-in reference against its published vectors).",
              file=sys.stderr)
        sys.exit(1)

    reference = _get_builtin_hash_fn(algorithm)
    # The reference's own published-vector check and the external checks are
    # counted separately. v0.2 pooled them, so a command that failed on every
    # message still had one passing check (the reference's) and was reported
    # PASS (found in the v0.3 review).
    results = {"algorithm": algorithm, "mode": None,
               "reference_checks": 0, "reference_mismatches": [],
               "checked": 0, "mismatches": [], "errors": [], "verdict": None}

    def check(label, message, expected, actual, bucket="checked", bad="mismatches"):
        results[bucket] += 1
        if actual != expected:
            results[bad].append({"message": label, "expected": expected, "actual": actual})
            if verbose:
                pos = next((i for i, (a, b) in enumerate(zip(expected, actual)) if a != b),
                           min(len(expected), len(actual)))
                print(f"  {Colors.red('✗')} {label}: digests first differ at hex position {pos} "
                      f"(expected …{expected[pos:pos + 8]}, got …{actual[pos:pos + 8]})")
        elif verbose and args.verbose:
            print(f"  {Colors.green('✓')} {label}")

    # 1. Self-check the built-in reference against published vectors
    for msg, expected in KNOWN_ANSWERS.get(algorithm, []):
        label = f"published vector {msg!r}" if isinstance(msg, str) else f"published vector ({len(msg)} bytes)"
        check(label, msg, expected, reference(msg), "reference_checks", "reference_mismatches")
    if algorithm not in KNOWN_ANSWERS and verbose:
        print(f"  (no published vectors embedded for {algorithm}; the reference is the library implementation)")

    # 2. Check the external implementation against the reference
    rng = random.Random(42)
    if args.command:
        results["mode"] = "command"
        under_test = make_hash_fn_from_command(args.command)
        if verbose:
            print(f"\n  Known-answer test: {args.command!r} vs built-in {algorithm}")
        for label, message in _kat_messages(rng):
            try:
                actual = under_test(message)
            except Exception as e:
                results["errors"].append({"message": label, "error": str(e)})
                if verbose:
                    print(f"  {Colors.red('!')} {label}: {e}")
                continue
            check(label, message, reference(message), actual)

    elif args.input:
        results["mode"] = "file"
        try:
            records = load_input(args.input)
        except (InputFormatError, OSError) as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(3)
        if verbose:
            print(f"\n  Known-answer test: {len(records):,} records in {args.input} vs built-in {algorithm}")
        for i, rec in enumerate(records):
            check(f"record {i + 1} ({rec['plaintext'][:24]!r})", rec["plaintext"],
                  reference(rec["plaintext"]), rec["hash"])

    else:
        results["mode"] = "self-check"

    # 3. Verdict. ERROR beats everything: a reference that fails its own
    # vectors cannot judge anything, and an implementation that could not be
    # run on some message has not been verified on it.
    n_bad = len(results["mismatches"])
    if results["reference_mismatches"]:
        results["verdict"] = "ERROR"
        results["reason"] = f"built-in {algorithm} reference failed its own published vectors"
    elif results["mode"] == "self-check":
        if results["reference_checks"] == 0:
            results["verdict"] = "ERROR"
            results["reason"] = f"no published vectors embedded for {algorithm}; nothing to self-check"
        else:
            results["verdict"] = "PASS"
            results["reason"] = "built-in reference only; no external implementation was tested"
    elif results["errors"]:
        results["verdict"] = "ERROR"
        results["reason"] = (f"{len(results['errors'])} of {len(results['errors']) + results['checked']} "
                             f"messages could not be hashed by the implementation under test")
    elif results["checked"] == 0:
        results["verdict"] = "ERROR"
        results["reason"] = "no messages were checked"
    elif n_bad:
        results["verdict"] = "FAIL"
        results["reason"] = f"{n_bad} of {results['checked']} checks disagree with the reference"
    else:
        results["verdict"] = "PASS"
        results["reason"] = f"{results['checked']} known-answer checks matched the reference"

    if args.json:
        print(json.dumps(results, indent=2, default=str))
    else:
        print()
        colour = {"PASS": Colors.green, "FAIL": Colors.red, "ERROR": Colors.red}[results["verdict"]]
        ref_note = ""
        if results["reference_checks"] and results["mode"] != "self-check":
            n_ref = results["reference_checks"]
            ref_note = f" ({algorithm} reference self-check: {n_ref} published vector{'s' if n_ref != 1 else ''} ok)"
        print(f"  {colour(results['verdict'])} — {results['reason']}{ref_note}.")
        if results["errors"] and verbose:
            print(f"  First error: {results['errors'][0]['message']}: {results['errors'][0]['error']}")
        if n_bad and results["verdict"] == "ERROR":
            print(f"  {n_bad} mismatch(es) were also found on the messages that did run.")
        print()

    sys.exit({"PASS": 0, "FAIL": 2, "ERROR": 3}[results["verdict"]])


def cmd_list_algorithms(args):
    """List available built-in algorithms."""
    from generate_dataset import HASH_FUNCTIONS, ORACLE_FOR_ALGO

    print("\n  Available algorithms:")
    print(f"  {'─' * 50}")

    # Group by category
    crypto = []
    block_cipher = []
    non_crypto = []

    for name in sorted(HASH_FUNCTIONS.keys()):
        oracle = ORACLE_FOR_ALGO.get(name, "")
        bits = ""
        if oracle:
            # Extract bit width from oracle name
            parts = oracle.split("_")
            if parts[-1].isdigit():
                bits = f"{parts[-1]}-bit"

        if name in ("aes128", "chacha20", "sm4", "camellia128"):
            block_cipher.append((name, bits))
        elif name in ("crc32", "adler32", "fnv1a_32", "fnv1a_64", "murmur3_32",
                       "siphash24", "djb2", "jenkins", "pearson64"):
            non_crypto.append((name, bits))
        else:
            crypto.append((name, bits))

    print(f"\n  {'Cryptographic hashes':}")
    for name, bits in crypto:
        print(f"    {name:<20} {bits}")

    print(f"\n  {'Block cipher constructions':}")
    for name, bits in block_cipher:
        print(f"    {name:<20} {bits}")

    print(f"\n  {'Non-cryptographic hashes':}")
    for name, bits in non_crypto:
        print(f"    {name:<20} {bits}")

    print()


# --- Main ---

def main():
    parser = argparse.ArgumentParser(
        prog="cryptid",
        description="Black-box cryptographic hash assessment toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  cryptid test -i samples.jsonl
  cryptid test -a sha256 -n 50000 --level full
  cryptid test --command "./my_hash_tool" -n 10000
  cryptid generate -a sha256 -n 100000 -o vectors.jsonl
  cryptid compare --target device.jsonl --reference openssl.jsonl
  cryptid kat -a sha256 --command "openssl dgst -sha256 -hex"
  cryptid kat -a sha256 -i device_output.jsonl
  cryptid list-algorithms
        """,
    )

    subparsers = parser.add_subparsers(dest="subcommand", help="Available commands")

    # --- test ---
    p_test = subparsers.add_parser(
        "test",
        help="Analyze a hash function for weaknesses",
        description="Run the detection pipeline on hash input/output data",
    )
    input_group = p_test.add_mutually_exclusive_group()
    input_group.add_argument("-i", "--input", help="JSONL file with plaintext/hash pairs")
    input_group.add_argument("-a", "--algorithm", help="Built-in algorithm name (use list-algorithms to see options)")
    input_group.add_argument("--command", help="Shell command that hashes stdin lines to stdout")

    p_test.add_argument("-n", "--samples", type=_positive_int, default=None,
                        help=f"Number of samples (default: 10000, or file size; minimum {MIN_RECORDS})")
    p_test.add_argument("--level", choices=["quick", "standard", "full"], default="standard",
                        help="Test depth: quick (stats only), standard (+differential), full (+extended+linear)")
    p_test.add_argument("--model", help="Path to meta-learner model file")
    p_test.add_argument("--skip-malformed", action="store_true",
                        help="Run on the usable records of a file that has unusable lines "
                             "(default: such a file is an error, exit 3)")
    p_test.add_argument("--json", action="store_true", help="Output results as JSON")
    p_test.add_argument("-q", "--quiet", action="store_true", help="Suppress progress output")
    p_test.set_defaults(func=cmd_test)

    # --- generate ---
    p_gen = subparsers.add_parser(
        "generate",
        help="Generate test vectors for a built-in algorithm",
        description="Create JSONL test vector files for later analysis",
    )
    p_gen.add_argument("-a", "--algorithm", required=True, help="Algorithm name")
    p_gen.add_argument("-n", "--samples", type=_positive_int, default=10000, help="Number of samples")
    p_gen.add_argument("-o", "--output", required=True, help="Output JSONL file path")
    p_gen.add_argument("-q", "--quiet", action="store_true", help="Suppress progress output")
    p_gen.set_defaults(func=cmd_generate)

    # --- compare ---
    p_cmp = subparsers.add_parser(
        "compare",
        help="Compare two hash implementations",
        description="Run statistical comparison between target and reference implementations",
    )
    p_cmp.add_argument("--target", required=True, help="Target implementation JSONL file")
    p_cmp.add_argument("--reference", required=True, help="Reference implementation JSONL file")
    p_cmp.add_argument("--model", help="Path to meta-learner model file")
    p_cmp.add_argument("--json", action="store_true", help="Output results as JSON")
    p_cmp.add_argument("-q", "--quiet", action="store_true", help="Suppress progress output")
    p_cmp.set_defaults(func=cmd_compare)

    # --- kat ---
    p_kat = subparsers.add_parser(
        "kat",
        help="Known-answer test: check an implementation against a trusted reference",
        description="Verify that an external implementation (a command, or a JSONL file of its "
                    "outputs) agrees with the built-in reference for a standard algorithm. This is "
                    "the faithfulness check; the statistical battery cannot detect a correct-looking "
                    "but non-standard implementation.",
    )
    p_kat.add_argument("-a", "--algorithm", required=True,
                       help="Reference algorithm name (see list-algorithms)")
    kat_src = p_kat.add_mutually_exclusive_group()
    kat_src.add_argument("--command", help="Shell command: raw message bytes on stdin, hex digest on stdout")
    kat_src.add_argument("-i", "--input", help="JSONL file of plaintext/hash pairs produced by the implementation")
    kat_src.add_argument("--self-check", action="store_true",
                         help="Only check the built-in reference against its embedded published vectors")
    p_kat.add_argument("--json", action="store_true", help="Output results as JSON")
    p_kat.add_argument("-v", "--verbose", action="store_true", help="Print every check, not just failures")
    p_kat.add_argument("-q", "--quiet", action="store_true", help="Suppress progress output")
    p_kat.set_defaults(func=cmd_kat)

    # --- list-algorithms ---
    p_list = subparsers.add_parser(
        "list-algorithms",
        help="List available built-in hash algorithms",
    )
    p_list.set_defaults(func=cmd_list_algorithms)

    # Parse and dispatch
    args = parser.parse_args()

    if not args.subcommand:
        parser.print_help()
        sys.exit(0)

    args.func(args)


if __name__ == "__main__":
    main()
