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
    load_input,
    generate_from_command,
    make_hash_fn_from_records,
    make_hash_fn_from_command,
    detect_output_width,
)
from engine import run_audit, AuditResult
from report import print_report, print_comparison_report, to_json, Colors


def _resolve_model_path(args_model: str = None) -> str:
    """Find the meta-learner model."""
    if args_model:
        return args_model

    candidates = [
        os.path.join(_project_dir, "models", "meta_learner_v3_scale_invariant.json"),
        os.path.join(_project_dir, "models", "meta_learner.json"),
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
    """Generate input/output records using a hash function."""
    import random
    rng = random.Random(42)
    records = []

    if verbose:
        print(f"  Generating {n_samples:,} test vectors...")

    for i in range(n_samples):
        # Mix of input distributions for robustness
        r = rng.random()
        if r < 0.5:
            # Random bytes
            data = bytes(rng.randint(0, 255) for _ in range(input_bytes))
            plaintext = data.hex()
        elif r < 0.8:
            # Dictionary-like words
            length = rng.randint(3, 15)
            chars = "abcdefghijklmnopqrstuvwxyz"
            plaintext = "".join(rng.choice(chars) for _ in range(length))
        else:
            # Sequential/counter
            plaintext = f"counter_{i:010d}"

        hash_val = hash_fn(plaintext)
        records.append({"plaintext": plaintext, "hash": hash_val})

    return records


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

    # Sample size warning
    if args.samples and args.samples < 2000 and verbose:
        print(f"  Warning: {args.samples} samples is low. Recommend 5000+ for reliable results.")

    # Determine input source
    if args.input:
        # Load from file
        if verbose:
            print(f"\n  Loading: {args.input}")
        records = load_input(args.input)
        name = os.path.splitext(os.path.basename(args.input))[0]
        if verbose:
            print(f"  Loaded {len(records):,} records ({detect_output_width(records)}-bit output)")

    elif args.algorithm:
        # Use built-in algorithm
        name = args.algorithm
        hash_fn = _get_builtin_hash_fn(args.algorithm)
        n = args.samples or 10000
        records = _generate_records(hash_fn, n, verbose=verbose)

    elif args.command:
        # Use external command
        name = args.command.split()[0] if args.command else "external"
        n = args.samples or 10000
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
        n_samples=args.samples or len(records),
        model_path=model_path,
        verbose=verbose,
    )

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
    n = args.samples or 10000

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

    if verbose:
        print(f"\n  Loading target: {args.target}")
    records_a = load_input(args.target)
    name_a = os.path.splitext(os.path.basename(args.target))[0]

    if verbose:
        print(f"  Loading reference: {args.reference}")
    records_b = load_input(args.reference)
    name_b = os.path.splitext(os.path.basename(args.reference))[0]

    if verbose:
        print(f"  Target:    {len(records_a):,} records")
        print(f"  Reference: {len(records_b):,} records")

    # Run audit on both
    result_a = run_audit(
        records=records_a, name=f"target ({name_a})",
        level="quick", model_path=model_path, verbose=verbose,
    )
    result_b = run_audit(
        records=records_b, name=f"reference ({name_b})",
        level="quick", model_path=model_path, verbose=verbose,
    )

    # Output
    if json_output:
        comparison = {
            "target": result_a.to_dict(),
            "reference": result_b.to_dict(),
        }
        print(json.dumps(comparison, indent=2, default=str))
    else:
        print_comparison_report(result_a, result_b)

    # Check for direct output divergence if inputs match
    _check_output_divergence(records_a, records_b, verbose)


def _check_output_divergence(records_a: list, records_b: list, verbose: bool):
    """Check if two datasets have matching inputs but different outputs."""
    lookup_b = {}
    for rec in records_b:
        lookup_b[rec["plaintext"]] = rec["hash"]

    mismatches = 0
    checked = 0
    for rec in records_a:
        if rec["plaintext"] in lookup_b:
            checked += 1
            if rec["hash"] != lookup_b[rec["plaintext"]]:
                mismatches += 1

    if checked == 0:
        if verbose:
            print("  Note: no overlapping inputs found between target and reference.")
            print("  For direct comparison, ensure both files hash the same inputs.")
    elif mismatches > 0:
        pct = mismatches / checked * 100
        print(f"\n  {Colors.red('!')} Output mismatch: {mismatches:,}/{checked:,} ({pct:.1f}%) of shared inputs differ")
        print(f"  This indicates the implementations are NOT equivalent.")
    else:
        if verbose:
            print(f"\n  {Colors.green('✓')} All {checked:,} shared inputs produce identical outputs.")


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

    p_test.add_argument("-n", "--samples", type=int, default=None,
                        help="Number of samples (default: 10000, or file size)")
    p_test.add_argument("--level", choices=["quick", "standard", "full"], default="standard",
                        help="Test depth: quick (stats only), standard (+differential), full (+extended+linear)")
    p_test.add_argument("--model", help="Path to meta-learner model file")
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
    p_gen.add_argument("-n", "--samples", type=int, default=10000, help="Number of samples")
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
