#!/usr/bin/env python3
"""
cryptid — black-box cryptographic hash assessment toolkit.

Top-level entry point. Run from the project root:
  python cryptid.py test -a sha256 -n 10000
  python cryptid.py test -i samples.jsonl --level full
  python cryptid.py list-algorithms
"""
import os
import sys

# Add the cryptid package to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "cryptid"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from cli import main

if __name__ == "__main__":
    main()
