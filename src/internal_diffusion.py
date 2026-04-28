#!/usr/bin/env python3
"""
Internal state diffusion analysis — white-box round-by-round measurement.

Instead of treating hash functions as black boxes, this module instruments
pure Python implementations to observe the internal state after each round.
By measuring how a 1-bit input change propagates through the internal state,
we can detect structural weaknesses that are invisible to output analysis.

A well-designed hash should reach ~50% state bit diffusion (Hamming distance
≈ state_bits/2) within a few rounds. A weak hash may:
  - Diffuse slowly (many rounds before reaching 50%)
  - Diffuse unevenly (some state bits never affected)
  - Have "differential paths" where certain input changes propagate predictably

Currently implemented:
  - MD5 (64 rounds, 128-bit state) — known weak diffusion
  - SHA-256 (64 rounds, 256-bit state) — expected strong diffusion
  - SHA-1 (80 rounds, 160-bit state) — known weak, between MD5 and SHA-256

Usage:
  python internal_diffusion.py analyze --algorithm md5 --size 10000
  python internal_diffusion.py compare --algorithms md5,sha256,sha1 --size 5000
  python internal_diffusion.py sweep --size 5000 --output-dir data/diffusion_sweep/
"""

import argparse
import json
import math
import os
import random
import struct
import sys
import time
from pathlib import Path


# --- Utility ---

def bits_of_state(state_words: tuple, word_bits: int = 32) -> list[int]:
    """Convert tuple of integer state words to flat bit list."""
    bits = []
    for w in state_words:
        for i in range(word_bits - 1, -1, -1):
            bits.append((w >> i) & 1)
    return bits


# Word size per algorithm (for bits_of_state)
WORD_BITS = {
    "md5": 32, "sha256": 32, "sha1": 32, "sm3": 32,
    "sha512": 64, "sha3_256": 64,
}


def hamming_distance_bits(bits1: list[int], bits2: list[int]) -> int:
    return sum(a != b for a, b in zip(bits1, bits2))


def flip_bit_in_bytes(data: bytes, bit_pos: int) -> bytes:
    """Flip a single bit in a bytes object."""
    ba = bytearray(data)
    byte_idx = bit_pos // 8
    bit_idx = 7 - (bit_pos % 8)
    if byte_idx < len(ba):
        ba[byte_idx] ^= (1 << bit_idx)
    return bytes(ba)


# ============================================================
# MD5 — Pure Python with round-state instrumentation
# ============================================================

def _md5_left_rotate(x, amount):
    x &= 0xFFFFFFFF
    return ((x << amount) | (x >> (32 - amount))) & 0xFFFFFFFF


def md5_instrumented(message: bytes) -> dict:
    """
    Compute MD5 with round-by-round state recording.
    Returns dict with 'digest' and 'round_states' (list of 4-word state after each round).
    """
    # MD5 constants
    S = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ]

    K = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
        0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
        0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
        0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
        0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
    ]

    # Padding
    msg = bytearray(message)
    orig_len = len(msg)
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack('<Q', orig_len * 8)

    # Initial state
    a0 = 0x67452301
    b0 = 0xefcdab89
    c0 = 0x98badcfe
    d0 = 0x10325476

    round_states = [(a0, b0, c0, d0)]  # initial state

    # Process each 512-bit block
    for block_start in range(0, len(msg), 64):
        block = msg[block_start:block_start + 64]
        M = struct.unpack('<16I', block)

        A, B, C, D = a0, b0, c0, d0

        for i in range(64):
            if i < 16:
                F = (B & C) | (~B & D)
                g = i
            elif i < 32:
                F = (D & B) | (~D & C)
                g = (5 * i + 1) % 16
            elif i < 48:
                F = B ^ C ^ D
                g = (3 * i + 5) % 16
            else:
                F = C ^ (B | ~D)
                g = (7 * i) % 16

            F = (F + A + K[i] + M[g]) & 0xFFFFFFFF
            A = D
            D = C
            C = B
            B = (B + _md5_left_rotate(F, S[i])) & 0xFFFFFFFF

            round_states.append((A, B, C, D))

        a0 = (a0 + A) & 0xFFFFFFFF
        b0 = (b0 + B) & 0xFFFFFFFF
        c0 = (c0 + C) & 0xFFFFFFFF
        d0 = (d0 + D) & 0xFFFFFFFF

    digest = struct.pack('<4I', a0, b0, c0, d0).hex()
    return {"digest": digest, "round_states": round_states}


# ============================================================
# SHA-256 — Pure Python with round-state instrumentation
# ============================================================

def _sha256_right_rotate(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF


def sha256_instrumented(message: bytes) -> dict:
    """
    Compute SHA-256 with round-by-round state recording.
    Returns dict with 'digest' and 'round_states' (list of 8-word state after each round).
    """
    # SHA-256 constants
    K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ]

    # Padding
    msg = bytearray(message)
    orig_len = len(msg)
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack('>Q', orig_len * 8)

    # Initial hash values
    h0, h1, h2, h3, h4, h5, h6, h7 = (
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    )

    round_states = [(h0, h1, h2, h3, h4, h5, h6, h7)]

    for block_start in range(0, len(msg), 64):
        block = msg[block_start:block_start + 64]
        w = list(struct.unpack('>16I', block))

        # Message schedule expansion
        for i in range(16, 64):
            s0 = _sha256_right_rotate(w[i-15], 7) ^ _sha256_right_rotate(w[i-15], 18) ^ (w[i-15] >> 3)
            s1 = _sha256_right_rotate(w[i-2], 17) ^ _sha256_right_rotate(w[i-2], 19) ^ (w[i-2] >> 10)
            w.append((w[i-16] + s0 + w[i-7] + s1) & 0xFFFFFFFF)

        a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7

        for i in range(64):
            S1 = _sha256_right_rotate(e, 6) ^ _sha256_right_rotate(e, 11) ^ _sha256_right_rotate(e, 25)
            ch = (e & f) ^ (~e & g)
            temp1 = (h + S1 + ch + K[i] + w[i]) & 0xFFFFFFFF
            S0 = _sha256_right_rotate(a, 2) ^ _sha256_right_rotate(a, 13) ^ _sha256_right_rotate(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (S0 + maj) & 0xFFFFFFFF

            h = g
            g = f
            f = e
            e = (d + temp1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xFFFFFFFF

            round_states.append((a, b, c, d, e, f, g, h))

        h0 = (h0 + a) & 0xFFFFFFFF
        h1 = (h1 + b) & 0xFFFFFFFF
        h2 = (h2 + c) & 0xFFFFFFFF
        h3 = (h3 + d) & 0xFFFFFFFF
        h4 = (h4 + e) & 0xFFFFFFFF
        h5 = (h5 + f) & 0xFFFFFFFF
        h6 = (h6 + g) & 0xFFFFFFFF
        h7 = (h7 + h) & 0xFFFFFFFF

    digest = struct.pack('>8I', h0, h1, h2, h3, h4, h5, h6, h7).hex()
    return {"digest": digest, "round_states": round_states}


# ============================================================
# SHA-1 — Pure Python with round-state instrumentation
# ============================================================

def _sha1_left_rotate(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def sha1_instrumented(message: bytes) -> dict:
    """
    Compute SHA-1 with round-by-round state recording.
    Returns dict with 'digest' and 'round_states' (list of 5-word state after each round).
    """
    # Padding
    msg = bytearray(message)
    orig_len = len(msg)
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack('>Q', orig_len * 8)

    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0

    round_states = [(h0, h1, h2, h3, h4)]

    for block_start in range(0, len(msg), 64):
        block = msg[block_start:block_start + 64]
        w = list(struct.unpack('>16I', block))

        for i in range(16, 80):
            w.append(_sha1_left_rotate(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1))

        a, b, c, d, e = h0, h1, h2, h3, h4

        for i in range(80):
            if i < 20:
                f = (b & c) | (~b & d)
                k = 0x5A827999
            elif i < 40:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif i < 60:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            temp = (_sha1_left_rotate(a, 5) + f + e + k + w[i]) & 0xFFFFFFFF
            e = d
            d = c
            c = _sha1_left_rotate(b, 30)
            b = a
            a = temp

            round_states.append((a, b, c, d, e))

        h0 = (h0 + a) & 0xFFFFFFFF
        h1 = (h1 + b) & 0xFFFFFFFF
        h2 = (h2 + c) & 0xFFFFFFFF
        h3 = (h3 + d) & 0xFFFFFFFF
        h4 = (h4 + e) & 0xFFFFFFFF

    digest = struct.pack('>5I', h0, h1, h2, h3, h4).hex()
    return {"digest": digest, "round_states": round_states}


# ============================================================
# SHA-512 — Pure Python with round-state instrumentation
# ============================================================

def _sha512_right_rotate(x, n):
    return ((x >> n) | (x << (64 - n))) & 0xFFFFFFFFFFFFFFFF


def sha512_instrumented(message: bytes) -> dict:
    """
    Compute SHA-512 with round-by-round state recording.
    Returns dict with 'digest' and 'round_states' (list of 8-word 64-bit state).
    """
    K = [
        0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
        0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
        0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
        0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
        0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
        0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
        0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
        0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
        0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
        0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
        0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
        0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
        0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
        0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
        0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
        0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
        0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
        0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
    ]

    MASK64 = 0xFFFFFFFFFFFFFFFF

    # Padding (128-byte blocks for SHA-512)
    msg = bytearray(message)
    orig_len = len(msg)
    msg.append(0x80)
    while len(msg) % 128 != 112:
        msg.append(0)
    msg += struct.pack('>QQ', 0, orig_len * 8)

    h0, h1, h2, h3, h4, h5, h6, h7 = (
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
        0x510e527fade682d1, 0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
    )

    round_states = [(h0, h1, h2, h3, h4, h5, h6, h7)]

    for block_start in range(0, len(msg), 128):
        block = msg[block_start:block_start + 128]
        w = list(struct.unpack('>16Q', block))

        for i in range(16, 80):
            s0 = _sha512_right_rotate(w[i-15], 1) ^ _sha512_right_rotate(w[i-15], 8) ^ (w[i-15] >> 7)
            s1 = _sha512_right_rotate(w[i-2], 19) ^ _sha512_right_rotate(w[i-2], 61) ^ (w[i-2] >> 6)
            w.append((w[i-16] + s0 + w[i-7] + s1) & MASK64)

        a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7

        for i in range(80):
            S1 = _sha512_right_rotate(e, 14) ^ _sha512_right_rotate(e, 18) ^ _sha512_right_rotate(e, 41)
            ch = (e & f) ^ (~e & g)
            temp1 = (h + S1 + ch + K[i] + w[i]) & MASK64
            S0 = _sha512_right_rotate(a, 28) ^ _sha512_right_rotate(a, 34) ^ _sha512_right_rotate(a, 39)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (S0 + maj) & MASK64

            h = g
            g = f
            f = e
            e = (d + temp1) & MASK64
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & MASK64

            round_states.append((a, b, c, d, e, f, g, h))

        h0 = (h0 + a) & MASK64
        h1 = (h1 + b) & MASK64
        h2 = (h2 + c) & MASK64
        h3 = (h3 + d) & MASK64
        h4 = (h4 + e) & MASK64
        h5 = (h5 + f) & MASK64
        h6 = (h6 + g) & MASK64
        h7 = (h7 + h) & MASK64

    digest = struct.pack('>8Q', h0, h1, h2, h3, h4, h5, h6, h7).hex()
    return {"digest": digest, "round_states": round_states}


# ============================================================
# SM3 — Pure Python with round-state instrumentation
# ============================================================

def _sm3_left_rotate(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def _sm3_ff(x, y, z, j):
    if j < 16:
        return x ^ y ^ z
    return (x & y) | (x & z) | (y & z)


def _sm3_gg(x, y, z, j):
    if j < 16:
        return x ^ y ^ z
    return (x & y) | (~x & z)


def _sm3_p0(x):
    return x ^ _sm3_left_rotate(x, 9) ^ _sm3_left_rotate(x, 17)


def _sm3_p1(x):
    return x ^ _sm3_left_rotate(x, 15) ^ _sm3_left_rotate(x, 23)


def sm3_instrumented(message: bytes) -> dict:
    """
    Compute SM3 with round-by-round state recording.
    SM3 has 64 rounds and 256-bit state (8 x 32-bit words).
    """
    MASK32 = 0xFFFFFFFF

    # T constants
    T = [0x79cc4519 if j < 16 else 0x7a879d8a for j in range(64)]

    # Padding
    msg = bytearray(message)
    orig_len = len(msg)
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack('>Q', orig_len * 8)

    # Initial values
    V = [
        0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
        0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e,
    ]

    round_states = [tuple(V)]

    for block_start in range(0, len(msg), 64):
        block = msg[block_start:block_start + 64]
        W = list(struct.unpack('>16I', block))

        # Message expansion
        for j in range(16, 68):
            W.append(_sm3_p1(W[j-16] ^ W[j-9] ^ _sm3_left_rotate(W[j-3], 15)) ^
                     _sm3_left_rotate(W[j-13], 7) ^ W[j-6])

        W_prime = [W[j] ^ W[j+4] for j in range(64)]

        A, B, C, D, E, F, G, H = V

        for j in range(64):
            SS1 = _sm3_left_rotate(
                (_sm3_left_rotate(A, 12) + E + _sm3_left_rotate(T[j], j % 32)) & MASK32, 7)
            SS2 = SS1 ^ _sm3_left_rotate(A, 12)
            TT1 = (_sm3_ff(A, B, C, j) + D + SS2 + W_prime[j]) & MASK32
            TT2 = (_sm3_gg(E, F, G, j) + H + SS1 + W[j]) & MASK32

            D = C
            C = _sm3_left_rotate(B, 9)
            B = A
            A = TT1
            H = G
            G = _sm3_left_rotate(F, 19)
            F = E
            E = _sm3_p0(TT2)

            round_states.append((A, B, C, D, E, F, G, H))

        V = [
            (V[0] ^ A) & MASK32, (V[1] ^ B) & MASK32,
            (V[2] ^ C) & MASK32, (V[3] ^ D) & MASK32,
            (V[4] ^ E) & MASK32, (V[5] ^ F) & MASK32,
            (V[6] ^ G) & MASK32, (V[7] ^ H) & MASK32,
        ]

    digest = struct.pack('>8I', *V).hex()
    return {"digest": digest, "round_states": round_states}


# ============================================================
# SHA-3 (Keccak) — Pure Python with round-state instrumentation
# ============================================================

def sha3_256_instrumented(message: bytes) -> dict:
    """
    Compute SHA-3-256 (Keccak) with round-by-round state recording.

    SHA-3 uses a sponge construction with a 1600-bit state (5x5 matrix of
    64-bit lanes). The permutation has 24 rounds, each consisting of 5
    sub-steps (theta, rho, pi, chi, iota). We record the full 1600-bit
    state after each of the 24 rounds.

    The state is represented as a tuple of 25 64-bit words (the 5x5 lane array).
    """
    MASK64 = 0xFFFFFFFFFFFFFFFF

    # Round constants
    RC = [
        0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
        0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
        0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
        0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
        0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
        0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
        0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
        0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
    ]

    # Rho offsets
    ROT = [
        [ 0, 36,  3, 41, 18],
        [ 1, 44, 10, 45,  2],
        [62,  6, 43, 15, 61],
        [28, 55, 25, 21, 56],
        [27, 20, 39,  8, 14],
    ]

    def keccak_f(state_lanes):
        """Apply 24 rounds of Keccak-f[1600]. Returns list of states after each round."""
        # state_lanes: list of 25 64-bit integers
        # Keccak state: A[x][y] = state_lanes[x + 5*y]
        A = [[state_lanes[x + 5*y] for y in range(5)] for x in range(5)]
        round_states_inner = []

        for round_idx in range(24):
            # Theta
            C = [A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4] for x in range(5)]
            D = [C[(x-1) % 5] ^ (((C[(x+1) % 5] << 1) | (C[(x+1) % 5] >> 63)) & MASK64)
                 for x in range(5)]
            for x in range(5):
                for y in range(5):
                    A[x][y] ^= D[x]

            # Rho and Pi
            B = [[0]*5 for _ in range(5)]
            for x in range(5):
                for y in range(5):
                    rot = ROT[x][y]
                    B[y][(2*x + 3*y) % 5] = ((A[x][y] << rot) | (A[x][y] >> (64 - rot))) & MASK64 if rot else A[x][y]

            # Chi
            for x in range(5):
                for y in range(5):
                    A[x][y] = B[x][y] ^ (~B[(x+1) % 5][y] & B[(x+2) % 5][y])

            # Iota
            A[0][0] ^= RC[round_idx]

            # Record state as flat array (x + 5*y ordering)
            flat = [A[x][y] for y in range(5) for x in range(5)]
            round_states_inner.append(tuple(flat))

        return round_states_inner

    # SHA-3-256 parameters
    rate = 1088 // 8  # 136 bytes
    capacity = 512 // 8  # 64 bytes
    output_len = 32  # 256 bits

    # Padding (SHA-3 uses domain separation + pad10*1)
    msg = bytearray(message)
    msg.append(0x06)  # SHA-3 domain separation
    while len(msg) % rate != (rate - 1):
        msg.append(0x00)
    msg.append(0x80)

    # Initialize state (25 x 64-bit lanes = 1600 bits)
    state = [0] * 25

    all_round_states = [tuple(state)]  # initial zero state

    # Absorb phase
    for block_start in range(0, len(msg), rate):
        block = msg[block_start:block_start + rate]

        # XOR block into state (rate portion only)
        for i in range(len(block) // 8):
            lane = int.from_bytes(block[i*8:(i+1)*8], 'little')
            state[i] ^= lane

        # Apply Keccak-f permutation
        inner_states = keccak_f(state)
        all_round_states.extend(inner_states)

        # Update state from last round
        last = inner_states[-1]
        state = list(last)

    # Squeeze phase (for SHA-3-256, one squeeze is enough since output_len <= rate)
    output_bytes = b''
    for i in range(output_len // 8):
        output_bytes += state[i].to_bytes(8, 'little')
    output_bytes = output_bytes[:output_len]

    digest = output_bytes.hex()
    return {"digest": digest, "round_states": all_round_states}


# ============================================================
# Diffusion Curve Analysis
# ============================================================

ALGORITHMS = {
    "md5": {"fn": md5_instrumented, "state_bits": 128, "n_rounds": 64},
    "sha256": {"fn": sha256_instrumented, "state_bits": 256, "n_rounds": 64},
    "sha1": {"fn": sha1_instrumented, "state_bits": 160, "n_rounds": 80},
    "sha512": {"fn": sha512_instrumented, "state_bits": 512, "n_rounds": 80},
    "sm3": {"fn": sm3_instrumented, "state_bits": 256, "n_rounds": 64},
    "sha3_256": {"fn": sha3_256_instrumented, "state_bits": 1600, "n_rounds": 24},
}


def compute_diffusion_curve(
    algo_name: str,
    n_samples: int = 1000,
    input_bytes: int = None,
    rng: random.Random = None,
    verbose: bool = True,
) -> dict:
    """
    Compute the average diffusion curve: Hamming distance of internal state
    after each round, when a single input bit is flipped.

    Returns per-round statistics: mean HD, stdev, min, max, and the
    normalized diffusion rate (HD / max_possible_HD).
    """
    if rng is None:
        rng = random.Random(42)

    algo = ALGORITHMS[algo_name]
    hash_fn = algo["fn"]
    state_bits = algo["state_bits"]
    n_rounds = algo["n_rounds"]
    word_bits = WORD_BITS.get(algo_name, 32)

    # Choose input size to fit in one block
    if input_bytes is None:
        if algo_name == "sha512":
            input_bytes = 111  # < 112 for SHA-512 (128-byte blocks)
        elif algo_name == "sha3_256":
            input_bytes = 135  # < 136 for SHA-3-256 (rate = 136 bytes)
        else:
            input_bytes = 55   # < 56 for MD5/SHA-256/SHA-1/SM3 (64-byte blocks)

    if verbose:
        print(f"  Computing diffusion curve for {algo_name} "
              f"({n_rounds} rounds, {state_bits}-bit state)")
        print(f"  {n_samples} input pairs...", end="", flush=True)

    # For each sample: generate random input, flip one bit, compare round states
    round_hds = [[] for _ in range(n_rounds + 1)]  # index 0 = initial state

    for sample in range(n_samples):
        # Random input
        inp = bytes(rng.randint(0, 255) for _ in range(input_bytes))

        # Random bit to flip
        flip_pos = rng.randint(0, input_bytes * 8 - 1)
        inp_flipped = flip_bit_in_bytes(inp, flip_pos)

        # Compute both hashes with instrumentation
        result1 = hash_fn(inp)
        result2 = hash_fn(inp_flipped)

        states1 = result1["round_states"]
        states2 = result2["round_states"]

        # Compare state at each round
        for r in range(min(len(states1), len(states2), n_rounds + 1)):
            bits1 = bits_of_state(states1[r], word_bits=word_bits)
            bits2 = bits_of_state(states2[r], word_bits=word_bits)
            hd = hamming_distance_bits(bits1, bits2)
            round_hds[r].append(hd)

    if verbose:
        print(f" done")

    # Compute statistics per round
    ideal_hd = state_bits / 2.0
    curve = []

    for r in range(n_rounds + 1):
        if not round_hds[r]:
            continue

        hds = round_hds[r]
        mean_hd = sum(hds) / len(hds)
        variance = sum((h - mean_hd) ** 2 for h in hds) / len(hds)
        stdev = math.sqrt(variance)
        min_hd = min(hds)
        max_hd = max(hds)

        # Normalized: 0.0 = no diffusion, 1.0 = ideal (50% bits flipped)
        normalized = mean_hd / ideal_hd if ideal_hd > 0 else 0

        curve.append({
            "round": r,
            "mean_hd": round(mean_hd, 2),
            "stdev": round(stdev, 2),
            "min_hd": min_hd,
            "max_hd": max_hd,
            "normalized": round(normalized, 4),
        })

    # Key metrics
    # Rounds to reach 90% of ideal diffusion
    rounds_to_90 = n_rounds  # default: never
    for c in curve:
        if c["normalized"] >= 0.9:
            rounds_to_90 = c["round"]
            break

    # Rounds to reach 50% of ideal
    rounds_to_50 = n_rounds
    for c in curve:
        if c["normalized"] >= 0.5:
            rounds_to_50 = c["round"]
            break

    # Final round normalized diffusion (should be ~1.0)
    final_normalized = curve[-1]["normalized"] if curve else 0

    # Diffusion uniformity: stdev of normalized values in last quarter of rounds
    last_quarter = [c["normalized"] for c in curve[3 * n_rounds // 4:]]
    uniformity = 1.0 - (max(last_quarter) - min(last_quarter)) if last_quarter else 0

    return {
        "algorithm": algo_name,
        "n_samples": n_samples,
        "state_bits": state_bits,
        "n_rounds": n_rounds,
        "ideal_hd": ideal_hd,
        "rounds_to_50pct": rounds_to_50,
        "rounds_to_90pct": rounds_to_90,
        "final_normalized_diffusion": round(final_normalized, 4),
        "diffusion_uniformity": round(uniformity, 4),
        "curve": curve,
    }


def print_diffusion_report(result: dict):
    """Print a human-readable diffusion analysis report."""
    algo = result["algorithm"]
    print(f"\n  {'='*65}")
    print(f"  DIFFUSION CURVE — {algo.upper()}")
    print(f"  {'='*65}")
    print(f"  State: {result['state_bits']} bits, {result['n_rounds']} rounds")
    print(f"  Rounds to 50% diffusion: {result['rounds_to_50pct']}")
    print(f"  Rounds to 90% diffusion: {result['rounds_to_90pct']}")
    print(f"  Final normalized diffusion: {result['final_normalized_diffusion']:.4f}")
    print(f"  Diffusion uniformity: {result['diffusion_uniformity']:.4f}")

    print(f"\n  Round-by-round diffusion (normalized to ideal):")
    print(f"  {'Round':>6} {'MeanHD':>8} {'Norm':>7} {'StdDev':>8}  Bar")
    print(f"  {'-'*55}")

    curve = result["curve"]
    # Show every round for first 10, then every 5th
    for c in curve:
        r = c["round"]
        if r <= 10 or r % 5 == 0 or r == len(curve) - 1:
            bar_len = int(c["normalized"] * 40)
            bar = "█" * bar_len + "░" * (40 - bar_len)
            print(f"  {r:>5}  {c['mean_hd']:>7.1f} {c['normalized']:>6.3f} {c['stdev']:>7.1f}  {bar}")


def compare_algorithms(
    algorithms: list[str],
    n_samples: int = 1000,
    verbose: bool = True,
) -> dict:
    """Compare diffusion curves across multiple algorithms."""
    results = {}
    for algo_name in algorithms:
        if algo_name not in ALGORITHMS:
            print(f"  Unknown algorithm: {algo_name}")
            continue
        results[algo_name] = compute_diffusion_curve(
            algo_name, n_samples=n_samples, verbose=verbose,
        )
        print_diffusion_report(results[algo_name])

    # Comparison summary
    print(f"\n  {'='*65}")
    print(f"  DIFFUSION COMPARISON SUMMARY")
    print(f"  {'='*65}")
    print(f"\n  {'Algorithm':<12} {'State':>6} {'Rnds':>5} {'→50%':>5} {'→90%':>5} {'Final':>7} {'Uniform':>8}")
    print(f"  {'-'*55}")

    for algo_name in algorithms:
        if algo_name not in results:
            continue
        r = results[algo_name]
        print(f"  {algo_name:<12} {r['state_bits']:>5}b {r['n_rounds']:>5} "
              f"{r['rounds_to_50pct']:>5} {r['rounds_to_90pct']:>5} "
              f"{r['final_normalized_diffusion']:>6.3f} {r['diffusion_uniformity']:>7.3f}")

    return results


# --- Main ---

def main():
    parser = argparse.ArgumentParser(
        description="Internal state diffusion analysis for hash functions."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Analyze single algorithm
    analyze_parser = subparsers.add_parser("analyze", help="Analyze one algorithm")
    analyze_parser.add_argument("--algorithm", required=True, choices=list(ALGORITHMS.keys()))
    analyze_parser.add_argument("--size", type=int, default=1000)

    # Compare algorithms
    compare_parser = subparsers.add_parser("compare", help="Compare multiple algorithms")
    compare_parser.add_argument("--algorithms", type=str, default="md5,sha256,sha1")
    compare_parser.add_argument("--size", type=int, default=1000)
    compare_parser.add_argument("--output-dir", default="data/diffusion/")

    args = parser.parse_args()

    if args.command == "analyze":
        result = compute_diffusion_curve(args.algorithm, n_samples=args.size)
        print_diffusion_report(result)

    elif args.command == "compare":
        algos = [a.strip() for a in args.algorithms.split(",")]
        os.makedirs(args.output_dir, exist_ok=True)

        results = compare_algorithms(algos, n_samples=args.size)

        results_path = os.path.join(args.output_dir, "diffusion_comparison.json")
        with open(results_path, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\n  Results saved to: {results_path}")


if __name__ == "__main__":
    main()
