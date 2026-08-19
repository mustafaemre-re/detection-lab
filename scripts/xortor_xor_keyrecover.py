#!/usr/bin/env python3
"""
xortor_xor_keyrecover.py - recover a repeating-XOR key with no key material.

Reproduces the central technical claim of analysis/xortor.md sections 3.4-3.5:
that XORTOR's 12-byte key was recovered from ciphertext alone. That claim was
previously supported only by a 15-line snippet in the report, with the Hamming
distance scan shown as four hand-picked results out of an unstated range. This
script produces the full scan and the key, so the result can be checked rather
than taken on trust.

Method
    1. Key length by normalised Hamming distance. For the true key length, byte
       blocks that far apart XOR against the same key byte, so their bitwise
       difference collapses toward the plaintext's own redundancy. Wrong lengths
       compare unrelated key bytes and score near random.
    2. Key bytes by column frequency. A PE is NUL-heavy, and NUL XOR k == k, so
       the most frequent ciphertext byte in each key-position column IS the key
       byte. No key material required.

Both steps are ordinary cryptanalysis, older than the malware by about a
century. They work here only because the author chose repeating-XOR over
authenticated encryption.

Usage
    python3 xortor_xor_keyrecover.py <ciphertext>
    python3 xortor_xor_keyrecover.py <ciphertext> --max-keylen 64
    python3 xortor_xor_keyrecover.py <ciphertext> --decrypt out.bin

Expected on XORTOR build 1 (uusd.exe from data_p002/):
    key length 12, key "tgn5AIyxKkQi", plaintext beginning 4D 5A ("MZ")

Author: Mustafa Emre
Report: analysis/xortor.md
"""

import argparse
import sys
from collections import Counter

POPCOUNT = bytes(bin(i).count("1") for i in range(256))


def hamming(a, b):
    """Bit-level distance between two equal-length byte strings."""
    return sum(POPCOUNT[x ^ y] for x, y in zip(a, b))


def score_keylen(data, klen, blocks=8):
    """Mean Hamming distance between consecutive blocks, normalised by length.

    Lower is better. Averaging several block pairs rather than the usual two
    materially reduces noise on short or structured inputs.
    """
    if len(data) < klen * (blocks + 1):
        blocks = max(2, len(data) // klen - 1)
    if blocks < 2:
        return None
    total = pairs = 0
    for i in range(blocks):
        a = data[i * klen:(i + 1) * klen]
        b = data[(i + 1) * klen:(i + 2) * klen]
        if len(a) == len(b) == klen:
            total += hamming(a, b)
            pairs += 1
    return (total / pairs) / klen if pairs else None


def find_keylen(data, max_keylen=40, show=10):
    """Full scan, printed in full. The report showed only four rows."""
    scores = []
    for klen in range(2, max_keylen + 1):
        s = score_keylen(data, klen)
        if s is not None:
            scores.append((s, klen))
    scores.sort()

    print("=== key length scan (normalised Hamming distance, lower is better) ===")
    for s, klen in scores[:show]:
        print("  keylen=%3d  score=%.4f" % (klen, s))

    best = scores[0][1]
    # A multiple of the true length scores well too. Prefer the smallest
    # candidate that the top results are multiples of.
    top = [k for _, k in scores[:5]]
    for cand in sorted(top):
        if sum(1 for k in top if k % cand == 0) >= 3:
            if cand != best:
                print("\n  [i] %d scores best, but %d divides most top results"
                      % (best, cand))
                print("      -> using %d (multiples of the true length also score well)"
                      % cand)
            return cand
    return best


def recover_key(data, klen):
    """Most frequent byte per key-position column == key byte, for NUL-heavy plaintext."""
    key = bytearray()
    confidence = []
    for i in range(klen):
        col = data[i::klen]
        counts = Counter(col)
        byte, n = counts.most_common(1)[0]
        key.append(byte)
        confidence.append(n / len(col))
    return bytes(key), confidence


def xor(data, key):
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def describe(head):
    known = {
        b"MZ": "PE executable",
        b"\x7fELF": "ELF executable",
        b"PK\x03\x04": "ZIP archive",
        b"\xff\xfe": "UTF-16LE text",
        b"\xef\xbb\xbf": "UTF-8 BOM text",
        b"var ": "JScript",
        b"func": "JScript",
        b"Rar!": "RAR archive",
        b"%PDF": "PDF",
    }
    for magic, name in known.items():
        if head.startswith(magic):
            return name
    return None


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file", help="ciphertext file")
    ap.add_argument("--max-keylen", type=int, default=40)
    ap.add_argument("--keylen", type=int, help="skip the scan, use this length")
    ap.add_argument("--decrypt", metavar="OUT", help="write plaintext to OUT")
    args = ap.parse_args()

    with open(args.file, "rb") as f:
        data = f.read()
    print("input: %s (%d bytes)\n" % (args.file, len(data)))

    klen = args.keylen or find_keylen(data, args.max_keylen)
    print("\n=== key length: %d ===" % klen)

    key, conf = recover_key(data, klen)
    printable = all(32 <= b < 127 for b in key)
    print("\n=== recovered key ===")
    print("  hex   : %s" % key.hex(" "))
    if printable:
        print("  ascii : %s" % key.decode("ascii"))
    print("  column confidence: min %.1f%%  mean %.1f%%"
          % (min(conf) * 100, sum(conf) / len(conf) * 100))
    if min(conf) < 0.05:
        print("  [!] a low-confidence column suggests the plaintext is not")
        print("      NUL-heavy at that position - verify before trusting")

    head = xor(data[:64], key)
    print("\n=== verification: first 16 plaintext bytes ===")
    print("  hex : %s" % head[:16].hex(" "))
    print("  repr: %r" % head[:16])
    fmt = describe(head)
    if fmt:
        print("  -> valid %s magic. Key confirmed." % fmt)
    else:
        print("  -> no known magic. Key may be wrong, or the plaintext is")
        print("     headerless (wordlist, address list, XML fragment).")

    if args.decrypt:
        with open(args.decrypt, "wb") as f:
            f.write(xor(data, key))
        print("\nplaintext written to %s" % args.decrypt)


if __name__ == "__main__":
    main()
