"""
CTF Crypto Solver — automatically attempts to decode/decrypt common CTF encodings.
No LLM required. Pure algorithmic decoding.

Supported:
  - Base64, Base32, Base58, Base85, Base16 (hex)
  - ROT-N (all 25 Caesar shifts)
  - XOR with single-byte and multi-byte keys (brute)
  - URL encode / HTML entities
  - Binary / octal / decimal char codes
  - Morse code
  - Atbash cipher
  - Vigenere (brute common keys)
  - JWT RS256→HS256 confusion
  - Hash identification + offline crack (MD5/SHA1 common wordlist)
  - Reversed string
  - Bacon cipher
  - Rail fence cipher (common rail counts)
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import html
import itertools
import re
import string
import urllib.parse
from typing import TYPE_CHECKING

from app.scanner.base import Finding, ScanResult
from app.scanner.flag_extractor import build_flag_pattern, extract_flags, search_flags_decoded

if TYPE_CHECKING:
    from app.scanner.context import ScanContext


# ── Morse code table ──────────────────────────────────────────────────────────

_MORSE = {
    '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
    '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
    '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
    '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
    '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
    '--..': 'Z', '-----': '0', '.----': '1', '..---': '2', '...--': '3',
    '....-': '4', '.....': '5', '-....': '6', '--...': '7', '---..': '8',
    '----.': '9',
}

# ── Bacon cipher ─────────────────────────────────────────────────────────────

_BACON = {
    'AAAAA': 'A', 'AAAAB': 'B', 'AAABA': 'C', 'AAABB': 'D', 'AABAA': 'E',
    'AABAB': 'F', 'AABBA': 'G', 'AABBB': 'H', 'ABAAA': 'I', 'ABAAB': 'J',
    'ABABA': 'K', 'ABABB': 'L', 'ABBAA': 'M', 'ABBAB': 'N', 'ABBBA': 'O',
    'ABBBB': 'P', 'BAAAA': 'Q', 'BAAAB': 'R', 'BAABA': 'S', 'BAABB': 'T',
    'BABAA': 'U', 'BABAB': 'V', 'BABBA': 'W', 'BABBB': 'X', 'BBAAA': 'Y',
    'BBAAB': 'Z',
}

# ── Common XOR / Vigenere keys ────────────────────────────────────────────────

_COMMON_KEYS = [
    'key', 'flag', 'secret', 'password', 'ctf', 'hack', 'admin',
    'letmein', 'abc', 'xyz', 'test', '1234', 'qwerty', 'base',
]

# ── Common hash → flag rainbow (tiny, symbolic) ───────────────────────────────

_HASH_WORDLIST = [
    'flag', 'Flag', 'FLAG', 'password', 'admin', 'secret', 'letmein',
    '123456', 'qwerty', 'abc123', 'monkey', 'master', 'dragon',
    'pass', 'hello', 'welcome', 'root', 'toor', 'test', 'guest',
]


# ── Individual decoders ───────────────────────────────────────────────────────

def _try_base64(data: str) -> list[str]:
    results = []
    for pad in ('', '=', '==', '==='):
        try:
            dec = base64.b64decode(data.strip() + pad)
            results.append(dec.decode('utf-8', errors='replace'))
        except Exception:
            pass
    # URL-safe variant
    try:
        dec = base64.urlsafe_b64decode(data.strip() + '==')
        results.append(dec.decode('utf-8', errors='replace'))
    except Exception:
        pass
    return results


def _try_base32(data: str) -> list[str]:
    try:
        dec = base64.b32decode(data.strip().upper() + '=' * (8 - len(data.strip()) % 8) if len(data.strip()) % 8 else data.strip().upper())
        return [dec.decode('utf-8', errors='replace')]
    except Exception:
        return []


def _try_base58(data: str) -> list[str]:
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    try:
        n = 0
        for char in data.strip():
            if char not in alphabet:
                return []
            n = n * 58 + alphabet.index(char)
        result = []
        while n > 0:
            result.append(n % 256)
            n //= 256
        return [bytes(reversed(result)).decode('utf-8', errors='replace')]
    except Exception:
        return []


def _try_base85(data: str) -> list[str]:
    try:
        dec = base64.b85decode(data.strip())
        return [dec.decode('utf-8', errors='replace')]
    except Exception:
        pass
    try:
        dec = base64.a85decode(data.strip())
        return [dec.decode('utf-8', errors='replace')]
    except Exception:
        pass
    return []


def _try_hex(data: str) -> list[str]:
    clean = data.strip().replace(' ', '').replace('0x', '').replace('\\x', '')
    if len(clean) % 2 != 0:
        clean = '0' + clean
    try:
        return [bytes.fromhex(clean).decode('utf-8', errors='replace')]
    except Exception:
        return []


def _try_binary(data: str) -> list[str]:
    clean = re.sub(r'[^01\s]', '', data.strip())
    groups = clean.split()
    if not groups or not all(len(g) == 8 for g in groups):
        # Try splitting into 8-bit chunks
        flat = clean.replace(' ', '')
        if len(flat) % 8 != 0:
            return []
        groups = [flat[i:i+8] for i in range(0, len(flat), 8)]
    try:
        return [''.join(chr(int(g, 2)) for g in groups)]
    except Exception:
        return []


def _try_octal(data: str) -> list[str]:
    groups = re.findall(r'\\(\d{3})', data)
    if not groups:
        groups = data.strip().split()
    try:
        return [''.join(chr(int(g, 8)) for g in groups)]
    except Exception:
        return []


def _try_decimal_chars(data: str) -> list[str]:
    groups = data.strip().split()
    try:
        if all(g.isdigit() and 32 <= int(g) <= 126 for g in groups):
            return [''.join(chr(int(g)) for g in groups)]
    except Exception:
        pass
    return []


def _try_url_decode(data: str) -> list[str]:
    try:
        return [urllib.parse.unquote(data)]
    except Exception:
        return []


def _try_html_entities(data: str) -> list[str]:
    try:
        return [html.unescape(data)]
    except Exception:
        return []


def _try_reverse(data: str) -> list[str]:
    return [data[::-1]]


def _try_caesar_all(data: str) -> list[str]:
    results = []
    for shift in range(1, 26):
        result = []
        for ch in data:
            if ch.isalpha():
                base = ord('A') if ch.isupper() else ord('a')
                result.append(chr((ord(ch) - base + shift) % 26 + base))
            else:
                result.append(ch)
        results.append(''.join(result))
    return results


def _try_atbash(data: str) -> list[str]:
    result = []
    for ch in data:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            result.append(chr(base + 25 - (ord(ch) - base)))
        else:
            result.append(ch)
    return [''.join(result)]


def _try_morse(data: str) -> list[str]:
    clean = data.strip()
    if not re.match(r'^[.\- /|]+$', clean):
        return []
    separator = '/' if '/' in clean else '|' if '|' in clean else ' '
    words = clean.split(separator)
    result_chars = []
    for word in words:
        chars = word.strip().split()
        for c in chars:
            result_chars.append(_MORSE.get(c, '?'))
        result_chars.append(' ')
    return [''.join(result_chars).strip()]


def _try_bacon(data: str) -> list[str]:
    clean = re.sub(r'[^AB]', '', data.upper())
    if len(clean) % 5 != 0:
        return []
    groups = [clean[i:i+5] for i in range(0, len(clean), 5)]
    try:
        return [''.join(_BACON.get(g, '?') for g in groups)]
    except Exception:
        return []


def _try_xor_single(data: bytes) -> list[str]:
    results = []
    for key in range(256):
        dec = bytes(b ^ key for b in data)
        try:
            text = dec.decode('utf-8', errors='strict')
            if all(32 <= ord(c) < 127 or c in '\n\r\t' for c in text):
                results.append(text)
        except Exception:
            pass
    return results


def _try_xor_key(data: bytes, key: str) -> list[str]:
    key_bytes = key.encode()
    dec = bytes(data[i] ^ key_bytes[i % len(key_bytes)] for i in range(len(data)))
    try:
        text = dec.decode('utf-8', errors='replace')
        return [text]
    except Exception:
        return []


def _try_vigenere(data: str, key: str) -> list[str]:
    result = []
    key_upper = key.upper()
    ki = 0
    for ch in data:
        if ch.isalpha():
            shift = ord(key_upper[ki % len(key_upper)]) - ord('A')
            base = ord('A') if ch.isupper() else ord('a')
            result.append(chr((ord(ch) - base - shift) % 26 + base))
            ki += 1
        else:
            result.append(ch)
    return [''.join(result)]


def _try_rail_fence(data: str, rails: int) -> str:
    n = len(data)
    fence = [[] for _ in range(rails)]
    rail, direction = 0, 1
    for i in range(n):
        fence[rail].append(i)
        if rail == 0:
            direction = 1
        elif rail == rails - 1:
            direction = -1
        rail += direction
    order = [i for rail in fence for i in rail]
    result = [''] * n
    for pos, char_idx in enumerate(order):
        result[char_idx] = data[pos]
    return ''.join(result)


def _try_hash_crack(hash_str: str) -> list[str]:
    hash_str = hash_str.strip().lower()
    results = []
    for word in _HASH_WORDLIST:
        for candidate in [word, word.upper(), word.capitalize()]:
            if hashlib.md5(candidate.encode()).hexdigest() == hash_str:
                results.append(f"MD5 cracked: {candidate}")
            if hashlib.sha1(candidate.encode()).hexdigest() == hash_str:
                results.append(f"SHA1 cracked: {candidate}")
            if hashlib.sha256(candidate.encode()).hexdigest() == hash_str:
                results.append(f"SHA256 cracked: {candidate}")
    return results


def _identify_hash(data: str) -> str | None:
    clean = data.strip()
    if re.match(r'^[0-9a-fA-F]{32}$', clean):
        return 'MD5'
    if re.match(r'^[0-9a-fA-F]{40}$', clean):
        return 'SHA1'
    if re.match(r'^[0-9a-fA-F]{64}$', clean):
        return 'SHA256'
    if re.match(r'^\$2[aby]\$', clean):
        return 'bcrypt'
    if re.match(r'^\$1\$', clean):
        return 'MD5crypt'
    return None


def _try_jwt_confusion(token: str) -> list[str]:
    """RS256 → HS256 key confusion: sign with public key as HMAC secret."""
    results = []
    try:
        import jose.jwt as jjwt
        parts = token.split('.')
        if len(parts) != 3:
            return []
        import base64 as b64
        payload_raw = b64.urlsafe_b64decode(parts[1] + '==')
        payload = __import__('json').loads(payload_raw)
        payload['admin'] = True
        payload['role'] = 'admin'
        payload.pop('exp', None)
        # Try signing with empty string (common weak RS256 confusion)
        for fake_key in ['', 'secret', 'public']:
            try:
                new_token = jjwt.encode(payload, fake_key, algorithm='HS256')
                results.append(f"JWT HS256 confusion token (key={fake_key!r}): {new_token}")
            except Exception:
                pass
    except Exception:
        pass
    return results


# ── Main solver ───────────────────────────────────────────────────────────────

_DECODERS = [
    ('Base64',        _try_base64),
    ('Base32',        _try_base32),
    ('Base58',        _try_base58),
    ('Base85',        _try_base85),
    ('Hex',           _try_hex),
    ('Binary',        _try_binary),
    ('URL decode',    _try_url_decode),
    ('HTML entities', _try_html_entities),
    ('Reverse',       _try_reverse),
    ('Atbash',        _try_atbash),
    ('Morse',         _try_morse),
    ('Bacon',         _try_bacon),
]


def solve(data: str, pattern, depth: int = 0) -> list[tuple[str, str]]:
    """
    Try all decoders on data. For each successful decode that produces
    printable text, also try decoding again (multi-layer, max depth 3).
    Returns list of (decoder_chain, decoded_text).
    """
    if depth > 3:
        return []
    results: list[tuple[str, str]] = []
    data = data.strip()
    if not data:
        return []

    for name, fn in _DECODERS:
        try:
            decoded_list = fn(data)
        except Exception:
            decoded_list = []
        for decoded in decoded_list:
            if not decoded or decoded == data:
                continue
            printable = sum(32 <= ord(c) < 127 for c in decoded) / max(len(decoded), 1)
            if printable < 0.7:
                continue
            flags = extract_flags(decoded, pattern)
            if flags:
                results.append((name, decoded))
                continue
            # Multi-layer: try decoding the result again
            if depth < 3:
                sub = solve(decoded, pattern, depth + 1)
                for sub_name, sub_decoded in sub:
                    results.append((f"{name} → {sub_name}", sub_decoded))

    # Caesar: try all 25 shifts
    for i, shifted in enumerate(_try_caesar_all(data), 1):
        flags = extract_flags(shifted, pattern)
        if flags:
            results.append((f'Caesar ROT{i}', shifted))

    # XOR single-byte brute
    try:
        raw = data.encode('latin-1')
        for xored in _try_xor_single(raw):
            flags = extract_flags(xored, pattern)
            if flags:
                results.append(('XOR single-byte brute', xored))
    except Exception:
        pass

    # XOR common keys
    try:
        raw = data.encode('latin-1')
        for key in _COMMON_KEYS:
            for xored in _try_xor_key(raw, key):
                flags = extract_flags(xored, pattern)
                if flags:
                    results.append((f'XOR key={key!r}', xored))
    except Exception:
        pass

    # Vigenere common keys
    for key in _COMMON_KEYS:
        vdec = _try_vigenere(data, key)[0]
        flags = extract_flags(vdec, pattern)
        if flags:
            results.append((f'Vigenere key={key!r}', vdec))

    # Rail fence (2-8 rails)
    for rails in range(2, 9):
        try:
            rfdec = _try_rail_fence(data, rails)
            flags = extract_flags(rfdec, pattern)
            if flags:
                results.append((f'Rail fence {rails} rails', rfdec))
        except Exception:
            pass

    # Hash crack
    hash_type = _identify_hash(data)
    if hash_type and hash_type in ('MD5', 'SHA1', 'SHA256'):
        for cracked in _try_hash_crack(data):
            results.append((f'{hash_type} crack', cracked))

    # Decimal char codes
    for dec_str in _try_decimal_chars(data):
        flags = extract_flags(dec_str, pattern)
        if flags:
            results.append(('Decimal char codes', dec_str))

    return results


# ── Scanner integration ───────────────────────────────────────────────────────

def _extract_suspicious_blobs(findings: list[Finding]) -> list[tuple[str, str]]:
    """
    Pull out strings that look like encoded data from all findings.
    Returns list of (source_description, blob).
    """
    blobs: list[tuple[str, str]] = []
    seen: set[str] = set()

    # Patterns for encoded-looking data
    blob_patterns = [
        # Base64-ish (min 16 chars, ends with =)
        re.compile(r'[A-Za-z0-9+/]{16,}={0,3}'),
        # Hex string min 16 chars
        re.compile(r'(?:0x)?[0-9a-fA-F]{16,}'),
        # Binary groups
        re.compile(r'(?:[01]{8}\s*){4,}'),
        # Morse
        re.compile(r'(?:[.\-]{1,6}\s+){3,}'),
    ]

    for f in findings:
        for field in [f.evidence, f.description, f.title, f.raw_output]:
            if not field:
                continue
            for pat in blob_patterns:
                for m in pat.finditer(field):
                    blob = m.group(0).strip()
                    if blob not in seen and len(blob) >= 8:
                        seen.add(blob)
                        blobs.append((f.type + '/' + (f.title or '')[:40], blob))

    return blobs[:50]  # cap at 50 blobs


async def run_crypto_solver(
    ctx: 'ScanContext',
    ctf_flag_format: str | None,
    all_findings: list[Finding],
) -> ScanResult:
    result = ScanResult()
    pattern = build_flag_pattern(ctf_flag_format)

    await ctx.log("Crypto solver: extracting encoded blobs from findings", module="crypto_solver")

    blobs = _extract_suspicious_blobs(all_findings)
    await ctx.log(f"Crypto solver: found {len(blobs)} candidate blobs", module="crypto_solver")

    flags_found = 0

    for source, blob in blobs:
        solutions = solve(blob, pattern)
        for chain, decoded in solutions:
            flags = extract_flags(decoded, pattern)
            for flag in flags:
                flags_found += 1
                await ctx.log(
                    f"  ★ CRYPTO FLAG via {chain}: {flag}",
                    level="success", module="crypto_solver",
                )
                result.findings.append(Finding(
                    type="flag",
                    title=f"FLAG CAPTURED via crypto: {flag}",
                    severity="critical",
                    description=(
                        f"Flag found by decoding encoded blob.\n\n"
                        f"Source: {source}\n"
                        f"Decoder chain: {chain}\n"
                        f"Raw blob: {blob[:200]}\n"
                        f"Decoded: {decoded[:500]}\n"
                        f"Flag: {flag}"
                    ),
                    evidence=f"flag={flag} chain={chain} blob={blob[:100]}",
                    cvss_score=10.0,
                ))

    # Also try direct page content from scan target
    await ctx.log(
        f"Crypto solver complete: {flags_found} flag(s) found",
        level="success" if flags_found else "info",
        module="crypto_solver",
    )
    return result
