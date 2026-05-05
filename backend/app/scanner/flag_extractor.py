"""
Flag extractor utility — shared across all CTF scanner modules.
Builds a compiled regex from user-supplied format + built-in patterns,
then finds flags in HTTP responses (body, headers, cookies).
Also decodes common encodings (base64, hex, url, rot13) and searches there.
"""
from __future__ import annotations

import base64
import binascii
import codecs
import re
import urllib.parse


# ── Built-in flag patterns ────────────────────────────────────────────────────

_BUILTIN_PREFIXES = [
    "FLAG", "CTF", "HTB", "THM", "DUCTF", "picoCTF", "flag", "ctf",
    "PCTF", "DH", "TUCTF", "RCTF", "BCTF", "ISITDTU", "WPICTF",
    "aues", "AUES",
]

_BUILTIN_PATTERN = (
    r"(?:"
    + "|".join(re.escape(p) for p in _BUILTIN_PREFIXES)
    + r")\{[A-Za-z0-9_!@#$%^&*()\-+=<>?.,:;|\\/ ]{1,200}\}"
)

# Generic: 2-12 uppercase letters/digits followed by {content}
_GENERIC_PATTERN = r"\b[A-Z][A-Z0-9_]{1,11}\{[A-Za-z0-9_!@#$%^&*()\-+=]{4,200}\}"


def build_flag_pattern(custom_format: str | None) -> re.Pattern:
    """
    Compile a regex that matches:
    1. The user's custom format (if provided) — treated as prefix before {
    2. All built-in CTF formats
    3. Generic WORD{...} pattern

    custom_format examples:
      "aues{...}"  → prefix "aues"
      "MYCTF{"     → prefix "MYCTF"
      raw regex    → used as-is if it contains special chars like (?:...)
    """
    parts: list[str] = []

    if custom_format:
        cf = custom_format.strip()
        # If user typed "aues{...}" or "aues{" — extract prefix
        m = re.match(r"^([A-Za-z0-9_]{1,20})\{", cf)
        if m:
            prefix = m.group(1)
            parts.append(
                re.escape(prefix) + r"\{[A-Za-z0-9_!@#$%^&*()\-+=<>?.,:;|\\/ ]{1,200}\}"
            )
        else:
            # Treat as raw regex fragment
            try:
                re.compile(cf)
                parts.append(cf)
            except re.error:
                parts.append(re.escape(cf))

    parts.append(_BUILTIN_PATTERN)
    parts.append(_GENERIC_PATTERN)

    combined = "(?:" + "|".join(parts) + ")"
    return re.compile(combined, re.IGNORECASE)


def extract_flags(text: str, pattern: re.Pattern) -> list[str]:
    """Return deduplicated list of flag strings found in text."""
    return list(dict.fromkeys(pattern.findall(text)))


def search_flags_in_response(
    body: str,
    headers: dict,
    cookies: dict,
    pattern: re.Pattern,
) -> list[str]:
    """Search body + all header values + all cookie values."""
    found: list[str] = []
    found.extend(extract_flags(body, pattern))
    for v in headers.values():
        found.extend(extract_flags(str(v), pattern))
    for v in cookies.values():
        found.extend(extract_flags(str(v), pattern))
    return list(dict.fromkeys(found))


# ── Encoding-aware search ─────────────────────────────────────────────────────

def _try_base64(text: str) -> str:
    """Attempt to decode base64 chunks found in text."""
    decoded_parts: list[str] = []
    # Find base64-like blobs (min 16 chars)
    for blob in re.findall(r"[A-Za-z0-9+/]{16,}={0,2}", text):
        try:
            dec = base64.b64decode(blob + "==").decode("utf-8", errors="ignore")
            if dec.isprintable() and len(dec) > 4:
                decoded_parts.append(dec)
        except Exception:
            pass
    return " ".join(decoded_parts)


def _try_hex(text: str) -> str:
    """Attempt to decode hex strings found in text."""
    decoded_parts: list[str] = []
    for blob in re.findall(r"(?:0x)?[0-9a-fA-F]{8,}", text):
        blob_clean = blob.lstrip("0x")
        if len(blob_clean) % 2 != 0:
            continue
        try:
            dec = bytes.fromhex(blob_clean).decode("utf-8", errors="ignore")
            if dec.isprintable() and len(dec) > 3:
                decoded_parts.append(dec)
        except Exception:
            pass
    return " ".join(decoded_parts)


def _try_rot13(text: str) -> str:
    return codecs.decode(text, "rot_13")


def _try_urldecode(text: str) -> str:
    return urllib.parse.unquote(text)


def search_flags_decoded(text: str, pattern: re.Pattern) -> list[str]:
    """
    Search for flags in text AND in decoded variants:
    base64, hex, rot13, url-decode.
    ROT13 is only applied when no flags found in plain text (avoids SYNT{} noise).
    Returns deduplicated list.
    """
    found: list[str] = extract_flags(text, pattern)

    # base64, hex, urldecode — always try
    for decoder in (_try_base64, _try_hex, _try_urldecode):
        try:
            decoded = decoder(text)
            if decoded:
                found.extend(extract_flags(decoded, pattern))
        except Exception:
            pass

    # ROT13 only if nothing found yet (prevents SYNT{} artifacts from FLAG{} text)
    if not found:
        try:
            decoded = _try_rot13(text)
            if decoded:
                found.extend(extract_flags(decoded, pattern))
        except Exception:
            pass

    return list(dict.fromkeys(found))
