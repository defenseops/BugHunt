"""
Hash cracking module — Phase 7.4.
Identifies hash type (haiti/hashid), then cracks with john/hashcat.
Receives hashes collected by smb_ad and post-exploitation modules.
Only runs on scan_type in ('full', 'vuln').
"""
from __future__ import annotations

import re
import shutil
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

from app.scanner.base import Finding, ScanResult, run_cmd

if TYPE_CHECKING:
    from app.scanner.context import ScanContext

# Minimal wordlist — enough for lab/CTF targets
_CRACK_PASSWORDS = [
    "password", "password1", "123456", "12345678", "qwerty", "letmein",
    "welcome", "admin", "admin123", "root", "toor", "test", "guest",
    "changeme", "default", "monkey", "dragon", "master", "secret",
    "sunshine", "princess", "iloveyou", "shadow", "sunshine",
    "1q2w3e4r", "abc123", "pass", "passw0rd", "pa$$word",
]

# hashcat mode map: (regex pattern, mode, name)
_HASH_MODES: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"^\$2[aby]\$"), "3200", "bcrypt"),
    (re.compile(r"^\$6\$"), "1800", "sha512crypt"),
    (re.compile(r"^\$5\$"), "500", "sha256crypt"),
    (re.compile(r"^\$1\$"), "500", "md5crypt"),
    (re.compile(r"^\$krb5asrep\$"), "18200", "Kerberos AS-REP"),
    (re.compile(r"^\$krb5tgs\$"), "13100", "Kerberos TGS"),
    (re.compile(r"^[a-fA-F0-9]{32}$"), "0", "MD5"),
    (re.compile(r"^[a-fA-F0-9]{40}$"), "100", "SHA1"),
    (re.compile(r"^[a-fA-F0-9]{64}$"), "1400", "SHA256"),
    (re.compile(r"^[a-fA-F0-9]{128}$"), "1700", "SHA512"),
    (re.compile(r"^[a-fA-F0-9]{32}:[a-fA-F0-9]{32}$"), "1000", "NTLM"),
    (re.compile(r"^\$NTLMv2\$|::.*:[a-fA-F0-9]{32}:[a-fA-F0-9]+:"), "5600", "NetNTLMv2"),
]


def _detect_hash_type(hash_str: str) -> tuple[str, str]:
    """Return (hashcat_mode, hash_name) for a given hash string."""
    for pattern, mode, name in _HASH_MODES:
        if pattern.search(hash_str.strip()):
            return mode, name
    return "0", "unknown"


def _extract_hashes_from_findings(findings: list[Finding]) -> list[str]:
    """Pull hash strings from finding evidence fields."""
    hashes: list[str] = []
    seen: set[str] = set()

    hash_pattern = re.compile(
        r"(?:"
        r"\$2[aby]\$\d+\$[A-Za-z0-9./]{53}"         # bcrypt
        r"|\$6\$[A-Za-z0-9./]+\$[A-Za-z0-9./]+"    # sha512crypt
        r"|\$krb5asrep\$[^\s]+"                     # AS-REP
        r"|\$krb5tgs\$[^\s]+"                       # TGS
        r"|[a-fA-F0-9]{32}(?::[a-fA-F0-9]{32})?"   # NTLM / MD5
        r"|[a-fA-F0-9]{40}"                         # SHA1
        r"|[a-fA-F0-9]{64}"                         # SHA256
        r")"
    )

    for f in findings:
        for src in (f.evidence or "", f.description or ""):
            for m in hash_pattern.finditer(src):
                h = m.group(0)
                if h not in seen:
                    hashes.append(h)
                    seen.add(h)

    return hashes[:50]


async def _crack_with_john(
    ctx: "ScanContext",
    hash_str: str,
    hash_name: str,
    words_file: str,
) -> str | None:
    if not shutil.which("john"):
        return None

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write(hash_str + "\n")
        hash_file = f.name

    try:
        rc, stdout, stderr = run_cmd(
            ["john", hash_file, f"--wordlist={words_file}", "--format=auto"],
            timeout=60,
        )
        if rc == -1:
            return None

        # Show cracked
        rc2, out2, _ = run_cmd(["john", "--show", hash_file], timeout=10)
        m = re.search(r"^[^:]+:(.+):", out2, re.MULTILINE)
        if m:
            return m.group(1).strip()
    finally:
        Path(hash_file).unlink(missing_ok=True)

    return None


async def _crack_with_hashcat(
    ctx: "ScanContext",
    hash_str: str,
    mode: str,
    words_file: str,
) -> str | None:
    if not shutil.which("hashcat"):
        return None

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write(hash_str + "\n")
        hash_file = f.name

    pot_file = hash_file + ".pot"
    try:
        rc, stdout, stderr = run_cmd(
            [
                "hashcat", "-m", mode, hash_file, words_file,
                "--potfile-path", pot_file,
                "--quiet", "--force",
                "-O",        # optimized kernel
            ],
            timeout=90,
        )

        if rc == -1:
            return None

        # Read potfile
        if Path(pot_file).exists():
            pot = Path(pot_file).read_text().strip()
            if ":" in pot:
                return pot.split(":", 1)[1]
    finally:
        Path(hash_file).unlink(missing_ok=True)
        Path(pot_file).unlink(missing_ok=True)

    return None


async def run_hash_crack(
    ctx: "ScanContext",
    scan_type: str,
    all_findings: list[Finding],
) -> ScanResult:
    result = ScanResult()

    if scan_type not in ("full", "vuln"):
        return result

    hashes = _extract_hashes_from_findings(all_findings)
    if not hashes:
        await ctx.log("hash_crack: no hashes found in findings", module="hash_crack")
        return result

    await ctx.log(f"hash_crack: found {len(hashes)} hash(es) to crack", module="hash_crack")

    # Write wordlist
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        # Try SecLists rockyou if available
        rockyou = Path("/usr/share/wordlists/rockyou.txt")
        if rockyou.exists():
            # Use first 10000 lines for speed
            try:
                lines = rockyou.read_text(errors="replace").splitlines()[:10000]
                f.write("\n".join(lines))
            except Exception:
                f.write("\n".join(_CRACK_PASSWORDS))
        else:
            f.write("\n".join(_CRACK_PASSWORDS))
        words_file = f.name

    try:
        for hash_str in hashes:
            mode, hash_name = _detect_hash_type(hash_str)
            await ctx.log(f"hash_crack: cracking {hash_name} hash", module="hash_crack")

            cracked: str | None = None

            # Try hashcat first (GPU), then john (CPU)
            cracked = await _crack_with_hashcat(ctx, hash_str, mode, words_file)
            if not cracked:
                cracked = await _crack_with_john(ctx, hash_str, hash_name, words_file)

            if cracked:
                await ctx.log(
                    f"hash_crack: CRACKED {hash_name}: {hash_str[:30]}... → {cracked}",
                    level="error",
                    module="hash_crack",
                )
                result.findings.append(Finding(
                    type="brute",
                    title=f"Password cracked ({hash_name}): {cracked!r}",
                    severity="critical",
                    description=(
                        f"Hash cracking succeeded for a {hash_name} hash.\n"
                        f"Hash: {hash_str[:60]}...\n"
                        f"Plaintext: {cracked}"
                    ),
                    evidence=f"hash={hash_str[:60]}... plaintext={cracked}",
                    remediation=(
                        "Change the compromised password immediately. "
                        "Enforce a strong password policy (min 16 chars, complexity). "
                        "Use bcrypt/argon2 for password hashing — avoid MD5/SHA1/NTLM. "
                        "Enable multi-factor authentication."
                    ),
                    cvss_score=9.8,
                ))
            else:
                await ctx.log(
                    f"hash_crack: could not crack {hash_name} hash",
                    module="hash_crack",
                )
    finally:
        Path(words_file).unlink(missing_ok=True)

    return result
