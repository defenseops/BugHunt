"""
Rule Engine — post-processing pipeline applied after all scanner modules finish.

Steps:
  1. Deduplicate findings (merge by canonical key)
  2. Enrich CVSS 3.1 scores (CVE lookup table + heuristics for non-CVE findings)
  3. Normalise severity based on final CVSS score
  4. Build attack paths (chain related findings into exploit chains)
  5. Sort findings: critical → high → medium → low → info
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from app.scanner.base import Finding

if TYPE_CHECKING:
    from app.scanner.context import ScanContext


# ── CVSS 3.1 severity bands ───────────────────────────────────────────────────

def cvss_to_severity(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "info"


_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


# ── Static CVE → CVSS 3.1 lookup ─────────────────────────────────────────────
# Covers common CVEs seen in pentest scope. Dynamically augmented at runtime
# via findings that already carry cvss_score from Shodan / scanner output.

_CVE_CVSS: dict[str, tuple[float, str]] = {
    # (score, vector)
    "CVE-2017-0144":  (9.3,  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),   # EternalBlue / MS17-010
    "CVE-2014-0160":  (7.5,  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),   # Heartbleed
    "CVE-2019-0708":  (9.8,  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),   # BlueKeep
    "CVE-2021-44228": (10.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),   # Log4Shell
    "CVE-2021-41773": (9.8,  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),   # Apache path traversal
    "CVE-2021-42013": (9.8,  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),   # Apache path traversal (followup)
    "CVE-2022-1388":  (9.8,  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),   # F5 BIG-IP auth bypass
    "CVE-2022-22965": (9.8,  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),   # Spring4Shell
    "CVE-2023-23397": (9.8,  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),   # Outlook NTLM relay
    "CVE-2023-44487": (7.5,  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"),   # HTTP/2 Rapid Reset
    "CVE-2014-6271":  (10.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),   # Shellshock
    "CVE-2021-21985": (9.8,  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),   # VMware vCenter RCE
    "CVE-2020-1472":  (10.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),   # Zerologon
    "CVE-2021-34527": (8.8,  "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"),   # PrintNightmare
    "CVE-2018-13379": (9.8,  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),   # Fortinet SSL-VPN path traversal
    "CVE-2019-11510": (10.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),   # Pulse Secure arbitrary file read
    "CVE-2017-5638":  (10.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),   # Apache Struts2 RCE
    "CVE-2018-7600":  (9.8,  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),   # Drupalgeddon2
    "CVE-2019-0192":  (9.8,  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),   # Apache Solr RCE
    "CVE-2020-14882": (9.8,  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),   # Oracle WebLogic RCE
}


def _lookup_cve(cve_id: str) -> tuple[float, str] | None:
    return _CVE_CVSS.get(cve_id.upper())


# ── Heuristic CVSS scores for non-CVE findings ───────────────────────────────
# Keyed by (finding_type, severity_word_in_title).

_TITLE_CVSS_HINTS: list[tuple[re.Pattern, float, str]] = [
    # brute-force / credential
    (re.compile(r"credential|valid login|brute.?force|password found|auth bypass", re.I),
     8.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),

    # remote code execution indicators
    (re.compile(r"\bRCE\b|remote code|command injection|shell upload", re.I),
     9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),

    # SQL injection
    (re.compile(r"sql.?inject|sqli\b", re.I),
     8.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),

    # XSS
    (re.compile(r"\bxss\b|cross.?site script", re.I),
     6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),

    # open redirect
    (re.compile(r"open redirect", re.I),
     6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),

    # LFI / path traversal
    (re.compile(r"path traversal|local file inclusion|lfi\b|directory traversal", re.I),
     7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),

    # SSRF
    (re.compile(r"\bssrf\b|server.?side request", re.I),
     8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"),

    # exposed admin / sensitive endpoint
    (re.compile(r"admin panel|phpmyadmin|wp-admin|webshell|/console|actuator", re.I),
     7.2, "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"),

    # weak SSL protocol
    (re.compile(r"SSLv2|SSLv3|TLS 1\.0|TLS 1\.1|BEAST|POODLE|weak cipher", re.I),
     5.9, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"),

    # cert expired / self-signed
    (re.compile(r"cert.*expir|self.?signed|cert.*mismatch", re.I),
     5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),

    # missing security header
    (re.compile(r"missing.*(HSTS|CSP|Content-Security|X-Frame|X-Content|Referrer|Permissions)", re.I),
     4.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N"),

    # Heartbleed (sslyze finding)
    (re.compile(r"heartbleed|CVE-2014-0160", re.I),
     7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),

    # zone transfer
    (re.compile(r"zone transfer|AXFR", re.I),
     5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),

    # open dangerous port
    (re.compile(r"port 23/|telnet|port 21/|ftp.*open|port 445|smb.*open|port 3389|rdp.*open", re.I),
     5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
]


def _heuristic_cvss(finding: Finding) -> tuple[float, str] | None:
    text = f"{finding.title} {finding.description or ''}"
    for pattern, score, vector in _TITLE_CVSS_HINTS:
        if pattern.search(text):
            return score, vector
    return None


# ── Deduplication ─────────────────────────────────────────────────────────────

def _dedup_key(f: Finding) -> str:
    """Canonical key: type + normalised title + port."""
    title_norm = re.sub(r"\s+", " ", (f.title or "").lower().strip())
    # strip leading [STATUS_CODE] from dirscan titles so /admin and /admin/ merge
    title_norm = re.sub(r"^\[\d{3}\]\s*", "", title_norm)
    port_part = str(f.port) if f.port else ""
    return f"{f.type}|{title_norm}|{port_part}"


def _merge(base: Finding, duplicate: Finding) -> Finding:
    """Merge duplicate into base, keeping the more severe / more informative fields."""
    if not base.cvss_score and duplicate.cvss_score:
        base.cvss_score = duplicate.cvss_score
    if not base.cvss_vector and duplicate.cvss_vector:
        base.cvss_vector = duplicate.cvss_vector
    if not base.cve_id and duplicate.cve_id:
        base.cve_id = duplicate.cve_id
    if not base.msf_module and duplicate.msf_module:
        base.msf_module = duplicate.msf_module
    if not base.remediation and duplicate.remediation:
        base.remediation = duplicate.remediation
    # Pick higher severity
    base_rank = _SEVERITY_RANK.get(base.severity or "info", 4)
    dup_rank  = _SEVERITY_RANK.get(duplicate.severity or "info", 4)
    if dup_rank < base_rank:
        base.severity = duplicate.severity
    return base


def deduplicate(findings: list[Finding]) -> list[Finding]:
    seen: dict[str, Finding] = {}
    for f in findings:
        key = _dedup_key(f)
        if key in seen:
            seen[key] = _merge(seen[key], f)
        else:
            seen[key] = f
    return list(seen.values())


# ── CVSS enrichment ───────────────────────────────────────────────────────────

def enrich_cvss(findings: list[Finding]) -> list[Finding]:
    for f in findings:
        # Already has a score — just normalise severity
        if f.cvss_score:
            f.severity = cvss_to_severity(f.cvss_score)
            continue

        # CVE lookup
        if f.cve_id:
            result = _lookup_cve(f.cve_id)
            if result:
                f.cvss_score, f.cvss_vector = result
                f.severity = cvss_to_severity(f.cvss_score)
                continue

        # Heuristic
        result = _heuristic_cvss(f)
        if result:
            f.cvss_score, f.cvss_vector = result
            f.severity = cvss_to_severity(f.cvss_score)

    return findings


# ── Attack Path Builder ───────────────────────────────────────────────────────

@dataclass
class AttackPath:
    id: str
    title: str
    severity: str
    steps: list[str] = field(default_factory=list)          # human-readable chain
    finding_ids: list[int] = field(default_factory=list)    # indices into findings list
    cvss_score: float | None = None
    msf_module: str | None = None
    description: str = ""


# Patterns linking a vulnerability class to its exploitation technique
_EXPLOIT_CHAINS: list[dict] = [
    {
        "trigger": re.compile(r"EternalBlue|MS17-010|CVE-2017-0144|port 445|smb.*open", re.I),
        "title":   "SMB → EternalBlue → Remote Code Execution",
        "steps":   ["Discovered open SMB port (445/tcp)",
                    "Target is vulnerable to EternalBlue (MS17-010 / CVE-2017-0144)",
                    "Exploit with metasploit/exploit/windows/smb/ms17_010_eternalblue",
                    "Obtain SYSTEM-level shell"],
        "severity": "critical",
        "cvss":    9.3,
    },
    {
        "trigger": re.compile(r"BlueKeep|CVE-2019-0708|port 3389|rdp.*open", re.I),
        "title":   "RDP → BlueKeep → Remote Code Execution",
        "steps":   ["Discovered open RDP port (3389/tcp)",
                    "Target may be vulnerable to BlueKeep (CVE-2019-0708)",
                    "Exploit with metasploit/exploit/windows/rdp/cve_2019_0708_bluekeep_rce",
                    "Obtain pre-auth remote code execution"],
        "severity": "critical",
        "cvss":    9.8,
    },
    {
        "trigger": re.compile(r"credential|valid login|brute.?force.*success|password found", re.I),
        "title":   "Credential Exposure → Lateral Movement",
        "steps":   ["Discovered valid credentials via brute-force or credential stuffing",
                    "Authenticate to exposed service",
                    "Leverage access for lateral movement or privilege escalation"],
        "severity": "high",
        "cvss":    8.1,
    },
    {
        "trigger": re.compile(r"sql.?inject|sqli\b", re.I),
        "title":   "SQLi → Data Exfiltration → Potential RCE",
        "steps":   ["Identified SQL injection parameter",
                    "Dump database credentials / user data",
                    "If xp_cmdshell or FILE privilege available — escalate to RCE"],
        "severity": "high",
        "cvss":    8.8,
    },
    {
        "trigger": re.compile(r"\bRCE\b|remote code execution|command injection|shell upload", re.I),
        "title":   "Remote Code Execution → Full Compromise",
        "steps":   ["Identified remote code / command injection vector",
                    "Upload or execute reverse shell payload",
                    "Obtain interactive shell on target"],
        "severity": "critical",
        "cvss":    9.8,
    },
    {
        "trigger": re.compile(r"Log4Shell|CVE-2021-44228", re.I),
        "title":   "Log4Shell → Remote Code Execution",
        "steps":   ["Target uses Log4j with JNDI lookup enabled",
                    "Inject JNDI payload via user-controlled field (e.g. User-Agent)",
                    "Trigger callback to attacker LDAP server",
                    "Achieve unauthenticated Remote Code Execution"],
        "severity": "critical",
        "cvss":    10.0,
    },
    {
        "trigger": re.compile(r"Shellshock|CVE-2014-6271", re.I),
        "title":   "Shellshock → Remote Code Execution",
        "steps":   ["Bash version vulnerable to Shellshock (CVE-2014-6271)",
                    "Inject payload into HTTP headers (User-Agent / Referer)",
                    "Achieve unauthenticated Remote Code Execution via CGI"],
        "severity": "critical",
        "cvss":    10.0,
    },
    {
        "trigger": re.compile(r"admin panel|phpmyadmin|wp-admin|exposed.*admin", re.I),
        "title":   "Exposed Admin Panel → Authentication Bypass / Account Takeover",
        "steps":   ["Discovered exposed administrative interface",
                    "Attempt default or brute-forced credentials",
                    "Gain admin-level access to application"],
        "severity": "high",
        "cvss":    7.2,
    },
    {
        "trigger": re.compile(r"zone transfer|AXFR", re.I),
        "title":   "DNS Zone Transfer → Infrastructure Enumeration",
        "steps":   ["DNS zone transfer (AXFR) succeeded",
                    "Full DNS records exposed (internal hostnames, IPs, MX, SPF)",
                    "Use exposed IPs/hosts as additional scan targets"],
        "severity": "medium",
        "cvss":    5.3,
    },
    {
        "trigger": re.compile(r"Spring4Shell|CVE-2022-22965", re.I),
        "title":   "Spring4Shell → Remote Code Execution",
        "steps":   ["Spring Framework vulnerable to CVE-2022-22965 (Spring4Shell)",
                    "Exploit via ClassLoader manipulation with multipart upload",
                    "Achieve unauthenticated Remote Code Execution"],
        "severity": "critical",
        "cvss":    9.8,
    },
]


def build_attack_paths(findings: list[Finding]) -> list[AttackPath]:
    paths: list[AttackPath] = []
    seen_triggers: set[str] = set()

    for chain in _EXPLOIT_CHAINS:
        pattern: re.Pattern = chain["trigger"]
        matched_indices: list[int] = []

        for idx, f in enumerate(findings):
            text = f"{f.title} {f.description or ''} {f.cve_id or ''}"
            if pattern.search(text):
                matched_indices.append(idx)

        if not matched_indices:
            continue

        trigger_key = chain["title"]
        if trigger_key in seen_triggers:
            continue
        seen_triggers.add(trigger_key)

        # Find best msf_module from matched findings
        msf = next(
            (findings[i].msf_module for i in matched_indices if findings[i].msf_module),
            None,
        )

        path = AttackPath(
            id=f"ap-{len(paths) + 1:03d}",
            title=chain["title"],
            severity=chain["severity"],
            steps=chain["steps"],
            finding_ids=matched_indices,
            cvss_score=chain["cvss"],
            msf_module=msf,
            description=(
                f"Attack chain identified from {len(matched_indices)} related finding(s). "
                f"CVSS {chain['cvss']} — {chain['severity'].upper()}."
            ),
        )
        paths.append(path)

    # Sort by severity
    paths.sort(key=lambda p: _SEVERITY_RANK.get(p.severity, 4))
    return paths


# ── Sorter ────────────────────────────────────────────────────────────────────

def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda f: (
            _SEVERITY_RANK.get(f.severity or "info", 4),
            -(f.cvss_score or 0.0),
        ),
    )


# ── Main entry point ──────────────────────────────────────────────────────────

@dataclass
class RuleEngineResult:
    findings: list[Finding]
    attack_paths: list[AttackPath]
    stats: dict


async def run_rule_engine(
    ctx: "ScanContext",
    findings: list[Finding],
) -> RuleEngineResult:
    """
    Post-processing pipeline: dedup → CVSS enrich → attack paths → sort.
    Returns enriched findings and attack path chains.
    """
    raw_count = len(findings)
    await ctx.log(f"Rule Engine: processing {raw_count} raw findings", module="rule_engine")

    # 1. Deduplicate
    findings = deduplicate(findings)
    dedup_count = len(findings)
    await ctx.log(
        f"Deduplication: {raw_count} → {dedup_count} findings ({raw_count - dedup_count} merged)",
        level="info",
        module="rule_engine",
    )

    # 2. CVSS enrichment
    findings = enrich_cvss(findings)
    enriched = sum(1 for f in findings if f.cvss_score)
    await ctx.log(
        f"CVSS enrichment: {enriched}/{dedup_count} findings have CVSS scores",
        level="info",
        module="rule_engine",
    )

    # 3. Attack paths
    attack_paths = build_attack_paths(findings)
    await ctx.log(
        f"Attack paths identified: {len(attack_paths)}",
        level="warning" if attack_paths else "info",
        module="rule_engine",
    )
    for ap in attack_paths:
        await ctx.log(
            f"  [{ap.severity.upper()}] {ap.title} (CVSS {ap.cvss_score})",
            level="warning" if ap.severity in ("critical", "high") else "info",
            module="rule_engine",
        )

    # 4. Sort
    findings = sort_findings(findings)

    # Stats
    sev_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        key = f.severity or "info"
        sev_counts[key] = sev_counts.get(key, 0) + 1

    stats = {
        "raw_findings": raw_count,
        "unique_findings": dedup_count,
        "duplicates_merged": raw_count - dedup_count,
        "with_cvss": enriched,
        "attack_paths": len(attack_paths),
        **sev_counts,
    }

    await ctx.log(
        f"Rule Engine complete: {dedup_count} findings | "
        f"critical={sev_counts['critical']} high={sev_counts['high']} "
        f"medium={sev_counts['medium']} low={sev_counts['low']} | "
        f"{len(attack_paths)} attack path(s)",
        level="warning" if sev_counts["critical"] or sev_counts["high"] else "success",
        module="rule_engine",
    )

    return RuleEngineResult(findings=findings, attack_paths=attack_paths, stats=stats)
