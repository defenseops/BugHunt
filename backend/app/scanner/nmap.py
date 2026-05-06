"""
Nmap recon module.
Runs: nmap -sV -sC -O --script vuln -oX - <target>
Parses XML output → Finding list.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import TYPE_CHECKING

from app.scanner.base import Finding, ScanResult, run_cmd

if TYPE_CHECKING:
    from app.scanner.context import ScanContext


def _strip_url_scheme(target: str) -> str:
    """Extract bare host[:port] from a URL, or return target unchanged."""
    target = re.sub(r"^https?://", "", target)
    return target.split("/")[0]

# CVE severity heuristics by CVSS (when nmap script reports score)
_CVSS_SEVERITY = [
    (9.0, "critical"),
    (7.0, "high"),
    (4.0, "medium"),
    (0.1, "low"),
]

_SERVICE_REMEDIATIONS: dict[str, str] = {
    "ftp":    "Disable anonymous FTP. Use SFTP/SCP instead.",
    "telnet": "Disable Telnet. Use SSH with key-based authentication.",
    "smtp":   "Configure SMTP authentication. Disable open relay.",
    "smb":    "Patch SMB. Disable SMBv1. Restrict access with firewall rules.",
    "rdp":    "Enable NLA. Restrict RDP access by IP. Keep OS patched.",
    "vnc":    "Require strong VNC password. Tunnel over SSH.",
    "http":   "Ensure web server is patched. Enable HTTPS.",
    "https":  "Check TLS version and cipher suites. Disable TLS 1.0/1.1.",
    "mysql":  "Bind to 127.0.0.1. Use strong credentials. Restrict remote access.",
    "mssql":  "Disable SA account. Use Windows Authentication. Patch regularly.",
    "ssh":    "Disable password auth. Use SSH keys. Keep OpenSSH patched.",
}


def _cvss_to_severity(score: float) -> str:
    for threshold, label in _CVSS_SEVERITY:
        if score >= threshold:
            return label
    return "info"


def _service_severity(service: str) -> str:
    risky = {"telnet", "ftp", "vnc", "rdp", "smb", "rpc"}
    medium = {"http", "smtp", "mysql", "mssql", "mongodb", "redis"}
    if service.lower() in risky:
        return "high"
    if service.lower() in medium:
        return "medium"
    return "info"


def _parse_nmap_xml(xml_text: str) -> list[Finding]:
    findings: list[Finding] = []

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return findings

    for host in root.findall("host"):
        state = host.find("status")
        if state is None or state.get("state") != "up":
            continue

        # ── Open ports → port findings ─────────────────────────────────────
        for port_el in host.findall(".//port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue

            portid   = int(port_el.get("portid", 0))
            protocol = port_el.get("protocol", "tcp")
            svc_el   = port_el.find("service")
            svc_name = svc_el.get("name", "unknown") if svc_el is not None else "unknown"
            svc_prod = svc_el.get("product", "") if svc_el is not None else ""
            svc_ver  = svc_el.get("version", "") if svc_el is not None else ""
            version_str = f"{svc_prod} {svc_ver}".strip() or None

            severity = _service_severity(svc_name)
            remediation = _SERVICE_REMEDIATIONS.get(svc_name.lower())

            findings.append(Finding(
                type="port",
                title=f"Open port {portid}/{protocol} — {svc_name}",
                severity=severity,
                description=f"Service '{svc_name}' detected on port {portid}/{protocol}."
                            + (f" Version: {version_str}" if version_str else ""),
                port=portid,
                protocol=protocol,
                service=svc_name,
                version=version_str,
                remediation=remediation,
            ))

            # ── NSE script output per port ─────────────────────────────────
            for script in port_el.findall("script"):
                script_id  = script.get("id", "")
                script_out = script.get("output", "")
                _extract_script_finding(findings, script_id, script_out, portid, protocol, svc_name)

        # ── Host-level scripts (OS detection, vuln, etc.) ──────────────────
        for script in host.findall(".//hostscript/script"):
            script_id  = script.get("id", "")
            script_out = script.get("output", "")
            _extract_script_finding(findings, script_id, script_out, None, None, None)

        # ── OS detection ───────────────────────────────────────────────────
        os_el = host.find("os")
        if os_el is not None:
            for osmatch in os_el.findall("osmatch"):
                name = osmatch.get("name", "")
                acc  = osmatch.get("accuracy", "?")
                if int(acc) >= 85:
                    findings.append(Finding(
                        type="osdetect",
                        title=f"OS detected: {name}",
                        severity="info",
                        description=f"Nmap identified OS as '{name}' with {acc}% accuracy.",
                    ))
                    break

    return findings


def _extract_script_finding(
    findings: list[Finding],
    script_id: str,
    script_out: str,
    port: int | None,
    protocol: str | None,
    service: str | None,
) -> None:
    """Map NSE script output to Finding objects."""
    out_lower = script_out.lower()

    # vuln scripts
    if "vuln" in script_id or "exploit" in script_id:
        severity = "high"
        cve_id = None

        # Extract CVE if present
        import re
        cve_match = re.search(r"CVE-\d{4}-\d+", script_out)
        if cve_match:
            cve_id = cve_match.group(0)

        if "vulnerable" in out_lower or "exploitable" in out_lower:
            severity = "critical" if "exploitable" in out_lower else "high"
        elif "not vulnerable" in out_lower:
            return

        findings.append(Finding(
            type="cve" if cve_id else "misconfig",
            title=f"NSE [{script_id}]: {script_out[:120]}",
            severity=severity,
            description=script_out,
            cve_id=cve_id,
            port=port,
            protocol=protocol,
            service=service,
            raw_output=script_out,
            remediation="Apply vendor patch or update software to latest version.",
        ))

    # ssl/tls issues
    elif script_id in ("ssl-dh-params", "ssl-poodle", "ssl-heartbleed", "ssl-ccs-injection"):
        findings.append(Finding(
            type="ssl",
            title=f"TLS/SSL issue: {script_id}",
            severity="high",
            description=script_out,
            port=port,
            protocol=protocol,
            service=service,
            remediation="Update TLS configuration. Disable weak ciphers and protocols.",
        ))

    # anonymous ftp
    elif script_id == "ftp-anon" and "anonymous" in out_lower:
        findings.append(Finding(
            type="misconfig",
            title="FTP anonymous login allowed",
            severity="high",
            description=script_out,
            port=port,
            protocol=protocol,
            service="ftp",
            remediation="Disable anonymous FTP access.",
        ))

    # smb signing
    elif script_id == "smb-security-mode" and "not required" in out_lower:
        findings.append(Finding(
            type="misconfig",
            title="SMB message signing not required",
            severity="medium",
            description=script_out,
            port=port,
            protocol=protocol,
            service="smb",
            remediation="Enable SMB signing: set 'Microsoft network server: Digitally sign communications' to Required.",
        ))


async def run_nmap(ctx: "ScanContext", target: str, scan_type: str) -> ScanResult:
    """
    Entry point called by the Celery task.
    scan_type: full | port | vuln | web | ctf
    """
    result = ScanResult()

    # nmap expects a bare host, not a URL
    nmap_target = _strip_url_scheme(target)

    # Build nmap command based on scan type
    base_flags = ["-sV", "--version-intensity", "5", "-T4", "--open"]
    script_flags: list[str] = []
    os_flags: list[str] = []

    if scan_type == "port":
        flags = ["-sV", "-T4", "--open", "-p-"]
    elif scan_type == "vuln":
        flags = base_flags + ["--script", "vuln,exploit", "-p-"]
        os_flags = ["-O"]
    elif scan_type in ("web", "ctf"):
        flags = base_flags + [
            "--script", "http-enum,http-headers,http-methods,http-title,http-auth-finder",
            "-p", "80,443,8080,8443,8000,8888,3000,5000,1337,4000,9000",
        ]
    else:  # full
        flags = base_flags + ["--script", "default,vuln", "-p-"]
        os_flags = ["-O"]

    cmd = ["nmap"] + flags + os_flags + ["-oX", "-", nmap_target]

    await ctx.log(f"Running: {' '.join(cmd)}", module="nmap")

    timeout = 600 if scan_type == "full" else 300
    rc, stdout, stderr = run_cmd(cmd, timeout=timeout)

    if rc == -1:
        err = stderr or "nmap timed out"
        await ctx.log(f"nmap error: {err}", level="error", module="nmap")
        result.errors.append(err)
        return result

    findings = _parse_nmap_xml(stdout)

    port_count = sum(1 for f in findings if f.type == "port")
    vuln_count = sum(1 for f in findings if f.type in ("cve", "misconfig", "ssl"))
    await ctx.log(
        f"nmap complete: {port_count} open ports, {vuln_count} vulnerabilities",
        level="success",
        module="nmap",
    )

    result.findings = findings
    return result
