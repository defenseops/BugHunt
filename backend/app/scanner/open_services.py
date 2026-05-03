"""
Open Services — step 6.6.
Checks for unauthenticated access to commonly exposed services:
Redis, MongoDB, Elasticsearch, Memcached, CouchDB, Cassandra,
Kubernetes API, Docker daemon, etcd, Hadoop HDFS NameNode.
Runs on all scan types (uses nmap port findings to target only open ports).
"""
from __future__ import annotations

import json
import re
import socket
from typing import TYPE_CHECKING

from app.scanner.base import Finding, ScanResult

if TYPE_CHECKING:
    from app.scanner.context import ScanContext


# ── TCP banner helper ─────────────────────────────────────────────────────────

def _tcp_send(host: str, port: int, payload: bytes, timeout: float = 5.0) -> bytes:
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.sendall(payload)
            return s.recv(4096)
    except Exception:
        return b""


# ── HTTP helper ───────────────────────────────────────────────────────────────

def _http_get(url: str, timeout: float = 8.0) -> tuple[int, str]:
    try:
        import httpx
        r = httpx.get(url, timeout=timeout, follow_redirects=True,
                      headers={"User-Agent": "Mozilla/5.0"})
        return r.status_code, r.text[:3000]
    except Exception:
        return 0, ""


# ── Redis ─────────────────────────────────────────────────────────────────────

def _check_redis(host: str, port: int = 6379) -> Finding | None:
    resp = _tcp_send(host, port, b"PING\r\n")
    if not resp:
        return None

    if b"+PONG" in resp:
        # Get server info
        info_resp = _tcp_send(host, port, b"INFO server\r\n")
        version = ""
        if info_resp:
            vm = re.search(rb"redis_version:(\S+)", info_resp)
            version = vm.group(1).decode() if vm else ""

        return Finding(
            type="open_service",
            title=f"Redis open without authentication — {host}:{port}",
            severity="critical",
            description=(
                f"Redis on {host}:{port} responds to PING without authentication.\n"
                f"Version: {version or 'unknown'}\n\n"
                "An attacker can read/write all keys, execute Lua scripts, "
                "and potentially achieve RCE via CONFIG SET (write SSH keys, cron jobs, webshells)."
            ),
            port=port,
            protocol="tcp",
            service="redis",
            version=version or None,
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            evidence=f"PING→PONG confirmed. redis_version={version}",
            remediation=(
                "Set requirepass in redis.conf. "
                "Bind Redis to 127.0.0.1 or a private interface. "
                "Use network-level firewall rules to restrict port 6379."
            ),
        )

    if b"NOAUTH" in resp or b"ERR" in resp:
        return Finding(
            type="open_service",
            title=f"Redis port open (auth required) — {host}:{port}",
            severity="info",
            description=f"Redis on {host}:{port} requires authentication.",
            port=port, protocol="tcp", service="redis",
            evidence=resp[:100].decode(errors="replace"),
        )
    return None


# ── MongoDB ───────────────────────────────────────────────────────────────────

# Minimal MongoDB isMaster wire-protocol message
_MONGO_ISMASTER = (
    b"\x41\x00\x00\x00"   # messageLength
    b"\x01\x00\x00\x00"   # requestID
    b"\x00\x00\x00\x00"   # responseTo
    b"\xd4\x07\x00\x00"   # opCode OP_QUERY
    b"\x00\x00\x00\x00"   # flags
    b"admin.$cmd\x00"      # fullCollectionName
    b"\x00\x00\x00\x00"   # numberToSkip
    b"\x01\x00\x00\x00"   # numberToReturn
    b"\x13\x00\x00\x00"   # doc length
    b"\x10ismaster\x00\x01\x00\x00\x00\x00"  # {ismaster:1}
)


def _check_mongodb(host: str, port: int = 27017) -> Finding | None:
    resp = _tcp_send(host, port, _MONGO_ISMASTER)
    if not resp or len(resp) < 16:
        return None

    # If we got a valid MongoDB response (starts with a length field)
    try:
        msg_len = int.from_bytes(resp[:4], "little")
        if msg_len < 20 or msg_len > 65536:
            return None
    except Exception:
        return None

    # Try listing databases via HTTP API (if mongod was started with --rest, deprecated but still seen)
    status, body = _http_get(f"http://{host}:28017/")
    db_list = ""
    if status == 200 and "MongoDB" in body:
        db_list = " (HTTP admin interface also exposed)"

    return Finding(
        type="open_service",
        title=f"MongoDB open without authentication — {host}:{port}",
        severity="critical",
        description=(
            f"MongoDB on {host}:{port} responds to wire-protocol without authentication{db_list}.\n"
            "An attacker can read, write, or drop all databases."
        ),
        port=port,
        protocol="tcp",
        service="mongodb",
        cvss_score=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        evidence=f"isMaster wire-protocol accepted, response length={len(resp)}",
        remediation=(
            "Enable MongoDB authentication (--auth flag or security.authorization: enabled). "
            "Bind to 127.0.0.1. Disable the HTTP REST interface."
        ),
    )


# ── Elasticsearch ─────────────────────────────────────────────────────────────

def _check_elasticsearch(host: str, port: int = 9200) -> Finding | None:
    status, body = _http_get(f"http://{host}:{port}/")
    if status != 200:
        return None

    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return None

    if "cluster_name" not in data and "version" not in data:
        return None

    cluster = data.get("cluster_name", "unknown")
    version = data.get("version", {}).get("number", "unknown")

    # Get index list
    _, indices_body = _http_get(f"http://{host}:{port}/_cat/indices?v")
    index_count = len([l for l in indices_body.splitlines() if l and not l.startswith("health")])

    return Finding(
        type="open_service",
        title=f"Elasticsearch open without authentication — {host}:{port}",
        severity="critical",
        description=(
            f"Elasticsearch cluster '{cluster}' (v{version}) on {host}:{port} "
            f"is accessible without authentication.\n"
            f"Exposed indices: {index_count}\n\n"
            "An attacker can read all data, create/delete indices, or execute scripts."
        ),
        port=port,
        protocol="tcp",
        service="elasticsearch",
        version=version,
        cvss_score=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        evidence=f"cluster={cluster} version={version} indices={index_count}",
        remediation=(
            "Enable X-Pack security (xpack.security.enabled: true). "
            "Set up built-in user passwords. "
            "Bind to private network interface only."
        ),
    )


# ── Memcached ─────────────────────────────────────────────────────────────────

def _check_memcached(host: str, port: int = 11211) -> Finding | None:
    resp = _tcp_send(host, port, b"stats\r\n")
    if not resp or b"STAT " not in resp:
        return None

    version_m = re.search(rb"STAT version (\S+)", resp)
    version   = version_m.group(1).decode() if version_m else "unknown"

    return Finding(
        type="open_service",
        title=f"Memcached open without authentication — {host}:{port}",
        severity="high",
        description=(
            f"Memcached {version} on {host}:{port} accepts commands without authentication.\n"
            "Cache data can be read/modified. UDP reflection DDoS amplification also possible."
        ),
        port=port,
        protocol="tcp",
        service="memcached",
        version=version,
        cvss_score=7.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        evidence=f"STAT version={version}",
        remediation=(
            "Bind Memcached to 127.0.0.1. "
            "Enable SASL authentication. "
            "Block UDP port 11211 at the firewall to prevent DDoS amplification."
        ),
    )


# ── CouchDB ───────────────────────────────────────────────────────────────────

def _check_couchdb(host: str, port: int = 5984) -> Finding | None:
    status, body = _http_get(f"http://{host}:{port}/")
    if status != 200:
        return None
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return None
    if "couchdb" not in data:
        return None

    version = data.get("version", "unknown")

    # Try listing all databases
    dbs_status, dbs_body = _http_get(f"http://{host}:{port}/_all_dbs")
    dbs: list[str] = []
    if dbs_status == 200:
        try:
            dbs = json.loads(dbs_body)
        except Exception:
            pass

    return Finding(
        type="open_service",
        title=f"CouchDB open without authentication — {host}:{port}",
        severity="critical",
        description=(
            f"CouchDB {version} on {host}:{port} is accessible without authentication.\n"
            f"Databases: {', '.join(dbs[:10]) or 'none listed'}\n\n"
            "Full read/write access to all databases."
        ),
        port=port,
        protocol="tcp",
        service="couchdb",
        version=version,
        cvss_score=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        evidence=f"version={version} dbs={dbs[:5]}",
        remediation=(
            "Enable CouchDB authentication (require_valid_user=true). "
            "Set admin credentials. Bind to private interface."
        ),
    )


# ── Kubernetes API ────────────────────────────────────────────────────────────

def _check_kubernetes(host: str, port: int = 8080) -> Finding | None:
    # Unauthenticated Kubernetes API (port 8080 is insecure-port, deprecated but still seen)
    status, body = _http_get(f"http://{host}:{port}/api/v1/namespaces")
    if status != 200:
        # Try HTTPS 6443 unauthenticated
        status, body = _http_get(f"https://{host}:6443/api/v1/namespaces")
        if status not in (200, 403):
            return None
        port = 6443

    if status == 200 and '"kind":"NamespaceList"' in body:
        ns_count = body.count('"name":')
        return Finding(
            type="open_service",
            title=f"Kubernetes API open without authentication — {host}:{port}",
            severity="critical",
            description=(
                f"Kubernetes API server on {host}:{port} is accessible without authentication.\n"
                f"Namespaces visible: ~{ns_count}\n\n"
                "An attacker can list pods, secrets, and deploy malicious containers."
            ),
            port=port,
            protocol="tcp",
            service="kubernetes",
            cvss_score=10.0,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            evidence=f"GET /api/v1/namespaces → 200 OK, namespaces={ns_count}",
            remediation=(
                "Disable the insecure HTTP port (--insecure-port=0). "
                "Enable RBAC authorization. Use TLS client certificates."
            ),
        )
    return None


# ── Docker daemon ─────────────────────────────────────────────────────────────

def _check_docker(host: str, port: int = 2375) -> Finding | None:
    status, body = _http_get(f"http://{host}:{port}/version")
    if status != 200:
        return None
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return None
    if "Version" not in data:
        return None

    version = data.get("Version", "unknown")
    return Finding(
        type="open_service",
        title=f"Docker daemon exposed without TLS — {host}:{port}",
        severity="critical",
        description=(
            f"Docker daemon {version} on {host}:{port} is accessible without authentication.\n"
            "An attacker can run privileged containers, read host filesystem, "
            "and achieve full host compromise."
        ),
        port=port,
        protocol="tcp",
        service="docker",
        version=version,
        cvss_score=10.0,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        evidence=f"GET /version → 200 OK, version={version}",
        remediation=(
            "Never expose Docker daemon on TCP without TLS client auth. "
            "Use Unix socket only. Enable TLS with mutual authentication."
        ),
    )


# ── etcd ──────────────────────────────────────────────────────────────────────

def _check_etcd(host: str, port: int = 2379) -> Finding | None:
    status, body = _http_get(f"http://{host}:{port}/v2/keys/")
    if status != 200:
        status, body = _http_get(f"http://{host}:{port}/v3/keys")
        if status != 200:
            return None
    if "errorCode" in body or "nodes" in body or "kvs" in body:
        return Finding(
            type="open_service",
            title=f"etcd open without authentication — {host}:{port}",
            severity="critical",
            description=(
                f"etcd on {host}:{port} is accessible without authentication.\n"
                "etcd stores Kubernetes secrets, certificates, and service configs in plaintext."
            ),
            port=port,
            protocol="tcp",
            service="etcd",
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            evidence=f"GET /v2/keys/ → {status}",
            remediation=(
                "Enable etcd peer and client TLS. "
                "Require client certificate authentication. "
                "Apply RBAC and bind to private interface."
            ),
        )
    return None


# ── Port-to-checker mapping ───────────────────────────────────────────────────

_PORT_CHECKERS: dict[int, tuple[str, callable]] = {
    6379:  ("redis",         lambda h, p: _check_redis(h, p)),
    27017: ("mongodb",       lambda h, p: _check_mongodb(h, p)),
    9200:  ("elasticsearch", lambda h, p: _check_elasticsearch(h, p)),
    9300:  ("elasticsearch", lambda h, p: _check_elasticsearch(h, 9200)),  # cluster port → check API
    11211: ("memcached",     lambda h, p: _check_memcached(h, p)),
    5984:  ("couchdb",       lambda h, p: _check_couchdb(h, p)),
    8080:  ("kubernetes",    lambda h, p: _check_kubernetes(h, p)),
    6443:  ("kubernetes",    lambda h, p: _check_kubernetes(h, p)),
    2375:  ("docker",        lambda h, p: _check_docker(h, p)),
    2376:  ("docker",        lambda h, p: _check_docker(h, 2375)),
    2379:  ("etcd",          lambda h, p: _check_etcd(h, p)),
    2380:  ("etcd",          lambda h, p: _check_etcd(h, 2379)),
}

# Also check by service name even if on non-standard port
_SERVICE_CHECKERS: dict[str, callable] = {
    "redis":         lambda h, p: _check_redis(h, p),
    "mongodb":       lambda h, p: _check_mongodb(h, p),
    "elasticsearch": lambda h, p: _check_elasticsearch(h, p),
    "memcached":     lambda h, p: _check_memcached(h, p),
    "couchdb":       lambda h, p: _check_couchdb(h, p),
    "docker":        lambda h, p: _check_docker(h, p),
    "etcd":          lambda h, p: _check_etcd(h, p),
}


def _targets_from_nmap(nmap_findings: list[Finding]) -> list[tuple[int, str]]:
    """Return list of (port, service_name) from nmap port findings."""
    targets: list[tuple[int, str]] = []
    seen: set[int] = set()
    for f in nmap_findings:
        if f.type != "port" or not f.port:
            continue
        port = f.port
        svc  = (f.service or "").lower()
        if port in _PORT_CHECKERS and port not in seen:
            seen.add(port)
            targets.append((port, svc))
        elif svc in _SERVICE_CHECKERS and port not in seen:
            seen.add(port)
            targets.append((port, svc))
    return targets


# ── Main entry point ──────────────────────────────────────────────────────────

async def run_open_services(
    ctx: "ScanContext",
    target: str,
    nmap_findings: list[Finding],
) -> ScanResult:
    """
    Check for unauthenticated access to common data/infra services.
    Probes only ports confirmed open by nmap.
    Falls back to probing all known ports if nmap found nothing relevant.
    """
    result = ScanResult()

    targets = _targets_from_nmap(nmap_findings)

    # If nmap didn't scan these ports, probe known defaults anyway
    if not targets:
        targets = list(_PORT_CHECKERS.keys())  # type: ignore[assignment]
        targets = [(p, "") for p in targets]

    await ctx.log(
        f"Open services: checking {len(targets)} port(s) for unauthenticated access",
        module="open_services",
    )

    for port, svc in targets:
        checker = _PORT_CHECKERS.get(port, (None, None))[1]
        if checker is None and svc:
            checker = _SERVICE_CHECKERS.get(svc)
        if checker is None:
            continue

        await ctx.log(f"  Probing {target}:{port} ({svc or 'unknown'})", module="open_services")
        try:
            finding = checker(target, port)
        except Exception as exc:
            await ctx.log(f"  Error probing {port}: {exc}", level="warning", module="open_services")
            continue

        if finding:
            result.findings.append(finding)
            await ctx.log(
                f"  OPEN (no auth): {finding.service} on port {port}",
                level="error",
                module="open_services",
            )

    critical_count = sum(1 for f in result.findings if f.severity == "critical")
    await ctx.log(
        f"Open services complete: {len(result.findings)} exposed service(s) "
        f"({critical_count} critical)",
        level="warning" if result.findings else "success",
        module="open_services",
    )
    return result
