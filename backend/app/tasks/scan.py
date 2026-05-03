"""
Main scan orchestrator task.
Runs all scanner modules in sequence, saves findings, updates scan status.
Phase 13: each scan runs in an isolated Docker container when available,
          falls back to in-process execution otherwise.
"""
import asyncio
import os
import uuid

from app.worker import celery


@celery.task(name="app.tasks.scan.run_scan", bind=True, max_retries=0)
def run_scan(self, scan_id: str) -> dict:
    return asyncio.run(_dispatch_scan(scan_id))


async def _dispatch_scan(scan_id: str) -> dict:
    """
    Try to run the scan in an isolated Docker container.
    Falls back to in-process execution if Docker is unavailable.
    """
    from app.scanner.isolation import _docker_available, run_scan_in_container, ensure_scan_network

    if _docker_available():
        ensure_scan_network()

        db_url    = os.getenv("DATABASE_URL", "")
        redis_url = os.getenv("REDIS_URL", "redis://redis:6379/0")

        # Load scan to get scan_type for capability decisions
        scan_type = await _get_scan_type(scan_id)

        rc, stdout, stderr = await run_scan_in_container(
            scan_id, scan_type, db_url, redis_url
        )

        if rc == 0:
            return {"scan_id": scan_id, "mode": "container", "status": "completed"}

        # Container failed — log and fall back to in-process
        import logging
        logging.getLogger("pentrascan").warning(
            f"Container scan failed (rc={rc}), falling back to in-process. "
            f"stderr: {stderr[:300]}"
        )

    # Fallback: run directly in this worker process
    return await _run_scan_async(scan_id)


async def _get_scan_type(scan_id: str) -> str:
    """Quick DB lookup for scan_type."""
    try:
        from sqlalchemy import select
        from app.db.session import AsyncSessionLocal
        from app.models.scan import Scan
        async with AsyncSessionLocal() as db:
            result = await db.execute(select(Scan.scan_type).where(Scan.id == uuid.UUID(scan_id)))
            row = result.scalar_one_or_none()
            return row or "recon"
    except Exception:
        return "recon"


async def _run_scan_async(scan_id: str) -> dict:
    from sqlalchemy import select

    from app.core.redis import get_redis
    from app.db.session import AsyncSessionLocal
    from app.models.scan import Scan
    from app.scanner.context import ScanContext
    from app.scanner.cve_mapper import run_cve_mapper
    from app.scanner.dns import run_dns
    from app.scanner.msf_mapper import run_msf_mapper
    from app.scanner.nmap import run_nmap
    from app.scanner.osint import run_osint
    from app.scanner.rule_engine import run_rule_engine

    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Scan).where(Scan.id == uuid.UUID(scan_id)))
        scan = result.scalar_one_or_none()
        if not scan:
            return {"error": "scan not found"}

        redis = await get_redis()
        ctx = ScanContext(db, scan, redis)

        try:
            await ctx.set_status("running")
            await ctx.commit()

            # ── Phase 0: DNS recon ─────────────────────────────────────────
            await ctx.set_phase("dns_recon")
            dns_result = await run_dns(ctx, scan.target, scan.scan_type)
            if dns_result.findings:
                await ctx.save_findings(dns_result.findings)
            for err in dns_result.errors:
                await ctx.log(err, level="error", module="dns")

            # ── Phase 0b: OSINT ────────────────────────────────────────────
            await ctx.set_phase("osint")
            osint_result = await run_osint(ctx, scan.target, scan.scan_type)
            if osint_result.findings:
                await ctx.save_findings(osint_result.findings)
            for err in osint_result.errors:
                await ctx.log(err, level="warning", module="osint")

            # ── Phase 1: Nmap recon ────────────────────────────────────────
            await ctx.set_phase("recon")
            nmap_result = await run_nmap(ctx, scan.target, scan.scan_type)

            if nmap_result.findings:
                await ctx.save_findings(nmap_result.findings)

            if nmap_result.errors:
                for err in nmap_result.errors:
                    await ctx.log(err, level="error", module="nmap")

            # ── Phase 1b: CVE mapping (NVD + searchsploit) ────────────────
            await ctx.set_phase("cve_mapping")
            cve_result = await run_cve_mapper(ctx, nmap_result.findings)
            if cve_result.findings:
                await ctx.save_findings(cve_result.findings)
            for err in cve_result.errors:
                await ctx.log(err, level="warning", module="cve_mapper")

            # ── Phase 2: Nikto web scan ───────────────────────────────────
            if scan.scan_type in ("web", "full"):
                await ctx.set_phase("web_scan")
                from app.scanner.nikto import run_nikto  # noqa: PLC0415
                nikto_result = await run_nikto(ctx, scan.target, scan.scan_type, nmap_result.findings)
                if nikto_result.findings:
                    await ctx.save_findings(nikto_result.findings)
                for err in nikto_result.errors:
                    await ctx.log(err, level="error", module="nikto")

            # ── Phase 2b: HTTP headers + SSL analysis ────────────────────
            if scan.scan_type in ("web", "full"):
                await ctx.set_phase("ssl_headers")
                from app.scanner.ssl_headers import run_ssl_headers  # noqa: PLC0415
                ssl_result = await run_ssl_headers(ctx, scan.target, scan.scan_type, nmap_result.findings)
                if ssl_result.findings:
                    await ctx.save_findings(ssl_result.findings)
                for err in ssl_result.errors:
                    await ctx.log(err, level="error", module="ssl_headers")

            # ── Phase 2c: Directory / endpoint enumeration ────────────────
            if scan.scan_type in ("web", "full"):
                await ctx.set_phase("dir_scan")
                from app.scanner.dirscan import run_dirscan  # noqa: PLC0415
                dir_result = await run_dirscan(ctx, scan.target, scan.scan_type, nmap_result.findings)
                if dir_result.findings:
                    await ctx.save_findings(dir_result.findings)
                for err in dir_result.errors:
                    await ctx.log(err, level="error", module="dirscan")

            # ── Phase 2d: SQL Injection (sqlmap) ─────────────────────────
            if scan.scan_type in ("web", "full"):
                await ctx.set_phase("sqli_scan")
                from app.scanner.sqlmap import run_sqlmap  # noqa: PLC0415
                _sqli_pool = (
                    osint_result.findings
                    + dir_result.findings
                    + nikto_result.findings
                )
                sqli_result = await run_sqlmap(ctx, scan.target, scan.scan_type, _sqli_pool)
                if sqli_result.findings:
                    await ctx.save_findings(sqli_result.findings)
                for err in sqli_result.errors:
                    await ctx.log(err, level="warning", module="sqlmap")

            # ── Phase 2e: XSS (dalfox) ───────────────────────────────────
            if scan.scan_type in ("web", "full"):
                await ctx.set_phase("xss_scan")
                from app.scanner.xss import run_xss  # noqa: PLC0415
                _xss_pool = (
                    osint_result.findings
                    + dir_result.findings
                    + nikto_result.findings
                    + sqli_result.findings
                )
                xss_result = await run_xss(
                    ctx, scan.target, scan.scan_type, _xss_pool, nmap_result.findings
                )
                if xss_result.findings:
                    await ctx.save_findings(xss_result.findings)
                for err in xss_result.errors:
                    await ctx.log(err, level="warning", module="xss")

            # ── Phase 2f: LFI / Path Traversal ───────────────────────────
            if scan.scan_type in ("web", "full"):
                await ctx.set_phase("lfi_scan")
                from app.scanner.lfi import run_lfi  # noqa: PLC0415
                _lfi_pool = (
                    osint_result.findings
                    + dir_result.findings
                    + nikto_result.findings
                    + sqli_result.findings
                    + xss_result.findings
                )
                lfi_result = await run_lfi(ctx, scan.target, scan.scan_type, _lfi_pool)
                if lfi_result.findings:
                    await ctx.save_findings(lfi_result.findings)
                for err in lfi_result.errors:
                    await ctx.log(err, level="warning", module="lfi")

            # ── Phase 2g: SSTI/SSRF/XXE/CORS/Smuggling/JWT (web_vulns) ──────
            if scan.scan_type in ("web", "full"):
                await ctx.set_phase("web_vulns")
                from app.scanner.web_vulns import run_web_vulns  # noqa: PLC0415
                _wv_pool = (
                    osint_result.findings
                    + dir_result.findings
                    + nikto_result.findings
                    + sqli_result.findings
                    + xss_result.findings
                    + lfi_result.findings
                )
                wv_result = await run_web_vulns(
                    ctx, scan.target, scan.scan_type, _wv_pool, nmap_result.findings
                )
                if wv_result.findings:
                    await ctx.save_findings(wv_result.findings)
                for err in wv_result.errors:
                    await ctx.log(err, level="warning", module="web_vulns")

            # ── Phase 2h: Open services (Redis/Mongo/ES/Docker/k8s…) ─────
            await ctx.set_phase("open_services")
            from app.scanner.open_services import run_open_services  # noqa: PLC0415
            open_result = await run_open_services(ctx, scan.target, nmap_result.findings)
            if open_result.findings:
                await ctx.save_findings(open_result.findings)

            # ── Phase 3: Hydra brute force (services) ────────────────────
            if scan.scan_type in ("full", "vuln"):
                await ctx.set_phase("brute_force")
                from app.scanner.hydra import run_hydra  # noqa: PLC0415
                hydra_result = await run_hydra(ctx, scan.target, scan.scan_type, nmap_result.findings)
                if hydra_result.findings:
                    await ctx.save_findings(hydra_result.findings)
                for err in hydra_result.errors:
                    await ctx.log(err, level="error", module="hydra")

            # ── Phase 3b: Web form brute force ────────────────────────────
            if scan.scan_type in ("full", "vuln", "web"):
                await ctx.set_phase("web_brute")
                from app.scanner.web_brute import run_web_brute  # noqa: PLC0415
                _wb_pool = (
                    osint_result.findings
                    + dir_result.findings
                    + nikto_result.findings
                ) if scan.scan_type in ("web", "full") else []
                web_brute_result = await run_web_brute(ctx, scan.target, scan.scan_type, _wb_pool)
                if web_brute_result.findings:
                    await ctx.save_findings(web_brute_result.findings)
                for err in web_brute_result.errors:
                    await ctx.log(err, level="warning", module="web_brute")

            # ── Phase 3c: SMB / AD / Kerberos ────────────────────────────
            if scan.scan_type in ("full", "vuln"):
                await ctx.set_phase("smb_ad")
                from app.scanner.smb_ad import run_smb_ad  # noqa: PLC0415
                smb_result = await run_smb_ad(ctx, scan.target, scan.scan_type, nmap_result.findings)
                if smb_result.findings:
                    await ctx.save_findings(smb_result.findings)
                for err in smb_result.errors:
                    await ctx.log(err, level="warning", module="smb_ad")

            # ── Phase 4: Metasploit exploit verification ──────────────────
            if scan.scan_type == "full":
                await ctx.set_phase("exploit_check")
                from app.scanner.msf import run_msf  # noqa: PLC0415
                msf_result = await run_msf(ctx, scan.target, scan.scan_type, nmap_result.findings)
                if msf_result.findings:
                    await ctx.save_findings(msf_result.findings)
                for err in msf_result.errors:
                    await ctx.log(err, level="warning", module="msf")

            # ── Phase 4b: Post-Exploitation (LinPEAS / WinPEAS / LES / pspy) ──
            if scan.scan_type == "full":
                await ctx.set_phase("post_exploit")
                from app.scanner.post_exploit import run_post_exploit  # noqa: PLC0415
                _brute_pool = hydra_result.findings + web_brute_result.findings
                postex_result = await run_post_exploit(
                    ctx,
                    scan.target,
                    scan.scan_type,
                    nmap_result.findings,
                    _brute_pool,
                    msf_result.findings,
                )
                if postex_result.findings:
                    await ctx.save_findings(postex_result.findings)
                for err in postex_result.errors:
                    await ctx.log(err, level="warning", module="post_exploit")

            # ── Phase 4c: Linux PrivEsc (SUID / sudo / cron) ─────────────
            if scan.scan_type == "full":
                await ctx.set_phase("privesc_linux")
                from app.scanner.privesc_linux import run_privesc_linux  # noqa: PLC0415
                _brute_all = hydra_result.findings + web_brute_result.findings
                privesc_result = await run_privesc_linux(
                    ctx,
                    scan.target,
                    scan.scan_type,
                    postex_result.findings,
                    _brute_all,
                )
                if privesc_result.findings:
                    await ctx.save_findings(privesc_result.findings)
                for err in privesc_result.errors:
                    await ctx.log(err, level="warning", module="privesc_linux")

            # ── Phase 4d: Windows PrivEsc (JuicyPotato / PrintSpoofer / UAC) ─
            if scan.scan_type == "full":
                await ctx.set_phase("privesc_windows")
                from app.scanner.privesc_windows import run_privesc_windows  # noqa: PLC0415
                _brute_all = hydra_result.findings + web_brute_result.findings
                privesc_win_result = await run_privesc_windows(
                    ctx,
                    scan.target,
                    scan.scan_type,
                    nmap_result.findings,
                    postex_result.findings,
                    _brute_all,
                    msf_result.findings,
                )
                if privesc_win_result.findings:
                    await ctx.save_findings(privesc_win_result.findings)
                for err in privesc_win_result.errors:
                    await ctx.log(err, level="warning", module="privesc_windows")

            # ── Phase 4e: Data Gathering (shadow/SAM/mimikatz/configs/keys) ─
            if scan.scan_type == "full":
                await ctx.set_phase("data_gather")
                from app.scanner.data_gather import run_data_gather  # noqa: PLC0415
                _brute_all = hydra_result.findings + web_brute_result.findings
                data_result = await run_data_gather(
                    ctx,
                    scan.target,
                    scan.scan_type,
                    nmap_result.findings,
                    _brute_all,
                    msf_result.findings,
                )
                if data_result.findings:
                    await ctx.save_findings(data_result.findings)
                for err in data_result.errors:
                    await ctx.log(err, level="warning", module="data_gather")

            # ── Phase 4f: HTTP Flood (Layer 7) ────────────────────────────
            if scan.scan_type == "full":
                await ctx.set_phase("ddos_http")
                from app.scanner.ddos_http import run_ddos_http  # noqa: PLC0415
                ddos_http_result = await run_ddos_http(
                    ctx, scan.target, scan.scan_type,
                )
                if ddos_http_result.findings:
                    await ctx.save_findings(ddos_http_result.findings)
                for err in ddos_http_result.errors:
                    await ctx.log(err, level="warning", module="ddos_http")

            # ── Phase 4g: Slow HTTP attacks (Slowloris / RUDY / slowhttptest) ─
            if scan.scan_type == "full":
                await ctx.set_phase("ddos_slow")
                from app.scanner.ddos_slow import run_ddos_slow  # noqa: PLC0415
                ddos_slow_result = await run_ddos_slow(
                    ctx, scan.target, scan.scan_type,
                )
                if ddos_slow_result.findings:
                    await ctx.save_findings(ddos_slow_result.findings)
                for err in ddos_slow_result.errors:
                    await ctx.log(err, level="warning", module="ddos_slow")

            # ── Phase 4h: Network Flood Layer 4 (hping3/scapy/xerxes/t50) ──
            if scan.scan_type == "full":
                await ctx.set_phase("ddos_network")
                from app.scanner.ddos_network import run_ddos_network  # noqa: PLC0415
                ddos_net_result = await run_ddos_network(
                    ctx, scan.target, scan.scan_type, nmap_result.findings,
                )
                if ddos_net_result.findings:
                    await ctx.save_findings(ddos_net_result.findings)
                for err in ddos_net_result.errors:
                    await ctx.log(err, level="warning", module="ddos_network")

            # ── Phase 5: Rule Engine (dedup + CVSS + attack paths) ────────────
            await ctx.set_phase("rule_engine")
            all_findings = (
                dns_result.findings
                + osint_result.findings
                + nmap_result.findings
                + cve_result.findings
            )
            if scan.scan_type in ("web", "full"):
                all_findings += (
                    nikto_result.findings
                    + ssl_result.findings
                    + dir_result.findings
                    + sqli_result.findings
                    + xss_result.findings
                    + lfi_result.findings
                    + wv_result.findings
                )
            all_findings += open_result.findings
            if scan.scan_type in ("full", "vuln"):
                all_findings += hydra_result.findings
            if scan.scan_type in ("full", "vuln", "web"):
                all_findings += web_brute_result.findings
            if scan.scan_type in ("full", "vuln"):
                all_findings += smb_result.findings
            if scan.scan_type == "full":
                all_findings += msf_result.findings
                all_findings += postex_result.findings
                all_findings += privesc_result.findings
                all_findings += privesc_win_result.findings
                all_findings += data_result.findings
                all_findings += ddos_http_result.findings
                all_findings += ddos_slow_result.findings
                all_findings += ddos_net_result.findings

            # ── Phase 5b: Hash Cracking (uses findings from prior phases) ─
            if scan.scan_type in ("full", "vuln"):
                await ctx.set_phase("hash_crack")
                from app.scanner.hash_crack import run_hash_crack  # noqa: PLC0415
                hash_result = await run_hash_crack(ctx, scan.scan_type, all_findings)
                if hash_result.findings:
                    await ctx.save_findings(hash_result.findings)
                all_findings += hash_result.findings

            # ── Phase 5.3: MSF module annotation (enriches in-place) ─────────
            await ctx.set_phase("msf_mapping")
            msf_map_result = await run_msf_mapper(ctx, all_findings)
            # summary finding added to all_findings for Rule Engine
            all_findings += msf_map_result.findings

            engine_result = await run_rule_engine(ctx, all_findings)

            # Persist enriched findings (replace per-phase saves)
            await ctx.save_findings(engine_result.findings, replace=True)

            # Attach attack paths as special findings
            from app.scanner.base import Finding as F  # noqa: PLC0415
            for ap in engine_result.attack_paths:
                ap_finding = F(
                    type="attack_path",
                    title=ap.title,
                    severity=ap.severity,
                    description=ap.description + "\n\nSteps:\n" + "\n".join(
                        f"  {i+1}. {s}" for i, s in enumerate(ap.steps)
                    ),
                    cvss_score=ap.cvss_score,
                    msf_module=ap.msf_module,
                    evidence=f"attack_path_id={ap.id}",
                )
                await ctx.save_findings([ap_finding])

            # ── Phase 6+: future modules ──────────────────────────────────────
            # Phase 6 — sqlmap / XSS / dalfox / OWASP

            await ctx.set_phase("done")
            await ctx.set_status("completed")
            await ctx.log("Scan completed successfully", level="success")
            await ctx.commit()

            return {
                "scan_id": scan_id,
                "status": "completed",
                "findings": engine_result.stats["unique_findings"],
                "attack_paths": engine_result.stats["attack_paths"],
                "severity": {
                    k: engine_result.stats[k]
                    for k in ("critical", "high", "medium", "low", "info")
                },
            }

        except Exception as exc:
            try:
                scan.status = "failed"
                scan.error_message = str(exc)[:500]
                await db.commit()
                await ctx.log(f"Scan failed: {exc}", level="error")
            except Exception:
                pass
            raise
