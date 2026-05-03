"""
Main scan orchestrator task.
Runs all scanner modules in sequence, saves findings, updates scan status.
"""
import asyncio
import uuid

from app.worker import celery


@celery.task(name="app.tasks.scan.run_scan", bind=True, max_retries=0)
def run_scan(self, scan_id: str) -> dict:
    return asyncio.run(_run_scan_async(scan_id))


async def _run_scan_async(scan_id: str) -> dict:
    from sqlalchemy import select

    from app.core.redis import get_redis
    from app.db.session import AsyncSessionLocal
    from app.models.scan import Scan
    from app.scanner.context import ScanContext
    from app.scanner.dns import run_dns
    from app.scanner.nmap import run_nmap

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

            # ── Phase 1: Nmap recon ────────────────────────────────────────
            await ctx.set_phase("recon")
            nmap_result = await run_nmap(ctx, scan.target, scan.scan_type)

            if nmap_result.findings:
                await ctx.save_findings(nmap_result.findings)

            if nmap_result.errors:
                for err in nmap_result.errors:
                    await ctx.log(err, level="error", module="nmap")

            # ── Phase 2: Nikto web scan ───────────────────────────────────
            if scan.scan_type in ("web", "full"):
                await ctx.set_phase("web_scan")
                from app.scanner.nikto import run_nikto  # noqa: PLC0415
                nikto_result = await run_nikto(ctx, scan.target, scan.scan_type, nmap_result.findings)
                if nikto_result.findings:
                    await ctx.save_findings(nikto_result.findings)
                for err in nikto_result.errors:
                    await ctx.log(err, level="error", module="nikto")

            # ── Phase 3: Hydra brute force ────────────────────────────────
            if scan.scan_type in ("full", "vuln"):
                await ctx.set_phase("brute_force")
                from app.scanner.hydra import run_hydra  # noqa: PLC0415
                hydra_result = await run_hydra(ctx, scan.target, scan.scan_type, nmap_result.findings)
                if hydra_result.findings:
                    await ctx.save_findings(hydra_result.findings)
                for err in hydra_result.errors:
                    await ctx.log(err, level="error", module="hydra")

            # ── Phase 4: Metasploit exploit verification ──────────────────
            if scan.scan_type == "full":
                await ctx.set_phase("exploit_check")
                from app.scanner.msf import run_msf  # noqa: PLC0415
                msf_result = await run_msf(ctx, scan.target, scan.scan_type, nmap_result.findings)
                if msf_result.findings:
                    await ctx.save_findings(msf_result.findings)
                for err in msf_result.errors:
                    await ctx.log(err, level="warning", module="msf")

            # ── Phase 5+: future modules ──────────────────────────────────
            # Phase 6 — sqlmap / XSS / OWASP
            # Phase 9 — OSINT (Shodan/Censys)

            await ctx.set_phase("done")
            await ctx.set_status("completed")
            await ctx.log("Scan completed successfully", level="success")
            await ctx.commit()

            total_findings = (
                len(dns_result.findings)
                + len(nmap_result.findings)
            )
            return {
                "scan_id": scan_id,
                "status": "completed",
                "findings": total_findings,
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
