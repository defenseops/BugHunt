"""
PDF report generator — Phase 10.
Loads scan data from DB, renders Jinja2 HTML template, converts to PDF via WeasyPrint.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any

TEMPLATES_DIR = Path(__file__).parent.parent / "templates"
REPORTS_DIR   = Path(os.getenv("REPORTS_DIR", "/app/reports"))

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

# Risk label thresholds (based on weighted score)
def _risk_label(counts: dict[str, int], lang: str) -> tuple[str, str]:
    """Return (label, css_class) for overall risk."""
    c = counts.get("critical", 0)
    h = counts.get("high", 0)
    m = counts.get("medium", 0)

    if c >= 1:
        label = "КРИТИЧЕСКИЙ" if lang == "ru" else "CRITICAL"
        return label, "risk-critical"
    if h >= 3:
        label = "ВЫСОКИЙ" if lang == "ru" else "HIGH"
        return label, "risk-high"
    if h >= 1 or m >= 3:
        label = "СРЕДНИЙ" if lang == "ru" else "MEDIUM"
        return label, "risk-medium"
    label = "НИЗКИЙ" if lang == "ru" else "LOW"
    return label, "risk-low"


def _cvss_float(v: Any) -> float:
    if v is None:
        return 0.0
    try:
        return float(v)
    except (ValueError, TypeError):
        return 0.0


def _fmt_dt(dt: datetime | None, lang: str) -> str:
    if not dt:
        return "—"
    locale = "ru" if lang == "ru" else "en"
    months_ru = ["", "января", "февраля", "марта", "апреля", "мая", "июня",
                 "июля", "августа", "сентября", "октября", "ноября", "декабря"]
    if locale == "ru":
        return f"{dt.day} {months_ru[dt.month]} {dt.year} г., {dt.hour:02d}:{dt.minute:02d}"
    return dt.strftime("%B %d, %Y %H:%M UTC")


def _duration(started: datetime | None, finished: datetime | None) -> str:
    if not started or not finished:
        return "—"
    delta = finished - started
    total = int(delta.total_seconds())
    h, rem = divmod(total, 3600)
    m, s   = divmod(rem, 60)
    if h:
        return f"{h}h {m}m"
    if m:
        return f"{m}m {s}s"
    return f"{s}s"


def build_report_context(scan, findings: list, user, lang: str) -> dict:
    """Build the Jinja2 template context dict from DB objects."""
    sev_counts: dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        key = (f.severity or "info").lower()
        sev_counts[key] = sev_counts.get(key, 0) + 1

    risk_label, risk_class = _risk_label(sev_counts, lang)

    # Sort findings: critical → high → medium → low → info
    sorted_findings = sorted(
        findings,
        key=lambda f: (SEVERITY_ORDER.index((f.severity or "info").lower()), -_cvss_float(f.cvss_score)),
    )

    # Attack paths
    attack_paths = [f for f in sorted_findings if f.type == "attack_path"]
    vuln_findings = [f for f in sorted_findings if f.type != "attack_path"]

    # Top 5 critical/high for executive summary
    top_findings = [f for f in vuln_findings if f.severity in ("critical", "high")][:5]

    # Unique CVEs
    cves = sorted({f.cve_id for f in findings if f.cve_id})

    generated_at = datetime.now(timezone.utc)

    return {
        "lang": lang,
        "generated_at": _fmt_dt(generated_at, lang),
        "scan_id": str(scan.id),
        "target": scan.target,
        "scan_type": scan.scan_type.upper(),
        "scan_status": scan.status,
        "started_at": _fmt_dt(scan.started_at, lang),
        "finished_at": _fmt_dt(scan.finished_at, lang),
        "duration": _duration(scan.started_at, scan.finished_at),
        "user_email": getattr(user, "email", "—"),
        "user_name": getattr(user, "full_name", None) or getattr(user, "email", "—"),
        "risk_label": risk_label,
        "risk_class": risk_class,
        "sev_counts": sev_counts,
        "total_findings": len(vuln_findings),
        "total_cves": len(cves),
        "cves": cves[:20],
        "top_findings": top_findings,
        "findings": vuln_findings,
        "attack_paths": attack_paths,
    }


def render_html(context: dict) -> str:
    from jinja2 import Environment, FileSystemLoader, select_autoescape
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=select_autoescape(["html"]),
    )
    env.filters["cvss_float"] = _cvss_float
    template_name = f"report_{context['lang']}.html"
    # Fall back to English if language template missing
    if not (TEMPLATES_DIR / template_name).exists():
        template_name = "report_en.html"
    tmpl = env.get_template(template_name)
    return tmpl.render(**context)


def render_pdf(html: str, output_path: Path) -> Path:
    from weasyprint import HTML  # type: ignore
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    HTML(string=html, base_url=str(TEMPLATES_DIR)).write_pdf(str(output_path))
    return output_path
