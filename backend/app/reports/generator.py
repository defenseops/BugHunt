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


def _build_llm_prompts(scan, findings: list, lang: str) -> list[dict]:
    """
    For each vulnerability that requires LLM to fully exploit,
    generate a ready-to-use Claude prompt the user can paste.
    """
    prompts = []

    for f in findings:
        ftype = (f.type or "").lower()
        title = f.title or ""
        evidence = f.evidence or ""
        description = f.description or ""
        url_m = __import__("re").search(r"https?://[^\s\"'<>]+", evidence + " " + description)
        url = url_m.group(0) if url_m else scan.target

        # Source code review / logic reversal
        if ftype in ("source_leak", "secret_leak") and f.raw_output:
            code_snippet = (f.raw_output or f.description or "")[:2000]
            if lang == "ru":
                prompt = (
                    f"Я нашёл утечку исходного кода CTF-задания. "
                    f"Цель: {scan.target}\n\n"
                    f"Вот исходный код:\n```\n{code_snippet}\n```\n\n"
                    f"Помоги мне:\n"
                    f"1. Найти где спрятан флаг или как его получить\n"
                    f"2. Найти уязвимую логику (проверки паролей, обход авторизации)\n"
                    f"3. Написать payload или эксплойт для получения флага\n"
                    f"Формат флага: {getattr(scan, 'ctf_flag_format', None) or 'FLAG{{...}}'}"
                )
            else:
                prompt = (
                    f"I found a source code leak in a CTF challenge. "
                    f"Target: {scan.target}\n\n"
                    f"Source code:\n```\n{code_snippet}\n```\n\n"
                    f"Help me:\n"
                    f"1. Find where the flag is hidden or how to obtain it\n"
                    f"2. Identify vulnerable logic (password checks, auth bypass)\n"
                    f"3. Write a payload or exploit to capture the flag\n"
                    f"Flag format: {getattr(scan, 'ctf_flag_format', None) or 'FLAG{{...}}'}"
                )
            prompts.append({
                "vuln_title": title,
                "vuln_type": "Source Code Review",
                "why_llm": "Requires understanding of program logic and algorithm reversal" if lang == "en" else "Требует понимания логики программы и обратного инжиниринга алгоритма",
                "prompt": prompt,
            })

        # Crypto / encoding that wasn't solved automatically
        if ftype in ("sqli_data",) and "ERROR_BASED_DATA" in evidence:
            raw_data = __import__("re").search(r"ERROR_BASED_DATA: (.+)", evidence)
            data_val = raw_data.group(1) if raw_data else description[:200]
            if lang == "ru":
                prompt = (
                    f"SQLi-инъекция на {url} вернула данные которые я не смог распознать автоматически.\n\n"
                    f"Полученные данные:\n```\n{data_val}\n```\n\n"
                    f"Помоги:\n"
                    f"1. Определить это схема БД, зашифрованные данные или флаг\n"
                    f"2. Если это хэш — подобрать его (MD5/SHA1/bcrypt)\n"
                    f"3. Написать следующий SQLi запрос для извлечения флага из БД\n"
                    f"Уже известно: таблица/столбец из которого получены данные: {title}"
                )
            else:
                prompt = (
                    f"SQLi on {url} returned data I couldn't automatically decode.\n\n"
                    f"Extracted data:\n```\n{data_val}\n```\n\n"
                    f"Help me:\n"
                    f"1. Identify if this is a DB schema, encrypted data, or a flag\n"
                    f"2. If it's a hash — crack it (MD5/SHA1/bcrypt)\n"
                    f"3. Write the next SQLi query to extract the flag\n"
                    f"Known context: table/column from which data was extracted: {title}"
                )
            prompts.append({
                "vuln_title": title,
                "vuln_type": "SQL Injection — Data Analysis",
                "why_llm": "Extracted data requires interpretation or hash cracking" if lang == "en" else "Извлечённые данные требуют интерпретации или взлома хэша",
                "prompt": prompt,
            })

        # SSTI found but RCE chain failed
        if ftype == "ssti" and "rce" not in title.lower():
            engine_m = __import__("re").search(r"(?:via|engine)[ :]+(\w+)", title, __import__("re").I)
            engine = engine_m.group(1) if engine_m else "unknown"
            if lang == "ru":
                prompt = (
                    f"Обнаружена SSTI уязвимость на {url}\n"
                    f"Шаблонный движок: {engine}\n"
                    f"Доказательство: {evidence[:300]}\n\n"
                    f"Автоматические RCE payload'ы не сработали. Помоги:\n"
                    f"1. Написать рабочий payload для {engine} чтобы выполнить `cat /flag.txt`\n"
                    f"2. Если прямой RCE невозможен — обойти sandbox и прочитать файл\n"
                    f"3. Попробовать альтернативные техники ({{config}}, {{self.__dict__}}, и т.д.)\n"
                    f"URL с параметром: {url}"
                )
            else:
                prompt = (
                    f"SSTI vulnerability found on {url}\n"
                    f"Template engine: {engine}\n"
                    f"Evidence: {evidence[:300]}\n\n"
                    f"Automatic RCE payloads failed. Help me:\n"
                    f"1. Write a working payload for {engine} to execute `cat /flag.txt`\n"
                    f"2. If direct RCE is blocked — bypass sandbox and read the file\n"
                    f"3. Try alternative techniques ({{config}}, {{self.__dict__}}, etc.)\n"
                    f"URL with parameter: {url}"
                )
            prompts.append({
                "vuln_title": title,
                "vuln_type": "SSTI → RCE Escalation",
                "why_llm": "RCE payload requires engine-specific bypass and sandbox escape" if lang == "en" else "RCE payload требует обхода sandbox специфичного для движка",
                "prompt": prompt,
            })

        # Blind SQLi confirmed but extraction failed
        if ftype in ("sqli", "lfi") and "blind" in title.lower() and not any(
            p.get("vuln_title") == title for p in prompts
        ):
            if lang == "ru":
                prompt = (
                    f"Подтверждена слепая инъекция на {url}\n"
                    f"Тип: {ftype.upper()}\n"
                    f"Детали: {description[:400]}\n\n"
                    f"Автоматическое извлечение не дало результата. Помоги:\n"
                    f"1. Написать оптимальный payload для побайтового извлечения флага\n"
                    f"2. Определить структуру БД (таблицы, столбцы) если ещё не сделано\n"
                    f"3. Предложить sqlmap команду с правильными параметрами для этой ситуации\n"
                    f"4. Попробовать out-of-band через DNS если time-based не работает"
                )
            else:
                prompt = (
                    f"Blind injection confirmed on {url}\n"
                    f"Type: {ftype.upper()}\n"
                    f"Details: {description[:400]}\n\n"
                    f"Automatic extraction yielded no result. Help me:\n"
                    f"1. Write an optimal payload for byte-by-byte flag extraction\n"
                    f"2. Enumerate DB structure (tables, columns) if not done\n"
                    f"3. Suggest the correct sqlmap command for this situation\n"
                    f"4. Try out-of-band via DNS if time-based doesn't work"
                )
            prompts.append({
                "vuln_title": title,
                "vuln_type": "Blind Injection — Manual Extraction",
                "why_llm": "Requires crafting precise extraction queries based on DB response" if lang == "en" else "Требует точной настройки запросов на основе ответов БД",
                "prompt": prompt,
            })

        # WAF detected — bypass needed
        if ftype in ("sqli", "xss") and any(
            kw in (description + evidence).lower()
            for kw in ["waf", "403", "blocked", "forbidden", "firewall", "cloudflare"]
        ):
            if lang == "ru":
                prompt = (
                    f"WAF/фаервол блокирует эксплойт на {url}\n"
                    f"Уязвимость: {title}\n"
                    f"Заблокированный payload: {evidence[:200]}\n\n"
                    f"Помоги обойти WAF:\n"
                    f"1. Предложи tamper-техники специфичные для этого типа WAF\n"
                    f"2. Попробуй HTTP parameter pollution, chunked encoding\n"
                    f"3. Найди endpoint без WAF (API, legacy endpoint)\n"
                    f"4. Используй sqlmap с правильными tamper скриптами"
                )
            else:
                prompt = (
                    f"WAF/firewall is blocking the exploit on {url}\n"
                    f"Vulnerability: {title}\n"
                    f"Blocked payload: {evidence[:200]}\n\n"
                    f"Help bypass the WAF:\n"
                    f"1. Suggest tamper techniques specific to this WAF type\n"
                    f"2. Try HTTP parameter pollution, chunked encoding\n"
                    f"3. Find an endpoint without WAF (API, legacy endpoint)\n"
                    f"4. Use sqlmap with appropriate tamper scripts"
                )
            prompts.append({
                "vuln_title": title,
                "vuln_type": "WAF Bypass",
                "why_llm": "WAF bypass requires adaptive payload crafting based on responses" if lang == "en" else "Обход WAF требует адаптивного подбора payload на основе ответов",
                "prompt": prompt,
            })

        # Deserialization indicators
        if any(kw in (title + description).lower() for kw in ["deserializ", "pickle", "ysoserial", "java serial", "phpggc"]):
            if lang == "ru":
                prompt = (
                    f"Обнаружены признаки уязвимости десериализации на {url}\n"
                    f"Детали: {description[:400]}\n\n"
                    f"Помоги:\n"
                    f"1. Определить язык/фреймворк (PHP, Java, Python pickle)\n"
                    f"2. Сгенерировать payload для RCE через phpggc / ysoserial\n"
                    f"3. Написать команду для чтения /flag.txt\n"
                    f"4. Если Python pickle — написать exploit класс"
                )
            else:
                prompt = (
                    f"Deserialization vulnerability indicators found on {url}\n"
                    f"Details: {description[:400]}\n\n"
                    f"Help me:\n"
                    f"1. Identify the language/framework (PHP, Java, Python pickle)\n"
                    f"2. Generate RCE payload via phpggc / ysoserial\n"
                    f"3. Write command to read /flag.txt\n"
                    f"4. If Python pickle — write exploit class"
                )
            prompts.append({
                "vuln_title": title,
                "vuln_type": "Deserialization RCE",
                "why_llm": "Deserialization exploits require framework-specific gadget chains" if lang == "en" else "Эксплойты десериализации требуют специфичных gadget chain для фреймворка",
                "prompt": prompt,
            })

    # Deduplicate by vuln_title
    seen = set()
    unique = []
    for p in prompts:
        if p["vuln_title"] not in seen:
            seen.add(p["vuln_title"])
            unique.append(p)
    return unique


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
    flag_findings = [f for f in sorted_findings if f.type == "flag"]
    vuln_findings = [f for f in sorted_findings if f.type not in ("attack_path", "flag")]

    # Top 5 critical/high for executive summary
    top_findings = [f for f in vuln_findings if f.severity in ("critical", "high")][:5]

    # Unique CVEs
    cves = sorted({f.cve_id for f in findings if f.cve_id})

    # CTF mode
    is_ctf = getattr(scan, "scan_type", "") == "ctf" or len(flag_findings) > 0
    ctf_flag_format = getattr(scan, "ctf_flag_format", None)

    # LLM prompts for unsolved/complex vulnerabilities
    llm_prompts = _build_llm_prompts(scan, vuln_findings, lang) if is_ctf else []

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
        # CTF-specific
        "is_ctf": is_ctf,
        "flag_findings": flag_findings,
        "ctf_flag_format": ctf_flag_format,
        "llm_prompts": llm_prompts,
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
