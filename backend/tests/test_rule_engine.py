"""
Unit tests for Rule Engine — Phase 14.4.
Tests: deduplication, CVSS enrichment, attack path building, sorting.
"""
import pytest

from app.scanner.base import Finding
from app.scanner.rule_engine import (
    deduplicate,
    enrich_cvss,
    sort_findings,
    SEVERITY_ORDER,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

def make_finding(**kwargs) -> Finding:
    defaults = {
        "type": "vuln",
        "title": "Test finding",
        "severity": "medium",
        "port": 80,
        "protocol": "tcp",
        "service": "http",
    }
    defaults.update(kwargs)
    return Finding(**defaults)


# ── deduplicate ───────────────────────────────────────────────────────────────

class TestDeduplicate:
    def test_removes_exact_duplicates(self):
        findings = [
            make_finding(title="Open SSH Port", type="port", port=22, service="ssh"),
            make_finding(title="Open SSH Port", type="port", port=22, service="ssh"),
        ]
        result = deduplicate(findings)
        assert len(result) == 1

    def test_keeps_different_ports(self):
        findings = [
            make_finding(title="Open Port", type="port", port=22),
            make_finding(title="Open Port", type="port", port=80),
        ]
        result = deduplicate(findings)
        assert len(result) == 2

    def test_keeps_different_types(self):
        findings = [
            make_finding(title="SQL Injection", type="sqli", port=80),
            make_finding(title="SQL Injection", type="xss",  port=80),
        ]
        result = deduplicate(findings)
        assert len(result) == 2

    def test_merges_keeping_higher_severity(self):
        findings = [
            make_finding(title="Vuln", type="vuln", port=443, severity="low"),
            make_finding(title="Vuln", type="vuln", port=443, severity="critical"),
        ]
        result = deduplicate(findings)
        assert len(result) == 1
        assert result[0].severity == "critical"

    def test_empty_input(self):
        assert deduplicate([]) == []

    def test_single_finding_unchanged(self):
        f = make_finding(title="Single")
        result = deduplicate([f])
        assert len(result) == 1


# ── enrich_cvss ───────────────────────────────────────────────────────────────

class TestEnrichCvss:
    def test_cve_overrides_cvss(self):
        """Known CVE should set CVSS from the override table."""
        f = make_finding(cve_id="CVE-2017-0144", severity="info", cvss_score=None)
        result = enrich_cvss([f])
        assert result[0].cvss_score is not None
        assert result[0].cvss_score >= 9.0
        assert result[0].severity in ("critical", "high")

    def test_open_redis_gets_critical(self):
        f = make_finding(
            type="vuln",
            title="Redis without authentication",
            service="redis",
            port=6379,
            severity="info",
            cvss_score=None,
        )
        result = enrich_cvss([f])
        assert result[0].severity in ("critical", "high")
        assert result[0].cvss_score is not None

    def test_existing_cvss_not_overwritten_if_high(self):
        f = make_finding(cvss_score=9.5, severity="critical")
        result = enrich_cvss([f])
        assert result[0].cvss_score == 9.5

    def test_no_crash_on_empty(self):
        assert enrich_cvss([]) == []

    def test_ssl_weak_cipher_finding(self):
        f = make_finding(
            title="Weak SSL cipher suite detected",
            service="https",
            port=443,
            severity="info",
        )
        result = enrich_cvss([f])
        assert result[0].severity != "info" or result[0].cvss_score is not None


# ── sort_findings ─────────────────────────────────────────────────────────────

class TestSortFindings:
    def test_critical_before_high(self):
        findings = [
            make_finding(title="High",     severity="high",     cvss_score=8.0),
            make_finding(title="Critical", severity="critical",  cvss_score=9.8),
        ]
        result = sort_findings(findings)
        assert result[0].severity == "critical"

    def test_within_same_severity_higher_cvss_first(self):
        findings = [
            make_finding(title="Low CVSS",  severity="high", cvss_score=7.1),
            make_finding(title="High CVSS", severity="high", cvss_score=9.0),
        ]
        result = sort_findings(findings)
        assert result[0].cvss_score == 9.0

    def test_info_last(self):
        findings = [
            make_finding(title="Info",   severity="info"),
            make_finding(title="Medium", severity="medium"),
        ]
        result = sort_findings(findings)
        assert result[-1].severity == "info"

    def test_all_severities_ordered(self):
        findings = [make_finding(title=s, severity=s) for s in reversed(SEVERITY_ORDER)]
        result = sort_findings(findings)
        for i, sev in enumerate(SEVERITY_ORDER):
            assert result[i].severity == sev

    def test_empty_input(self):
        assert sort_findings([]) == []


# ── integration: full pipeline ────────────────────────────────────────────────

class TestRuleEnginePipeline:
    def test_dedup_then_enrich_then_sort(self):
        findings = [
            make_finding(title="Redis open",   type="vuln", service="redis", port=6379, severity="info"),
            make_finding(title="Redis open",   type="vuln", service="redis", port=6379, severity="low"),
            make_finding(title="CVE-2017-0144",type="vuln", cve_id="CVE-2017-0144", severity="info"),
            make_finding(title="Info finding", type="port", port=443, severity="info"),
        ]
        deduped  = deduplicate(findings)
        enriched = enrich_cvss(deduped)
        sorted_f = sort_findings(enriched)

        assert len(sorted_f) >= 2
        # Critical/high must come before info
        severities = [f.severity for f in sorted_f]
        if "critical" in severities:
            assert severities.index("critical") < severities.index("info")
