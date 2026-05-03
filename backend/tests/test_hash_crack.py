"""
Unit tests for hash detection — Phase 14.4.
"""
import pytest

from app.scanner.hash_crack import _detect_hash_type, _extract_hashes_from_findings
from app.scanner.base import Finding


class TestDetectHashType:
    def test_bcrypt(self):
        h = "$2b$12$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234"
        mode, name = _detect_hash_type(h)
        assert mode == "3200"
        assert "bcrypt" in name.lower()

    def test_md5(self):
        mode, name = _detect_hash_type("d41d8cd98f00b204e9800998ecf8427e")
        assert mode == "0"
        assert "md5" in name.lower()

    def test_sha1(self):
        mode, name = _detect_hash_type("da39a3ee5e6b4b0d3255bfef95601890afd80709")
        assert mode == "100"

    def test_sha256(self):
        h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        mode, name = _detect_hash_type(h)
        assert mode == "1400"

    def test_ntlm(self):
        mode, name = _detect_hash_type(
            "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"
        )
        assert mode == "1000"

    def test_krb5asrep(self):
        h = "$krb5asrep$23$user@DOMAIN:abcdef1234"
        mode, name = _detect_hash_type(h)
        assert mode == "18200"

    def test_krb5tgs(self):
        h = "$krb5tgs$23$*user$DOMAIN$service*$abcdef1234"
        mode, name = _detect_hash_type(h)
        assert mode == "13100"


class TestExtractHashes:
    def test_extracts_md5_from_evidence(self):
        f = Finding(
            type="postex",
            title="test",
            evidence="Found hash: d41d8cd98f00b204e9800998ecf8427e in /etc/shadow",
        )
        hashes = _extract_hashes_from_findings([f])
        assert any(len(h) == 32 for h in hashes)

    def test_extracts_asrep_from_description(self):
        f = Finding(
            type="postex",
            title="AS-REP",
            description="$krb5asrep$23$admin@CORP:deadbeef1234567890abcdef",
        )
        hashes = _extract_hashes_from_findings([f])
        assert any("krb5asrep" in h for h in hashes)

    def test_empty_findings(self):
        assert _extract_hashes_from_findings([]) == []

    def test_no_hashes_in_findings(self):
        f = Finding(type="port", title="Open port", evidence="port 80 open")
        assert _extract_hashes_from_findings([f]) == []
