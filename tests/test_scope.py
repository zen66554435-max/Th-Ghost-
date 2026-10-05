# -*- coding: utf-8 -*-
"""اختبارات حارس النطاق: التطبيع، البادئات، SSRF، metadata، DNS rebinding."""
import ipaddress

import pytest

from app.scope import (ScopePolicy, ScopeViolation, in_scope, normalize_origin,
                       resolve_host)


class TestNormalizeOrigin:
    def test_basic_http(self):
        assert normalize_origin("http://example.com/path?x=1") == "http://example.com"

    def test_default_ports_dropped(self):
        assert normalize_origin("https://example.com:443/") == "https://example.com"
        assert normalize_origin("http://example.com:80") == "http://example.com"

    def test_custom_port_kept(self):
        assert normalize_origin("http://127.0.0.1:8080/x") == "http://127.0.0.1:8080"

    def test_reject_non_http(self):
        with pytest.raises(ValueError):
            normalize_origin("ftp://example.com")

    def test_reject_no_host(self):
        with pytest.raises(ValueError):
            normalize_origin("http://")

    def test_reject_userinfo(self):
        with pytest.raises(ValueError):
            normalize_origin("http://user:pass@example.com")

    def test_ipv6_bracketed(self):
        assert normalize_origin("http://[::1]:8080/") == "http://[::1]:8080"


class TestInScope:
    def test_same_origin(self):
        assert in_scope("http://a.test/x", "http://a.test")

    def test_different_host(self):
        assert not in_scope("http://b.test/x", "http://a.test")

    def test_different_port(self):
        assert not in_scope("http://a.test:9090/x", "http://a.test:8080")

    def test_prefix_allows(self):
        assert in_scope("http://a.test/app/x", "http://a.test", ["/app"])

    def test_prefix_blocks(self):
        assert not in_scope("http://a.test/admin", "http://a.test", ["/app"])


class TestScopePolicy:
    def test_local_target_allowed(self):
        p = ScopePolicy.build("http://127.0.0.1:8765", ["/"])
        assert p.is_local is True
        p.validate_url("http://127.0.0.1:8765/x")  # لا يرفع

    def test_cloud_metadata_blocked(self):
        with pytest.raises(ScopeViolation):
            ScopePolicy.build("http://169.254.169.254", ["/"])

    def test_out_of_origin_rejected(self):
        p = ScopePolicy.build("http://127.0.0.1:8765", ["/"])
        with pytest.raises(ScopeViolation):
            p.validate_url("http://127.0.0.1:9999/other")

    def test_prefix_enforced(self):
        p = ScopePolicy.build("http://127.0.0.1:8765", ["/app"])
        p.validate_url("http://127.0.0.1:8765/app/x")
        with pytest.raises(ScopeViolation):
            p.validate_url("http://127.0.0.1:8765/other")

    def test_rebinding_detected(self, monkeypatch):
        """إذا تغيّرت عناوين DNS بعد التثبيت يُرفض الطلب."""
        real = resolve_host
        state = {"n": 0}

        def flaky(host):
            state["n"] += 1
            if state["n"] == 1:
                return {ipaddress.ip_address("93.184.216.34")}
            return {ipaddress.ip_address("93.184.216.34"), ipaddress.ip_address("10.0.0.5")}

        monkeypatch.setattr("app.scope.resolve_host", flaky)
        p = ScopePolicy.build("http://public-test.invalid", ["/"])
        with pytest.raises(ScopeViolation):
            p.validate_url("http://public-test.invalid/")
        monkeypatch.setattr("app.scope.resolve_host", real)

    def test_public_target_ok(self, monkeypatch):
        monkeypatch.setattr("app.scope.resolve_host",
                            lambda h: {ipaddress.ip_address("93.184.216.34")})
        p = ScopePolicy.build("http://public-test.invalid", ["/"])
        assert p.is_local is False
        p.validate_url("http://public-test.invalid/x")

    def test_public_resolving_private_rejected(self, monkeypatch):
        """هدف عام يحل لعنوان داخلي — SSRF."""
        monkeypatch.setattr("app.scope.resolve_host",
                            lambda h: {ipaddress.ip_address("192.168.1.10")})
        # يُقبل كـ«محلي» لكن يبقى مثبتاً؛ المهم: لا يرمي خطأ بناءً، لكنه مثبت بدقة
        p = ScopePolicy.build("http://sneaky.invalid", ["/"])
        assert p.is_local is True
        assert p.pinned_ips == frozenset({ipaddress.ip_address("192.168.1.10")})
