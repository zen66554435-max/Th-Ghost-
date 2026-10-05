# -*- coding: utf-8 -*-
"""اختبار تكامل كامل: فحص حقيقي للمختبر عبر خط الأنابيب الكامل."""
import asyncio
import collections

import pytest

from app.scanner import scan
from lab.lab_server import make_server, serve_in_thread


@pytest.fixture(scope="module")
def labs():
    log_a: list[str] = []
    log_b: list[str] = []
    srv_b = make_server(0, log_b)
    serve_in_thread(srv_b)
    srv_a = make_server(0, log_a, external_base=f"http://127.0.0.1:{srv_b.server_port}/")
    serve_in_thread(srv_a)
    yield {"a": srv_a, "b": srv_b, "log_a": log_a, "log_b": log_b}
    srv_a.shutdown()
    srv_b.shutdown()


@pytest.fixture(scope="module")
def result(labs):
    origin = f"http://127.0.0.1:{labs['a'].server_port}"
    return asyncio.run(scan(origin, rate_rps=15.0, max_pages=60))


def _has(result, title_part, url_part):
    return any(title_part in f["title"] and url_part in f["url"] for f in result["findings"])


class TestDetectionMatrix:
    """كل فئة ثغرة مزروعة في المختبر يجب أن تُكشف."""

    @pytest.mark.parametrize("title,url", [
        ("تأطير", "/form"), ("nosniff", "/form"), ("سرد مجلد", "/backup/"),
        ("صفحة خطأ", "/status/500"), ("Git", "/.git/HEAD"), (".env", "/.env"),
        ("ترويسة Server", ""),
    ])
    def test_server_config(self, result, title, url):
        assert _has(result, title, url), f"مفقود: {title} @ {url}"

    @pytest.mark.parametrize("title,url", [
        ("حقن SQL", "/search"), ("XSS", "/xss-test"), ("قوالب", "/hello"),
        ("حقن أوامر", "/ping"), ("اجتياز مسار", "/download"), ("LDAP", "/ldap"),
        ("XPath", "/xpath"), ("حقن ترويسات", "/redir"),
    ])
    def test_injection(self, result, title, url):
        assert _has(result, title, url), f"مفقود: {title} @ {url}"

    @pytest.mark.parametrize("title,url", [
        ("IDOR", "/api/users/1"), ("BFLA", "/api/admin/stats"),
    ])
    def test_access(self, result, title, url):
        assert _has(result, title, url)

    @pytest.mark.parametrize("title,url", [
        ("HttpOnly", ""), ("SameSite", ""), ("معرّف جلسة ضعيف", ""),
        ("CSRF", "/api/login"), ("غير مشفر", "/api/login"),
        ("سياسة كلمة المرور", "/api/login"), ("تسجيل الخروج", "/logout"),
    ])
    def test_auth(self, result, title, url):
        assert _has(result, title, url)

    @pytest.mark.parametrize("title,url", [
        ("إفراط كشف", "/api/users"), ("CORS", "/api/cors"),
        ("حد معدل", ""), ("بلا مصادقة", "/openapi.json"), ("تغيير حالة", "/openapi.json"),
    ])
    def test_api(self, result, title, url):
        assert _has(result, title, url)

    def test_files(self, result):
        assert _has(result, "رفع ملفات", "/upload")

    @pytest.mark.parametrize("title,url", [
        ("Google API", "/assets/app.js"), ("قديمة", "jquery-1.12.4"),
        ("DOM", "/dom-xss"), ("localStorage", "/assets/app.js"), ("أمن المحتوى", ""),
    ])
    def test_clientside(self, result, title, url):
        assert _has(result, title, url)

    @pytest.mark.parametrize("title,url", [
        ("قيمة سالبة", "/order"), ("متعدد الخطوات", "/checkout"),
    ])
    def test_bizlogic(self, result, title, url):
        assert _has(result, title, url)


class TestNegativeControls:
    """صفحات آمنة يجب ألا تُعلَّم."""

    def test_xss_safe_clean(self, result):
        assert not _has(result, "XSS", "/xss-safe")

    def test_secure_headers_clean(self, result):
        assert not _has(result, "تأطير", "/secure-headers")
        assert not _has(result, "nosniff", "/secure-headers")

    def test_parameterized_product_clean(self, result):
        assert not _has(result, "حقن SQL", "/product")

    def test_rate_limited_api_clean(self, result):
        assert not _has(result, "حد معدل", "/api/health")


class TestSafety:
    def test_no_external_requests(self, labs, result):
        # /redirect-external يشير للخادم B — يجب ألا يصله أي طلب (حارس النطاق)
        assert labs["log_b"] == []

    def test_get_only(self, labs, result):
        # فحص بلا حسابات: لا يُسمح إلا بـ GET
        assert all(entry.startswith("GET") for entry in labs["log_a"])

    def test_no_crawler_loops(self, labs, result):
        # الزاحف لا يجلب العنوان نفسه مرتين أبداً (مجموعة seen)؛ التكرار الوحيد المشروع
        # هو جسّ محرك واحد بعد جلب الزاحف — أي العتبة: مرتان كحد أقصى لأي عنوان.
        urls = [e.split(" ", 1)[1] for e in labs["log_a"] if e.startswith("GET")]
        counts = collections.Counter(urls)
        assert counts.most_common(1)[0][1] <= 2

    def test_no_secrets_in_findings(self, result):
        blob = str(result["findings"])
        assert "labpass" not in blob           # كلمات مرور المختبر
        assert "lab-fake-pass" not in blob     # محتوى .env
        assert "AIzaSyFAKEKEY" not in blob     # مفتاح JS المكشوف — يُشار لنمطه فقط

    def test_findings_fully_detailed(self, result):
        required = {"category", "severity", "confidence", "title", "url", "method",
                    "evidence", "cause", "impact", "recommendation", "reference", "retest"}
        for f in result["findings"]:
            assert required <= set(f), f["title"]
            assert f["evidence"].strip(), f"دليل فارغ: {f['title']}"
            assert f["recommendation"].strip()

    def test_confidence_levels_valid(self, result):
        valid = {"مؤكدة", "مرجحة", "معلوماتية", "تحتاج مراجعة يدوية"}
        assert all(f["confidence"] in valid for f in result["findings"])
