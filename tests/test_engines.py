# -*- coding: utf-8 -*-
"""اختبارات وحدات للمحركات وأدوات التحقق."""
from app.engines.authcheck import cookie_attributes
from app.engines.deps import (audit_dependencies, audit_python_source,
                              parse_package_lock, parse_requirements)
from app.engines.passive import analyze_response
from app.verify import (CONFIRMED, LIKELY, make, post_process, scrub_evidence,
                        similarity_ratio)


class TestPassiveAnalysis:
    def test_html_missing_headers_http(self):
        fs = analyze_response("http://x/", "http://x", {}, "", "<html></html>", 200, "text/html")
        titles = [f["title"] for f in fs]
        assert any("تأطير" in t for t in titles)
        assert any("nosniff" in t for t in titles)
        assert not any("HSTS" in t for t in titles)  # http لا https

    def test_https_adds_hsts(self):
        fs = analyze_response("https://x/", "https://x", {}, "", "<html></html>", 200, "text/html")
        assert any("HSTS" in f["title"] for f in fs)

    def test_non_html_skipped(self):
        fs = analyze_response("http://x/api", "http://x", {}, "", "{}", 200, "application/json")
        assert fs == []

    def test_secure_page_clean(self):
        h = {"X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff"}
        fs = analyze_response("http://x/", "http://x", h, "", "<html></html>", 200, "text/html")
        assert fs == []

    def test_dir_listing(self):
        fs = analyze_response("http://x/b/", "http://x", {}, "",
                              "<title>Index of /b/</title>", 200, "text/html")
        assert any("سرد مجلد" in f["title"] for f in fs)
        assert fs[0]["confidence"] == CONFIRMED

    def test_error_leak_on_500(self):
        fs = analyze_response("http://x/", "http://x", {}, "",
                              "Traceback (most recent call last):", 500, "text/html")
        assert any("خطأ" in f["title"] for f in fs)
        assert any(f["confidence"] == LIKELY for f in fs)


class TestCookies:
    def test_parse_flags(self):
        a = cookie_attributes("sid=abc; HttpOnly; Secure; SameSite=Lax; Path=/")
        assert a["name"] == "sid" and a["secure"] and a["httponly"] and a["samesite"] == "lax"

    def test_missing_flags(self):
        a = cookie_attributes("sid=abc; Path=/")
        assert not a["secure"] and not a["httponly"] and a["samesite"] == ""

    def test_garbage(self):
        assert cookie_attributes("") == {}


class TestDeps:
    def test_parse_requirements(self):
        pkgs = parse_requirements("requests==2.19.0\n# comment\nflask==2.0.0\n-e .\n")
        assert pkgs == {"requests": "2.19.0", "flask": "2.0.0"}

    def test_parse_package_lock(self):
        lock = '{"dependencies":{"lodash":{"version":"4.17.20"}},"packages":{"node_modules/axios":{"version":"0.21.0"}}}'
        pkgs = parse_package_lock(lock)
        assert pkgs["lodash"] == "4.17.20" and pkgs["axios"] == "0.21.0"

    def test_advisory_match(self):
        findings, count = audit_dependencies({"requests": "2.19.0"}, "requirements.txt")
        assert count == 1
        assert len(findings) == 1
        assert "CVE-2018-18074" in findings[0]["evidence"]
        assert findings[0]["confidence"] == CONFIRMED

    def test_advisory_no_match_when_new(self):
        findings, _ = audit_dependencies({"requests": "2.32.3"})
        assert findings == []


class TestSourceAudit:
    def test_eval_with_line(self):
        src = "x = 1\ny = eval(user_input)\n"
        fs = audit_python_source(src, "a.py")
        ev = [f for f in fs if "eval" in f["title"]]
        assert ev and ev[0]["location"] == "السطر 2"

    def test_shell_true(self):
        fs = audit_python_source('import subprocess\nsubprocess.run("ls", shell=True)\n', "b.py")
        assert any("shell=True" in f["title"] for f in fs)

    def test_yaml_load(self):
        fs = audit_python_source("import yaml\nd = yaml.load(data)\n", "c.py")
        assert any("yaml" in f["title"].lower() for f in fs)

    def test_verify_false_regex(self):
        fs = audit_python_source('import requests\nr = requests.get("https://x", verify=False)\n', "d.py")
        assert any("TLS" in f["title"] for f in fs)

    def test_syntax_error_handled(self):
        fs = audit_python_source("def broken(:\n", "bad.py")
        assert len(fs) == 1 and "تعذر" in fs[0]["title"]

    def test_clean_file(self):
        assert audit_python_source("def add(a, b):\n    return a + b\n", "ok.py") == []


class TestVerify:
    def test_similarity(self):
        assert similarity_ratio("abc", "abc") == 1.0
        assert similarity_ratio("aaaa", "bbbb") < 0.5

    def test_scrub_masks_secrets(self):
        out = scrub_evidence("found password=Sup3rSecret123 in body")
        assert "Sup3rSecret123" not in out and "***" in out

    def test_make_complete(self):
        f = make("فئة", "عالٍ", CONFIRMED, "عنوان", "http://x/", "eng")
        for k in ("category", "severity", "confidence", "title", "url", "method",
                  "evidence", "recommendation", "engine"):
            assert k in f

    def test_post_process_dedup_and_downgrade(self):
        a = make("فئة", "عالٍ", CONFIRMED, "t", "http://x/", "eng", evidence="دليل")
        b = make("فئة", "عالٍ", CONFIRMED, "t", "http://x/", "eng", evidence="دليل")
        c = make("فئة", "عالٍ", CONFIRMED, "t2", "http://x/", "eng", evidence="")
        out = post_process([a, b, c])
        assert len(out) == 2
        assert out[1]["confidence"] == LIKELY  # بلا دليل → خُفّضت
