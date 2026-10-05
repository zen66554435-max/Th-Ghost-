# -*- coding: utf-8 -*-
"""اختبارات تراجعية: هيكل المشروع، منع XSS مخزن، تعقّب أسرار، سلامة SQL."""
import re
from pathlib import Path

import pytest

from app import audit, db
from app.verify import make, post_process

ROOT = Path(__file__).resolve().parent.parent


class TestProjectHygiene:
    def test_requirements_wellformed(self):
        lines = [l.strip() for l in (ROOT / "requirements.txt").read_text().splitlines()
                 if l.strip() and not l.startswith("#")]
        assert len(lines) >= 5
        for l in lines:
            assert re.match(r"^[a-z0-9_\-]+(\[[a-z]+\])?(>=|==)[0-9]", l), l

    def test_gitignore_has_db(self):
        assert "*.db" in (ROOT / ".gitignore").read_text()

    def test_db_path_absolute_and_anchored(self):
        assert db.DB.is_absolute()
        assert db.DB.parent == ROOT

    def test_no_fstring_sql(self):
        src = (ROOT / "app" / "db.py").read_text(encoding="utf-8")
        assert not re.search(r'execute\(f["\']', src), "استعلام SQL بسلسلة-f — ممنوع"


class TestStoredXSSPrevention:
    """واجهة العرض يجب أن تبني DOM عبر textContent حصراً."""

    def test_no_innerhtml_in_static(self):
        for name in ("app.js", "index.html"):
            src = (ROOT / "app" / "static" / name).read_text(encoding="utf-8")
            assert "innerHTML" not in src, name
            assert "document.write" not in src, name

    def test_inert_payload_survives_roundtrip(self, tmp_path, monkeypatch):
        monkeypatch.setattr(db, "DB", tmp_path / "t.db")
        db.init()
        pid = db.add_project("x", "http://127.0.0.1:9", ["/"])
        sid = db.create_scan(pid, {})
        payload = "<script>alert('xss')</script>"
        db.add_finding(sid, make("اختبار", "منخفض", "معلوماتية", "عنوان",
                                 "http://127.0.0.1:9/", "t", evidence=payload,
                                 recommendation="r"))
        db.finish_scan(sid, {})
        got = db.scan_detail(sid)["findings"][0]["evidence"]
        assert got == payload  # يُخزَّن كنص خام — ويعرضه المتصفح كنص عبر textContent


class TestSecretHygiene:
    def test_finding_evidence_scrubbed(self):
        f = make("c", "منخفض", "معلوماتية", "t", "http://x/", "e",
                 evidence="token=abcdef123456789 leaked", recommendation="r")
        assert "abcdef123456789" not in f["evidence"]

    def test_audit_scrubbed(self, tmp_path, monkeypatch):
        monkeypatch.setattr(db, "DB", tmp_path / "t.db")
        db.init()
        audit.audit("test_action", "user=u password=TopSecret999")
        entries = db.audit_log()
        assert entries and "TopSecret999" not in entries[0]["detail"]

    def test_accounts_masked_by_default(self, tmp_path, monkeypatch):
        monkeypatch.setattr(db, "DB", tmp_path / "t.db")
        db.init()
        pid = db.add_project("x", "http://127.0.0.1:9", ["/"])
        db.add_account(pid, "lbl", "user1", "HiddenPw123")
        assert "password" not in db.accounts(pid)[0]
        assert db.accounts(pid, reveal=True)[0]["password"] == "HiddenPw123"


class TestCascade:
    def test_project_delete_cascades(self, tmp_path, monkeypatch):
        monkeypatch.setattr(db, "DB", tmp_path / "t.db")
        db.init()
        pid = db.add_project("x", "http://127.0.0.1:9", ["/"])
        sid = db.create_scan(pid, {})
        db.add_finding(sid, make("c", "عالٍ", "مرجحة", "t", "http://x/", "e",
                                 evidence="d", recommendation="r"))
        db.add_route(sid, "http://127.0.0.1:9/", "بذرة", 200)
        db.finish_scan(sid, {})
        db.delete_project(pid)
        assert db.scan_detail(sid) is None
        assert db.projects() == []


class TestSqliPayloadInert:
    def test_probe_payloads_are_safe_strings(self):
        from app.engines import injection
        for p in (injection.XSS_MARKER, injection.CMD_MARKER, injection.BASE_VALUE,
                  *injection.TRAVERSAL_PAYLOADS):
            assert isinstance(p, str) and len(p) < 200
        # علامة الأمر لا تحوي أي أمر حقيقي — مجرد echo لنص ثابت
        assert injection.CMD_MARKER == "THG9273"
