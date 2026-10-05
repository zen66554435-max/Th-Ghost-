# -*- coding: utf-8 -*-
"""اختبارات واجهة API عبر TestClient مع قاعدة بيانات مؤقتة معزولة."""
import time

import pytest
from fastapi.testclient import TestClient

from app import db


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB", tmp_path / "test.db")
    db.init()
    from app.main import app
    with TestClient(app) as c:
        yield c


def _mk_project(client, origin="http://127.0.0.1:1", name="مشروع اختبار"):
    return client.post("/projects",
                       data={"name": name, "origin": origin, "scope_prefixes": "/"})


class TestBasics:
    def test_health(self, client):
        r = client.get("/api/health")
        assert r.status_code == 200 and r.json()["ok"]

    def test_index_served(self, client):
        r = client.get("/")
        assert r.status_code == 200 and "TH Ghost" in r.text

    def test_security_headers(self, client):
        r = client.get("/api/health")
        assert r.headers["x-content-type-options"] == "nosniff"
        assert r.headers["x-frame-options"] == "DENY"
        assert "content-security-policy" in r.headers


class TestProjects:
    def test_create_and_list(self, client):
        r = _mk_project(client)
        assert r.status_code == 200 and r.json()["id"] >= 1
        projects = client.get("/api/projects").json()["projects"]
        assert any(p["origin"] == "http://127.0.0.1:1" for p in projects)

    def test_duplicate_origin_409(self, client):
        _mk_project(client)
        r = _mk_project(client, name="نسخة")
        assert r.status_code == 409

    def test_invalid_origin_400(self, client):
        r = _mk_project(client, origin="ftp://x")
        assert r.status_code == 400

    def test_cloud_metadata_rejected(self, client):
        r = _mk_project(client, origin="http://169.254.169.254")
        assert r.status_code == 400

    def test_scope_update(self, client):
        pid = _mk_project(client).json()["id"]
        r = client.put(f"/api/projects/{pid}/scope", json={"scope_prefixes": ["/app"]})
        assert r.status_code == 200 and r.json()["scope_prefixes"] == ["/app"]

    def test_delete_project(self, client):
        pid = _mk_project(client).json()["id"]
        assert client.delete(f"/api/projects/{pid}").status_code == 200
        assert client.get(f"/api/projects/{pid}").status_code == 404

    def test_missing_project_404(self, client):
        assert client.get("/api/projects/999").status_code == 404


class TestAccounts:
    def test_add_and_masked_listing(self, client):
        pid = _mk_project(client).json()["id"]
        r = client.post(f"/api/projects/{pid}/accounts",
                        json={"label": "منخفض", "username": "u1", "password": "Sup3rSecret!"})
        assert r.status_code == 200
        accounts = client.get(f"/api/projects/{pid}/accounts").json()["accounts"]
        assert len(accounts) == 1
        assert "password" not in accounts[0]  # لا تُعاد كلمات المرور أبداً

    def test_validation_422(self, client):
        pid = _mk_project(client).json()["id"]
        r = client.post(f"/api/projects/{pid}/accounts", json={"label": "", "username": ""})
        assert r.status_code == 422


class TestScans:
    def test_enqueue_and_complete_against_dead_port(self, client):
        pid = _mk_project(client).json()["id"]
        r = client.post(f"/api/projects/{pid}/scans",
                        json={"depth": "سطحي", "rate_rps": 20, "max_duration_sec": 60})
        assert r.status_code == 200
        sid = r.json()["scan_id"]
        # المنفذ :1 يرفض الاتصال فوراً — يكتمل الفحص بصفر نتائج دون تعليق
        for _ in range(60):
            d = client.get(f"/api/scans/{sid}").json()
            if d["status"] not in ("queued", "running"):
                break
            time.sleep(0.5)
        assert d["status"] in ("completed", "stopped")

    def test_stop_scan(self, client):
        pid = _mk_project(client).json()["id"]
        sid = client.post(f"/api/projects/{pid}/scans", json={}).json()["scan_id"]
        r = client.post(f"/api/scans/{sid}/stop")
        assert r.status_code == 200 and r.json()["ok"]

    def test_missing_scan_404(self, client):
        assert client.get("/api/scans/999").status_code == 404

    def test_report_and_json_export(self, client):
        pid = _mk_project(client).json()["id"]
        sid = db.create_scan(pid, {"depth": "متوسط"})
        db.set_scan_status(sid, "running")
        db.add_finding(sid, {
            "category": "الحقن", "severity": "عالٍ", "confidence": "مؤكدة",
            "title": "حقن SQL", "url": "http://127.0.0.1:1/search", "method": "GET",
            "parameter": "q", "location": "", "evidence": "دليل اختبار",
            "cause": "سبب", "impact": "أثر", "recommendation": "إصلاح",
            "reference": "https://owasp.org", "retest": "أعد", "cvss": 9.8, "engine": "injection"})
        db.finish_scan(sid, {"mode": "اختبار", "findings_total": 1}, status="completed")
        rep = client.get(f"/api/scans/{sid}/report")
        assert rep.status_code == 200 and "حقن SQL" in rep.text and "CVSS" in rep.text
        js = client.get(f"/api/scans/{sid}/export.json")
        assert js.status_code == 200 and js.json()["findings"][0]["title"] == "حقن SQL"

    def test_rescan_uses_stored_config(self, client):
        pid = _mk_project(client).json()["id"]
        sid = db.create_scan(pid, {"depth": "سطحي"})
        db.finish_scan(sid, {}, status="completed")
        scans = client.get("/api/scans").json()["scans"]
        assert any(s["id"] == sid and s["config"]["depth"] == "سطحي" for s in scans)


class TestDepsAudit:
    def test_requirements_audit(self, client):
        pid = _mk_project(client).json()["id"]
        r = client.post(f"/api/projects/{pid}/deps-audit",
                        files=[("files", ("requirements.txt", b"requests==2.19.0\nflask==2.0.0\n"))])
        assert r.status_code == 200
        assert r.json()["findings"] >= 2 and r.json()["dependencies"] == 2

    def test_python_source_audit(self, client):
        pid = _mk_project(client).json()["id"]
        r = client.post(f"/api/projects/{pid}/deps-audit",
                        files=[("files", ("app.py", b"import os\nos.system(user)\n"))])
        assert r.status_code == 200 and r.json()["findings"] >= 1

    def test_reject_bad_extension(self, client):
        pid = _mk_project(client).json()["id"]
        r = client.post(f"/api/projects/{pid}/deps-audit",
                        files=[("files", ("evil.exe", b"MZ"))])
        assert r.status_code == 400


class TestAuditLog:
    def test_actions_logged_and_scrubbed(self, client):
        pid = _mk_project(client).json()["id"]
        client.post(f"/api/projects/{pid}/accounts",
                    json={"label": "x", "username": "u", "password": "NeverShowMe123"})
        entries = client.get("/api/audit-log").json()["entries"]
        assert any(e["action"] == "project_created" for e in entries)
        assert "NeverShowMe123" not in str(entries)

    def test_stats(self, client):
        _mk_project(client)
        s = client.get("/api/stats").json()
        assert s["projects"] >= 1
