# -*- coding: utf-8 -*-
"""تحقق نهائي بدورة حية: خادم uvicorn حقيقي + مختبر حقيقي + سيناريو مستخدم كامل."""
import json
import subprocess
import sys
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from lab.lab_server import make_server, serve_in_thread  # noqa: E402

APP = "http://127.0.0.1:8399"
failures = []


def check(name, cond, extra=""):
    mark = "✅" if cond else "❌"
    print(f"{mark} {name}" + (f" — {extra}" if extra and not cond else ""))
    if not cond:
        failures.append(name)


def main():
    lab = make_server(0, [])
    serve_in_thread(lab)
    lab_origin = f"http://127.0.0.1:{lab.server_port}"
    print(f"[i] المختبر: {lab_origin}")

    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8399"],
        cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(60):
            try:
                httpx.get(f"{APP}/api/health", timeout=2).raise_for_status()
                break
            except Exception:
                time.sleep(0.5)
        c = httpx.Client(base_url=APP, timeout=30)

        r = c.get("/api/health").json()
        check("نقطة الصحة", r["ok"])

        r = c.get("/")
        check("لوحة التحكم تُقدَّم", r.status_code == 200 and "TH Ghost" in r.text)
        check("ترويسة CSP على الواجهة", "content-security-policy" in r.headers)

        r = c.post("/projects", data={"name": "مختبر", "origin": lab_origin,
                                      "scope_prefixes": "/", "notes": "فحص تدريبي مصرح"})
        check("إنشاء مشروع للمختبر", r.status_code == 200, r.text[:200])
        pid = r.json()["id"]

        r = c.post("/projects", data={"name": "مكرر", "origin": lab_origin})
        check("رفض الأصل المكرر 409", r.status_code == 409)

        r = c.post("/projects", data={"name": "خبيث", "origin": "http://169.254.169.254"})
        check("رفض عنوان metadata السحابي", r.status_code == 400)

        r = c.post(f"/api/projects/{pid}/accounts",
                   json={"label": "حساب1", "username": "labuser1", "password": "labpass1"})
        check("إضافة حساب اختباري", r.status_code == 200)
        r = c.post(f"/api/projects/{pid}/accounts",
                   json={"label": "حساب2", "username": "labuser2", "password": "labpass2"})
        accs = c.get(f"/api/projects/{pid}/accounts").json()["accounts"]
        check("الحسابات لا تكشف كلمات المرور", all("password" not in a for a in accs))

        r = c.post(f"/api/projects/{pid}/scans",
                   json={"depth": "متوسط", "rate_rps": 15, "max_duration_sec": 300,
                         "use_accounts": True})
        check("بدء فحص عبر API", r.status_code == 200, r.text[:200])
        sid = r.json()["scan_id"]

        status = ""
        for _ in range(240):
            d = c.get(f"/api/scans/{sid}").json()
            status = d["status"]
            if status not in ("queued", "running"):
                break
            time.sleep(1)
        check("اكتمال الفحص", status == "completed", f"status={status}")
        s = d["summary"]
        check("تخزين النتائج", s.get("findings_total", 0) > 50, str(s.get("findings_total")))
        check("تخزين المسارات", len(d["routes"]) > 25, str(len(d["routes"])))
        check("تسجيل دخول الحسابات أثناء الفحص",
              any("تسجيل دخول" in n for n in s.get("notes", [])), str(s.get("notes")))
        titles = [f["title"] for f in d["findings"]]
        check("كشف SQLi عبر API", any("حقن SQL" in t for t in titles))
        check("كشف IDOR عبر API", any("IDOR" in t for t in titles))
        check("لا أسرار في النتائج", "labpass" not in json.dumps(d, ensure_ascii=False))

        r = c.get(f"/api/scans/{sid}/report")
        check("تقرير Markdown", r.status_code == 200 and "تقرير فحص TH Ghost" in r.text
              and "إعادة الاختبار" in r.text)
        check("التقرير بلا أسرار", "labpass" not in r.text and "AIzaSy" not in r.text)

        r = c.get(f"/api/scans/{sid}/export.json")
        check("تصدير JSON", r.status_code == 200 and len(r.json()["findings"]) > 50)

        # إعادة فحص
        r = c.post(f"/api/projects/{pid}/scans", json={"depth": "سطحي", "rate_rps": 15})
        sid2 = r.json()["scan_id"]
        for _ in range(240):
            st = c.get(f"/api/scans/{sid2}").json()["status"]
            if st not in ("queued", "running"):
                break
            time.sleep(1)
        check("إعادة الفحص تكتمل", st in ("completed", "stopped"), st)

        r = c.post(f"/api/projects/{pid}/deps-audit",
                   files=[("files", ("requirements.txt", b"requests==2.19.0\npyyaml==5.3\n"))])
        check("تدقيق التبعيات عبر API", r.status_code == 200 and r.json()["findings"] >= 2,
              r.text[:150])

        r = c.get("/api/audit-log")
        check("سجل التدقيق يعمل", any(e["action"] == "scan_start" for e in r.json()["entries"]))
        check("سجل التدقيق بلا أسرار", "labpass" not in json.dumps(r.json(), ensure_ascii=False))

        r = c.get("/api/stats")
        check("إحصاءات اللوحة", r.json()["projects"] >= 1 and r.json()["findings"] > 50)

        # فحص الإيقاف: فحص بطيء ثم إيقافه
        r = c.post(f"/api/projects/{pid}/scans",
                   json={"depth": "عميق", "rate_rps": 0.5, "max_duration_sec": 3600})
        sid3 = r.json()["scan_id"]
        time.sleep(2)
        c.post(f"/api/scans/{sid3}/stop")
        for _ in range(60):
            st = c.get(f"/api/scans/{sid3}").json()["status"]
            if st in ("stopped", "completed"):
                break
            time.sleep(1)
        check("زر الإيقاف يوقف الفحص", st == "stopped", st)

        r = c.get("/api/queue")
        check("حالة الطابور", r.status_code == 200)
    finally:
        proc.terminate()
        lab.shutdown()
    print()
    if failures:
        print(f"❌ إخفاقات: {failures}")
        return 1
    print("🎉 كل فحوصات الدورة الحية ناجحة")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
