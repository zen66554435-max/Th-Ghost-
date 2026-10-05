# -*- coding: utf-8 -*-
"""خادم TH Ghost — واجهة FastAPI: لوحة تحكم عربية، مشاريع، فحوص، تقارير، تدقيق تبعيات."""
from __future__ import annotations

import json
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import api_audit, audit, db, jobs, scanner
from .engines.deps import (audit_dependencies, audit_python_source,
                           parse_package_lock, parse_requirements)
from .scope import ScopePolicy, ScopeViolation
from .verify import post_process

BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = BASE_DIR / "app" / "static"

app = FastAPI(title="TH Ghost — منصة التدقيق الأمني", version="1.0.0",
              docs_url=None, redoc_url=None, openapi_url=None)


@app.on_event("startup")
def _startup():
    db.init()
    jobs.mark_orphan_scans()
    jobs.start_worker()


@app.middleware("http")
async def security_headers(request, call_next):
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; connect-src 'self'")
    return resp


@app.get("/")
def index():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/health")
def health():
    return {"ok": True, "version": "1.0.0", "mode": "فحص دفاعي غير تدميري"}


# ---------- المشاريع ----------

@app.post("/projects")
def create_project(name: str = Form(...), origin: str = Form(...),
                   scope_prefixes: str = Form("/"), notes: str = Form("")):
    prefixes = [p.strip() for p in scope_prefixes.split(",") if p.strip()] or ["/"]
    try:
        policy = ScopePolicy.build(origin, prefixes)
    except (ScopeViolation, ValueError) as exc:
        audit.audit("project_rejected", f"{origin}: {exc}")
        raise HTTPException(400, f"عنوان مرفوض حسب سياسة النطاق: {exc}")
    try:
        pid = db.add_project(name.strip() or policy.origin, policy.origin, prefixes, notes.strip())
    except ValueError:
        raise HTTPException(409, "هذا الأصل مُسجّل مسبقاً كمشروع.")
    audit.audit("project_created", f"id={pid} origin={policy.origin} scope={prefixes}")
    return {"id": pid, "origin": policy.origin, "scope_prefixes": prefixes}


@app.get("/api/projects")
def list_projects():
    return {"projects": db.projects()}


@app.get("/api/projects/{pid}")
def get_project(pid: int):
    p = db.project(pid)
    if not p:
        raise HTTPException(404, "المشروع غير موجود.")
    return {"project": p, "accounts": db.accounts(pid), "scans": db.scans_for_project(pid)}


@app.delete("/api/projects/{pid}")
def remove_project(pid: int):
    if not db.project(pid):
        raise HTTPException(404, "المشروع غير موجود.")
    db.delete_project(pid)
    audit.audit("project_deleted", f"id={pid}")
    return {"ok": True}


class ScopeIn(BaseModel):
    scope_prefixes: list[str] = Field(default=["/"])


@app.put("/api/projects/{pid}/scope")
def update_scope(pid: int, body: ScopeIn):
    p = db.project(pid)
    if not p:
        raise HTTPException(404, "المشروع غير موجود.")
    prefixes = [x for x in body.scope_prefixes if x.startswith("/")] or ["/"]
    db.update_project_scope(pid, prefixes)
    audit.audit("scope_updated", f"id={pid} scope={prefixes}")
    return {"ok": True, "scope_prefixes": prefixes}


# ---------- الحسابات الاختبارية ----------

class AccountIn(BaseModel):
    label: str = Field(min_length=1, max_length=60)
    username: str = Field(min_length=1, max_length=120)
    password: str = Field(min_length=1, max_length=200)


@app.post("/api/projects/{pid}/accounts")
def add_account(pid: int, body: AccountIn):
    if not db.project(pid):
        raise HTTPException(404, "المشروع غير موجود.")
    if db.count_accounts(pid) >= 10:
        raise HTTPException(400, "الحد الأقصى 10 حسابات اختبارية لكل مشروع.")
    aid = db.add_account(pid, body.label.strip(), body.username.strip(), body.password)
    audit.audit("account_added", f"project={pid} label={body.label.strip()}")
    return {"id": aid}


@app.get("/api/projects/{pid}/accounts")
def list_accounts(pid: int):
    if not db.project(pid):
        raise HTTPException(404, "المشروع غير موجود.")
    # لا تُعاد كلمات المرور أبداً
    return {"accounts": db.accounts(pid, reveal=False)}


@app.delete("/api/projects/{pid}/accounts/{aid}")
def remove_account(pid: int, aid: int):
    db.delete_account(pid, aid)
    audit.audit("account_deleted", f"project={pid} account={aid}")
    return {"ok": True}


# ---------- الفحوص ----------

class ScanConfig(BaseModel):
    depth: str = "متوسط"
    rate_rps: float = Field(5.0, ge=0.5, le=20.0)
    max_duration_sec: int = Field(600, ge=30, le=3600)
    checks: list[str] = Field(default_factory=lambda: list(scanner.CHECK_TO_ENGINE.keys()))
    use_accounts: bool = False


@app.post("/api/projects/{pid}/scans")
def start_scan(pid: int, body: ScanConfig):
    p = db.project(pid)
    if not p:
        raise HTTPException(404, "المشروع غير موجود.")
    config = scanner.normalize_config(body.model_dump())
    if config["use_accounts"] and db.count_accounts(pid) == 0:
        raise HTTPException(400, "فعّلتَ استخدام الحسابات لكن لا توجد حسابات اختبارية في المشروع.")
    sid = db.create_scan(pid, config)
    position = jobs.QUEUE.enqueue(sid)
    audit.audit("scan_queued", f"scan={sid} project={pid} checks={','.join(config['checks'])}")
    return {"scan_id": sid, "queue_position": position}


@app.get("/api/scans")
def list_scans():
    return {"scans": db.all_scans(limit=100)}


@app.get("/api/scans/{sid}")
def get_scan(sid: int):
    detail = db.scan_detail(sid)
    if not detail:
        raise HTTPException(404, "الفحص غير موجود.")
    detail["queue_position"] = jobs.QUEUE.position(sid)
    return detail


@app.post("/api/scans/{sid}/stop")
def stop_scan(sid: int):
    scan = db.get_scan(sid)
    if not scan:
        raise HTTPException(404, "الفحص غير موجود.")
    jobs.QUEUE.request_stop(sid)
    if scan["status"] == "queued":
        db.set_scan_status(sid, "stopped")
        db.finish_scan(sid, {"note": "أُوقف قبل البدء."}, status="stopped")
    audit.audit("scan_stop", f"scan={sid}")
    return {"ok": True}


@app.get("/api/queue")
def queue_state():
    return jobs.QUEUE.snapshot()


# ---------- التقارير ----------

SEV_EMOJI = {"حرج": "🔴", "عالٍ": "🟠", "متوسط": "🟡", "منخفض": "🔵"}


@app.get("/api/scans/{sid}/report")
def report_markdown(sid: int):
    detail = db.scan_detail(sid)
    if not detail:
        raise HTTPException(404, "الفحص غير موجود.")
    scan, findings, routes = detail, detail["findings"], detail["routes"]
    s = scan.get("summary") or {}
    lines = [
        f"# تقرير فحص TH Ghost — {scan['project_name']}",
        "",
        f"- **الأصل:** {scan['project_origin']}",
        f"- **الحالة:** {scan['status']} | **النمط:** {s.get('mode', '—')}",
        f"- **المسارات:** {s.get('routes', 0)} | **الطلبات:** {s.get('requests', 0)} | "
        f"**المدة:** {s.get('duration_sec', 0)} ثانية",
        f"- **النتائج:** {s.get('findings_total', len(findings))} "
        f"(بالشدة: {json.dumps(s.get('by_severity', {}), ensure_ascii=False)})",
        f"- **الثقة:** {json.dumps(s.get('by_confidence', {}), ensure_ascii=False)}",
        "",
        "> لا يتضمن هذا التقرير كلمات مرور أو رموزاً أو بيانات شخصية — تُخفى الأدلة الحساسة آلياً.",
        "",
        "## النتائج",
        "",
    ]
    if not findings:
        lines.append("لا نتائج مسجلة.")
    for i, f in enumerate(findings, 1):
        lines += [
            f"### {i}. {SEV_EMOJI.get(f['severity'], '⚪')} {f['title']}",
            "",
            f"- **الفئة:** {f['category']} | **الشدة:** {f['severity']} | **الثقة:** {f['confidence']}"
            + (f" | **CVSS:** {f['cvss']}" if f.get("cvss") else ""),
            f"- **الموقع:** `{f['method']} {f['url']}`"
            + (f" — المعامل: `{f['parameter']}`" if f.get("parameter") else "")
            + (f" — {f['location']}" if f.get("location") else ""),
            f"- **الدليل:** {f['evidence']}",
            f"- **السبب:** {f['cause']}",
            f"- **الأثر:** {f['impact']}",
            f"- **الإصلاح:** {f['recommendation']}",
            f"- **المرجع:** {f['reference']}",
            f"- **إعادة الاختبار:** {f['retest']}",
            "",
        ]
    if s.get("notes"):
        lines += ["## ملاحظات المحركات", ""]
        lines += [f"- {n}" for n in s["notes"]]
        lines.append("")
    if routes:
        lines += ["## خريطة الموقع المكتشفة", "",
                  "| المسار | المصدر | الحالة | المعاملات |", "|---|---|---|---|"]
        for r in routes[:200]:
            lines.append(f"| `{r['url']}` | {r['source']} | {r['status_code']} | {r['params']} |")
        lines.append("")
    return PlainTextResponse("\n".join(lines), media_type="text/markdown; charset=utf-8",
                             headers={"Content-Disposition": f'attachment; filename="th-ghost-report-{sid}.md"'})


@app.get("/api/scans/{sid}/export.json")
def report_json(sid: int):
    detail = db.scan_detail(sid)
    if not detail:
        raise HTTPException(404, "الفحص غير موجود.")
    return JSONResponse(detail)


# ---------- تدقيق التبعيات والمصدر ----------

ALLOWED_UPLOAD_SUFFIXES = (".txt", ".lock", ".py", ".json")


@app.post("/api/projects/{pid}/deps-audit")
async def deps_audit(pid: int, files: list[UploadFile] = File(...)):
    p = db.project(pid)
    if not p:
        raise HTTPException(404, "المشروع غير موجود.")
    if not files or len(files) > 10:
        raise HTTPException(400, "ارفع بين ملف و10 ملفات (requirements.txt / package-lock.json / *.py).")
    all_findings = []
    parsed_count = 0
    for f in files:
        name = Path(f.filename or "file").name
        if not name.endswith(ALLOWED_UPLOAD_SUFFIXES) and name not in ("requirements", "Pipfile.lock"):
            raise HTTPException(400, f"نوع ملف غير مدعوم: {name}")
        data = await f.read()
        if len(data) > 2 * 1024 * 1024:
            raise HTTPException(400, f"الملف أكبر من 2MB: {name}")
        text = data.decode("utf-8", errors="replace")
        if name.endswith(".py"):
            all_findings += audit_python_source(text, name)
        elif "package-lock" in name or name.endswith(".lock") and name.endswith(".json"):
            findings, cnt = audit_dependencies(parse_package_lock(text), source=name)
            all_findings += findings
            parsed_count += cnt
        else:
            findings, cnt = audit_dependencies(parse_requirements(text), source=name)
            all_findings += findings
            parsed_count += cnt
    all_findings = post_process(all_findings)
    sid = db.create_scan(pid, {"depth": "تدقيق ملفات", "checks": ["deps"], "rate_rps": 0,
                                 "max_duration_sec": 0, "use_accounts": False})
    db.set_scan_status(sid, "running")
    for f in all_findings:
        db.add_finding(sid, f)
    summary = {"mode": "تدقيق تبعيات ومصدر (ملفات مرفوعة)", "routes": 0, "requests": 0,
               "duration_sec": 0, "findings_total": len(all_findings),
               "by_severity": {}, "by_confidence": {}, "by_category": {},
               "notes": [f"حُلّلت {len(files)} ملفاً، {parsed_count} تبعية مثبتة."]}
    for f in all_findings:
        summary["by_severity"][f["severity"]] = summary["by_severity"].get(f["severity"], 0) + 1
        summary["by_confidence"][f["confidence"]] = summary["by_confidence"].get(f["confidence"], 0) + 1
        summary["by_category"][f["category"]] = summary["by_category"].get(f["category"], 0) + 1
    db.finish_scan(sid, summary, status="done")
    audit.audit("deps_audit", f"project={pid} files={len(files)} findings={len(all_findings)}")
    return {"scan_id": sid, "findings": len(all_findings), "dependencies": parsed_count}


# ---------- قديم متوافق ----------

@app.post("/api/projects/{pid}/openapi-audit")
def openapi_audit(pid: int):
    p = db.project(pid)
    if not p:
        raise HTTPException(404, "المشروع غير موجود.")
    try:
        result = api_audit.inspect_openapi(p["origin"])
    except Exception as exc:
        raise HTTPException(502, f"تعذر تدقيق OpenAPI: {type(exc).__name__}")
    audit.audit("openapi_audit", f"project={pid} found={result.get('found')}")
    return result


# ---------- سجل التدقيق والإحصاءات ----------

@app.get("/api/audit-log")
def get_audit_log(limit: int = 100):
    return {"entries": db.audit_log(min(max(limit, 1), 500))}


@app.get("/api/stats")
def stats():
    return db.dashboard_stats()


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
