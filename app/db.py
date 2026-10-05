# -*- coding: utf-8 -*-
"""قاعدة بيانات TH Ghost — SQLite محلية مع استعلامات معلّمة فقط.

المخطط v2: مشاريع، حسابات اختبارية، فحوصات، نتائج موسعة، خريطة مسارات، سجل تدقيق.
لا تُخزَّن الأسرار في السجلات، ولا تُرجع واجهات القراءة كلمات المرور.
"""
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

# مسار ثابت نسبةً لجذر المشروع، لا لمجلد التشغيل، حتى لا تضيع البيانات عند التشغيل من مجلد آخر.
DB = Path(__file__).resolve().parent.parent / "th_ghost.db"

SEVERITY_ORDER = "CASE severity WHEN 'حرج' THEN 1 WHEN 'عالٍ' THEN 2 WHEN 'متوسط' THEN 3 WHEN 'منخفض' THEN 4 ELSE 5 END"


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def connect():
    c = sqlite3.connect(DB, timeout=30)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    c.execute("PRAGMA journal_mode=WAL")
    return c


SCHEMA = """
CREATE TABLE IF NOT EXISTS projects(
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  origin TEXT NOT NULL UNIQUE,
  scope_prefixes TEXT NOT NULL DEFAULT '[]',
  notes TEXT NOT NULL DEFAULT '',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS accounts(
  id INTEGER PRIMARY KEY,
  project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  label TEXT NOT NULL,
  username TEXT NOT NULL,
  password TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(project_id, username));
CREATE TABLE IF NOT EXISTS scans(
  id INTEGER PRIMARY KEY,
  project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  status TEXT NOT NULL DEFAULT 'queued',
  config TEXT NOT NULL DEFAULT '{}',
  progress INTEGER NOT NULL DEFAULT 0,
  started_at TEXT,
  finished_at TEXT,
  summary TEXT NOT NULL DEFAULT '{}',
  error TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS findings(
  id INTEGER PRIMARY KEY,
  scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  category TEXT NOT NULL,
  severity TEXT NOT NULL,
  confidence TEXT NOT NULL DEFAULT 'مرجحة',
  title TEXT NOT NULL,
  url TEXT NOT NULL,
  method TEXT NOT NULL DEFAULT 'GET',
  parameter TEXT NOT NULL DEFAULT '',
  location TEXT NOT NULL DEFAULT '',
  evidence TEXT NOT NULL,
  cause TEXT NOT NULL DEFAULT '',
  impact TEXT NOT NULL DEFAULT '',
  recommendation TEXT NOT NULL,
  reference TEXT NOT NULL DEFAULT '',
  retest TEXT NOT NULL DEFAULT '',
  cvss REAL,
  engine TEXT NOT NULL DEFAULT '',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(scan_id, title, url, parameter));
CREATE TABLE IF NOT EXISTS routes(
  id INTEGER PRIMARY KEY,
  scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  url TEXT NOT NULL,
  source TEXT NOT NULL,
  status_code INTEGER,
  method TEXT NOT NULL DEFAULT 'GET',
  params TEXT NOT NULL DEFAULT '[]',
  discovered_at TEXT DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(scan_id, url));
CREATE TABLE IF NOT EXISTS audit_log(
  id INTEGER PRIMARY KEY,
  ts TEXT DEFAULT CURRENT_TIMESTAMP,
  action TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT '');
"""


def init():
    with connect() as c:
        c.executescript(SCHEMA)


# ---------------- المشاريع ----------------
def add_project(name, origin, scope_prefixes=None, notes=""):
    try:
        with connect() as c:
            cur = c.execute(
                "INSERT INTO projects(name,origin,scope_prefixes,notes) VALUES(?,?,?,?)",
                (name, origin, json.dumps(scope_prefixes or [], ensure_ascii=False), notes))
            return cur.lastrowid
    except sqlite3.IntegrityError:
        raise ValueError("الأصل مسجل مسبقاً") from None


def projects():
    with connect() as c:
        rows = [dict(r) for r in c.execute(
            "SELECT id,name,origin,scope_prefixes,notes,created_at FROM projects ORDER BY id DESC")]
    for r in rows:
        r["scope_prefixes"] = json.loads(r["scope_prefixes"] or "[]")
        r["accounts_count"] = count_accounts(r["id"])
        r["last_scan"] = last_scan_summary(r["id"])
    return rows


def project(pid):
    with connect() as c:
        r = c.execute(
            "SELECT id,name,origin,scope_prefixes,notes,created_at FROM projects WHERE id=?", (pid,)).fetchone()
        if not r:
            return None
        d = dict(r)
        d["scope_prefixes"] = json.loads(d["scope_prefixes"] or "[]")
        return d


def delete_project(pid):
    with connect() as c:
        cur = c.execute("DELETE FROM projects WHERE id=?", (pid,))
        return cur.rowcount > 0


def update_project_scope(pid, prefixes, notes=None):
    with connect() as c:
        if notes is None:
            c.execute("UPDATE projects SET scope_prefixes=? WHERE id=?",
                      (json.dumps(prefixes or [], ensure_ascii=False), pid))
        else:
            c.execute("UPDATE projects SET scope_prefixes=?, notes=? WHERE id=?",
                      (json.dumps(prefixes or [], ensure_ascii=False), notes, pid))


# ---------------- الحسابات الاختبارية ----------------
def add_account(pid, label, username, password):
    with connect() as c:
        cur = c.execute(
            "INSERT INTO accounts(project_id,label,username,password) VALUES(?,?,?,?)",
            (pid, label, username, password))
        return cur.lastrowid


def accounts(pid, reveal=False):
    """يعيد الحسابات دون كلمات المرور افتراضياً؛ كشفها فقط لمحرك الفحص الداخلي."""
    with connect() as c:
        rows = [dict(r) for r in c.execute(
            "SELECT * FROM accounts WHERE project_id=? ORDER BY id", (pid,))]
    if not reveal:
        for r in rows:
            r.pop("password", None)
    return rows


def delete_account(pid, aid):
    with connect() as c:
        cur = c.execute("DELETE FROM accounts WHERE id=? AND project_id=?", (aid, pid))
        return cur.rowcount > 0


def count_accounts(pid):
    with connect() as c:
        return c.execute("SELECT COUNT(*) FROM accounts WHERE project_id=?", (pid,)).fetchone()[0]


# ---------------- الفحوصات ----------------
def create_scan(pid, config=None):
    with connect() as c:
        cur = c.execute(
            "INSERT INTO scans(project_id,status,config,started_at) VALUES(?,'queued',?,?)",
            (pid, json.dumps(config or {}, ensure_ascii=False), utcnow()))
        return cur.lastrowid


def set_scan_status(sid, status, error=""):
    with connect() as c:
        finished = utcnow() if status in ("completed", "failed", "stopped") else None
        if finished:
            c.execute("UPDATE scans SET status=?,error=?,finished_at=? WHERE id=?",
                      (status, error, finished, sid))
        else:
            c.execute("UPDATE scans SET status=?,error=? WHERE id=?", (status, error, sid))


def set_scan_progress(sid, progress):
    with connect() as c:
        c.execute("UPDATE scans SET progress=? WHERE id=?", (progress, sid))


def add_route(sid, url, source, status_code=None, method="GET", params=None):
    with connect() as c:
        c.execute(
            "INSERT OR IGNORE INTO routes(scan_id,url,source,status_code,method,params) VALUES(?,?,?,?,?,?)",
            (sid, url, source, status_code, method, json.dumps(params or [], ensure_ascii=False)))


def add_finding(sid, f):
    with connect() as c:
        c.execute(
            """INSERT OR IGNORE INTO findings
               (scan_id,category,severity,confidence,title,url,method,parameter,location,
                evidence,cause,impact,recommendation,reference,retest,cvss,engine)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (sid, f.get("category", "عام"), f["severity"], f.get("confidence", "مرجحة"),
             f["title"], f["url"], f.get("method", "GET"), f.get("parameter", ""),
             f.get("location", ""), f["evidence"], f.get("cause", ""), f.get("impact", ""),
             f["recommendation"], f.get("reference", ""), f.get("retest", ""),
             f.get("cvss"), f.get("engine", "")))


def finish_scan(sid, summary, status="completed"):
    status = {"done": "completed", "error": "failed"}.get(status, status)
    if status not in ("completed", "failed", "stopped"):
        status = "completed"
    with connect() as c:
        c.execute(
            "UPDATE scans SET status=?,finished_at=?,summary=? WHERE id=?",
            (status, utcnow(), json.dumps(summary, ensure_ascii=False), sid))


def get_scan(sid):
    with connect() as c:
        s = c.execute("SELECT * FROM scans WHERE id=?", (sid,)).fetchone()
        if not s:
            return None
        d = dict(s)
        d["summary"] = json.loads(d["summary"] or "{}")
        d["config"] = json.loads(d["config"] or "{}")
        return d


def all_scans(limit=100):
    """كل الفحوصات مع اسم المشروع وأصله — لجدول سجل الفحوصات."""
    with connect() as c:
        rows = [dict(r) for r in c.execute(
            """SELECT s.id,s.project_id,s.status,s.config,s.progress,s.started_at,
                      s.finished_at,s.summary,s.error,p.name AS project_name,p.origin AS project_origin
               FROM scans s JOIN projects p ON p.id=s.project_id
               ORDER BY s.id DESC LIMIT ?""", (limit,))]
    for r in rows:
        r["summary"] = json.loads(r["summary"] or "{}")
        r["config"] = json.loads(r["config"] or "{}")
    return rows


def scan_detail(sid):
    with connect() as c:
        s = c.execute(
            """SELECT s.*, p.name AS project_name, p.origin AS project_origin
               FROM scans s JOIN projects p ON p.id=s.project_id WHERE s.id=?""", (sid,)).fetchone()
        if not s:
            return None
        d = dict(s)
        d["summary"] = json.loads(d["summary"] or "{}")
        d["config"] = json.loads(d["config"] or "{}")
        d["findings"] = [dict(r) for r in c.execute(
            f"SELECT * FROM findings WHERE scan_id=? ORDER BY {SEVERITY_ORDER}, id", (sid,))]
        d["routes"] = [dict(r) for r in c.execute(
            "SELECT * FROM routes WHERE scan_id=? ORDER BY id", (sid,))]
        for r in d["routes"]:
            r["params"] = json.loads(r["params"] or "[]")
    return d


def scans_for_project(pid):
    with connect() as c:
        rows = [dict(r) for r in c.execute(
            "SELECT id,project_id,status,config,progress,started_at,finished_at,summary,error "
            "FROM scans WHERE project_id=? ORDER BY id DESC", (pid,))]
    for r in rows:
        r["summary"] = json.loads(r["summary"] or "{}")
        r["config"] = json.loads(r["config"] or "{}")
    return rows


def last_scan_summary(pid):
    rows = scans_for_project(pid)
    if not rows:
        return None
    r = rows[0]
    return {"id": r["id"], "status": r["status"], "started_at": r["started_at"],
            "summary": r["summary"]}


def running_scans():
    with connect() as c:
        return [dict(r) for r in c.execute(
            "SELECT id,project_id,status FROM scans WHERE status IN ('queued','running')")]


# ---------------- سجل التدقيق ----------------
def audit(action, detail=""):
    with connect() as c:
        c.execute("INSERT INTO audit_log(action,detail) VALUES(?,?)", (action, detail))


def audit_log(limit=200):
    with connect() as c:
        return [dict(r) for r in c.execute(
            "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))]


# ---------------- إحصاءات اللوحة ----------------
def dashboard_stats():
    with connect() as c:
        stats = {
            "projects": c.execute("SELECT COUNT(*) FROM projects").fetchone()[0],
            "scans": c.execute("SELECT COUNT(*) FROM scans").fetchone()[0],
            "findings": c.execute("SELECT COUNT(*) FROM findings").fetchone()[0],
            "by_severity": {r[0]: r[1] for r in c.execute(
                "SELECT severity,COUNT(*) FROM findings GROUP BY severity")},
            "by_confidence": {r[0]: r[1] for r in c.execute(
                "SELECT confidence,COUNT(*) FROM findings GROUP BY confidence")},
        }
    return stats
