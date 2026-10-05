# -*- coding: utf-8 -*-
"""منسق الفحص: يبني سياسة النطاق، يزحف، يشغّل المحركات، يعالج النتائج ويخزنها."""
from __future__ import annotations

import asyncio
import time

from . import audit, db
from .crawler import crawl
from .engines import CHECK_TO_ENGINE, REGISTRY, ScanContext
from .net import BudgetExceeded, Fetcher
from .scope import ScopePolicy
from .verify import post_process

# إعادة تصدير للتوافق مع الواجهة القديمة
from .engines.passive import analyze_response  # noqa: F401
from .engines.authcheck import cookie_attributes as _cookie_attributes  # noqa: F401
from .scope import in_scope  # noqa: F401

DEPTH_PRESETS = {
    "سطحي": dict(max_pages=15, depth=1, request_budget=300),
    "متوسط": dict(max_pages=50, depth=3, request_budget=600),
    "عميق": dict(max_pages=150, depth=5, request_budget=1500),
}
DEFAULT_DEPTH = "متوسط"


def normalize_config(raw: dict | None) -> dict:
    raw = raw or {}
    depth = raw.get("depth", DEFAULT_DEPTH)
    preset = DEPTH_PRESETS.get(depth, DEPTH_PRESETS[DEFAULT_DEPTH])
    rate = max(0.5, min(20.0, float(raw.get("rate_rps", 5.0))))
    duration = max(30, min(3600, int(raw.get("max_duration_sec", 600) or 600)))
    checks = raw.get("checks") or list(CHECK_TO_ENGINE.keys())
    checks = [c for c in checks if c in CHECK_TO_ENGINE]
    return {
        "depth": depth,
        "max_pages": preset["max_pages"],
        "depth_limit": preset["depth"],
        "request_budget": preset["request_budget"],
        "rate_rps": rate,
        "max_duration_sec": duration,
        "checks": checks,
        "use_accounts": bool(raw.get("use_accounts", False)),
    }


async def _login_test_accounts(ctx: ScanContext):
    """تسجيل دخول الحسابات الاختبارية المصرح بها (POST الوحيد المسموح)."""
    login_forms = [f for f in ctx.sitemap.forms if f.method == "POST" and f.has_password]
    if not login_forms:
        ctx.notes.append("فُعّل استخدام الحسابات لكن لم يُعثر على نموذج دخول.")
        return
    form = login_forms[0]
    user_field = next((i["name"] for i in form.inputs
                       if i["type"] in ("text", "email")
                       or any(k in i["name"].lower() for k in ("user", "login", "email"))), None)
    pass_field = next((i["name"] for i in form.inputs if i["type"] == "password"), None)
    if not user_field or not pass_field:
        ctx.notes.append("تعذر تحديد حقول اسم المستخدم/كلمة المرور في نموذج الدخول.")
        return
    for acc in ctx.accounts[:3]:
        try:
            r = await ctx.fetcher.post_form(form.action, {
                user_field: acc["username"], pass_field: acc["password"]})
        except Exception:
            ctx.notes.append(f"فشل تسجيل دخول الحساب الاختباري «{acc['label']}» (خطأ شبكة).")
            continue
        cookies = r.headers.get_list("set-cookie")
        if cookies:
            pairs = "; ".join(c.split(";", 1)[0] for c in cookies)
            ctx.sessions[acc["label"]] = {"Cookie": pairs}
            ctx.notes.append(f"تم تسجيل دخول الحساب الاختباري «{acc['label']}».")
        else:
            ctx.notes.append(f"تسجيل دخول «{acc['label']}» لم يُعد كوكي جلسة.")


async def run_scan(sid: int, project: dict, config: dict, stop_flag=lambda: False) -> dict:
    origin = project["origin"]
    policy = ScopePolicy.build(origin, project.get("scope_prefixes") or ["/"])
    audit.audit("scan_start", f"scan={sid} origin={origin} depth={config['depth']}")
    accounts = db.accounts(project["id"], reveal=True) if config.get("use_accounts") else []
    started = time.monotonic()
    findings = []
    routes_count = 0
    requests_count = 0
    stopped_early = False

    try:
        async with Fetcher(policy, rate_rps=config["rate_rps"], timeout=10.0,
                           max_requests=config["request_budget"],
                           max_duration_sec=config["max_duration_sec"],
                           stop_flag=stop_flag) as fetcher:
            from .crawler import SiteMap
            ctx = ScanContext(origin=origin, policy=policy, fetcher=fetcher,
                              sitemap=SiteMap(origin=origin), config=config, accounts=accounts)

            def _on_route(r):
                db.add_route(sid, r.url, r.source, r.status_code, r.method, r.params)
                db.set_scan_progress(sid, len(ctx.sitemap.routes))

            try:
                ctx.sitemap = await crawl(origin, policy, fetcher,
                                          max_pages=config["max_pages"],
                                          depth=config["depth_limit"], on_route=_on_route)
                routes_count = len(ctx.sitemap.routes)
                if config.get("use_accounts") and accounts:
                    await _login_test_accounts(ctx)
                engine_names = {CHECK_TO_ENGINE[c] for c in config["checks"]}
                for eng in REGISTRY.values():
                    if eng.name not in engine_names:
                        continue
                    if stop_flag():
                        stopped_early = True
                        break
                    try:
                        await eng.run(ctx)
                    except BudgetExceeded:
                        stopped_early = True
                        break
                    except Exception as exc:  # عزل فشل المحرك — لا يُسقط الفحص
                        ctx.notes.append(f"تعذر إكمال محرك «{eng.title}»: {type(exc).__name__}.")
                findings = post_process(ctx.findings)
                requests_count = fetcher.requests_count
                stopped_early = stopped_early or stop_flag() or fetcher.requests_count >= fetcher.max_requests
                notes = ctx.notes
            except BudgetExceeded:
                stopped_early = True
                requests_count = fetcher.requests_count
                notes = ["توقف الفحص عند بلوغ حد الطلبات/الزمن/الإيقاف."]
    except Exception as exc:
        db.finish_scan(sid, {"error": f"{type(exc).__name__}"}, status="failed")
        audit.audit("scan_error", f"scan={sid} {type(exc).__name__}")
        raise

    for f in findings:
        db.add_finding(sid, f)

    by_sev: dict[str, int] = {}
    by_conf: dict[str, int] = {}
    by_cat: dict[str, int] = {}
    for f in findings:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
        by_conf[f["confidence"]] = by_conf.get(f["confidence"], 0) + 1
        by_cat[f["category"]] = by_cat.get(f["category"], 0) + 1
    summary = {
        "mode": "فحص دفاعي غير تدميري (GET فقط)",
        "routes": routes_count,
        "requests": requests_count,
        "duration_sec": round(time.monotonic() - started, 1),
        "findings_total": len(findings),
        "by_severity": by_sev,
        "by_confidence": by_conf,
        "by_category": by_cat,
        "notes": notes,
        "stopped_early": stopped_early,
    }
    db.finish_scan(sid, summary, status="stopped" if (stop_flag() or stopped_early) else "completed")
    audit.audit("scan_done", f"scan={sid} findings={len(findings)} routes={routes_count}")
    return summary


def scan_project(sid: int, stop_flag=lambda: False) -> dict | None:
    """نقطة دخول عامل الطابور (تعمل داخل خيط منفصل)."""
    scan = db.get_scan(sid)
    if not scan:
        return None
    project = db.project(scan["project_id"])
    if not project:
        return None
    config = normalize_config(scan.get("config") or {})
    try:
        return asyncio.run(run_scan(sid, project, config, stop_flag))
    except Exception:
        return None


async def scan(origin: str, rate_rps: float = 5.0, max_pages: int = 50) -> dict:
    """واجهة مبسطة متوافقة مع الإصدار السابق: تفحص دون قاعدة بيانات."""
    from .crawler import SiteMap
    policy = ScopePolicy.build(origin, ["/"])
    findings = []
    notes: list[str] = []
    routes_count = 0
    async with Fetcher(policy, rate_rps=rate_rps, max_requests=2000,
                       max_duration_sec=900) as fetcher:
        config = normalize_config({"checks": list(CHECK_TO_ENGINE.keys())})
        ctx = ScanContext(origin=origin, policy=policy, fetcher=fetcher,
                          sitemap=SiteMap(origin=origin), config=config, accounts=[])
        try:
            ctx.sitemap = await crawl(origin, policy, fetcher, max_pages=max_pages, depth=3)
            routes_count = len(ctx.sitemap.routes)
            for eng in REGISTRY.values():
                try:
                    await eng.run(ctx)
                except BudgetExceeded:
                    break
                except Exception as exc:
                    ctx.notes.append(f"تعذر إكمال محرك «{eng.title}»: {type(exc).__name__}.")
            findings = post_process(ctx.findings)
            notes = ctx.notes
        except BudgetExceeded:
            notes = ["توقف الفحص عند بلوغ الحدود."]
        requests_count = fetcher.requests_count
    return {
        "origin": origin,
        "routes": routes_count,
        "requests": requests_count,
        "findings": findings,
        "notes": notes,
    }
