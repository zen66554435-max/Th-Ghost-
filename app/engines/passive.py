# -*- coding: utf-8 -*-
"""محرك الخادم والإعدادات (Server & Configuration).

فحوصات سلبية على الاستجابات المخزنة من الزاحف + تحققات آمنة محدودة:
ترويسات الأمان (صفحات HTML)، كشف معلومات الخادم (مجمّعة)، Directory Listing،
صفحات أخطاء مسربة، ملفات إعدادات مكشوفة (توقيعات فقط دون تخزين محتوى)،
وإعداد TLS للأهداف HTTPS.
"""
from __future__ import annotations

import re
import socket
import ssl
from urllib.parse import urljoin, urlparse

from ..net import BudgetExceeded, FetchError
from ..scope import ScopeViolation
from ..verify import (CONFIRMED, INFO, LIKELY, TRACE_ERROR_RE, has_any, make)
from . import Engine, ScanContext

NAME = "passive"

# ملفات معروفة آمنة الجس — توقيع مطابقة فقط، لا يُخزَّن محتواها أبداً
EXPOSED_PROBES = [
    ("/.git/HEAD", re.compile(r"^ref:\s+refs/", re.M),
     "مستودع Git مكشوف", "عالٍ", CONFIRMED,
     "ظهر توقيع HEAD الخاص بمستودع Git (ref: refs/...) — لم يُقرأ أي محتوى آخر.",
     "قد يتيح تنزيل كامل الشيفرة المصدرية وتاريخها.",
     "امنع الوصول إلى /.git من خادم الويب واحذفه من بيئة الإنتاج.",
     "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/04-Review_Webpage_Content_for_Information_Leakage",
     7.5),
    ("/.env", re.compile(r"(?im)^[A-Z_]{3,}\s*=\s*\S"),
     "ملف بيئة .env مكشوف", "حرج", CONFIRMED,
     "ظهر توقيع ملف بيئة (KEY=VALUE) — أُخفي المحتوى ولم يُخزَّن.",
     "قد يحتوي مفاتيح قواعد بيانات وأسرار تطبيق.",
     "انقل .env خارج جذر الويب ودوّر أي أسرار تسربت فوراً.",
     "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
     9.1),
    ("/server-status", re.compile(r"(?i)apache server status|scoreboard"),
     "صفحة حالة خادم Apache مكشوفة", "متوسط", LIKELY,
     "ظهر توقيع صفحة server-status.",
     "تكشف تفاصيل الطلبات والعمال والمسارات الداخلية.",
     "قيّد mod_status بعناوين IP موثوقة أو عطّله.",
     "https://httpd.apache.org/docs/2.4/mod/mod_status.html",
     5.3),
    ("/phpinfo.php", re.compile(r"(?i)<title>phpinfo\(\)</title>|php version"),
     "صفحة phpinfo مكشوفة", "متوسط", LIKELY,
     "ظهر توقيع صفحة phpinfo.",
     "تكشف إصدارات PHP والوحدات ومسارات النظام.",
     "احذف phpinfo من بيئة الإنتاج.",
     "https://owasp.org/www-project-web-security-testing-guide/",
     5.3),
]

DIR_LISTING_RE = re.compile(r"(?i)<title>index of /|parent directory")


def analyze_response(url: str, origin: str, headers, set_cookies, body: str = "",
                     status: int = 200, content_type: str = "") -> list:
    """فحوصات سلبية على استجابة واحدة — دالة نقية قابلة لاختبار الوحدات.

    فحوص الترويسات الأمنية تُطبق على صفحات HTML؛ خواص الكوكيز يفحصها محرك الجلسات.
    """
    h = {k.lower(): v for k, v in headers.items()}
    origin_scheme = urlparse(origin).scheme
    is_html = "text/html" in (content_type or headers.get("Content-Type", "")).lower()
    out = []

    if is_html:
        checks = [
            ("غياب سياسة منع التأطير",
             "x-frame-options" not in h and "frame-ancestors" not in h.get("content-security-policy", "").lower(),
             "منخفض", "أضف CSP frame-ancestors أو X-Frame-Options.",
             "يغيب أي مانع لتأطير الصفحة داخل إطارات خارجية.",
             "هجوم Clickjacking قد يخدع المستخدمين لتنفيذ إجراءات غير مقصودة.",
             "https://owasp.org/www-community/attacks/Clickjacking", 4.3),
            ("غياب سياسة MIME nosniff",
             h.get("x-content-type-options", "").lower() != "nosniff",
             "منخفض", "اضبط X-Content-Type-Options: nosniff.",
             "لا تمنع الصفحة تخمين نوع MIME.",
             "قد يفسر المتصفح محتوى غير موثوق كسكربت.",
             "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options", 3.1),
            ("غياب سياسة HSTS",
             origin_scheme == "https" and "strict-transport-security" not in h,
             "منخفض", "فعّل Strict-Transport-Security بعد التأكد من HTTPS على كامل النطاق.",
             "لا تفرض الصفحة الاتصال المشفر مستقبلاً.",
             "هجمات إسقاط الاتصال إلى HTTP.",
             "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security", 4.0),
        ]
        for title, hit, severity, fix, cause, impact, ref, cvss in checks:
            if hit:
                out.append(make("الخادم والإعدادات", severity, CONFIRMED, title, url, NAME,
                                evidence="فحص سلبي للترويسات المرسلة فعلياً.",
                                cause=cause, impact=impact, recommendation=fix,
                                reference=ref, cvss=cvss,
                                retest="أعد الفحص بعد الإصلاح وتحقق من الترويسة يدوياً عبر curl -I."))

    if DIR_LISTING_RE.search(body or ""):
        out.append(make("الخادم والإعدادات", "متوسط", CONFIRMED, "سرد مجلد مكشوف (Directory Listing)", url, NAME,
                        evidence="توقيع صفحة سرد مجلد (Index of /) في جسم الصفحة.",
                        cause="تمكين سرد المجلدات افتراضياً.",
                        impact="كشف أسماء ملفات ونسخ احتياطية وحساسة.",
                        recommendation="عطّل سرد المجلدات وأضف فهرساً افتراضياً.",
                        reference="https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
                        retest="افتح المسار وتأكد من ظهور 403 أو صفحة مخصصة.", cvss=5.3))

    if status >= 500:
        sig = has_any(body or "", TRACE_ERROR_RE)
        if sig:
            out.append(make("الخادم والإعدادات", "منخفض", LIKELY, "صفحة خطأ تكشف معلومات داخلية", url, NAME,
                            evidence=f"توقيع تتبع خطأ: «{sig}».",
                            cause="عرض تتبع الأخطاء للمستخدمين في بيئة الإنتاج.",
                            impact="كشف مسارات ومكتبات وبنية الكود للمهاجم.",
                            recommendation="فعّل صفحات خطأ مخصصة وعطّل العرض التفصيلي للأخطاء.",
                            reference="https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
                            retest="أعد إنتاج الخطأ وتأكد من ظهور صفحة عامة.", cvss=3.7))
    return out


def check_tls(origin: str) -> list:
    """فحص TLS خفيف للأهداف HTTPS: الإصدار وصلاحية الشهادة."""
    p = urlparse(origin)
    if p.scheme != "https":
        return []
    host, port = p.hostname, p.port or 443
    out = []
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                proto = ssock.version()
                cert = ssock.getpeercert()
    except (ssl.SSLError, socket.timeout, OSError):
        return [make("الخادم والإعدادات", "متوسط", LIKELY, "تعذر إتمام مصافحة TLS", origin, NAME,
                     evidence="فشلت مصافحة TLS أو الشهادة غير صالحة.",
                     cause="شهادة منتهية/موقعة ذاتياً أو إعداد TLS خاطئ.",
                     impact="قد لا يحمي الاتصال فعلياً.",
                     recommendation="راجع الشهادة وإعدادات TLS.",
                     reference="https://ssl-config.mozilla.org/",
                     retest="openssl s_client -connect host:443", cvss=5.9)]
    if proto in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
        out.append(make("الخادم والإعدادات", "متوسط", CONFIRMED, f"إصدار TLS قديم ({proto})", origin, NAME,
                        evidence=f"تفاوض الاتصال على {proto}.",
                        cause="بروتوكول تشفير متقادم ما يزال ممكناً.",
                        impact="هجمات معروفة على الإصدارات القديمة (POODLE/BEAST).",
                        recommendation="اقتصر على TLS 1.2 و1.3.",
                        reference="https://ssl-config.mozilla.org/",
                        retest="testssl.sh أو openssl s_client -tls1_2", cvss=6.5))
    try:
        from datetime import datetime, timezone
        exp = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days = (exp - datetime.now(timezone.utc)).days
        if days < 30:
            out.append(make("الخادم والإعدادات", "منخفض", CONFIRMED,
                            f"شهادة TLS تنتهي خلال {days} يوماً", origin, NAME,
                            evidence=f"تاريخ الانتهاء: {cert['notAfter']}.",
                            cause="شهادة قاربت على الانتهاء.",
                            impact="انقطاع الخدمة أو تحذيرات للمستخدمين.",
                            recommendation="جدّد الشهادة قبل انتهائها.",
                            reference="https://letsencrypt.org/docs/",
                            retest="افحص تاريخ الانتهاء بعد التجديد."))
    except (KeyError, ValueError):
        pass
    return out


class Engine(Engine):
    name = NAME
    title = "الخادم والإعدادات"

    async def run(self, ctx: ScanContext):
        # 1) تحليل سلبي لكل استجابة مخزنة + تجميع كشف Server في نتيجة واحدة
        server_leaks = []
        for url, r in ctx.sitemap.responses.items():
            if url.endswith("#inline-js"):
                continue
            body = r.text[:800_000] if hasattr(r, "text") else ""
            for f in analyze_response(url, ctx.origin, r.headers,
                                      r.headers.get_list("set-cookie"), body, r.status_code,
                                      r.headers.get("content-type", "")):
                ctx.add(f)
            if r.headers.get("server", "").strip():
                server_leaks.append(urlparse(url).path or "/")
        if server_leaks:
            ctx.add(make("الخادم والإعدادات", "معلوماتية", INFO, "كشف ترويسة Server",
                         ctx.origin, NAME,
                         evidence=f"الخادم يرسل ترويسة Server على {len(server_leaks)} مساراً؛ لم يُستنتج إصدار أو يُستغل. أمثلة: {', '.join(server_leaks[:8])}",
                         cause="إعداد افتراضي يكشف هوية الخادم.",
                         impact="يساعد المهاجم على استهداف إصدار محدد.",
                         recommendation="قلّل تفاصيل ترويسة Server إن أمكن، مع عدم اعتبار إخفائها بديلاً عن التحديثات.",
                         reference="https://owasp.org/www-project-web-security-testing-guide/",
                         retest="curl -sI للعنوان ومراجعة الترويسة."))

        # 2) جسّات ملفات مكشوفة — توقيعات فقط
        for path, sig, title, sev, conf, ev, impact, fix, ref, cvss in EXPOSED_PROBES:
            u = urljoin(ctx.origin, path)
            try:
                r = await ctx.fetcher.get(u)
            except (FetchError, BudgetExceeded, ScopeViolation):
                continue
            if r.status_code == 200 and sig.search(r.text[:200_000] or ""):
                ctx.add(make("الخادم والإعدادات", sev, conf, title, u, NAME,
                             evidence=ev, cause="ملف/مسار حساس مكشوف للعامة.",
                             impact=impact, recommendation=fix, reference=ref, cvss=cvss,
                             retest="اطلب المسار بعد الحظر وتأكد من 403/404."))

        # 3) TLS (HTTPS فقط)
        for f in check_tls(ctx.origin):
            ctx.add(f)
