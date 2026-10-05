# -*- coding: utf-8 -*-
"""محرك جانب العميل: أسرار في JS، مكتبات قديمة، مصادر/مصارف DOM، تخزين المتصفح، CSP."""
from __future__ import annotations

import re

from ..net import BudgetExceeded, FetchError
from ..scope import ScopeViolation
from ..verify import CONFIRMED, INFO, LIKELY, MANUAL, make, scrub_evidence
from . import Engine, ScanContext

NAME = "clientside"
MAX_JS = 15

SECRET_PATTERNS = [
    (re.compile(r"AIza[0-9A-Za-z_\-]{35}"), "مفتاح Google API مكشوف", "عالٍ", CONFIRMED, 7.5),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "مفتاح AWS Access Key مكشوف", "حرج", CONFIRMED, 9.0),
    (re.compile(r"-----BEGIN (?:RSA |EC |)PRIVATE KEY-----"), "مفتاح خاص مكشوف", "حرج", CONFIRMED, 9.0),
    (re.compile(r"(?i)(api[_-]?key|secret|token)[\"']?\s*[:=]\s*[\"'][0-9a-zA-Z_\-]{16,}[\"']"),
     "سر محتمل مضمّن في JavaScript", "متوسط", LIKELY, 5.3),
]
OLD_LIBS = [
    (re.compile(r"jquery[-.]1\.\d"), "jQuery 1.x قديمة بثغرات معروفة", "متوسط", 6.1),
    (re.compile(r"jquery[-.]2\.\d"), "jQuery 2.x قديمة بثغرات معروفة", "متوسط", 6.1),
    (re.compile(r"bootstrap[-.]3\."), "Bootstrap 3 منتهي الدعم", "منخفض", 4.3),
    (re.compile(r"angular(?:\.min)?[-.]1\."), "AngularJS 1.x منتهي الدعم", "متوسط", 6.1),
    (re.compile(r"lodash[-.]([0-3]\.|4\.(0|1[0-6])\.)"), "Lodash بإصدار بثغرات معروفة", "متوسط", 6.1),
]
DOM_SOURCES = re.compile(r"(location\.(hash|search|href)|document\.URL|document\.referrer|window\.name)")
DOM_SINKS = re.compile(r"(\.innerHTML\s*=|document\.write|eval\(|setTimeout\(['\"]|\.outerHTML\s*=)")
STORAGE_RE = re.compile(r"(?i)localStorage\.setItem\(['\"]([a-z0-9_\-]*(?:token|secret|password|session|auth)[a-z0-9_\-]*)['\"]")


class Engine(Engine):
    name = NAME
    title = "جانب العميل"

    async def run(self, ctx: ScanContext):
        await self._analyze_js(ctx)
        self._csp(ctx)

    async def _analyze_js(self, ctx: ScanContext):
        urls = list(ctx.sitemap.js_files)[:MAX_JS]
        sink_only_count = 0
        for url in urls:
            body = None
            if url in ctx.sitemap.responses:
                body = ctx.sitemap.responses[url].text[:400_000]
            elif url.endswith("#inline-js"):
                continue
            else:
                try:
                    r = await ctx.fetcher.get(url)
                    body = r.text[:400_000]
                except (FetchError, BudgetExceeded, ScopeViolation):
                    continue
            if not body:
                continue

            for rx, title, sev, conf, cvss in SECRET_PATTERNS:
                m = rx.search(body)
                if m:
                    ctx.add(make("جانب العميل", sev, conf, title, url, NAME,
                                 evidence="عُثر على نمط السر في الملف — أُخفيت القيمة كاملة ولم تُخزَّن.",
                                 cause="تضمين أسرار في كود يصل المتصفح.",
                                 impact="أي زائر يستطيع سرقة السر وإساءة استخدامه.",
                                 recommendation="انقل الأسرار إلى الخادم ودوّر المكشوف فوراً.",
                                 reference="https://owasp.org/www-community/vulnerabilities/Password_plaintext_storage",
                                 retest="افحص مصدر الصفحة وملفات JS وتأكد من غياب الأسرار.",
                                 cvss=cvss))

            for rx, title, sev, cvss in OLD_LIBS:
                if rx.search(url) or rx.search(body[:2000]):
                    ctx.add(make("جانب العميل", sev, LIKELY, f"مكتبة قديمة: {title}", url, NAME,
                                 evidence="رُصد توقيع إصدار قديم في الاسم أو المحتوى.",
                                 cause="عدم تحديث تبعيات الواجهة.",
                                 impact="ثغرات معروفة موثقة في الإصدار القديم.",
                                 recommendation="حدّث المكتبة لأحدث إصدار مدعوم.",
                                 reference="https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
                                 retest="تحقق من الإصدار الفعلي وقارنه بالنشرات الأمنية.",
                                 cvss=cvss))
                    break

            src = DOM_SOURCES.search(body)
            sink = DOM_SINKS.search(body)
            if src and sink:
                ctx.add(make("جانب العميل", "متوسط", MANUAL, "تدفق DOM خطير محتمل (مصدر→مصرف)",
                             url, NAME,
                             evidence=f"وُجد مصدر «{src.group(1)}» ومصرف «{sink.group(1)}» في الملف نفسه.",
                             cause="قد تصل بيانات URL إلى DOM دون تنقية.",
                             impact="XSS مبني على DOM.",
                             recommendation="نقّ البيانات واستخدم textContent لا innerHTML.",
                             reference="https://owasp.org/www-community/attacks/DOM_Based_XSS",
                             retest="جرّب ‎#<img src=x onerror=alert(1)>‎ في بيئة اختبار معزولة.",
                             cvss=6.1))
            elif sink and not src and sink_only_count < 3:
                sink_only_count += 1
                ctx.add(make("جانب العميل", "منخفض", INFO, "مصرف DOM خطير مستخدم",
                             url, NAME,
                             evidence=f"استخدام «{sink.group(1)}» — راجع مصادر البيانات يدوياً.",
                             cause="—", impact="احتمال XSS إن وصلته بيانات غير موثوقة.",
                             recommendation="استبدله بـ textContent أو منقّي HTML.",
                             reference="https://owasp.org/www-community/attacks/DOM_Based_XSS",
                             retest="تتبع مصادر البيانات يدوياً."))

            m = STORAGE_RE.search(body)
            if m:
                ctx.add(make("جانب العميل", "منخفض", LIKELY, "بيانات حساسة في localStorage",
                             url, NAME,
                             evidence=f"تخزين مفتاح «{m.group(1)}» في localStorage.",
                             cause="تخزين رموز/أسرار في تخزين المتصفح الدائم.",
                             impact="أي XSS يقرأها؛ تبقى بعد إغلاق الجلسة.",
                             recommendation="استخدم كوكي HttpOnly للجلسات وتجنب تخزين الرموز في localStorage.",
                             reference="https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html",
                             retest="افحص Application > Local Storage في المتصفح.",
                             cvss=4.3))

        # السكربتات المضمّنة المخزنة أثناء الزحف (قيمها قوائم نصوص لا استجابات)
        for key, val in ctx.sitemap.responses.items():
            if not key.endswith("#inline-js"):
                continue
            body = "\n".join(val)[:200_000] if isinstance(val, list) else str(getattr(val, "text", ""))[:200_000]
            src = DOM_SOURCES.search(body)
            sink = DOM_SINKS.search(body)
            if src and sink:
                page = key[:-len("#inline-js")]
                ctx.add(make("جانب العميل", "متوسط", MANUAL, "تدفق DOM خطير محتمل في سكربت مضمّن",
                             page, NAME, location="سكربت مضمّن",
                             evidence=f"مصدر «{src.group(1)}» ومصرف «{sink.group(1)}» في سكربت الصفحة.",
                             cause="قد تصل بيانات URL إلى DOM دون تنقية.",
                             impact="XSS مبني على DOM.",
                             recommendation="نقّ البيانات واستخدم textContent.",
                             reference="https://owasp.org/www-community/attacks/DOM_Based_XSS",
                             retest="جرّب حمولة hash خاملة في بيئة معزولة.",
                             cvss=6.1))

    def _csp(self, ctx: ScanContext):
        pages = [(u, r) for u, r in ctx.sitemap.responses.items()
                 if not u.endswith("#inline-js") and hasattr(r, "headers")
                 and "text/html" in r.headers.get("content-type", "")]
        if not pages:
            return
        missing = sum(1 for _, r in pages if "content-security-policy" not in
                      {k.lower() for k in r.headers.keys()})
        if missing == len(pages):
            ctx.add(make("جانب العميل", "منخفض", INFO, "غياب سياسة أمن المحتوى (CSP)",
                         ctx.origin, NAME,
                         evidence=f"لا ترويسة CSP في {missing}/{len(pages)} صفحة HTML.",
                         cause="عدم تعريف CSP.",
                         impact="تغيب طبقة دفاع ضد XSS وتضمين المحتوى.",
                         recommendation="عرّف CSP تدريجية تبدأ بـ default-src 'self'.",
                         reference="https://developer.mozilla.org/docs/Web/HTTP/CSP",
                         retest="افحص ترويسات الاستجابة وتأكد من وجود CSP فعالة."))
        else:
            for u, r in pages:
                csp = r.headers.get("content-security-policy", "")
                if "'unsafe-inline'" in csp or "'unsafe-eval'" in csp:
                    ctx.add(make("جانب العميل", "منخفض", LIKELY, "CSP تسمح بـ unsafe-inline/eval",
                                 u, NAME,
                                 evidence="سياسة CSP تتضمن unsafe-inline أو unsafe-eval.",
                                 cause="تساهل في السياسة يلغي جزءاً من فائدتها.",
                                 impact="يسهّل استغلال XSS رغم وجود CSP.",
                                 recommendation="استخدم nonces/hashes بدل unsafe-inline.",
                                 reference="https://content-security-policy.com/",
                                 retest="راجع السياسة وتأكد من إزالة unsafe-*.",
                                 cvss=4.3))
                    break
