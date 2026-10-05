# -*- coding: utf-8 -*-
"""محرك التحكم بالوصول (Access Control): IDOR / BOLA / BFLA / تجاوز صلاحيات.

المنهج دون حسابات: كشف كائنات ذات معرفات رقمية متسلسلة متاحة بلا مصادقة.
مع حسابات اختبارية مصرح بها: مقارنة وصول حسابين بصلاحيات مختلفة —
ولا يُعتبر مجرد اختلاف الاستجابة دليلاً كافياً، لذا تُختم بالمراجعة اليدوية.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse, urlunparse

from ..net import BudgetExceeded, FetchError
from ..scope import ScopeViolation
from ..verify import LIKELY, MANUAL, make
from . import Engine, ScanContext

NAME = "access"
ID_RE = re.compile(r"(/)(\d+)(/?)$")
ADMIN_RE = re.compile(r"(?i)/(admin|manage|dashboard|internal)(/|$)")


def _bump_id(url: str) -> str | None:
    """يعيد العنوان مع زيادة المعرف الرقمي الأخير بمقدار 1."""
    p = urlparse(url)
    m = ID_RE.search(p.path)
    if not m:
        return None
    new_path = p.path[:m.start()] + f"/{int(m.group(2)) + 1}" + m.group(3)
    return urlunparse((p.scheme, p.netloc, new_path, "", "", ""))


class Engine(Engine):
    name = NAME
    title = "التحكم بالوصول"

    async def run(self, ctx: ScanContext):
        checked = 0
        for route in list(ctx.sitemap.routes):
            if checked >= 15:
                break
            path = urlparse(route.url).path
            # --- BOLA/IDOR: معرفات رقمية متسلسلة في مسارات API ---
            if ("/api/" in path or re.search(r"/(user|account|order|invoice|profile)s?/\d+", path)) \
                    and ID_RE.search(path):
                other = _bump_id(route.url)
                if not other:
                    continue
                checked += 1
                # أعد استخدام استجابة الزاحف للكائن الأول — لا حاجة لطلب مكرر
                r1 = ctx.sitemap.responses.get(route.url)
                try:
                    if r1 is None:
                        r1 = await ctx.fetcher.get(route.url)
                    r2 = await ctx.fetcher.get(other)
                except (FetchError, BudgetExceeded, ScopeViolation):
                    continue
                if r1.status_code == 200 and r2.status_code == 200 \
                        and r1.text[:200_000] != r2.text[:200_000]:
                    sensitive = bool(re.search(
                        r'(?i)"(email|phone|address|password|token|ssn|name)"\s*:', r2.text[:200_000]))
                    confidence = LIKELY if sensitive else MANUAL
                    ctx.add(make("التحكم بالوصول", "عالٍ" if sensitive else "متوسط", confidence,
                                 "وصول مباشر لكائنات بمعرفات متسلسلة دون تفويض ظاهر (IDOR/BOLA)",
                                 route.url, NAME, parameter="معرف الكائن في المسار",
                                 evidence=f"كُشف الكائنان {path} و{urlparse(other).path} بلا بيانات اعتماد، "
                                          f"والاستجابتان مختلفتان" +
                                          (" وتحتويان حقولاً شخصية." if sensitive else "."),
                                 cause="الخادم لا يتحقق من ملكية الكائن للمستدعي.",
                                 impact="وصول أفقي/عمودي غير مصرح لبيانات مستخدمين آخرين.",
                                 recommendation="فرض تفويض على مستوى الكائن لكل طلب، واستخدم معرفات غير قابلة للتخمين.",
                                 reference="https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
                                 retest="بصلاحية مستخدم A اطلب كائن مستخدم B — يجب 403.",
                                 cvss=7.5 if sensitive else 5.3))
            # --- BFLA: وظائف إدارية متاحة بلا مصادقة ---
            elif ADMIN_RE.search(path) and route.status_code == 200:
                checked += 1
                ctx.add(make("التحكم بالوصول", "عالٍ", MANUAL,
                             "وظيفة إدارية متاحة دون مصادقة ظاهرة (BFLA)", route.url, NAME,
                             evidence="المسار يبدو إدارياً وأعاد 200 دون أي بيانات اعتماد.",
                             cause="الاعتماد على إخفاء الرابط بدل التفويض الفعلي.",
                             impact="وصول غير مصرح لوظائف إدارية.",
                             recommendation="فرض تفويض على مستوى الوظيفة وتحقق من الدور.",
                             reference="https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
                             retest="اطلب المسار بلا جلسة وبجلسة مستخدم عادي — يجب 401/403.",
                             cvss=7.5))

        # --- تحقق بحسابين اختباريين (إن وُجدا وفعّل المستخدم الخيار) ---
        if ctx.config.get("use_accounts") and len(ctx.accounts) >= 2:
            await self._compare_two_accounts(ctx)

    async def _compare_two_accounts(self, ctx: ScanContext):
        """مقارنة آمنة بين حسابين مصرح بهما: كائن المستخدم وكائن غيره بجلسة كل حساب.

        اختلاف الاستجابة وحده ليس دليلاً كافياً — النتيجة دائماً «تحتاج مراجعة يدوية».
        """
        if len(ctx.sessions) < 2:
            return
        labels = list(ctx.sessions.keys())[:2]
        for route in list(ctx.sitemap.routes):
            if not ID_RE.search(urlparse(route.url).path):
                continue
            other = _bump_id(route.url)
            if not other:
                continue
            try:
                r_a = await ctx.fetcher.get(route.url, headers=ctx.sessions[labels[0]])
                r_b = await ctx.fetcher.get(other, headers=ctx.sessions[labels[1]])
            except (FetchError, BudgetExceeded, ScopeViolation):
                continue
            if r_a.status_code == 200 and r_b.status_code == 200 \
                    and r_a.text[:100_000] != r_b.text[:100_000]:
                ctx.add(make("التحكم بالوصول", "متوسط", MANUAL,
                             "اختلاف وصول بين كائنين بحسابات اختبارية — راجع التفويض يدوياً",
                             other, NAME, parameter="معرف الكائن",
                             evidence="أُجريت المقارنة بحسابين مصرح بهما؛ الاختلاف وحده لا يثبت ثغرة.",
                             cause="احتمال غياب تحقق ملكية الكائن.",
                             impact="وصول غير مصرح إن تأكد يدوياً.",
                             recommendation="تحقق يدوياً من منطق التفويض لهذا المسار.",
                             reference="https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
                             retest="كرر الاختبار يدوياً ووثّق مالك كل كائن."))
                break
