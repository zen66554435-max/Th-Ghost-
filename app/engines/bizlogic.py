# -*- coding: utf-8 -*-
"""محرك منطق الأعمال: جسّات قيم سلبية خاملة وملاحظات تدفقات متعددة الخطوات."""
from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ..net import BudgetExceeded, FetchError
from ..scope import ScopeViolation
from ..verify import INFO, LIKELY, MANUAL, make
from . import Engine, ScanContext

NAME = "bizlogic"
MONEY_PARAMS = re.compile(r"(?i)^(price|amount|total|quantity|qty|discount|cost)$")
STEP_RE = re.compile(r"(?i)(step|stage|phase)=?\d*")


class Engine(Engine):
    name = NAME
    title = "منطق الأعمال"

    async def run(self, ctx: ScanContext):
        probed = 0
        for route in ctx.sitemap.routes:
            if probed >= 6:
                break
            p = urlparse(route.url)
            params = [k for k, _ in parse_qsl(p.query)]
            for param in params:
                if not MONEY_PARAMS.match(param):
                    continue
                probed += 1
                # قيمة غير رقمية يجب أن تُرفض، وقيمة سالبة يجب أن تُرفض أيضاً
                r_bad = await self._get(ctx, p, param, "abc")
                r_neg = await self._get(ctx, p, param, "-1")
                if r_bad is None or r_neg is None:
                    continue
                rejected_bad = r_bad.status_code >= 400
                accepted_neg = r_neg.status_code == 200 and not re.search(
                    r"(?i)(invalid|error|خطأ|مرفوض)", r_neg.text[:100_000])
                if rejected_bad and accepted_neg:
                    ctx.add(make("منطق الأعمال", "عالٍ", LIKELY,
                                 "قبول قيمة سالبة لمعامل مالي/كمية", route.url, NAME,
                                 parameter=param,
                                 evidence="رفُضت «abc» (سليم) لكن قُبلت «-1» باستجابة نجاح — تحقق يدوياً من الأثر.",
                                 cause="غياب تحقق دلالي (range) رغم وجود تحقق نوعي.",
                                 impact="التلاعب بالأسعار/الكميات/الخصومات.",
                                 recommendation="فرض حدود دنيا/قصوى خادمية وتحقق من سلامة العملية كاملة.",
                                 reference="https://owasp.org/www-community/vulnerabilities/Business_logic_vulnerability",
                                 retest="أرسل قيمة سالبة وراقب أثرها على العملية — يجب رفضها.",
                                 cvss=7.5))

        # ملاحظة تدفق متعدد الخطوات
        for route in ctx.sitemap.routes:
            if STEP_RE.search(urlparse(route.url).query) or STEP_RE.search(urlparse(route.url).path):
                ctx.add(make("منطق الأعمال", "منخفض", MANUAL,
                             "تدفق متعدد الخطوات — راجع إمكانية القفز", route.url, NAME,
                             evidence="معامل/مسار يشير إلى خطوات متسلسلة (step/stage).",
                             cause="قد لا يتحقق الخادم من إتمام الخطوات السابقة.",
                             impact="تخطي خطوات دفع/تحقق.",
                             recommendation="تتبع حالة التدفق خادمياً وارفض القفز.",
                             reference="https://owasp.org/www-project-web-security-testing-guide/",
                             retest="اطلب خطوة لاحقة مباشرة دون إتمام السابقة — يجب رفضها."))
                break

    async def _get(self, ctx, parsed, param, value):
        q = [(k, (value if k == param else v)) for k, v in parse_qsl(parsed.query)]
        url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", urlencode(q), ""))
        try:
            return await ctx.fetcher.get(url)
        except (FetchError, BudgetExceeded, ScopeViolation):
            return None
