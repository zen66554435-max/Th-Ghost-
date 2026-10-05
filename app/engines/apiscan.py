# -*- coding: utf-8 -*-
"""محرك أمان API: BOLA (عبر محرك الوصول)، BFLA، إفراط كشف البيانات،
تحليل OpenAPI الهيكلي، حدود المعدل، وCORS."""
from __future__ import annotations

import json
import re
from urllib.parse import urlparse

from ..net import BudgetExceeded, FetchError
from ..scope import ScopeViolation
from ..verify import CONFIRMED, INFO, LIKELY, MANUAL, make
from . import Engine, ScanContext

NAME = "apiscan"
SENSITIVE_KEYS = re.compile(
    r'(?i)"(password|passwd|token|secret|api[_-]?key|ssn|national[_-]?id|credit[_-]?card|cvv|phone|email)"')
RATE_HEADERS = ("x-ratelimit-limit", "x-rate-limit-limit", "ratelimit-limit",
                "retry-after", "x-ratelimit-remaining")


class Engine(Engine):
    name = NAME
    title = "أمان API"

    async def run(self, ctx: ScanContext):
        await self._openapi_structural(ctx)
        await self._excessive_data(ctx)
        await self._rate_limit(ctx)
        await self._cors(ctx)

    async def _openapi_structural(self, ctx: ScanContext):
        if not ctx.sitemap.openapi_docs:
            return
        oapi_url = ctx.sitemap.openapi_docs[0]
        resp = ctx.sitemap.responses.get(oapi_url)
        doc = getattr(resp, "text", "") or ""
        if not doc:
            return
        try:
            spec = json.loads(doc)
        except json.JSONDecodeError:
            return
        paths = spec.get("paths") or {}
        no_sec: list[str] = []
        state_changing: list[str] = []
        global_sec = spec.get("security")
        for p, item in paths.items():
            if not isinstance(item, dict):
                continue
            for method, op in item.items():
                if method.lower() not in ("get", "post", "put", "patch", "delete"):
                    continue
                if not isinstance(op, dict):
                    continue
                eff_sec = op.get("security", global_sec)
                if not eff_sec:
                    no_sec.append(f"{method.upper()} {p}")
                if method.lower() in ("put", "patch", "delete"):
                    state_changing.append(f"{method.upper()} {p}")
        if no_sec:
            ctx.add(make("أمان API", "متوسط", MANUAL,
                         "عمليات API بلا مصادقة في تعريف OpenAPI", oapi_url, NAME,
                         evidence="عمليات بلا security: " + "، ".join(no_sec[:10]) +
                                  (" …" if len(no_sec) > 10 else ""),
                         cause="التعريف يعلن عمليات بلا أي مخطط مصادقة.",
                         impact="قد تكون العمليات متاحة للعموم.",
                         recommendation="حدد مخطط أمان لكل عملية وتحقق خادمياً.",
                         reference="https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/",
                         retest="اطلب كل عملية بلا اعتماد وتأكد من 401/403 حيث يلزم."))
        if state_changing:
            ctx.add(make("أمان API", "منخفض", INFO,
                         "عمليات تغيير حالة (PUT/PATCH/DELETE) معرّفة", oapi_url, NAME,
                         evidence="عمليات: " + "، ".join(state_changing[:10]),
                         cause="—",
                         impact="تتطلب تفويضاً دقيقاً على مستوى الوظيفة.",
                         recommendation="راجع تفويض كل عملية تغيير حالة يدوياً.",
                         reference="https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
                         retest="جرّبها بصلاحية مستخدم منخفض — يجب 403."))

    async def _excessive_data(self, ctx: ScanContext):
        checked = 0
        for route in ctx.sitemap.routes:
            if checked >= 20:
                break
            if "/api/" not in urlparse(route.url).path:
                continue
            resp = ctx.sitemap.responses.get(route.url)
            if resp is None:
                continue
            body = (getattr(resp, "text", "") or "")[:200_000]
            if not body.strip().startswith(("{", "[")):
                continue
            checked += 1
            keys = set(k.lower() for k in SENSITIVE_KEYS.findall(body))
            if keys:
                ctx.add(make("أمان API", "عالٍ", LIKELY,
                             "إفراط كشف بيانات في استجابة API", route.url, NAME,
                             evidence="الاستجابة تتضمن حقولاً حساسة: " + "، ".join(sorted(keys)[:6]) +
                                      " (لم تُخزَّن قيمها).",
                             cause="إعادة الكائن الكامل من الخادم بدل حقول منتقاة.",
                             impact="كشف بيانات حساسة لأي مستدعٍ للواجهة.",
                             recommendation="أعد DTO محدداً بالحقول اللازمة فقط واستبعد الحساسة.",
                             reference="https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
                             retest="افحص الاستجابة وتأكد من غياب الحقول الحساسة.",
                             cvss=7.5))

    async def _rate_limit(self, ctx: ScanContext):
        api_routes = [r for r in ctx.sitemap.routes if "/api/" in urlparse(r.url).path]
        if not api_routes:
            return
        sample = api_routes[:5]
        missing = 0
        for r in sample:
            resp = ctx.sitemap.responses.get(r.url)
            if resp is None:
                continue
            hdrs = {k.lower() for k in resp.headers.keys()}
            if not any(h in hdrs for h in RATE_HEADERS):
                missing += 1
        if missing and missing >= len(sample) - 1:
            ctx.add(make("أمان API", "منخفض", MANUAL,
                         "لا توجد مؤشرات حد معدل على واجهات API", ctx.origin, NAME,
                         evidence="لا ترويسات RateLimit في الاستجابات المفحوصة — لا يُجس TH Ghost بكثافة لأسباب أمنية.",
                         cause="قد تغيب حماية حد المعدل.",
                         impact="إساءة استخدام الموارد وهجمات حشو الاعتماد.",
                         recommendation="فرض حد معدل خادمي مع 429 وترويسات إرشادية.",
                         reference="https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
                         retest="أرسل سلسلة طلبات سريعة يدوياً وتأكد من ظهور 429."))

    async def _cors(self, ctx: ScanContext):
        checked = 0
        for route in ctx.sitemap.routes:
            if checked >= 10:
                break
            if "/api/" not in urlparse(route.url).path:
                continue
            resp = ctx.sitemap.responses.get(route.url)
            if resp is None:
                continue
            checked += 1
            acao = resp.headers.get("access-control-allow-origin", "")
            acac = resp.headers.get("access-control-allow-credentials", "").lower()
            if acao == "*" and acac == "true":
                ctx.add(make("أمان API", "متوسط", CONFIRMED, "تهيئة CORS خطيرة (* مع credentials)",
                             route.url, NAME,
                             evidence="Access-Control-Allow-Origin: * مع Allow-Credentials: true.",
                             cause="تهيئة CORS متساهلة.",
                             impact="قراءة استجابات مصادق عليها من أي أصل.",
                             recommendation="حدد قائمة أصول مسموحة صراحة ولا تجمع * مع credentials.",
                             reference="https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny",
                             retest="أرسل Origin: https://evil.example وتأكد من عدم انعكاسه.",
                             cvss=6.5))
            elif acao == "*":
                ctx.add(make("أمان API", "منخفض", CONFIRMED, "CORS مفتوح لكل الأصول",
                             route.url, NAME,
                             evidence="Access-Control-Allow-Origin: * على مورد API.",
                             cause="تهيئة CORS متساهلة.",
                             impact="قراءة البيانات العامة من أي أصل (أقل خطورة بلا credentials).",
                             recommendation="قيد الأصول المسموحة إن لم يكن المورد عاماً قصداً.",
                             reference="https://developer.mozilla.org/docs/Web/HTTP/CORS",
                             retest="أرسل Origin خارجياً وتأكد من رفضه إن لم يكن عاماً.",
                             cvss=3.7))
