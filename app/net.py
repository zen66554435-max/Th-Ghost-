# -*- coding: utf-8 -*-
"""طبقة الجلب الآمن — كل طلب شبكة في TH Ghost يمر من هنا.

تفرض: حارس النطاق لكل طلب، حد معدل الطلبات، حد التزامن، مهلة لكل طلب،
تتبع إعادة التوجيه يدوياً مع التحقق من كل قفزة، وعدّاد طلبات بسقف أقصى.
"""
from __future__ import annotations

import asyncio
import time
from urllib.parse import urljoin

import httpx

from .scope import ScopePolicy, ScopeViolation

USER_AGENT = "TH-Ghost/1.0 (authorized defensive audit; +local)"


class FetchError(Exception):
    pass


class BudgetExceeded(FetchError):
    """تجاوز سقف الطلبات أو الزمن المسموح للفحص أو طلب المستخدم الإيقاف."""


class Fetcher:
    def __init__(self, policy: ScopePolicy, rate_rps: float = 5.0, concurrency: int = 2,
                 timeout: float = 8.0, max_requests: int = 600, max_duration_sec: float = 300,
                 stop_flag=None):
        self.policy = policy
        self.min_interval = 1.0 / max(0.2, min(rate_rps, 20.0))
        self.timeout = timeout
        self.max_requests = max_requests
        self.deadline = time.monotonic() + max_duration_sec
        self.stop_flag = stop_flag  # كائن قابل للاستدعاء يعيد True عند طلب الإيقاف
        self.requests_count = 0
        self._sem = asyncio.Semaphore(max(1, min(concurrency, 8)))
        self._rate_lock = asyncio.Lock()
        self._last_ts = 0.0
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self):
        self._client = httpx.AsyncClient(
            timeout=self.timeout, follow_redirects=False, verify=True,
            headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
        return self

    async def __aexit__(self, *exc):
        if self._client:
            await self._client.aclose()

    def _check_budget(self):
        if self.requests_count >= self.max_requests:
            raise BudgetExceeded("بلغ الفحص سقف الطلبات المسموح")
        if time.monotonic() > self.deadline:
            raise BudgetExceeded("تجاوز الفحص المدة القصوى المسموحة")
        if self.stop_flag and self.stop_flag():
            raise BudgetExceeded("أُوقف الفحص بطلب المستخدم")

    async def _throttle(self):
        async with self._rate_lock:
            now = time.monotonic()
            wait = self._last_ts + self.min_interval - now
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_ts = time.monotonic()

    async def _request(self, method: str, url: str, headers: dict | None = None,
                       data: dict | None = None):
        self._check_budget()
        self.policy.validate_url(url)
        async with self._sem:
            await self._throttle()
            self._check_budget()
            self.requests_count += 1
            try:
                return await self._client.request(method, url, headers=headers or {}, data=data)
            except httpx.HTTPError as e:
                raise FetchError(f"تعذر الطلب: {url}") from e

    async def get(self, url: str, follow_redirects: bool = True, max_hops: int = 3,
                  headers: dict | None = None):
        """GET آمن ضمن النطاق. يعيد استجابة httpx أو يرفع FetchError/ScopeViolation.

        لا يتتبع إعادة التوجيه إلا بعد التحقق من كل قفزة بحارس النطاق.
        """
        r = await self._request("GET", url, headers=headers)
        hops = 0
        while follow_redirects and r.status_code in (301, 302, 303, 307, 308) and hops < max_hops:
            loc = r.headers.get("location")
            if not loc:
                break
            target = urljoin(str(r.url), loc)
            self.policy.validate_redirect(target)  # قد يرفع ScopeViolation — لا نتبع خارج النطاق
            r = await self._request("GET", target, headers=headers)
            hops += 1
        return r

    async def post_form(self, url: str, data: dict):
        """POST نموذج واحد آمن — يُستخدم حصرياً لتسجيل دخول الحسابات الاختبارية المصرح بها.

        يخضع لنفس حارس النطاق وحدود المعدل والميزانية. بلا تتبع إعادة توجيه.
        """
        return await self._request("POST", url, data=data)
