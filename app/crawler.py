# -*- coding: utf-8 -*-
"""محرك اكتشاف الموقع (Site Crawler).

يكتشف: الروابط الداخلية، sitemap.xml وrobots.txt، النماذج وطرقها ومعاملاتها،
ملفات JavaScript، صفحات تسجيل الدخول، مسارات API، ووثائق OpenAPI/Swagger —
ويبني خريطة مسارات بمصدر اكتشاف كل مسار وحالة استجابته ووقته.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urljoin, urlparse, urlunparse

from .net import BudgetExceeded, Fetcher, FetchError
from .scope import ScopePolicy, in_scope

MAX_BODY = 1_500_000  # بايت — سقف قراءة الجسم الواحد

OPENAPI_CANDIDATES = [
    "/openapi.json", "/swagger.json", "/api-docs", "/api/docs",
    "/swagger/v1/swagger.json", "/v1/openapi.json", "/api/openapi.json",
]


@dataclass
class Route:
    url: str
    source: str                 # بذرة / رابط داخلي / sitemap / robots / openapi
    status_code: int | None = None
    method: str = "GET"
    params: list[str] = field(default_factory=list)
    discovered_at: str = ""


@dataclass
class Form:
    page_url: str
    action: str
    method: str = "GET"
    inputs: list[dict] = field(default_factory=list)   # [{name, type, accept}]
    has_password: bool = False
    has_file: bool = False
    has_csrf_token: bool = False


@dataclass
class SiteMap:
    origin: str
    routes: list[Route] = field(default_factory=list)
    forms: list[Form] = field(default_factory=list)
    js_files: list[str] = field(default_factory=list)
    openapi_docs: list[str] = field(default_factory=list)
    login_pages: list[str] = field(default_factory=list)
    api_routes: list[str] = field(default_factory=list)
    responses: dict = field(default_factory=dict)      # url -> httpx.Response snapshot
    started_at: float = 0.0


class _HTMLDiscover(HTMLParser):
    """مستخرج HTML: روابط، نماذج بحقولها، سكربتات، سكربتات مضمّنة."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.forms: list[dict] = []
        self.scripts: list[str] = []
        self.inline_scripts: list[str] = []
        self._form: dict | None = None
        self._in_script = False
        self._script_buf: list[str] = []

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "form":
            self._form = {"action": a.get("action", ""), "method": (a.get("method") or "GET").upper(),
                          "inputs": []}
        elif tag == "input" and self._form is not None:
            self._form["inputs"].append({"name": a.get("name", ""),
                                         "type": (a.get("type") or "text").lower(),
                                         "accept": a.get("accept", "")})
        elif tag in ("textarea", "select") and self._form is not None:
            self._form["inputs"].append({"name": a.get("name", ""), "type": tag, "accept": ""})
        elif tag == "script":
            if a.get("src"):
                self.scripts.append(a["src"])
            else:
                self._in_script = True
                self._script_buf = []
        elif tag == "link":
            href = a.get("href", "")
            if any(k in href.lower() for k in ("openapi", "swagger", "api-docs")):
                self.links.append(href)

    def handle_endtag(self, tag):
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None
        elif tag == "script" and self._in_script:
            self._in_script = False
            body = "".join(self._script_buf).strip()
            if body:
                self.inline_scripts.append(body)

    def handle_data(self, data):
        if self._in_script:
            self._script_buf.append(data)


def _norm_url(url: str) -> str:
    """توحيد عنوان: إزالة المقطع # وإعادة بناء نظيفة (المعاملات تُحفظ)."""
    p = urlparse(url)
    return urlunparse((p.scheme, p.netloc, p.path or "/", "", p.query, ""))


def _classify_form(f: dict, page_url: str, origin: str) -> Form | None:
    action = urljoin(page_url, f["action"] or page_url)
    action = _norm_url(action)
    if not in_scope(action, origin):
        return None
    inputs = [i for i in f["inputs"] if i["name"]]
    names = {i["name"].lower() for i in inputs}
    types = {i["type"] for i in inputs}
    has_csrf = any(("csrf" in n or "token" in n or "authenticity" in n) for n in names)
    return Form(page_url=page_url, action=action, method=f["method"], inputs=inputs,
                has_password="password" in types, has_file="file" in types,
                has_csrf_token=has_csrf)


def _query_params(url: str) -> list[str]:
    return [k for k, _ in parse_qsl(urlparse(url).query)]


def _looks_openapi(text: str) -> bool:
    head = text[:400].lower()
    return '"openapi"' in head or '"swagger"' in head


async def crawl(origin: str, policy: ScopePolicy, fetcher: Fetcher,
                max_pages: int = 50, depth: int = 3, on_route=None) -> SiteMap:
    """زاحف BFS آمن. on_route(route) يُستدعى لكل مسار مكتشف (للحفظ الفوري)."""
    sm = SiteMap(origin=origin, started_at=time.time())
    root = origin.rstrip("/") + "/"
    queue: list[tuple[str, int, str]] = [(root, 0, "بذرة")]
    queued = {root}
    seen: set[str] = set()

    def emit(url, source, status=None, params=None):
        r = Route(url=url, source=source, status_code=status,
                  params=params if params is not None else _query_params(url),
                  discovered_at=time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()))
        sm.routes.append(r)
        if on_route:
            on_route(r)
        return r

    # 1) مصادر بنيوية أولاً: robots.txt ثم sitemap.xml
    for path, source in (("/robots.txt", "robots"), ("/sitemap.xml", "sitemap")):
        u = urljoin(root, path)
        try:
            r = await fetcher.get(u)
        except (FetchError, BudgetExceeded):
            continue
        if r.status_code == 200:
            emit(u, source, r.status_code)
            for loc in _extract_seed_urls(r.text[:MAX_BODY], source):
                t = _norm_url(urljoin(root, loc))
                if in_scope(t, origin, list(policy.prefixes) or None) and t not in queued:
                    queued.add(t)
                    queue.append((t, 1, source))

    # 2) BFS على الصفحات
    while queue and len(seen) < max_pages:
        url, lvl, source = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)
        try:
            r = await fetcher.get(url)
        except BudgetExceeded:
            break
        except Exception:
            emit(url, source, None)   # فشل جلب أو خروج نطاق — يُوثَّق بلا حالة
            continue
        emit(url, source, r.status_code)
        sm.responses[url] = r
        ctype = r.headers.get("content-type", "").lower()
        path = urlparse(url).path.lower()

        if _looks_openapi(r.text[:400]) and path.endswith(".json"):
            sm.openapi_docs.append(url)
        if "/api/" in path or "application/json" in ctype:
            sm.api_routes.append(url)

        if lvl >= depth or "text/html" not in ctype:
            continue
        parser = _HTMLDiscover()
        try:
            parser.feed(r.text[:MAX_BODY])
        except Exception:
            pass

        for raw in parser.links:
            t = _norm_url(urljoin(url, raw))
            if not in_scope(t, origin, list(policy.prefixes) or None):
                continue
            if _is_static_asset(t):
                continue
            if t not in queued and t not in seen and len(queued) < max_pages * 4:
                queued.add(t)
                queue.append((t, lvl + 1, "رابط داخلي"))

        for f in parser.forms:
            form = _classify_form(f, url, origin)
            if not form:
                continue
            sm.forms.append(form)
            if form.has_password and form.page_url not in sm.login_pages:
                sm.login_pages.append(form.page_url)

        for src in parser.scripts:
            t = urljoin(url, src)
            if in_scope(t, origin, list(policy.prefixes) or None) and t not in sm.js_files:
                sm.js_files.append(t)

        if parser.inline_scripts:
            sm.responses[url + "#inline-js"] = parser.inline_scripts

    # 3) استكشاف وثائق OpenAPI المعهودة (ضمن النطاق حصراً)
    for cand in OPENAPI_CANDIDATES:
        u = urljoin(root, cand)
        if u in seen:
            continue
        try:
            r = await fetcher.get(u)
        except (FetchError, BudgetExceeded):
            continue
        seen.add(u)
        if r.status_code == 200 and _looks_openapi(r.text[:400]):
            emit(u, "openapi", r.status_code)
            sm.openapi_docs.append(u)
            sm.responses[u] = r
            for p in _openapi_paths(r.text[:MAX_BODY]):
                t = _norm_url(urljoin(root, p))
                if t not in seen and in_scope(t, origin, list(policy.prefixes) or None):
                    try:
                        rr = await fetcher.get(t)
                        emit(t, "openapi", rr.status_code)
                        sm.responses[t] = rr
                        if "/api/" in urlparse(t).path.lower():
                            sm.api_routes.append(t)
                    except (FetchError, BudgetExceeded):
                        emit(t, "openapi", None)

    return sm


def _extract_seed_urls(text: str, source: str) -> list[str]:
    if source == "robots":
        out = []
        for line in text.splitlines():
            line = line.strip()
            if line.lower().startswith(("disallow:", "allow:", "sitemap:")):
                val = line.split(":", 1)[1].strip()
                if val and val != "/":
                    out.append(val)
        return out[:50]
    return re.findall(r"<loc>\s*([^<]+)\s*</loc>", text)[:200]


def _openapi_paths(text: str) -> list[str]:
    import json
    try:
        doc = json.loads(text)
    except ValueError:
        return []
    if not isinstance(doc, dict) or not isinstance(doc.get("paths"), dict):
        return []
    return [p for p in doc["paths"] if isinstance(p, str) and p.startswith("/")][:50]


def _is_static_asset(url: str) -> bool:
    return bool(re.search(r"\.(css|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|mp4|webm|pdf|zip)(\?|$)",
                          urlparse(url).path.lower()))
