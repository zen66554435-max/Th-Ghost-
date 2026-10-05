# -*- coding: utf-8 -*-
"""TH Ghost Vulnerable Lab — مختبر تدريبي متعمد الثغرات، معزول بالكامل.

ضمانات السلامة:
- يرتبط بـ 127.0.0.1 فقط ولا يقبل اتصالات خارجية.
- لا ينفذ أوامر نظام، ولا يقرأ ملفات حقيقية، ولا يتصل بالإنترنت.
- كل «الثغرات» محاكاة بمحتوى جاهز (canned): ملف passwd مزيف، علامة echo ثابتة،
  أخطاء LDAP/XPath نصية — لا يوجد أي تنفيذ فعلي.
- قاعدة البيانات SQLite في الذاكرة ببيانات وهمية فقط.
"""
from __future__ import annotations

import html
import json
import re
import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl, urlparse

# ---------- محتوى جاهز (كله مزيف تعليمي) ----------
CANNED_PASSWD = "root:x:0:0:root:/root:/bin/bash\nlabuser:x:1000:1000:lab:/home/lab:/bin/sh\n"
CANNED_WININI = "[extensions]\nexe=C:\\WINDOWS\\system32\\cmd.exe\n[fonts]\n"
CMD_MARKER = "THG9273"
FAKE_PRODUCTS = [("تفاحة", 3.5), ("موز", 2.25), ("برتقال", 4.0), ("عنب", 7.75)]
FAKE_USERS = {
    1: {"id": 1, "username": "labuser1", "email": "labuser1@example.invalid",
        "password_hash": "5f4dcc3b5aa765d61d8327deb882cf99", "role": "user"},
    2: {"id": 2, "username": "labuser2", "email": "labuser2@example.invalid",
        "password_hash": "e99a18c428cb38d5f260853678922e03", "role": "user"},
    3: {"id": 3, "username": "labadmin", "email": "admin@example.invalid",
        "password_hash": "25d55ad283aa400af464c76d713c07ad", "role": "admin"},
}
LAB_ACCOUNTS = {"labuser1": "labpass1", "labuser2": "labpass2"}

OPENAPI_DOC = {
    "openapi": "3.0.0",
    "info": {"title": "TH Ghost Lab API", "version": "1.0.0"},
    "paths": {
        "/api/users": {"get": {"operationId": "listUsers", "responses": {"200": {"description": "ok"}}}},
        "/api/users/{id}": {
            "get": {"operationId": "getUser", "responses": {"200": {"description": "ok"}}},
            "delete": {"operationId": "deleteUser", "responses": {"200": {"description": "ok"}}},
        },
        "/api/admin/stats": {"get": {"operationId": "adminStats", "responses": {"200": {"description": "ok"}}}},
        "/api/health": {"get": {"operationId": "health", "security": [{"apiKey": []}],
                                "responses": {"200": {"description": "ok"}}}},
    },
    "components": {"securitySchemes": {"apiKey": {"type": "apiKey", "name": "X-API-Key", "in": "header"}}},
}

ASSETS_APP_JS = """// TH Ghost Lab — ملف JS تعليمي بمشاكل متعمدة
// يعتمد على jquery-1.12.4 (مكتبة قديمة بثغرات معروفة)
const GOOGLE_KEY = "AIzaSyFAKEKEYFORTESTINGONLY000000000000";  // مفتاح مكشوف (مزيف)
function render() {
  var frag = location.hash.substring(1);           // مصدر DOM
  document.getElementById("out").innerHTML = frag; // مصرف DOM خطير
}
localStorage.setItem("auth_token", "lab-token-1234567890abcdef");  // سر في تخزين المتصفح
window.addEventListener("hashchange", render);
"""

JQUERY_STUB = "/*! jquery-1.12.4.min.js — نسخة تعليمية مختصرة */ var jQuery = {};\n"


def _page(title: str, body: str) -> bytes:
    return (f"<!DOCTYPE html><html lang=ar dir=rtl><head><meta charset=utf-8>"
            f"<title>{title}</title></head><body>{body}</body></html>").encode()


def _db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.execute("CREATE TABLE products(name TEXT, price REAL)")
    conn.executemany("INSERT INTO products VALUES(?,?)", FAKE_PRODUCTS)
    return conn


_DB_LOCK = threading.Lock()


class LabHandler(BaseHTTPRequestHandler):
    server_version = ""      # نتحكم يدوياً بترويسة Server
    sys_version = ""
    db = _db()

    # ----- بنية تحتية -----
    def log_message(self, fmt, *args):
        access_log = getattr(self.server, "access_log", None)
        if access_log is not None:
            access_log.append(f"{self.command} {self.path}")

    def _send(self, body: bytes, status=200, ctype="text/html; charset=utf-8",
              headers: dict | None = None, cookies: list[str] | None = None,
              server_header=True):
        self.send_response(status)
        if server_header:
            self.send_header("Server", "LabApache/2.4.49 (Ubuntu)")
        self.send_header("Content-Type", ctype)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        for c in (cookies or []):
            self.send_header("Set-Cookie", c)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _404(self, api=False):
        if api:
            self._send(json.dumps({"detail": "not found"}).encode(), status=404,
                       ctype="application/json")
        else:
            self._send(_page("404", "<h1>404 — الصفحة غير موجودة</h1>"), status=404)

    # ----- GET -----
    def do_GET(self):
        u = urlparse(self.path)
        path = u.path
        q = dict(parse_qsl(u.query, keep_blank_values=True))
        ext = getattr(self.server, "external_base", None) or "http://203.0.113.10/"

        if path == "/":
            links = ["/secure-headers", "/form", "/register", "/xss-test?q=مرحبا", "/xss-safe?q=مرحبا",
                     "/search", "/product?id=1", "/download?file=hello.txt", "/hello?name=ضيف",
                     "/ping?host=127.0.0.1", "/ldap?user=ali", "/xpath?q=book", "/redir?next=/",
                     "/api/users", "/api/users/1", "/api/users/2", "/api/users/3", "/api/admin/stats",
                     "/api/cors", "/api/health", "/upload", "/dom-xss", "/order?price=10",
                     "/checkout?step=2", "/server-info", "/backup/", "/status/404", "/status/500",
                     "/logout", "/redirect-external", "/openapi.json"]
            body = "<h1>TH Ghost Lab</h1><ul>" + "".join(f'<li><a href="{l}">{l}</a></li>' for l in links) \
                   + "</ul><script src=/assets/app.js></script><script src=/assets/jquery-1.12.4.min.js></script>"
            self._send(_page("المختبر", body),
                       cookies=["lab_session=abc123; Path=/"])  # كوكي ضعيف متعمد

        elif path == "/secure-headers":
            # ضابط سلبي: كل الترويسات صحيحة وكوكي آمن، بلا ترويسة Server
            self._send(_page("آمنة", "<h1>صفحة مؤمّنة</h1>"),
                       headers={"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
                                "Referrer-Policy": "no-referrer"},
                       cookies=["good_cookie=" + "x" * 40 + "; Path=/; HttpOnly; SameSite=Lax"],
                       server_header=False)

        elif path == "/form":
            self._send(_page("دخول", """
<h1>تسجيل الدخول</h1>
<form method="POST" action="/api/login">
  <input type="text" name="username">
  <input type="password" name="password">
  <button>دخول</button>
</form>"""))

        elif path == "/register":
            self._send(_page("تسجيل", """
<h1>إنشاء حساب</h1>
<form method="POST" action="/register">
  <input type="text" name="username">
  <input type="password" name="password">
  <button>تسجيل</button>
</form>"""))

        elif path == "/xss-test":
            # ثغرة XSS منعكسة حقيقية (في سياق معزول): انعكاس خام
            self._send(_page("بحث", f"<h1>نتائج: {q.get('q', '')}</h1>"))

        elif path == "/xss-safe":
            # ضابط سلبي: انعكاس مرمّز
            self._send(_page("بحث آمن", f"<h1>نتائج: {html.escape(q.get('q', ''))}</h1>"))

        elif path == "/search":
            term = q.get("q")
            if term is None:
                self._send(_page("بحث المنتجات", """
<h1>ابحث عن منتج</h1>
<form method="GET" action="/search"><input name="q"><button>بحث</button></form>"""))
                return
            try:
                # SQLi تعليمي على قاعدة ذاكرة ببيانات وهمية فقط
                with _DB_LOCK:
                    rows = self.db.execute(
                        f"SELECT name, price FROM products WHERE name = '{term}'").fetchall()
            except sqlite3.Error as e:
                self._send(_page("خطأ", f"<h1>sqlite3.OperationalError</h1><pre>sqlite3.OperationalError: {e}</pre>"),
                           status=500)
                return
            items = "".join(f"<li>{html.escape(n)} — {p}</li>" for n, p in rows) or "<li>لا نتائج</li>"
            self._send(_page("نتائج", f"<h1>النتائج</h1><ul>{items}</ul>"))

        elif path == "/product":
            # ضابط سلبي: استعلام معلّم آمن ولا انعكاس للمدخل
            try:
                pid = int(q.get("id", "1"))
            except ValueError:
                pid = 1
            row = None
            with _DB_LOCK:
                row = self.db.execute("SELECT name, price FROM products LIMIT 1 OFFSET ?",
                                      ((pid - 1) % len(FAKE_PRODUCTS),)).fetchone()
            self._send(_page("منتج", f"<h1>المنتج: {html.escape(row[0])} — {row[1]}</h1>"))

        elif path == "/download":
            f = q.get("file", "")
            if "etc/passwd" in f:
                self._send(CANNED_PASSWD.encode(), ctype="text/plain; charset=utf-8")
            elif "win.ini" in f.lower():
                self._send(CANNED_WININI.encode(), ctype="text/plain; charset=utf-8")
            elif f == "hello.txt":
                self._send(b"hello lab\n", ctype="text/plain; charset=utf-8")
            else:
                self._404()

        elif path == "/hello":
            name = q.get("name", "ضيف")
            # محاكاة SSTI: يقيّم {{7*7}} و ${7*7} حسابياً فقط — بلا أي محرك قوالب
            name = name.replace("{{7*7}}", "49").replace("${7*7}", "49")
            self._send(_page("مرحبا", f"<h1>أهلاً بك يا {html.escape(name)}</h1>"))

        elif path == "/ping":
            host = q.get("host", "")
            m = re.search(r";\s*echo\s+([A-Za-z0-9_]+)", host)
            if m:
                # محاكاة تنفيذ echo: تظهر العلامة منفردة دون نص الحمولة
                self._send(_page("ping", f"<h1>PING ok</h1><pre>{m.group(1)}</pre>"))
            else:
                self._send(_page("ping", f"<h1>PING {html.escape(host)}: ok</h1>"))

        elif path == "/ldap":
            user = q.get("user", "")
            if any(ch in user for ch in "*()|&"):
                self._send(_page("LDAP", "<h1>javax.naming.directory.InvalidSearchFilterException</h1>"
                                         "<pre>javax.naming.directory.InvalidSearchFilterException: Bad search filter</pre>"),
                           status=500)
            else:
                self._send(_page("LDAP", f"<h1>بحث LDAP عن: {html.escape(user)}</h1>"))

        elif path == "/xpath":
            term = q.get("q", "")
            if "']['" in term:
                self._send(_page("XPath", "<h1>javax.xml.xpath.XPathExpressionException</h1>"
                                          "<pre>javax.xml.xpath.XPathExpressionException: javax.xml.xpath.XPathExpressionException</pre>"),
                           status=500)
            else:
                self._send(_page("XPath", f"<h1>نتائج XPath: {html.escape(term)}</h1>"))

        elif path == "/redir":
            nxt = q.get("next", "/")
            if "\r\n" in nxt or "\r" in nxt or "\n" in nxt:
                # محاكاة حقن ترويسة: يعكس الجزء المحقون كترويسة استجابة
                injected = re.split(r"[\r\n]+", nxt)
                hdr = {}
                for part in injected:
                    if ":" in part:
                        k, v = part.split(":", 1)
                        if re.fullmatch(r"[A-Za-z0-9\-]{1,40}", k.strip()):
                            hdr[k.strip()] = v.strip()[:40]
                self._send(b"", status=302, headers={**hdr, "Location": "/"})
            else:
                target = nxt if nxt.startswith("/") else "/"
                self._send(b"", status=302, headers={"Location": target})

        elif path == "/api/users":
            self._send(json.dumps(list(FAKE_USERS.values()), ensure_ascii=False).encode(),
                       ctype="application/json")

        elif re.fullmatch(r"/api/users/(\d+)", path):
            uid = int(path.rsplit("/", 1)[1])
            if uid in FAKE_USERS:
                self._send(json.dumps(FAKE_USERS[uid], ensure_ascii=False).encode(),
                           ctype="application/json")
            else:
                self._404(api=True)

        elif path == "/api/users/{id}":
            self._404(api=True)

        elif path == "/api/admin/stats":
            self._send(json.dumps({"users": 3, "orders": 42, "secret_note": "lab-only"}).encode(),
                       ctype="application/json")

        elif path == "/api/cors":
            self._send(json.dumps({"ok": True}).encode(), ctype="application/json",
                       headers={"Access-Control-Allow-Origin": "*",
                                "Access-Control-Allow-Credentials": "true"})

        elif path == "/api/health":
            # ضابط سلبي: واجهة عليها حد معدل فعلاً
            self._send(json.dumps({"status": "up"}).encode(), ctype="application/json",
                       headers={"X-RateLimit-Limit": "100", "X-RateLimit-Remaining": "99"})

        elif path == "/upload":
            self._send(_page("رفع", """
<h1>رفع ملف</h1>
<form method="POST" action="/upload" enctype="multipart/form-data">
  <input type="file" name="file">
  <button>رفع</button>
</form>"""))

        elif path == "/dom-xss":
            self._send(_page("DOM", """
<h1>اختبار DOM</h1><div id="out"></div>
<script>
var frag = location.hash.substring(1);
document.getElementById("out").innerHTML = frag;
</script>"""))

        elif path == "/order":
            price = q.get("price", "")
            try:
                val = float(price)
            except ValueError:
                self._send(json.dumps({"error": "invalid price"}).encode(), status=400,
                           ctype="application/json")
                return
            # خلل منطقي: يقبل القيم السالبة
            self._send(json.dumps({"order": "placed", "charged": val}).encode(),
                       ctype="application/json")

        elif path == "/checkout":
            self._send(_page("دفع", f"<h1>إتمام الشراء — الخطوة {html.escape(q.get('step', '1'))}</h1>"))

        elif path == "/server-info":
            self._send(_page("معلومات", "<h1>الخادم</h1><p>LabApache/2.4.49 على Ubuntu — Python http.server</p>"))

        elif path == "/backup/":
            self._send(_page("Index of /backup/", """
<h1>Index of /backup/</h1>
<ul><li><a href="/backup/db.sql">db.sql</a></li>
<li><a href="/backup/">Parent Directory</a></li></ul>"""))

        elif path == "/backup/db.sql":
            # نسخة احتياطية وهمية بنص عادي — لا ترويسات HTML ولا محتوى حقيقي
            self._send(b"-- lab fake dump (educational)\nCREATE TABLE t(x);\n",
                       ctype="text/plain; charset=utf-8")

        elif path == "/status/404":
            self._404()

        elif path == "/status/500":
            self._send(_page("500", "<h1>خطأ داخلي</h1><pre>Traceback (most recent call last):\n"
                                    "  File \"/app/lab.py\", line 42, in handler\n</pre>"), status=500)

        elif path == "/logout":
            # خلل: لا يبطل الكوكي (لا Set-Cookie)
            self._send(_page("خروج", "<h1>تم تسجيل خروجك (نظرياً)</h1>"))

        elif path == "/redirect-external":
            self._send(b"", status=302, headers={"Location": ext})

        elif path == "/assets/app.js":
            self._send(ASSETS_APP_JS.encode(), ctype="application/javascript")

        elif path == "/assets/jquery-1.12.4.min.js":
            self._send(JQUERY_STUB.encode(), ctype="application/javascript")

        elif path == "/.git/HEAD":
            self._send(b"ref: refs/heads/main\n", ctype="text/plain")

        elif path == "/.env":
            # أسرار وهمية تعليمية فقط — ليست حقيقية بأي شكل
            self._send(b"APP_SECRET=lab-fake-secret-educational-only\nDB_PASSWORD=lab-fake-pass\n",
                       ctype="text/plain")

        elif path == "/robots.txt":
            self._send(b"User-agent: *\nDisallow: /backup/\nDisallow: /api/admin/\n",
                       ctype="text/plain")

        elif path == "/sitemap.xml":
            base = f"http://127.0.0.1:{self.server.server_port}"
            locs = "".join(f"<url><loc>{base}{p}</loc></url>"
                           for p in ("/", "/form", "/register", "/upload"))
            self._send(f'<?xml version="1.0" encoding="UTF-8"?>\n<urlset>{locs}</urlset>'.encode(),
                       ctype="application/xml")

        elif path == "/openapi.json":
            self._send(json.dumps(OPENAPI_DOC).encode(), ctype="application/json")

        elif path == "/api/admin/" or path == "/api/admin":
            # مسار مكشوف عبر robots — صفحة 404 HTML بترويسات ناقصة (سلوك واقعي)
            self._404()

        else:
            self._404(api=path.startswith("/api/"))

    # ----- POST (نموذج الدخول فقط — يقبله الفاحص للحسابات الاختبارية) -----
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(min(length, 64 * 1024)).decode("utf-8", "replace")
        data = dict(parse_qsl(body, keep_blank_values=True))
        u = urlparse(self.path)
        if u.path == "/api/login":
            if LAB_ACCOUNTS.get(data.get("username", "")) == data.get("password", ""):
                token = "lab_auth_" + "a1b2c3d4e5f60718"[:24]
                self._send(json.dumps({"ok": True}).encode(), ctype="application/json",
                           cookies=[f"lab_auth={token}; Path=/; HttpOnly; SameSite=Lax"])
            else:
                self._send(json.dumps({"ok": False, "error": "bad credentials"}).encode(),
                           status=401, ctype="application/json")
        elif u.path in ("/register", "/upload"):
            # لا يعالج فعلياً — لا رفع ولا تخزين في المختبر
            self._send(json.dumps({"ok": True, "note": "lab no-op"}).encode(), ctype="application/json")
        else:
            self._404(api=u.path.startswith("/api/"))


def make_server(port: int = 0, access_log: list | None = None, external_base: str | None = None):
    """ينشئ خادم المختبر مرتبطاً بـ 127.0.0.1 حصراً. port=0 يعني منفذاً حراً."""
    srv = ThreadingHTTPServer(("127.0.0.1", port), LabHandler)
    srv.access_log = access_log
    srv.external_base = external_base
    return srv


def serve_in_thread(srv) -> threading.Thread:
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return t


if __name__ == "__main__":
    server = make_server(8765)
    print(f"TH Ghost Vulnerable Lab يعمل على http://127.0.0.1:8765 — بيئة تدريب معزولة")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
