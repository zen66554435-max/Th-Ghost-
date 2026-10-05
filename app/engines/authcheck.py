# -*- coding: utf-8 -*-
"""محرك المصادقة والجلسات: سمات الكوكيز، CSRF، سياسة كلمة المرور، تسجيل الخروج."""
from __future__ import annotations

import re
from http.cookies import SimpleCookie

from ..net import BudgetExceeded, FetchError
from ..scope import ScopeViolation
from ..verify import CONFIRMED, INFO, LIKELY, MANUAL, make
from . import Engine, ScanContext

NAME = "authcheck"
SESSION_NAME_RE = re.compile(r"(?i)(session|sess|sid|auth|token|jwt)")


def cookie_attributes(set_cookie: str) -> dict:
    """يستخرج سمات أول كوكي من ترويسة Set-Cookie."""
    jar = SimpleCookie()
    try:
        jar.load(set_cookie)
    except Exception:
        return {}
    if not jar:
        return {}
    morsel = next(iter(jar.values()))
    return {
        "name": morsel.key,
        "value": morsel.value,
        "secure": bool(morsel["secure"]),
        "httponly": bool(morsel["httponly"]),
        "samesite": (morsel["samesite"] or "").lower(),
    }


class Engine(Engine):
    name = NAME
    title = "المصادقة والجلسات"

    async def run(self, ctx: ScanContext):
        # --- 1) سمات الكوكيز من الاستجابات المخزنة (بالعنوان النهائي بعد التحويلات) ---
        seen_cookies: set[tuple[str, str]] = set()
        for url, r in ctx.sitemap.responses.items():
            if url.endswith("#inline-js") or not hasattr(r, "headers"):
                continue
            final_url = str(r.url)
            for sc in r.headers.get_list("set-cookie"):
                attrs = cookie_attributes(sc)
                if not attrs:
                    continue
                key = (final_url, attrs["name"])
                if key in seen_cookies:
                    continue
                seen_cookies.add(key)
                base = dict(url=final_url, parameter=attrs["name"], engine=NAME)
                if ctx.origin.startswith("https://") and not attrs["secure"]:
                    ctx.add(make("المصادقة والجلسات", "منخفض", CONFIRMED,
                                 "كوكي دون سمة Secure", **base,
                                 evidence=f"الكوكي «{attrs['name']}» أُرسل عبر HTTPS دون سمة Secure.",
                                 cause="إهمال سمة Secure عند إنشاء الكوكي.",
                                 impact="قد يُرسل الكوكي عبر قناة غير مشفرة.",
                                 recommendation="فعّل سمة Secure لكل كوكيز HTTPS.",
                                 reference="https://owasp.org/www-community/controls/SecureCookieAttribute",
                                 retest="افحص ترويسة Set-Cookie وتأكد من وجود Secure.",
                                 cvss=3.7))
                if not attrs["httponly"]:
                    ctx.add(make("المصادقة والجلسات", "منخفض", CONFIRMED,
                                 "كوكي دون سمة HttpOnly", **base,
                                 evidence=f"الكوكي «{attrs['name']}» يفتقد HttpOnly.",
                                 cause="إهمال سمة HttpOnly.",
                                 impact="إن حدث XSS يمكن سرقة الكوكي من JavaScript.",
                                 recommendation="فعّل HttpOnly لكوكيز الجلسة على الأقل.",
                                 reference="https://owasp.org/www-community/HttpOnly",
                                 retest="افحص Set-Cookie وتأكد من وجود HttpOnly.",
                                 cvss=3.7))
                if attrs["samesite"] not in ("lax", "strict"):
                    ctx.add(make("المصادقة والجلسات", "منخفض", CONFIRMED,
                                 "كوكي دون سياسة SameSite فعالة", **base,
                                 evidence=f"الكوكي «{attrs['name']}» سمة SameSite فيه: «{attrs['samesite'] or 'غائبة'}».",
                                 cause="عدم ضبط SameSite يترك الكوكي متاحاً عبر المواقع.",
                                 impact="يسهّل هجمات CSRF.",
                                 recommendation="اضبط SameSite=Lax أو Strict لكوكيز الجلسة.",
                                 reference="https://owasp.org/www-community/SameSite",
                                 retest="افحص Set-Cookie وتأكد من SameSite.",
                                 cvss=3.7))
                if SESSION_NAME_RE.search(attrs["name"]) and len(attrs["value"]) < 16:
                    ctx.add(make("المصادقة والجلسات", "متوسط", LIKELY,
                                 "معرّف جلسة ضعيف العشوائية", **base,
                                 evidence=f"معرّف الجلسة قصير ({len(attrs['value'])} محارف) — قد يكون قابلاً للتخمين.",
                                 cause="مولّد جلسات ضعيف الإنتروبيا.",
                                 impact="تخمين جلسات مستخدمين آخرين.",
                                 recommendation="استخدم مولّد أرقام عشوائية آمن بطول 128 بت على الأقل.",
                                 reference="https://owasp.org/www-community/vulnerabilities/Insufficient_Session-ID_Length",
                                 retest="اجمع عدة جلسات وحلل إنتروبيا المعرّفات.",
                                 cvss=5.3))

        # --- 2) CSRF: نماذج POST بلا رمز حماية ظاهر ---
        for form in ctx.sitemap.forms:
            if form.method != "POST":
                continue
            names = {i["name"].lower() for i in form.inputs}
            has_token = any("csrf" in n or "token" in n or "nonce" in n for n in names)
            if not has_token:
                ctx.add(make("المصادقة والجلسات", "متوسط", LIKELY,
                             "نموذج POST بلا رمز CSRF ظاهر", form.action, NAME,
                             method="POST",
                             evidence=f"النموذج «{form.action}» لا يتضمن حقلاً مخفياً باسم يشير إلى CSRF/token.",
                             cause="عدم ربط النموذج برمز مضاد للتزوير.",
                             impact="تنفيذ طلبات مزورة باسم المستخدم إن لم توجد حماية أخرى (SameSite قد تحد).",
                             recommendation="أضف رمز CSRF فريداً لكل جلسة وتحقق منه خادمياً.",
                             reference="https://owasp.org/www-community/attacks/csrf",
                             retest="أرسل النموذج دون رمز من صفحة خارجية — يجب رفضه.",
                             cvss=6.5))

        # --- 3) نماذج كلمات المرور عبر HTTP غير مشفر (كل نموذج على حدة) ---
        if ctx.origin.startswith("http://"):
            for form in ctx.sitemap.forms:
                if any(i["type"] == "password" for i in form.inputs):
                    ctx.add(make("المصادقة والجلسات", "متوسط", CONFIRMED,
                                 "نموذج كلمة مرور عبر اتصال غير مشفر", form.action, NAME,
                                 method=form.method,
                                 evidence=f"نموذج في «{form.page_url}» يحوي حقل password يُرسل عبر http دون تشفير.",
                                 cause="غياب TLS.",
                                 impact="اعتراض بيانات الاعتماد على الشبكة.",
                                 recommendation="فرض HTTPS بشهادة صالحة وفعّل HSTS.",
                                 reference="https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
                                 retest="تأكد أن النموذج يُقدَّم ويُرسَل عبر https فقط.",
                                 cvss=6.5))

        # --- 4) سياسة كلمة المرور (معلوماتية — تحتاج تفاعلاً يدوياً) ---
        password_forms = [f for f in ctx.sitemap.forms
                          if any(i["type"] == "password" for i in f.inputs)]
        if password_forms:
            f = password_forms[0]
            ctx.add(make("المصادقة والجلسات", "منخفض", INFO,
                         "راجع سياسة كلمة المرور يدوياً", f.action, NAME,
                         method=f.method,
                         evidence="وُجد نموذج كلمة مرور؛ لا يفحص TH Ghost السياسة آلياً (لا brute-force).",
                         cause="—",
                         impact="كلمات مرور ضعيفة تسهّل التخمين.",
                         recommendation="فرض طولاً أدنى وتحقق من القوائم المسربة وحدّد المحاولات.",
                         reference="https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
                         retest="جرّب يدوياً كلمات مرور ضعيفة وراقب القبول وعدد المحاولات المسموحة."))

        # --- 5) تسجيل الخروج ---
        logout_urls = [r.url for r in ctx.sitemap.routes
                       if re.search(r"(?i)/(logout|signout|sign-out|logoff)", r.url)]
        for url in logout_urls[:2]:
            try:
                r = await ctx.fetcher.get(url)
            except (FetchError, BudgetExceeded, ScopeViolation):
                continue
            if r.status_code in (200, 302) and not r.headers.get_list("set-cookie"):
                ctx.add(make("المصادقة والجلسات", "منخفض", MANUAL,
                             "تسجيل الخروج لا يبدو أنه يبطل الكوكي", url, NAME,
                             evidence="استجابة تسجيل الخروج لا تحمل Set-Cookie لإبطال الجلسة.",
                             cause="احتمال بقاء الجلسة صالحة بعد الخروج.",
                             impact="إساءة استخدام جلسة مسروقة حتى بعد «الخروج».",
                             recommendation="أبطل الجلسة خادمياً واحذف الكوكي عبر Set-Cookie منتهية.",
                             reference="https://owasp.org/www-project-web-security-testing-guide/",
                             retest="سجّل دخولاً ثم خروجاً وأعد استخدام الكوكي القديم — يجب رفضه."))
