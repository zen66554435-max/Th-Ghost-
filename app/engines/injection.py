# -*- coding: utf-8 -*-
"""محرك الحقن (Injection) — جسّات خاملة غير تدميرية بطريقة GET فقط.

المبدأ: لا استغلال، بل مقارنات سلوكية وعلامات حسابية خاملة:
- SQLi: توقيع خطأ (مرجحة) + فرق منطقي آمن بين شرطين صادق/خادع (مؤكدة).
- XSS: انعكاس علامة بأحرف خاصة غير مشفرة (مرجحة — بلا تنفيذ JS).
- SSTI: ‏{{7*7}}‏ تُقيَّم إلى 49 (مؤكدة — حساب خامس لا يضر).
- Command Injection: علامة echo خاملة تظهر خارج سياق الصدى (مؤكدة).
- Path Traversal: توقيعات ملفات نظام معروفة مع إخفاء المحتوى (مؤكدة).
- LDAP/XPath: توقيعات أخطاء المحرك (مرجحة).
- Header Injection: ترويسة علامة تظهر في الاستجابة (مؤكدة).
"""
from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ..net import BudgetExceeded, FetchError
from ..scope import ScopeViolation
from ..verify import (CONFIRMED, LIKELY, LDAP_ERROR_RE, PASSWD_SIG, SQL_ERROR_RE,
                      WININI_SIG, XPATH_ERROR_RE, has_any, make, similarity_ratio)
from . import Engine, ScanContext

NAME = "injection"
MAX_TARGETS = 40          # سقف أهداف الجس لكل فحص
BASE_VALUE = "thg7k9"     # قيمة أساس خاملة
CMD_MARKER = "THG9273"

XSS_MARKER = "thg<\"'>x7"
TRAVERSAL_PAYLOADS = [
    "....//....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "..\\..\\..\\windows\\win.ini",
    "....//....//....//....//windows/win.ini",
]


def _set_param(url: str, param: str, value: str) -> str:
    p = urlparse(url)
    q = [(k, v) for k, v in parse_qsl(p.query)]
    done = False
    for i, (k, _) in enumerate(q):
        if k == param:
            q[i] = (k, value)
            done = True
    if not done:
        q.append((param, value))
    return urlunparse((p.scheme, p.netloc, p.path, "", urlencode(q), ""))


class Engine(Engine):
    name = NAME
    title = "الحقن"

    async def run(self, ctx: ScanContext):
        targets: dict[tuple[str, str], str] = {}
        for route in ctx.sitemap.routes:
            for param in route.params:
                base = urlunparse((*urlparse(route.url)[:4], "", ""))
                targets.setdefault((base, param), route.url)
        for form in ctx.sitemap.forms:
            if form.method == "GET":
                for i in form.inputs:
                    targets.setdefault((form.action, i["name"]), form.action)
        targets = dict(list(targets.items())[:MAX_TARGETS])

        for (base, param), _sample in targets.items():
            try:
                await self._probe_param(ctx, base, param)
            except BudgetExceeded:
                return
            except (FetchError, ScopeViolation):
                continue

    async def _get(self, ctx, url, follow_redirects=False):
        # الجسّات لا تتبع التحويلات: الانعكاس/الفرق يهمّان في الاستجابة المباشرة،
        # وهذا يوفر طلبات كثيرة عند أهداف تعيد التوجيه للجذر.
        try:
            return await ctx.fetcher.get(url, follow_redirects=follow_redirects)
        except (FetchError, ScopeViolation):
            return None

    async def _probe_param(self, ctx: ScanContext, base: str, param: str):
        r0 = await self._get(ctx, _set_param(base, param, BASE_VALUE))
        if r0 is None:
            return
        b0 = r0.text[:600_000]

        # --- 1) SQL Injection ---
        r_err = await self._get(ctx, _set_param(base, param, "'"))
        if r_err is not None:
            sig = has_any(r_err.text[:600_000], SQL_ERROR_RE)
            if sig and sig not in b0:
                confidence = LIKELY
                evidence = f"توقيع خطأ SQL عند إرسال علامة اقتباس: «{sig[:80]}»."
                # تحقق سلوكي إضافي: أزواج شرطية آمنة صادقة/كاذبة
                for p_true, p_false in (("' AND '1'='1", "' AND '1'='2"),
                                        ("' OR '1'='1", "' OR '1'='2")):
                    r_t = await self._get(ctx, _set_param(base, param, p_true))
                    r_f = await self._get(ctx, _set_param(base, param, p_false))
                    if r_t is not None and r_f is not None and r_t.status_code == 200 \
                            and r_f.status_code == 200:
                        sim = similarity_ratio(r_t.text[:600_000], r_f.text[:600_000])
                        if sim < 0.90:
                            confidence = CONFIRMED
                            evidence += f" واختلاف سلوكي مثبت بين شرط صادق وشرط خادع (تشابه {sim:.0%})."
                            break
                ctx.add(make("الحقن", "عالٍ", confidence, "حقن SQL", base, NAME,
                             parameter=param, evidence=evidence,
                             cause="تمرير مدخل المستخدم إلى استعلام SQL دون تمعيل/تهريب.",
                             impact="قراءة أو تعديل بيانات قاعدة البيانات وتجاوز المصادقة.",
                             recommendation="استخدم استعلامات معلّمة وORM، وقيّد صلاحيات حساب القاعدة.",
                             reference="https://owasp.org/Top10/A03_2021-Injection/",
                             retest="أعد الجس بعلامة الاقتباس وتأكد من غياب خطأ SQL وتوحّد الاستجابتين.",
                             cvss=9.8 if confidence == CONFIRMED else 7.5))

        # --- 2) XSS منعكس ---
        r_x = await self._get(ctx, _set_param(base, param, XSS_MARKER))
        if r_x is not None and XSS_MARKER in r_x.text[:600_000] and XSS_MARKER not in b0:
            ctx.add(make("الحقن", "متوسط", LIKELY, "انعكاس XSS دون ترميز", base, NAME,
                         parameter=param,
                         evidence="انعكست علامة الاختبار بأحرفها الخاصة (< \" ' >) دون ترميز HTML.",
                         cause="إخراج مدخل المستخدم في HTML دون ترميز حسب السياق.",
                         impact="تنفيذ JavaScript في متصفح الضحية وسرقة الجلسة.",
                         recommendation="رمّز المخرجات حسب السياق وفعّل CSP صارمة.",
                         reference="https://owasp.org/www-community/attacks/xss/",
                         retest="أرسل العلامة وراجع مصدر الصفحة: يجب أن تظهر &lt; لا <.",
                         cvss=6.1))

        # --- 3) حقن القوالب SSTI (حساب خامس خاملة) ---
        for payload, tag in (("{{7*7}}", "Jinja2/Twig"), ("${7*7}", "Freemarker/EL")):
            r_s = await self._get(ctx, _set_param(base, param, payload))
            if r_s is not None:
                body = r_s.text[:600_000]
                if "49" in body and payload not in body and "49" not in b0:
                    ctx.add(make("الحقن", "عالٍ", CONFIRMED, f"حقن قوالب ({tag})", base, NAME,
                                 parameter=param,
                                 evidence=f"أُرسلت «{payload}» فظهرت «49» في الاستجابة — تُقيَّم القوالب من مدخل المستخدم.",
                                 cause="تمرير مدخل المستخدم إلى محرك قوالب يقيّمه.",
                                 impact="تنفيذ كود على الخادم في كثير من محركات القوالب.",
                                 recommendation="لا تمرر مداخل المستخدم إلى محرك القوالب أبداً؛ استخدم سياق بيانات.",
                                 reference="https://portswigger.net/web-security/server-side-template-injection",
                                 retest="أرسل {{7*7}} وتأكد أنها تظهر حرفياً لا 49.",
                                 cvss=9.8))
                    break

        # --- 4) حقن أوامر — علامة echo خاملة مع تمييز الصدى ---
        r_c = await self._get(ctx, _set_param(base, param, f";echo {CMD_MARKER}"))
        if r_c is not None:
            body = r_c.text[:600_000]
            if CMD_MARKER in body and f";echo {CMD_MARKER}" not in body and CMD_MARKER not in b0:
                ctx.add(make("الحقن", "حرج", CONFIRMED, "حقن أوامر نظام", base, NAME,
                             parameter=param,
                             evidence=f"أُرسلت «;echo {CMD_MARKER}» فظهرت العلامة منفردة في الاستجابة — نُفّذ الأمر الخامل.",
                             cause="تمرير مدخل المستخدم إلى صدفة النظام.",
                             impact="تنفيذ أوامر عشوائية على الخادم.",
                             recommendation="لا تستدعِ الصدفة؛ استخدم مكتبات آمنة وقوائم سماح للمدخلات.",
                             reference="https://owasp.org/www-community/attacks/Command_Injection",
                             retest="أعد الجس بالعلامة وتأكد من عدم ظهورها منفردة.",
                             cvss=9.8))

        # --- 5) اجتياز المسار ---
        for payload in TRAVERSAL_PAYLOADS:
            r_t = await self._get(ctx, _set_param(base, param, payload))
            if r_t is None:
                continue
            body = r_t.text[:600_000]
            if PASSWD_SIG.search(body):
                ctx.add(make("الحقن", "عالٍ", CONFIRMED, "اجتياز مسار (Path Traversal)", base, NAME,
                             parameter=param,
                             evidence="ظهر توقيع ملف passwd النمطي — أُخفي المحتوى ولم يُخزَّن.",
                             cause="استخدام مدخل المستخدم كجزء من مسار ملف دون تحقق.",
                             impact="قراءة ملفات النظام الحساسة.",
                             recommendation="استخدم قائمة سماح بأسماء ملفات وثبّت المسار الجذر.",
                             reference="https://owasp.org/www-community/attacks/Path_Traversal",
                             retest="أعد الجس بحمولة الاجتياز وتأكد من رفضها.",
                             cvss=8.6))
                break
            if WININI_SIG.search(body):
                ctx.add(make("الحقن", "عالٍ", CONFIRMED, "اجتياز مسار (Path Traversal)", base, NAME,
                             parameter=param,
                             evidence="ظهر توقيع ملف win.ini النمطي — أُخفي المحتوى.",
                             cause="استخدام مدخل المستخدم كجزء من مسار ملف دون تحقق.",
                             impact="قراءة ملفات النظام الحساسة.",
                             recommendation="استخدم قائمة سماح بأسماء ملفات وثبّت المسار الجذر.",
                             reference="https://owasp.org/www-community/attacks/Path_Traversal",
                             retest="أعد الجس بحمولة الاجتياز وتأكد من رفضها.",
                             cvss=8.6))
                break

        # --- 6) LDAP Injection ---
        r_l = await self._get(ctx, _set_param(base, param, "*)(uid=*"))
        if r_l is not None:
            sig = has_any(r_l.text[:600_000], LDAP_ERROR_RE)
            if sig and sig not in b0:
                ctx.add(make("الحقن", "متوسط", LIKELY, "حقن LDAP محتمل", base, NAME,
                             parameter=param,
                             evidence=f"توقيع خطأ LDAP عند إرسال أحرف خاصة: «{sig[:80]}».",
                             cause="مدخل المستخدم يدخل استعلام LDAP دون تهريب.",
                             impact="تجاوز مصادقة أو استخراج بيانات الدليل.",
                             recommendation="هرّب مدخلات LDAP وفق RFC 4515.",
                             reference="https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html",
                             retest="أعد الجس وتأكد من غياب خطأ LDAP.",
                             cvss=7.3))

        # --- 7) XPath Injection ---
        r_xp = await self._get(ctx, _set_param(base, param, "']['"))
        if r_xp is not None:
            sig = has_any(r_xp.text[:600_000], XPATH_ERROR_RE)
            if sig and sig not in b0:
                ctx.add(make("الحقن", "متوسط", LIKELY, "حقن XPath محتمل", base, NAME,
                             parameter=param,
                             evidence=f"توقيع خطأ XPath: «{sig[:80]}».",
                             cause="مدخل المستخدم يدخل استعلام XPath دون تهريب.",
                             impact="استخراج بيانات XML أو تجاوز منطق.",
                             recommendation="استخدم معاملات XPath المعلّمة.",
                             reference="https://owasp.org/www-community/attacks/XPATH_Injection",
                             retest="أعد الجس وتأكد من غياب خطأ XPath.",
                             cvss=7.3))

        # --- 8) حقن الترويسات --- (أحرف CRLF حقيقية تُرمَّز تلقائياً؛ بلا تتبع إعادة توجيه)
        r_h = await self._get(ctx, _set_param(base, param, "x\r\nX-THG-Mark: thg1"),
                              follow_redirects=False)
        if r_h is not None and "x-thg-mark" in {k.lower() for k in r_h.headers.keys()}:
            ctx.add(make("الحقن", "عالٍ", CONFIRMED, "حقن ترويسات HTTP", base, NAME,
                         parameter=param,
                         evidence="ظهرت ترويسة العلامة X-THG-Mark في الاستجابة بعد إرسال CRLF مرمّز.",
                         cause="مدخل المستخدم يصل ترويسات الاستجابة دون تنقية CRLF.",
                         impact="تسميم الكاش وإعداد كوكيز مزيفة وانقسام استجابة.",
                         recommendation="نقّ أحرف CRLF من أي قيمة تُكتب في الترويسات.",
                         reference="https://owasp.org/www-community/attacks/HTTP_Response_Splitting",
                         retest="أعد الجس بـ CRLF مرمّز وتأكد من عدم ظهور الترويسة.",
                         cvss=7.5))
