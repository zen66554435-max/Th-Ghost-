# -*- coding: utf-8 -*-
"""محرك التحقق (Verification Engine).

يوحد أساليب التحقق ومستويات الثقة عبر كل المحركات:
- مؤكدة (Confirmed): دليل سلوكي قاطع (اختلاف سلوك مثبت، أو تنفيذ علامة خاملة، أو تسرب محتوى بتوقيع واضح).
- مرجحة (Likely): مؤشرات قوية (توقيع خطأ، انعكاس غير مشفر، نمط معروف) دون إثبات سلوكي كامل.
- معلوماتية (Informational): ملاحظة تقنية ذات قيمة.
- تحتاج مراجعة يدوية (Needs Manual Review): يتعذر البت آلياً دون تدخل بشري.

قاعدة: لا تُصنَّف ثغرة «مؤكدة» بسبب رسالة خطأ أو استجابة غير معتادة وحدها.
"""
from __future__ import annotations

import re

CONFIRMED = "مؤكدة"
LIKELY = "مرجحة"
INFO = "معلوماتية"
MANUAL = "تحتاج مراجعة يدوية"

# توقيعات أخطاء قواعد البيانات الشائعة (دليل مرجّح لا مؤكد)
SQL_ERRORS = [
    r"SQL syntax.*MySQL", r"Warning.*mysql_", r"MySqlException", r"valid MySQL result",
    r"PostgreSQL.*ERROR", r"pg_query\(\)", r"PSQLException", r"ORA-\d{5}",
    r"Oracle error", r"SQLite3?::?SQLException", r"sqlite3\.OperationalError",
    r"SQLSTATE\[\w+\]", r"Unclosed quotation mark", r"Microsoft OLE DB Provider for SQL Server",
    r"Incorrect syntax near", r"Syntax error.*in query expression",
]
LDAP_ERRORS = [r"javax\.naming\.[A-Za-z.]*Exception", r"Bad search filter",
               r"LDAPException", r"invalid DN syntax", r"LdapErr"]
XPATH_ERRORS = [r"XPath\w*Exception", r"XPATH syntax error", r"xmlXPathEval",
                r"SimpleXMLElement", r"XPath query"]
TRACE_ERRORS = [r"Traceback \(most recent call last\)", r"NullPointerException",
                r"Stack trace:", r"Fatal error.*on line \d+", r"at [\w.$]+\([\w.]+:\d+\)",
                r"Exception in thread", r"System\.NullReferenceException"]

SQL_ERROR_RE = [re.compile(p, re.I | re.S) for p in SQL_ERRORS]
LDAP_ERROR_RE = [re.compile(p, re.I) for p in LDAP_ERRORS]
XPATH_ERROR_RE = [re.compile(p, re.I) for p in XPATH_ERRORS]
TRACE_ERROR_RE = [re.compile(p, re.I) for p in TRACE_ERRORS]

PASSWD_SIG = re.compile(r"root:.{0,30}:0:0:", re.S)
WININI_SIG = re.compile(r"\[(extensions|fonts)\]", re.I)


def has_any(text: str, patterns) -> str | None:
    """يعيد أول توقيع مطابق في النص أو None."""
    for p in patterns:
        m = p.search(text or "")
        if m:
            return m.group(0)[:120]
    return None


def similarity_ratio(a: str, b: str) -> float:
    """نسبة تشابه تقريبية بين نصين (0..1) عبر الانجرافات الثنائية."""
    if a == b:
        return 1.0
    if not a or not b:
        return 0.0
    grams = lambda s: {s[i:i + 2] for i in range(max(1, len(s) - 1))}
    ga, gb = grams(a[:8000]), grams(b[:8000])
    if not ga or not gb:
        return 0.0
    return 2 * len(ga & gb) / (len(ga) + len(gb))


_SECRET_VALUE = re.compile(
    r"(?i)(password|passwd|token|secret|api[_-]?key|authorization|session|cookie)"
    r"(['\"\s:=]+)([^\s'\";,&]{6,})")


def scrub_evidence(text: str, limit: int = 400) -> str:
    """ينظف الدليل من أي قيم تشبه الأسرار ويقيد طوله — لا أسرار في التقارير أبداً."""
    out = _SECRET_VALUE.sub(lambda m: m.group(1) + m.group(2) + "***", str(text))
    return out[:limit]


def make(category, severity, confidence, title, url, engine, method="GET", parameter="",
         location="", evidence="", cause="", impact="", recommendation="",
         reference="", retest="", cvss=None) -> dict:
    """باني نتيجة موحد — يضمن اكتمال الحقول وتنظيف الدليل."""
    return {
        "category": category, "severity": severity, "confidence": confidence,
        "title": title, "url": url, "method": method, "parameter": parameter,
        "location": location, "evidence": scrub_evidence(evidence),
        "cause": cause, "impact": impact, "recommendation": recommendation,
        "reference": reference, "retest": retest, "cvss": cvss, "engine": engine,
    }


def post_process(findings: list[dict]) -> list[dict]:
    """معالجة لاحقة: إزالة التكرار، وخفض الثقة عند غياب الدليل، وتنظيف نهائي."""
    seen = set()
    out = []
    for f in findings:
        key = (f["title"], f["url"], f.get("parameter", ""))
        if key in seen:
            continue
        seen.add(key)
        if not f.get("evidence") and f["confidence"] == CONFIRMED:
            f["confidence"] = LIKELY
        f["evidence"] = scrub_evidence(f.get("evidence", ""))
        out.append(f)
    return out
