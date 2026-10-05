# -*- coding: utf-8 -*-
"""محرك تدقيق التبعيات والمصدر: مطابقة إصدارات lockfiles مع قاعدة إرشادات مدمجة،
وتحليل ساكن لكود Python بتحديد الملف والسطر. لا يدّعي كشف ثغرات كود داخلي من URL."""
from __future__ import annotations

import ast
import json
import re

from ..verify import CONFIRMED, INFO, LIKELY, make

NAME = "deps"

# (الحزمة, أقل إصدار آمن, المعرف, الشدة, الملخص) — قاعدة مدمجة محدودة
ADVISORIES = [
    ("requests", "2.20.0", "CVE-2018-18074", "متوسط", "تسريب اعتماد عبر إعادة توجيه http→https"),
    ("urllib3", "1.26.5", "CVE-2021-33503", "عالٍ", "catastrophic backtracking في تحليل URL"),
    ("django", "3.2.15", "CVE-2022-36359", "عالٍ", "XSS منعكس في FileResponse"),
    ("django", "4.0.7", "CVE-2022-36359", "عالٍ", "XSS منعكس في FileResponse"),
    ("flask", "2.2.5", "CVE-2023-30861", "عالٍ", "تسريب كوكي جلسة عبر كاش وكيل"),
    ("jinja2", "3.1.3", "CVE-2024-34064", "متوسط", "XSS عبر سمة xmlattr"),
    ("pyyaml", "5.4", "CVE-2020-14343", "حرج", "تنفيذ كود عبر full_load مع FullLoader غير الآمن"),
    ("pillow", "10.0.0", "CVE-2023-4863", "عالٍ", "ثغرة heap overflow في معالجة WebP"),
    ("cryptography", "41.0.0", "CVE-2023-0286", "عالٍ", "تجاوز نوع في X.400 address"),
    ("aiohttp", "3.8.5", "CVE-2023-37276", "عالٍ", "تجاوز مسار في الملفات الساكنة"),
    ("werkzeug", "2.3.8", "CVE-2023-46136", "متوسط", "استهلاك موارد في تحليل multipart"),
    ("paramiko", "2.10.1", "CVE-2022-24302", "متوسط", "race condition في كتابة مفتاح خاص"),
    ("sqlalchemy", "1.4.49", "CVE-2023-31047", "متوسط", "ترتيب معاملات قد يسمح بحقن في ظروف خاصة"),
    ("lodash", "4.17.21", "CVE-2020-8203", "عالٍ", "تلوث النموذج الأولي prototype pollution"),
    ("jquery", "3.5.0", "CVE-2020-11023", "متوسط", "XSS عبر تمرير HTML غير موثوق"),
    ("axios", "0.21.1", "CVE-2020-28168", "متوسط", "SSRF عبر بروكسي إعادة التوجيه"),
    ("express", "4.17.3", "CVE-2022-24999", "عالٍ", "تلوث النموذج الأولي عبر qs"),
    ("minimatch", "3.0.5", "CVE-2022-3517", "عالٍ", "ReDoS في مطابقة الأنماط"),
    ("jsonwebtoken", "9.0.0", "CVE-2022-23529", "عالٍ", "RCE عبر secretOrPublicKey خبيث"),
    ("node-fetch", "2.6.7", "CVE-2022-0235", "متوسط", "كشف ترويسة Authorization عبر إعادة توجيه"),
]


def _parse_version(v: str) -> tuple[int, ...]:
    nums = re.findall(r"\d+", v)[:4]
    return tuple(int(n) for n in nums) if nums else ()


def _version_below(version: tuple[int, ...], floor: str) -> bool:
    f = _parse_version(floor)
    if not version or not f:
        return False
    ln = max(len(version), len(f))
    return version + (0,) * (ln - len(version)) < f + (0,) * (ln - len(f))


def parse_requirements(text: str) -> dict[str, str]:
    pkgs = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        m = re.match(r"^([A-Za-z0-9_.\-]+)==([0-9][0-9A-Za-z.\-]*)", line)
        if m:
            pkgs[m.group(1).lower()] = m.group(2)
    return pkgs


def parse_package_lock(text: str) -> dict[str, str]:
    pkgs: dict[str, str] = {}
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return pkgs
    for name, info in (data.get("dependencies") or {}).items():
        if isinstance(info, dict) and info.get("version"):
            pkgs[name.lower()] = str(info["version"])
    for key, info in (data.get("packages") or {}).items():
        if isinstance(info, dict) and info.get("version") and key.startswith("node_modules/"):
            pkgs[key.split("node_modules/")[-1].lower()] = str(info["version"])
    return pkgs


def audit_dependencies(pkgs: dict[str, str], source: str = "ملف تبعيات") -> tuple[list, int]:
    """يطابق الإصدارات المثبتة مع قاعدة الإرشادات المدمجة."""
    findings = []
    for name, floor, cve, sev, summary in ADVISORIES:
        if name in pkgs and _version_below(_parse_version(pkgs[name]), floor):
            findings.append(make("تدقيق التبعيات", sev, CONFIRMED,
                                 f"تبعية بثغرة معروفة: {name} {pkgs[name]}", source, NAME,
                                 evidence=f"{name}=={pkgs[name]} أقدم من {floor} — {cve}: {summary}.",
                                 cause="تبعية مثبتة بإصدار متأثر بثغرة موثقة.",
                                 impact="حسب الثغرة: قد تصل لتنفيذ كود أو كشف بيانات.",
                                 recommendation=f"حدّث {name} إلى {floor} أو أحدث وراجع التوافق.",
                                 reference=f"https://nvd.nist.gov/vuln/detail/{cve}",
                                 retest=f"ثبّت الإصدار الجديد وتحقق من إصدار {name} الفعلي.",
                                 cvss={"حرج": 9.8, "عالٍ": 7.5, "متوسط": 5.3, "منخفض": 3.1}[sev]))
    return findings, len(pkgs)


# ---------- التحليل الساكن لكود Python ----------

PY_RULES = [
    ("eval(", "استخدام eval على مدخلات محتملة", "عالٍ", CONFIRMED, 8.6),
    ("exec(", "استخدام exec على مدخلات محتملة", "عالٍ", CONFIRMED, 8.6),
    ("os.system(", "استدعاء صدفة النظام os.system", "عالٍ", CONFIRMED, 8.6),
    ("pickle.loads(", "إلغاء تسلسل pickle لبيانات غير موثوقة", "عالٍ", LIKELY, 8.1),
    ("yaml.load(", "yaml.load دون Loader آمن", "عالٍ", LIKELY, 7.5),
    ("shell=True", "subprocess مع shell=True", "عالٍ", LIKELY, 8.1),
]
REGEX_RULES = [
    (re.compile(r"verify\s*=\s*False"), "تعطيل التحقق من شهادة TLS (verify=False)", "متوسط", CONFIRMED, 5.9),
    (re.compile(r"(?i)(password|secret|api[_-]?key)\s*=\s*[\"'][^\"']{6,}[\"']"),
     "سر مكتوب حرفياً في الكود", "عالٍ", LIKELY, 7.5),
    (re.compile(r"debug\s*=\s*True"), "وضع التصحيح مفعّل (debug=True)", "متوسط", LIKELY, 5.3),
    (re.compile(r"(?i)(SELECT|INSERT|UPDATE|DELETE)[^'\n]*(%s|\.format\(|f[\"'])"),
     "بناء استعلام SQL بتنسيق نصوص", "عالٍ", LIKELY, 8.1),
]


def audit_python_source(source: str, filename: str) -> list:
    """تحليل ساكن سريع لملف Python مع تحديد رقم السطر."""
    findings = []
    try:
        tree = ast.parse(source, filename=filename)
    except SyntaxError:
        findings.append(make("تدقيق المصدر", "منخفض", INFO, "تعذر تحليل الملف (خطأ صياغة)",
                             filename, NAME, evidence="فشل ast.parse.",
                             cause="—", impact="—",
                             recommendation="راجع الملف يدوياً.",
                             reference="", retest=""))
        return findings

    src_lines = source.splitlines()

    class _Visitor(ast.NodeVisitor):
        def __init__(self):
            self.shell_true_lines: set[int] = set()

        def visit_Call(self, node):
            func = node.func
            name = ""
            if isinstance(func, ast.Attribute):
                base = func.value
                base_name = ""
                while isinstance(base, ast.Attribute):
                    base = base.value
                if isinstance(base, ast.Name):
                    base_name = base.id
                name = f"{base_name}.{func.attr}"
            elif isinstance(func, ast.Name):
                name = func.id
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self.shell_true_lines.add(node.lineno)
            if name in ("eval", "exec"):
                self._report(name, node.lineno)
            elif name == "os.system":
                self._report("os.system(", node.lineno)
            elif name == "pickle.loads":
                self._report("pickle.loads(", node.lineno)
            elif name in ("yaml.load",) and not any(kw.arg == "Loader" for kw in node.keywords):
                self._report("yaml.load(", node.lineno)
            elif name in ("hashlib.md5", "hashlib.sha1"):
                findings.append(make("تدقيق المصدر", "منخفض", CONFIRMED,
                                     f"دالة تجزئة ضعيفة ({name.split('.')[-1]})", filename, NAME,
                                     location=f"السطر {node.lineno}",
                                     evidence=src_lines[node.lineno - 1].strip()[:120],
                                     cause="استخدام خوارزمية تجزئة مكسورة.",
                                     impact="سهولة كسر/اصطدام التجزئة.",
                                     recommendation="استخدم SHA-256 أو أقوى.",
                                     reference="https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
                                     retest="استبدل الخوارزمية وأعد الفحص.",
                                     cvss=3.7))
            self.generic_visit(node)

        def _report(self, marker: str, lineno: int):
            for m, title, sev, conf, cvss in PY_RULES:
                if m.rstrip("(") in marker.rstrip("("):
                    findings.append(make("تدقيق المصدر", sev, conf, title, filename, NAME,
                                         location=f"السطر {lineno}",
                                         evidence=src_lines[lineno - 1].strip()[:120],
                                         cause="نمط خطير في الكود المصدري.",
                                         impact="حسب السياق: قد يصل لتنفيذ كود.",
                                         recommendation="استخدم بدائل آمنة وقيّد المدخلات.",
                                         reference="https://owasp.org/www-community/attacks/",
                                         retest="أعد التحليل بعد التصحيح.",
                                         cvss=cvss))
                    break

    v = _Visitor()
    v.visit(tree)
    for lineno in sorted(v.shell_true_lines):
        findings.append(make("تدقيق المصدر", "عالٍ", LIKELY, "subprocess مع shell=True",
                             filename, NAME, location=f"السطر {lineno}",
                             evidence=src_lines[lineno - 1].strip()[:120],
                             cause="تمرير أمر نصي للصدفة.",
                             impact="حقن أوامر إن وصلته مدخلات مستخدم.",
                             recommendation="مرّر الوسائط كقائمة بلا shell=True.",
                             reference="https://owasp.org/www-community/attacks/Command_Injection",
                             retest="أعد التحليل بعد التصحيح.", cvss=8.1))

    for rx, title, sev, conf, cvss in REGEX_RULES:
        for i, line in enumerate(src_lines, 1):
            if rx.search(line):
                findings.append(make("تدقيق المصدر", sev, conf, title, filename, NAME,
                                     location=f"السطر {i}",
                                     evidence=line.strip()[:120],
                                     cause="نمط خطير في الكود المصدري.",
                                     impact="حسب السياق.",
                                     recommendation="راجع النمط وصححه.",
                                     reference="https://owasp.org/www-community/",
                                     retest="أعد التحليل بعد التصحيح.",
                                     cvss=cvss))
                break
    return findings
