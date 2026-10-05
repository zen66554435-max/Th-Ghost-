# -*- coding: utf-8 -*-
"""سجل تدقيق آمن — يسجل العمليات دون أي أسرار.

قاعدة صارمة: لا تمرر كلمة مرور أو رمز جلسة إلى audit(). لطبقة حماية إضافية
تُزال الأنماط الشائعة للأسرار من التفاصيل قبل التخزين.
"""
import re

from . import db

_SECRET_PATTERNS = [
    re.compile(r"(?i)(password|passwd|token|secret|api[_-]?key|authorization)\s*[:=]\s*\S+"),
    re.compile(r"(?i)(set-cookie|cookie)\s*:\s*\S+"),
]


def _scrub(text: str) -> str:
    out = str(text)
    for pat in _SECRET_PATTERNS:
        out = pat.sub(lambda m: m.group(1) + "=***", out)
    return out[:500]


def audit(action: str, detail: str = "") -> None:
    db.audit(action, _scrub(detail))
