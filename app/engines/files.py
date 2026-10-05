# -*- coding: utf-8 -*-
"""محرك أمان الملفات: نماذج الرفع وقيود الأنواع (فحص سلبي — لا رفع فعلي)."""
from __future__ import annotations

from ..verify import INFO, MANUAL, make
from . import Engine, ScanContext

NAME = "files"


class Engine(Engine):
    name = NAME
    title = "أمان الملفات"

    async def run(self, ctx: ScanContext):
        for form in ctx.sitemap.forms:
            file_inputs = [i for i in form.inputs if i["type"] == "file"]
            if not file_inputs:
                continue
            accepts = [i.get("accept", "") for i in file_inputs]
            if not any(accepts):
                ctx.add(make("أمان الملفات", "متوسط", MANUAL,
                             "نموذج رفع ملفات بلا قيد نوع ظاهر", form.action, NAME,
                             method=form.method,
                             evidence="حقل file بلا سمة accept — ولا يمكن التحقق من قيود الخادم سلبياً.",
                             cause="قد يقبل الخادم أنواعاً خطيرة (تنفيذية/سكربتات).",
                             impact="رفع ملف خبيث وتنفيذه على الخادم.",
                             recommendation="قيّد الأنواع والحجم خادمياً، وخزّن خارج جذر الويب وأعد تسمية الملفات.",
                             reference="https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
                             retest="ارفع يدوياً ملفاً بامتداد تنفيذي وتأكد من رفضه.",
                             cvss=7.3))
            else:
                ctx.add(make("أمان الملفات", "منخفض", INFO,
                             "نموذج رفع ملفات — راجع قيود الخادم", form.action, NAME,
                             method=form.method,
                             evidence=f"accept معلن: {', '.join(a for a in accepts if a)} — هذا قيد عميل فقط.",
                             cause="—",
                             impact="قيد العميل يُتجاوز بسهولة؛ الأمان في الخادم.",
                             recommendation="كرر القيود خادمياً وافحص محتوى الملف لا امتداده فقط.",
                             reference="https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
                             retest="تجاوز قيد العميل وارفع نوعاً غير مسموح — يجب رفضه خادمياً."))
