# -*- coding: utf-8 -*-
"""محركات فحص الثغرات — مستقلة وقابلة للتوسعة.

كل محرك صنف يملك name ودالة async run(ctx) تضيف نتائجها إلى ctx.findings.
لإضافة محرك جديد: أنشئ صنفاً هنا وسجّله في all_engines().
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ScanContext:
    """سياق الفحص المشترك بين المحركات."""
    origin: str
    policy: object           # ScopePolicy
    fetcher: object          # Fetcher
    sitemap: object          # SiteMap
    config: dict
    accounts: list = field(default_factory=list)   # حسابات اختبارية (مصرح بها)
    sessions: dict = field(default_factory=dict)   # label -> ترويسة كوكي الجلسة
    findings: list = field(default_factory=list)
    notes: list = field(default_factory=list)

    def add(self, finding: dict):
        self.findings.append(finding)


class Engine:
    name = "base"
    title = "محرك أساسي"

    async def run(self, ctx: ScanContext):  # pragma: no cover
        raise NotImplementedError


def all_engines() -> list:
    from . import (access, apiscan, authcheck, bizlogic, clientside, files,
                   injection, passive)
    return [passive.Engine(), injection.Engine(), access.Engine(), authcheck.Engine(),
            apiscan.Engine(), files.Engine(), clientside.Engine(), bizlogic.Engine()]


REGISTRY = {e.name: e for e in all_engines()}

# مفاتيح الفحص التي يختارها المستخدم في الواجهة → أسماء المحركات
CHECK_TO_ENGINE = {
    "server": "passive",
    "injection": "injection",
    "access": "access",
    "auth": "authcheck",
    "api": "apiscan",
    "files": "files",
    "client": "clientside",
    "business": "bizlogic",
}
