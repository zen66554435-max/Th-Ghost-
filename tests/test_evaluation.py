# -*- coding: utf-8 -*-
"""اختبار التقييم: يشغّل الفاحص على المختبر ويتحقق من مقاييس الكشف.

عتبات ثابتة ومعلنة (P≥0.90، R≥0.85) — النتيجة الفعلية تُقاس ولا تُفترض.
"""
import asyncio
import json
from pathlib import Path

import pytest

from app.scanner import scan
from lab.lab_server import make_server, serve_in_thread
from scripts.evaluate import evaluate

GT = json.loads((Path(__file__).resolve().parent.parent / "lab" / "ground_truth.json")
                .read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def evaluation():
    srv = make_server(0, [])
    serve_in_thread(srv)
    origin = f"http://127.0.0.1:{srv.server_port}"
    try:
        result = asyncio.run(scan(origin, rate_rps=15.0, max_pages=60))
    finally:
        srv.shutdown()
    return evaluate(result["findings"], GT)


class TestDetectionMetrics:
    def test_no_control_violations(self, evaluation):
        assert evaluation["control_violations"] == []

    def test_precision(self, evaluation):
        assert evaluation["precision"] >= 0.90

    def test_recall(self, evaluation):
        assert evaluation["recall"] >= 0.85

    def test_no_critical_engine_missed(self, evaluation):
        """لا يُقبل فقدان أي ثغرة حقن أو تحكم وصول من المختبر."""
        missed_cats = {m["category"] for m in evaluation["missed"]}
        assert "الحقن" not in missed_cats
        assert "التحكم بالوصول" not in missed_cats

    def test_metrics_computed_not_assumed(self, evaluation):
        # الأرقام ناتجة عن مطابقة فعلية: TP + FN = عدد الحالات المرجعية
        assert evaluation["tp"] + evaluation["fn"] == evaluation["gt_instances"]
        assert evaluation["tp"] > 50
