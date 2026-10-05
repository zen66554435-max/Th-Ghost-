# -*- coding: utf-8 -*-
"""تقييم قدرة الكشف: يشغّل TH Ghost على المختبر ويقارن بالحقيقة المرجعية.

يحسب TP/FP/FN وPrecision/Recall/F1 إجمالاً ولكل فئة، ويتحقق من الضوابط السلبية.
لا تُعدَّل النتائج يدوياً — الأرقام ناتجة عن تشغيل فعلي حصراً.

الاستخدام:
  python3 scripts/evaluate.py [--min-precision 0.85] [--min-recall 0.80] [--write-docs]
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.scanner import scan  # noqa: E402
from lab.lab_server import make_server, serve_in_thread  # noqa: E402

GT_PATH = ROOT / "lab" / "ground_truth.json"
DOCS_MD = ROOT / "docs" / "EVALUATION_AR.md"
DOCS_JSON = ROOT / "docs" / "evaluation_result.json"


def path_of(url: str) -> str:
    return urlparse(url).path or "/"


def expand_instances(gt: dict) -> list[dict]:
    """يحوّل إدخالات الحقيقة المرجعية إلى حالات فردية متوقعة."""
    instances = []
    for e in gt["entries"]:
        for u in e.get("url_contains", []):
            instances.append({"id": e["id"], "category": e["category"],
                              "title": e["title_contains"], "url": u, "kind": "contains"})
        for p in e.get("path_exact", []):
            instances.append({"id": e["id"], "category": e["category"],
                              "title": e["title_contains"], "url": p, "kind": "path"})
        for p in e.get("root_exact", []):
            instances.append({"id": e["id"], "category": e["category"],
                              "title": e["title_contains"], "url": p, "kind": "root"})
        for _ in range(int(e.get("expected_count", 0))):
            instances.append({"id": e["id"], "category": e["category"],
                              "title": e["title_contains"], "url": "", "kind": "any"})
    return instances


def _matches(inst: dict, finding: dict) -> bool:
    if inst["title"] not in finding.get("title", ""):
        return False
    url = finding.get("url", "")
    if inst["kind"] == "contains":
        return inst["url"] in url
    if inst["kind"] == "path":
        return path_of(url) == inst["url"]
    if inst["kind"] == "root":
        return path_of(url) == "/" and inst["url"] == "/"
    return True


def evaluate(findings: list[dict], gt: dict) -> dict:
    instances = expand_instances(gt)
    # الأكثر تحديداً أولاً: /api/users/1 قبل /api/users حتى لا يبتلع العام الخاص
    instances.sort(key=lambda i: -len(i["url"]))

    remaining = list(findings)
    matched_findings: set[int] = set()
    tp_instances, fn_instances = [], []
    for inst in instances:
        hit = None
        for i, f in enumerate(remaining):
            if i in matched_findings:
                continue
            if _matches(inst, f):
                hit = i
                break
        if hit is not None:
            matched_findings.add(hit)
            tp_instances.append((inst, remaining[hit]))
        else:
            fn_instances.append(inst)

    fp_findings = [f for i, f in enumerate(remaining) if i not in matched_findings]

    control_violations = []
    for ctl in gt.get("negative_controls", []):
        for f in findings:
            if ctl["title_contains"] in f.get("title", "") and ctl["url_contains"] in f.get("url", ""):
                control_violations.append({"control": ctl, "finding": f})

    tp, fp, fn = len(tp_instances), len(fp_findings), len(fn_instances)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0

    per_cat: dict[str, dict] = {}
    for inst, _f in tp_instances:
        c = per_cat.setdefault(inst["category"], {"tp": 0, "fn": 0})
        c["tp"] += 1
    for inst in fn_instances:
        c = per_cat.setdefault(inst["category"], {"tp": 0, "fn": 0})
        c["fn"] += 1
    for cat, c in per_cat.items():
        c["recall"] = c["tp"] / (c["tp"] + c["fn"]) if c["tp"] + c["fn"] else 0.0

    return {
        "tp": tp, "fp": fp, "fn": fn,
        "precision": precision, "recall": recall, "f1": f1,
        "per_category": per_cat,
        "detected": [{"gt": i["id"], "title": f["title"], "url": f["url"],
                      "severity": f["severity"], "confidence": f["confidence"]}
                     for i, f in tp_instances],
        "missed": [{"gt": i["id"], "category": i["category"], "expected": f'{i["title"]} @ {i["url"] or "(أي موقع)"}'}
                   for i in fn_instances],
        "false_positives": [{"title": f["title"], "url": f["url"], "severity": f["severity"],
                             "confidence": f["confidence"], "evidence": f.get("evidence", "")[:160]}
                            for f in fp_findings],
        "control_violations": [{"why": v["control"].get("why", ""),
                                "title": v["finding"]["title"], "url": v["finding"]["url"]}
                               for v in control_violations],
        "total_findings": len(findings),
        "gt_instances": len(instances),
    }


def render_markdown(result: dict, meta: dict) -> str:
    p, r, f1 = (result["precision"] * 100, result["recall"] * 100, result["f1"] * 100)
    lines = [
        "# تقرير تقييم قدرة الكشف — TH Ghost على المختبر التعليمي",
        "",
        f"- **التاريخ:** {meta['date']}",
        f"- **الهدف:** {meta['origin']} (TH Ghost Vulnerable Lab — بيئة معزولة)",
        f"- **الطلبات:** {meta['requests']} | **المسارات المكتشفة:** {meta['routes']} | "
        f"**المدة:** {meta['duration_sec']} ثانية",
        f"- **حالات الحقيقة المرجعية:** {result['gt_instances']} | **إجمالي نتائج الفاحص:** {result['total_findings']}",
        "",
        "## المقاييس الإجمالية",
        "",
        "| المقياس | القيمة |",
        "|---|---|",
        f"| True Positives (صحيحة) | {result['tp']} |",
        f"| False Positives (إيجابيات كاذبة) | {result['fp']} |",
        f"| False Negatives (مفقودة) | {result['fn']} |",
        f"| **Precision (الدقة)** | **{p:.1f}%** |",
        f"| **Recall (الاستدعاء)** | **{r:.1f}%** |",
        f"| **F1** | **{f1:.1f}%** |",
        f"| انتهاكات الضوابط السلبية | {len(result['control_violations'])} |",
        "",
        "## الاستدعاء لكل فئة",
        "",
        "| الفئة | مكتشف | مفقود | Recall |",
        "|---|---|---|---|",
    ]
    for cat, c in sorted(result["per_category"].items()):
        lines.append(f"| {cat} | {c['tp']} | {c['fn']} | {c['recall'] * 100:.0f}% |")
    lines += ["", "## الثغرات المكتشفة (TP)", ""]
    for d in result["detected"]:
        lines.append(f"- ✅ **{d['gt']}** — {d['title']} @ `{d['url']}` ({d['severity']} / {d['confidence']})")
    lines += ["", "## الثغرات المفقودة (FN)", ""]
    if result["missed"]:
        for m in result["missed"]:
            lines.append(f"- ❌ **{m['gt']}** ({m['category']}): {m['expected']}")
    else:
        lines.append("لا شيء — كل حالات الحقيقة المرجعية كُشفت.")
    lines += ["", "## الإيجابيات الكاذبة (FP)", ""]
    if result["false_positives"]:
        for fpx in result["false_positives"]:
            lines.append(f"- ⚠️ {fpx['title']} @ `{fpx['url']}` ({fpx['confidence']}) — {fpx['evidence']}")
    else:
        lines.append("لا شيء — كل النتائج المبلغة تقابل حالة مرجعية.")
    lines += ["", "## الضوابط السلبية", ""]
    if result["control_violations"]:
        for v in result["control_violations"]:
            lines.append(f"- ❌ انتهاك: {v['title']} @ `{v['url']}` — {v['why']}")
    else:
        lines.append("كل الضوابط السلبية محترمة — لا إيجابيات كاذبة على الصفحات الآمنة.")
    lines += [
        "",
        "## منهجية وحدود",
        "",
        "- الأرقام أعلاه ناتجة عن تشغيل فعلي للفاحص ضد المختبر — لا تعديل يدوي ولا تضخيم.",
        "- المختبر يحاكي الثغرات بمحتوى تعليمي جاهز؛ القياس على تطبيقات حقيقية قد يختلف.",
        "- المطابقة حتمية: عنوان النتيجة وموقعها مقابل تعريف كل حالة مرجعية (الأكثر تحديداً أولاً).",
        "- لا يدّعي TH Ghost كشف جميع الثغرات بلا استثناء؛ هذه النتيجة خاصة بهذا المختبر.",
    ]
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--min-precision", type=float, default=0.85)
    ap.add_argument("--min-recall", type=float, default=0.80)
    ap.add_argument("--rate", type=float, default=15.0)
    ap.add_argument("--write-docs", action="store_true")
    args = ap.parse_args()

    gt = json.loads(GT_PATH.read_text(encoding="utf-8"))
    access_log: list[str] = []
    srv = make_server(0, access_log)
    serve_in_thread(srv)
    origin = f"http://127.0.0.1:{srv.server_port}"
    print(f"[i] المختبر يعمل على {origin} — بدء الفحص الكامل…")
    t0 = time.monotonic()
    try:
        result_scan = asyncio.run(scan(origin, rate_rps=args.rate, max_pages=60))
    finally:
        srv.shutdown()
    duration = round(time.monotonic() - t0, 1)

    findings = result_scan["findings"]
    result = evaluate(findings, gt)
    meta = {"date": time.strftime("%Y-%m-%d %H:%M:%S"), "origin": origin,
            "requests": result_scan["requests"], "routes": result_scan["routes"],
            "duration_sec": duration}
    result["meta"] = meta

    print(f"\n=== النتائج ===")
    print(f"TP={result['tp']}  FP={result['fp']}  FN={result['fn']}")
    print(f"Precision={result['precision'] * 100:.1f}%  Recall={result['recall'] * 100:.1f}%  "
          f"F1={result['f1'] * 100:.1f}%")
    print(f"انتهاكات الضوابط السلبية: {len(result['control_violations'])}")
    if result["missed"]:
        print("\n— مفقود:")
        for m in result["missed"]:
            print(f"  ❌ {m['gt']} ({m['category']}): {m['expected']}")
    if result["false_positives"]:
        print("\n— إيجابيات كاذبة:")
        for fpx in result["false_positives"]:
            print(f"  ⚠️ {fpx['title']} @ {fpx['url']} ({fpx['confidence']})")
    if result["control_violations"]:
        print("\n— انتهاكات ضوابط:")
        for v in result["control_violations"]:
            print(f"  ❌ {v['title']} @ {v['url']}")
    if result_scan.get("notes"):
        print("\n— ملاحظات المحركات:")
        for n in result_scan["notes"]:
            print(f"  • {n}")

    if args.write_docs:
        DOCS_MD.write_text(render_markdown(result, meta), encoding="utf-8")
        DOCS_JSON.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"\n[i] كُتب {DOCS_MD} و{DOCS_JSON}")

    ok = (result["precision"] >= args.min_precision and result["recall"] >= args.min_recall
          and not result["control_violations"])
    print(f"\nالعتبات: P≥{args.min_precision:.0%} R≥{args.min_recall:.0%} → {'ناجح ✅' if ok else 'راسب ❌'}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
