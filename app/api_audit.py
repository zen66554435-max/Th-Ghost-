# -*- coding: utf-8 -*-
"""تدقيق OpenAPI/Swagger (واجهة قديمة متوافقة): جلب الوثيقة وتحليلها هيكلياً."""
from __future__ import annotations

import json
from urllib.parse import urljoin

import httpx

OPENAPI_CANDIDATES = ("/openapi.json", "/swagger.json", "/api-docs",
                      "/v1/openapi.json", "/docs/openapi.json")


def inspect_openapi(origin: str, timeout: float = 10.0) -> dict:
    """يجلب تعريف OpenAPI من المسارات الشائعة ويحلله (GET فقط)."""
    found_url = None
    doc = None
    errors: list[str] = []
    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        for path in OPENAPI_CANDIDATES:
            url = urljoin(origin + "/", path.lstrip("/"))
            try:
                r = client.get(url)
            except httpx.HTTPError as exc:
                errors.append(f"{path}: {type(exc).__name__}")
                continue
            if r.status_code == 200 and ("openapi" in r.text[:2000] or "swagger" in r.text[:2000]):
                try:
                    doc = r.json()
                    found_url = url
                    break
                except json.JSONDecodeError:
                    continue
    if doc is None:
        return {"found": False, "errors": errors}

    paths = doc.get("paths") or {}
    global_sec = doc.get("security")
    operations = []
    for p, item in paths.items():
        if not isinstance(item, dict):
            continue
        for method, op in item.items():
            if method.lower() not in ("get", "post", "put", "patch", "delete", "head", "options"):
                continue
            op = op if isinstance(op, dict) else {}
            eff_sec = op.get("security", global_sec)
            operations.append({
                "path": p,
                "method": method.upper(),
                "operation_id": op.get("operationId", ""),
                "authenticated": bool(eff_sec),
                "state_changing": method.lower() in ("post", "put", "patch", "delete"),
                "parameters": [prm.get("name", "") for prm in op.get("parameters", [])
                               if isinstance(prm, dict)],
            })
    return {
        "found": True,
        "url": found_url,
        "title": (doc.get("info") or {}).get("title", ""),
        "version": doc.get("openapi") or doc.get("swagger", ""),
        "operations": operations,
        "no_security": [f"{o['method']} {o['path']}" for o in operations if not o["authenticated"]],
        "errors": errors,
    }
