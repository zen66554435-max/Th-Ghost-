# -*- coding: utf-8 -*-
"""حارس النطاق (Scope Guard) — قلب السلامة في TH Ghost.

المسؤوليات:
- تطبيع عنوان الأصل (المخطط+المضيف+المنفذ) ورفض العناوين غير الصالحة.
- التحقق أن أي عنوان يُطلب يقع حرفياً داخل الأصل المصرح به (وبادئات مسارات اختيارية).
- منع SSRF: رفض الأهداف العامة التي تُحلّ إلى عناوين داخلية/استرجاعية/محجوزة.
- حظر عناوين metadata السحابية (169.254.169.254 وغيرها) دائماً.
- كشف DNS rebinding: تثبيت عناوين IP عند بناء السياسة ورفض أي تغيير لاحق.
- السماح بأهداف محلية (مثل مختبر التدريب على 127.0.0.1) مع تثبيت عنوانها بدقة.
"""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

# عناوين metadata سحابية معروفة — محظورة دائماً مهما كان الهدف
CLOUD_METADATA_IPS = {
    "169.254.169.254",  # AWS / GCP / Azure
    "169.254.170.2",    # AWS ECS task metadata
    "100.100.100.200",  # Alibaba Cloud
    "169.254.169.253",
    "fd00:ec2::254",    # AWS IPv6 metadata
}


class ScopeViolation(ValueError):
    """رفض عنوان لأنه يخالف النطاق المصرح أو سياسة الشبكة."""


def normalize_origin(url: str) -> str:
    """يعيد الأصل بصيغة scheme://host[:port] أو يرفع ValueError برسالة عربية نظيفة."""
    p = urlparse(url.strip())
    if p.scheme not in ("http", "https") or not p.hostname:
        raise ValueError("يجب إدخال عنوان HTTP أو HTTPS صالح")
    if p.username or p.password:
        raise ValueError("بيانات الدخول داخل الرابط غير مسموحة")
    try:
        port = p.port
    except ValueError:
        raise ValueError("منفذ غير صالح في العنوان") from None
    default = (p.scheme == "https" and port in (None, 443)) or (p.scheme == "http" and port in (None, 80))
    host = p.hostname.lower()
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"  # IPv6: أعد الأقواس حتى يبقى العنوان صالحاً
    return f"{p.scheme}://{host}" + ("" if default else f":{port}")


def in_scope(url: str, allowed_origin: str, prefixes: list[str] | None = None) -> bool:
    """True إذا كان url داخل الأصل المصرح تماماً (وضمن بادئة مسار مسموحة إن حُددت)."""
    try:
        if normalize_origin(url) != normalize_origin(allowed_origin):
            return False
    except (ValueError, TypeError):
        return False
    if prefixes:
        path = urlparse(url).path or "/"
        return any(path.startswith(pre) for pre in prefixes)
    return True


def resolve_host(hostname: str) -> set:
    """يحلّ المضيف إلى مجموعة عناوين IP (يدعم عناوين IP الحرفية مباشرة)."""
    host = hostname.strip("[]")
    try:
        return {ipaddress.ip_address(host)}
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise ScopeViolation(f"تعذر حل اسم المضيف: {host}") from None
    ips = {ipaddress.ip_address(i[4][0]) for i in infos}
    if not ips:
        raise ScopeViolation(f"تعذر حل اسم المضيف: {host}")
    return ips


def _is_public(ip) -> bool:
    """عنوان عام قابل للتوجيه عالمياً (وليس خاصاً/استرجاعياً/محجوزاً/غير محدد)."""
    return not (
        ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
        or ip.is_reserved or ip.is_unspecified
    )


def _blocked_always(ips) -> str | None:
    for ip in ips:
        if str(ip) in CLOUD_METADATA_IPS:
            return str(ip)
    return None


class ScopePolicy:
    """سياسة نطاق مثبتة لهدف واحد — تُبنى في بداية الفحص وتُستخدم لكل طلب.

    - هدف عام: يجب أن تكون كل عناوينه المحلولة عامة، وتُثبَّت لكشف DNS rebinding.
    - هدف محلي (مختبر تدريبي مثلاً): يُسمح بالعناوين الداخلية لكن تُثبَّت بدقة،
      وتبقى عناوين metadata السحابية محظورة دائماً.
    """

    def __init__(self, origin: str, pinned_ips: frozenset, is_local: bool,
                 prefixes: tuple = ()):
        self.origin = origin
        self.pinned_ips = pinned_ips
        self.is_local = is_local
        self.prefixes = prefixes

    @classmethod
    def build(cls, origin: str, prefixes: list | None = None) -> "ScopePolicy":
        o = normalize_origin(origin)
        host = urlparse(o).hostname
        ips = frozenset(resolve_host(host))
        bad = _blocked_always(ips)
        if bad:
            raise ScopeViolation("عنوان metadata سحابي محظور كهدف للفحص")
        is_local = not all(_is_public(ip) for ip in ips)
        if not is_local and not all(_is_public(ip) for ip in ips):
            raise ScopeViolation("الهدف العام يحل إلى عنوان شبكة داخلية — رفض لمنع SSRF")
        clean_prefixes = tuple(p for p in (prefixes or []) if isinstance(p, str) and p.startswith("/"))
        return cls(o, ips, is_local, clean_prefixes)

    def validate_url(self, url: str) -> None:
        """يرفع ScopeViolation إذا خرج العنوان عن النطاق أو خالف سياسة الشبكة."""
        if not in_scope(url, self.origin, list(self.prefixes) or None):
            raise ScopeViolation("العنوان خارج النطاق المصرح به")
        host = urlparse(normalize_origin(url)).hostname
        ips = resolve_host(host)
        bad = _blocked_always(ips)
        if bad:
            raise ScopeViolation("العنوان يحل إلى عنوان metadata سحابي محظور")
        if not ips.issubset(self.pinned_ips):
            raise ScopeViolation("تغيّرت عناوين DNS للهدف أثناء الفحص — اشتباه DNS rebinding")
        if not self.is_local and not all(_is_public(ip) for ip in ips):
            raise ScopeViolation("العنوان يحل إلى شبكة داخلية — رفض لمنع SSRF")

    def validate_redirect(self, url: str) -> None:
        """إعادة التوجيه تخضع لنفس القواعد تماماً."""
        self.validate_url(url)
