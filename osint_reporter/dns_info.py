from __future__ import annotations

from typing import Any

import dns.resolver


def _resolve(rr: str, rdtype: str, timeout_s: int) -> list[str]:
    r = dns.resolver.Resolver()
    r.lifetime = timeout_s
    r.timeout = min(5, timeout_s)
    try:
        ans = r.resolve(rr, rdtype)
    except Exception:
        return []

    out: list[str] = []
    for item in ans:
        out.append(str(item).strip())
    return out


def collect_dns(hostname: str, timeout_s: int) -> dict[str, Any]:
    return {
        "A": _resolve(hostname, "A", timeout_s),
        "MX": _resolve(hostname, "MX", timeout_s),
        "NS": _resolve(hostname, "NS", timeout_s),
        "TXT": _resolve(hostname, "TXT", timeout_s),
    }

