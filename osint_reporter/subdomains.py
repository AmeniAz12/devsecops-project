from __future__ import annotations

import re
from typing import Any

import requests


_HOST_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$")


def _looks_like_hostname(s: str) -> bool:
    return bool(_HOST_RE.match(s.strip()))


def collect_subdomains_via_crtsh(registrable_domain: str, timeout_s: int, user_agent: str) -> dict[str, Any]:
    """
    Source: certificate transparency (crt.sh).
    - Public data
    - Best-effort (service may rate-limit)
    """
    url = "https://crt.sh/"
    params = {"q": f"%.{registrable_domain}", "output": "json"}
    headers = {"User-Agent": user_agent}

    try:
        resp = requests.get(url, params=params, headers=headers, timeout=timeout_s)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        return {"source": "crt.sh", "error": str(e), "subdomains": []}

    subs: set[str] = set()
    for row in data if isinstance(data, list) else []:
        name_val = str(row.get("name_value", "")).strip()
        for candidate in name_val.splitlines():
            c = candidate.strip().strip(".").lower()
            if not c or "*" in c:
                continue
            if c.endswith("." + registrable_domain) or c == registrable_domain:
                if _looks_like_hostname(c):
                    subs.add(c)

    return {"source": "crt.sh", "error": None, "subdomains": sorted(subs)}


def collect_subdomains_via_certspotter(registrable_domain: str, timeout_s: int, user_agent: str) -> dict[str, Any]:
    """
    Source: Cert Spotter (certificate transparency).
    Public API, best-effort.
    """
    url = "https://api.certspotter.com/v1/issuances"
    params = {
        "domain": registrable_domain,
        "include_subdomains": "true",
        "expand": "dns_names",
    }
    headers = {"User-Agent": user_agent, "accept": "application/json"}

    try:
        resp = requests.get(url, params=params, headers=headers, timeout=timeout_s)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        return {"source": "certspotter", "error": str(e), "subdomains": []}

    subs: set[str] = set()
    for row in data if isinstance(data, list) else []:
        dns_names = row.get("dns_names")
        if not isinstance(dns_names, list):
            continue
        for candidate in dns_names:
            c = str(candidate).strip().strip(".").lower()
            if not c or "*" in c:
                continue
            if c.endswith("." + registrable_domain) or c == registrable_domain:
                if _looks_like_hostname(c):
                    subs.add(c)

    return {"source": "certspotter", "error": None, "subdomains": sorted(subs)}


def collect_subdomains(registrable_domain: str, timeout_s: int, user_agent: str) -> dict[str, Any]:
    """
    Tries multiple public CT sources and merges results.
    """
    r1 = collect_subdomains_via_crtsh(registrable_domain, timeout_s=timeout_s, user_agent=user_agent)
    r2 = collect_subdomains_via_certspotter(registrable_domain, timeout_s=timeout_s, user_agent=user_agent)

    subs = sorted(set((r1.get("subdomains") or []) + (r2.get("subdomains") or [])))
    errors = [r for r in [r1, r2] if r.get("error")]
    return {
        "source": ["crt.sh", "certspotter"],
        "error": None if subs else (errors[0].get("error") if errors else None),
        "subdomains": subs,
        "details": {"crt.sh": r1.get("error"), "certspotter": r2.get("error")},
    }

