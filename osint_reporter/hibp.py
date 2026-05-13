from __future__ import annotations

import os
import time
from typing import Any

import requests


def _unique_emails(emails: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for e in emails:
        e2 = (e or "").strip().lower()
        if not e2 or "@" not in e2:
            continue
        if e2 not in seen:
            seen.add(e2)
            out.append(e2)
    return out


def _hibp_get_breaches_for_email(email: str, api_key: str, timeout_s: int, user_agent: str) -> dict[str, Any]:
    """
    HIBP v3 endpoint: /breachedaccount/{account}
    We only request breach metadata (no sensitive data).
    """
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    headers = {
        "hibp-api-key": api_key,
        "user-agent": user_agent,
        "accept": "application/json",
    }
    params = {
        "truncateResponse": "true",  # smaller + avoids unnecessary fields
    }

    try:
        resp = requests.get(url, headers=headers, params=params, timeout=timeout_s)
        if resp.status_code == 404:
            return {"email": email, "breaches": [], "error": None}
        if resp.status_code == 429:
            return {"email": email, "breaches": [], "error": "rate_limited (429)"}
        resp.raise_for_status()
        breaches = resp.json()
        if not isinstance(breaches, list):
            breaches = []
        # Keep only a minimal safe subset
        slim = []
        for b in breaches:
            if not isinstance(b, dict):
                continue
            slim.append(
                {
                    "Name": b.get("Name"),
                    "Title": b.get("Title"),
                    "Domain": b.get("Domain"),
                    "BreachDate": b.get("BreachDate"),
                    "AddedDate": b.get("AddedDate"),
                    "DataClasses": b.get("DataClasses"),
                    "IsVerified": b.get("IsVerified"),
                    "IsFabricated": b.get("IsFabricated"),
                    "IsSensitive": b.get("IsSensitive"),
                    "IsRetired": b.get("IsRetired"),
                    "IsSpamList": b.get("IsSpamList"),
                }
            )
        return {"email": email, "breaches": slim, "error": None}
    except Exception as e:
        return {"email": email, "breaches": [], "error": str(e)}


def collect_hibp_breaches(
    emails_from_site: list[str],
    extra_emails: list[str],
    api_key: str | None,
    timeout_s: int,
    user_agent: str,
) -> dict[str, Any]:
    key = (api_key or os.environ.get("HIBP_API_KEY") or "").strip()
    all_emails = _unique_emails(list(emails_from_site or []) + list(extra_emails or []))
    if not key:
        return {
            "enabled": True,
            "error": "HIBP API key manquante (utilise --hibp-api-key ou env HIBP_API_KEY).",
            "results": {},
        }

    results: dict[str, Any] = {}
    last_rate_limit_hit = False
    for i, email in enumerate(all_emails):
        if i > 0:
            # Be polite to the API; adjust if you have a paid key with higher limits.
            time.sleep(1.7 if not last_rate_limit_hit else 3.0)

        r = _hibp_get_breaches_for_email(email, api_key=key, timeout_s=timeout_s, user_agent=user_agent)
        results[email] = {"breaches": r["breaches"], "error": r["error"]}
        last_rate_limit_hit = r["error"] == "rate_limited (429)"

    return {"enabled": True, "error": None, "results": results}

