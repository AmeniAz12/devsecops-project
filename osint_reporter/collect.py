from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .dns_info import collect_dns
from .emails import collect_public_emails
from .normalize import normalize_target
from .subdomains import collect_subdomains
from .web_tech import collect_technologies
from .hibp import collect_hibp_breaches
from .whois_info import collect_whois


def collect_all(
    target: str,
    timeout_s: int,
    user_agent: str,
    hibp_enabled: bool = False,
    hibp_api_key: str | None = None,
    hibp_emails: list[str] | None = None,
) -> dict[str, Any]:
    t = normalize_target(target)

    # Prefer a canonical URL for web fetches.
    base_url = f"https://{t.hostname}"

    dns = collect_dns(t.hostname, timeout_s=timeout_s)
    subdomains = collect_subdomains(t.registrable_domain, timeout_s=timeout_s, user_agent=user_agent)
    emails = collect_public_emails(base_url, timeout_s=timeout_s, user_agent=user_agent)
    tech = collect_technologies(base_url)
    who = collect_whois(t.registrable_domain)
    hibp = (
        collect_hibp_breaches(
            emails_from_site=emails.get("emails") or [],
            extra_emails=hibp_emails or [],
            api_key=hibp_api_key,
            timeout_s=timeout_s,
            user_agent=user_agent,
        )
        if hibp_enabled
        else {"enabled": False, "error": None, "results": {}}
    )

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "input": {
            "raw": t.raw,
            "input_url": t.input_url,
            "hostname": t.hostname,
            "registrable_domain": t.registrable_domain,
            "base_url": base_url,
        },
        "dns": dns,
        "subdomains": subdomains,
        "emails": emails,
        "technologies": tech,
        "hibp": hibp,
        "whois": who,
        "limitations": [
            "Collecte basée sur sources publiques et accès réseau.",
            "Les sous-domaines viennent de la transparence de certificats (peut être incomplet).",
            "La détection de technologies est heuristique (faux positifs/negatifs possibles).",
            "HIBP nécessite une clé API et ne vérifie que des e-mails fournis/collectés (pas de mots de passe).",
            "WHOIS peut être masqué (RGPD) ou rate-limité selon le registrar.",
        ],
    }

