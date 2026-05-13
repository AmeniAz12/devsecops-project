from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

import tldextract


@dataclass(frozen=True)
class NormalizedTarget:
    raw: str
    input_url: str
    hostname: str
    registrable_domain: str


def normalize_target(target: str) -> NormalizedTarget:
    raw = target.strip()
    if not raw:
        raise ValueError("target vide")

    # Accept domain-only input by adding a scheme.
    parsed = urlparse(raw if "://" in raw else f"https://{raw}")
    hostname = (parsed.hostname or "").strip(".").lower()
    if not hostname:
        raise ValueError("Impossible d'extraire un hostname depuis la cible")

    ext = tldextract.extract(hostname)
    registrable = ".".join(part for part in [ext.domain, ext.suffix] if part)
    if not registrable:
        # Fallback: best-effort (ex: localhost)
        registrable = hostname

    input_url = parsed.geturl()
    return NormalizedTarget(raw=raw, input_url=input_url, hostname=hostname, registrable_domain=registrable)

