from __future__ import annotations

import re
from typing import Any

import requests
from bs4 import BeautifulSoup


_EMAIL_RE = re.compile(r"(?i)\b[a-z0-9._%+\-]+@(?:[a-z0-9\-]+\.)+[a-z]{2,}\b")


def collect_public_emails(url: str, timeout_s: int, user_agent: str, max_pages: int = 3) -> dict[str, Any]:
    """
    Scraping léger: page d'accueil + quelques liens internes fréquents.
    Objectif: e-mails affichés publiquement (contact, mentions légales).
    """
    headers = {"User-Agent": user_agent}
    visited: set[str] = set()
    to_visit: list[str] = [url]
    found: set[str] = set()

    def same_site(link: str) -> bool:
        return link.startswith(url.rstrip("/") + "/") or link == url.rstrip("/")

    while to_visit and len(visited) < max_pages:
        cur = to_visit.pop(0)
        if cur in visited:
            continue
        visited.add(cur)

        try:
            resp = requests.get(cur, headers=headers, timeout=timeout_s, allow_redirects=True)
            resp.raise_for_status()
            html = resp.text
        except Exception:
            continue

        for m in _EMAIL_RE.findall(html):
            found.add(m.lower())

        try:
            soup = BeautifulSoup(html, "html.parser")
        except Exception:
            continue

        # Add likely pages
        for a in soup.select("a[href]"):
            href = str(a.get("href") or "").strip()
            if not href:
                continue
            if href.startswith("mailto:"):
                mail = href.split(":", 1)[1].split("?", 1)[0].strip()
                if _EMAIL_RE.fullmatch(mail):
                    found.add(mail.lower())
                continue
            if href.startswith("#") or href.startswith("javascript:"):
                continue
            if href.startswith("/"):
                nxt = url.rstrip("/") + href
            elif href.startswith("http://") or href.startswith("https://"):
                nxt = href
            else:
                nxt = url.rstrip("/") + "/" + href.lstrip("./")

            text = (a.get_text(" ", strip=True) or "").lower()
            if any(k in text for k in ["contact", "mentions", "legal", "privacy", "support", "about"]):
                if same_site(nxt) and nxt not in visited:
                    to_visit.append(nxt)

    return {"pages_visited": sorted(visited), "emails": sorted(found)}

