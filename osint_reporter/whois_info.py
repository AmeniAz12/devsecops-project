from __future__ import annotations

from typing import Any

import whois


def collect_whois(registrable_domain: str) -> dict[str, Any]:
    try:
        w = whois.whois(registrable_domain)
        # whois lib returns a dict-like object with mixed types
        data = dict(w)
        # normalize a few common fields to str/list[str]
        for k, v in list(data.items()):
            if v is None:
                continue
            if isinstance(v, (str, int, float, bool)):
                continue
            if isinstance(v, (list, tuple, set)):
                data[k] = [str(x) for x in v]
            else:
                data[k] = str(v)
        return {"error": None, "whois": data}
    except Exception as e:
        return {"error": str(e), "whois": {}}

