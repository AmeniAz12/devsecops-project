from __future__ import annotations

from typing import Any

import builtwith


def collect_technologies(url: str) -> dict[str, Any]:
    """
    Heuristique via builtwith.
    Note: dépend de l'accessibilité réseau et peut échouer.
    """
    try:
        tech = builtwith.parse(url)
        # builtwith returns dict[str, list[str]]
        return {"error": None, "technologies": tech}
    except Exception as e:
        return {"error": str(e), "technologies": {}}

