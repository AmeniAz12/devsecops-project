from __future__ import annotations

import argparse
import json
from pathlib import Path

from osint_reporter.collect import collect_all
from osint_reporter.exporters import export_pdf, export_txt


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="domain-osint",
        description="Collecte OSINT défensive pour une URL/un domaine (rapport TXT/PDF).",
    )
    p.add_argument("--target", required=True, help="URL ou nom de domaine (ex: https://example.com)")
    p.add_argument("--out-dir", default="reports", help="Dossier de sortie (défaut: reports)")
    p.add_argument("--timeout", type=int, default=15, help="Timeout réseau en secondes (défaut: 15)")
    p.add_argument("--user-agent", default="domain-osint/1.0", help="User-Agent HTTP")
    p.add_argument(
        "--hibp-api-key",
        default=None,
        help="Clé API HaveIBeenPwned (sinon variable d'env HIBP_API_KEY).",
    )
    p.add_argument(
        "--hibp-email",
        action="append",
        default=[],
        help="E-mail(s) à vérifier via HIBP (peut être répété).",
    )
    p.add_argument(
        "--hibp",
        action="store_true",
        help="Active la vérification de compromission HIBP (nécessite une clé API).",
    )
    p.add_argument("--json", action="store_true", help="Sauver aussi un JSON brut")
    return p


def main() -> int:
    args = build_parser().parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    report = collect_all(
        target=args.target,
        timeout_s=args.timeout,
        user_agent=args.user_agent,
        hibp_enabled=args.hibp,
        hibp_api_key=args.hibp_api_key,
        hibp_emails=args.hibp_email,
    )

    safe_name = report["input"]["registrable_domain"].replace(".", "_")
    txt_path = out_dir / f"{safe_name}.txt"
    pdf_path = out_dir / f"{safe_name}.pdf"

    export_txt(report, txt_path)
    export_pdf(report, pdf_path)

    if args.json:
        json_path = out_dir / f"{safe_name}.json"
        json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"OK: {txt_path}")
    print(f"OK: {pdf_path}")
    if args.json:
        print(f"OK: {json_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
