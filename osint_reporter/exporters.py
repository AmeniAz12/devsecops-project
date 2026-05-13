from __future__ import annotations

from pathlib import Path
from typing import Any

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


def _format_dns(rrs: dict[str, list[str]]) -> str:
    lines: list[str] = []
    for k in ["A", "MX", "NS", "TXT"]:
        vals = rrs.get(k) or []
        lines.append(f"{k}:")
        if vals:
            for v in vals:
                lines.append(f"  - {v}")
        else:
            lines.append("  - (vide)")
    return "\n".join(lines)


def _format_kv(obj: Any, indent: int = 0) -> list[str]:
    pad = " " * indent
    if isinstance(obj, dict):
        out: list[str] = []
        for k in sorted(obj.keys(), key=lambda x: str(x)):
            v = obj[k]
            if isinstance(v, (dict, list)):
                out.append(f"{pad}{k}:")
                out.extend(_format_kv(v, indent=indent + 2))
            else:
                out.append(f"{pad}{k}: {v}")
        return out
    if isinstance(obj, list):
        out = []
        for v in obj:
            if isinstance(v, (dict, list)):
                out.append(f"{pad}-")
                out.extend(_format_kv(v, indent=indent + 2))
            else:
                out.append(f"{pad}- {v}")
        return out
    return [f"{pad}{obj}"]


def export_txt(report: dict[str, Any], out_path: Path) -> None:
    inp = report["input"]
    lines: list[str] = []
    lines.append("=== Rapport OSINT (défensif) ===")
    lines.append(f"Généré le (UTC): {report.get('generated_at')}")
    lines.append("")
    lines.append("== Cible ==")
    lines.append(f"Entrée: {inp.get('raw')}")
    lines.append(f"Hostname: {inp.get('hostname')}")
    lines.append(f"Domaine principal: {inp.get('registrable_domain')}")
    lines.append(f"URL base: {inp.get('base_url')}")
    lines.append("")

    lines.append("== DNS ==")
    lines.append(_format_dns(report.get("dns") or {}))
    lines.append("")

    lines.append("== Sous-domaines publics (CT) ==")
    sd = report.get("subdomains") or {}
    if sd.get("error"):
        lines.append(f"Erreur: {sd.get('error')}")
    for s in sd.get("subdomains") or []:
        lines.append(f"- {s}")
    if not (sd.get("subdomains") or []):
        lines.append("- (aucun trouvé)")
    lines.append("")

    lines.append("== E-mails (publics) ==")
    em = report.get("emails") or {}
    for e in em.get("emails") or []:
        lines.append(f"- {e}")
    if not (em.get("emails") or []):
        lines.append("- (aucun trouvé)")
    lines.append("")

    lines.append("== Technologies (heuristique) ==")
    tech = report.get("technologies") or {}
    if tech.get("error"):
        lines.append(f"Erreur: {tech.get('error')}")
    tdict = tech.get("technologies") or {}
    if tdict:
        lines.extend(_format_kv(tdict, indent=0))
    else:
        lines.append("(vide)")
    lines.append("")

    lines.append("== Compromission (HIBP) ==")
    hibp = report.get("hibp") or {}
    if not hibp.get("enabled"):
        lines.append("(désactivé)")
    else:
        if hibp.get("error"):
            lines.append(f"Erreur: {hibp.get('error')}")
        res = hibp.get("results") or {}
        if not res:
            lines.append("(aucun e-mail à vérifier)")
        for email, entry in res.items():
            lines.append(f"- {email}")
            err = (entry or {}).get("error")
            if err:
                lines.append(f"  - erreur: {err}")
                continue
            breaches = (entry or {}).get("breaches") or []
            if not breaches:
                lines.append("  - aucune breach trouvée")
            else:
                for b in breaches:
                    title = (b or {}).get("Title") or (b or {}).get("Name") or "Unknown"
                    bdate = (b or {}).get("BreachDate") or "?"
                    lines.append(f"  - {title} ({bdate})")
    lines.append("")

    lines.append("== WHOIS ==")
    wh = report.get("whois") or {}
    if wh.get("error"):
        lines.append(f"Erreur: {wh.get('error')}")
    wdict = wh.get("whois") or {}
    if wdict:
        lines.extend(_format_kv(wdict, indent=0))
    else:
        lines.append("(vide)")
    lines.append("")

    lines.append("== Limitations ==")
    for lim in report.get("limitations") or []:
        lines.append(f"- {lim}")
    lines.append("")

    out_path.write_text("\n".join(lines), encoding="utf-8")


def export_pdf(report: dict[str, Any], out_path: Path) -> None:
    # PDF on white background with brand header + tables.
    width, height = A4

    # Best-effort UTF-8: try to register a common Windows font if present.
    # If it fails, ReportLab falls back; some accents may render poorly.
    for font_path in [
        r"C:\Windows\Fonts\consola.ttf",
        r"C:\Windows\Fonts\arial.ttf",
    ]:
        try:
            pdfmetrics.registerFont(TTFont("CustomFont", font_path))
            break
        except Exception:
            continue

    font_name = "CustomFont" if "CustomFont" in pdfmetrics.getRegisteredFontNames() else "Helvetica"

    theme_panel = colors.Color(0.96, 0.98, 1.0)  # very light blue
    theme_text = colors.Color(0.07, 0.11, 0.20)  # slate-ish
    theme_muted = colors.Color(0.32, 0.41, 0.55)
    theme_accent = colors.Color(0.14, 0.38, 0.95)  # blue

    styles = getSampleStyleSheet()
    normal = styles["BodyText"]
    normal.fontName = font_name
    normal.fontSize = 9
    normal.leading = 12
    title_style = styles["Title"]
    title_style.fontName = font_name
    title_style.fontSize = 16
    title_style.textColor = theme_text

    def p(txt: str) -> Paragraph:
        return Paragraph(txt, normal)

    doc = SimpleDocTemplate(
        str(out_path),
        pagesize=A4,
        leftMargin=2 * cm,
        rightMargin=2 * cm,
        topMargin=2.2 * cm,
        bottomMargin=2 * cm,
        title="Domain OSINT Report",
    )

    inp = report.get("input") or {}
    domain = inp.get("registrable_domain") or ""
    generated = report.get("generated_at") or ""

    def draw_header(canv: canvas.Canvas, doc_: Any) -> None:
        canv.saveState()
        w, h = A4
        left = doc_.leftMargin
        right = w - doc_.rightMargin

        # panel
        canv.setFillColor(theme_panel)
        canv.roundRect(left, h - 1.7 * cm, right - left, 1.1 * cm, 10, fill=1, stroke=0)

        # accent line
        canv.setStrokeColor(theme_accent)
        canv.setLineWidth(2.5)
        canv.line(left, h - 1.7 * cm, right, h - 1.7 * cm)

        # text
        canv.setFillColor(theme_text)
        canv.setFont(font_name, 12)
        canv.drawString(left + 0.3 * cm, h - 1.3 * cm, "Domain OSINT — Rapport")
        canv.setFillColor(theme_muted)
        canv.setFont(font_name, 9)
        canv.drawRightString(right - 0.3 * cm, h - 1.3 * cm, f"Page {canv.getPageNumber()}")
        canv.drawString(left + 0.3 * cm, h - 1.55 * cm, f"{domain}  •  {generated}")
        canv.restoreState()

    elements: list[Any] = []
    elements.append(Spacer(1, 0.2 * cm))

    # Summary table
    summary_rows = [
        ["Champ", "Valeur"],
        ["Entrée", str(inp.get("raw") or "")],
        ["Hostname", str(inp.get("hostname") or "")],
        ["Domaine principal", str(inp.get("registrable_domain") or "")],
        ["URL base", str(inp.get("base_url") or "")],
    ]
    summary = Table(summary_rows, colWidths=[4.2 * cm, 11.8 * cm])
    summary.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), theme_panel),
                ("TEXTCOLOR", (0, 0), (-1, 0), theme_text),
                ("FONTNAME", (0, 0), (-1, -1), font_name),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.Color(0.86, 0.89, 0.93)),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.Color(0.98, 0.99, 1.0)]),
            ]
        )
    )
    elements.append(p("<b>Résumé</b>"))
    elements.append(Spacer(1, 0.15 * cm))
    elements.append(summary)
    elements.append(Spacer(1, 0.45 * cm))

    # DNS table
    dns = report.get("dns") or {}
    dns_rows = [["Type", "Valeurs"]]
    for k in ["A", "MX", "NS", "TXT"]:
        vals = dns.get(k) or []
        dns_rows.append([k, "<br/>".join(vals) if vals else "(vide)"])
    dns_tbl = Table(dns_rows, colWidths=[2.2 * cm, 13.8 * cm])
    dns_tbl.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), theme_panel),
                ("TEXTCOLOR", (0, 0), (-1, 0), theme_text),
                ("FONTNAME", (0, 0), (-1, -1), font_name),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.Color(0.86, 0.89, 0.93)),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    elements.append(p("<b>DNS</b>"))
    elements.append(Spacer(1, 0.15 * cm))
    elements.append(dns_tbl)
    elements.append(Spacer(1, 0.45 * cm))

    # Subdomains / Emails / HIBP / Tech / WHOIS tables (compact)
    subs = (report.get("subdomains") or {}).get("subdomains") or []
    elements.append(p("<b>Sous-domaines (publics)</b>"))
    elements.append(Spacer(1, 0.15 * cm))
    subs_tbl = Table([["Total", str(len(subs))], ["Échantillon", "<br/>".join(subs[:30]) if subs else "(aucun)"]], colWidths=[3.2 * cm, 12.8 * cm])
    subs_tbl.setStyle(TableStyle([("FONTNAME", (0, 0), (-1, -1), font_name), ("FONTSIZE", (0, 0), (-1, -1), 9), ("GRID", (0, 0), (-1, -1), 0.4, colors.Color(0.86, 0.89, 0.93)), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    elements.append(subs_tbl)
    elements.append(Spacer(1, 0.35 * cm))

    emails = (report.get("emails") or {}).get("emails") or []
    elements.append(p("<b>E-mails (publics)</b>"))
    elements.append(Spacer(1, 0.15 * cm))
    emails_tbl = Table([["Total", str(len(emails))], ["Liste", "<br/>".join(emails) if emails else "(aucun)"]], colWidths=[3.2 * cm, 12.8 * cm])
    emails_tbl.setStyle(TableStyle([("FONTNAME", (0, 0), (-1, -1), font_name), ("FONTSIZE", (0, 0), (-1, -1), 9), ("GRID", (0, 0), (-1, -1), 0.4, colors.Color(0.86, 0.89, 0.93)), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    elements.append(emails_tbl)
    elements.append(Spacer(1, 0.35 * cm))

    hibp = report.get("hibp") or {}
    hibp_rows = [["E-mail", "Breaches (titre • date) / Erreur"]]
    if not hibp.get("enabled"):
        hibp_rows.append(["(désactivé)", ""])
    else:
        if hibp.get("error"):
            hibp_rows.append(["Erreur", str(hibp.get("error"))])
        res = hibp.get("results") or {}
        if not res:
            hibp_rows.append(["(aucun)", ""])
        for email, entry in res.items():
            err = (entry or {}).get("error")
            if err:
                hibp_rows.append([email, f"erreur: {err}"])
            else:
                breaches = (entry or {}).get("breaches") or []
                if not breaches:
                    hibp_rows.append([email, "aucune breach"])
                else:
                    hibp_rows.append([email, "<br/>".join([f"{(b.get('Title') or b.get('Name') or 'Unknown')} • {b.get('BreachDate') or '?'}" for b in breaches[:20]])])
    hibp_tbl = Table(hibp_rows, colWidths=[5.0 * cm, 11.0 * cm])
    hibp_tbl.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), theme_panel), ("TEXTCOLOR", (0, 0), (-1, 0), theme_text), ("FONTNAME", (0, 0), (-1, -1), font_name), ("FONTSIZE", (0, 0), (-1, -1), 9), ("GRID", (0, 0), (-1, -1), 0.4, colors.Color(0.86, 0.89, 0.93)), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    elements.append(p("<b>Compromission (HIBP)</b>"))
    elements.append(Spacer(1, 0.15 * cm))
    elements.append(hibp_tbl)
    elements.append(Spacer(1, 0.45 * cm))

    tech = report.get("technologies") or {}
    tdict = tech.get("technologies") or {}
    tech_rows = [["Catégorie", "Valeurs"]]
    if tech.get("error"):
        tech_rows.append(["Erreur", str(tech.get("error"))])
    if not tdict:
        tech_rows.append(["(vide)", ""])
    else:
        for cat, items in tdict.items():
            tech_rows.append([str(cat), "<br/>".join([str(x) for x in (items or [])])])
    tech_tbl = Table(tech_rows, colWidths=[4.5 * cm, 11.5 * cm])
    tech_tbl.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), theme_panel), ("TEXTCOLOR", (0, 0), (-1, 0), theme_text), ("FONTNAME", (0, 0), (-1, -1), font_name), ("FONTSIZE", (0, 0), (-1, -1), 9), ("GRID", (0, 0), (-1, -1), 0.4, colors.Color(0.86, 0.89, 0.93)), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    elements.append(p("<b>Technologies</b>"))
    elements.append(Spacer(1, 0.15 * cm))
    elements.append(tech_tbl)
    elements.append(Spacer(1, 0.45 * cm))

    who = report.get("whois") or {}
    wdict = who.get("whois") or {}
    who_rows = [["Champ", "Valeur"]]
    if who.get("error"):
        who_rows.append(["Erreur", str(who.get("error"))])
    if not wdict:
        who_rows.append(["(vide)", ""])
    else:
        for k in ["registrar", "domain_name", "creation_date", "expiration_date", "updated_date", "name_servers", "status", "whois_server"]:
            if k in wdict and wdict.get(k) is not None:
                who_rows.append([k, str(wdict.get(k))])
    who_tbl = Table(who_rows, colWidths=[4.5 * cm, 11.5 * cm])
    who_tbl.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), theme_panel), ("TEXTCOLOR", (0, 0), (-1, 0), theme_text), ("FONTNAME", (0, 0), (-1, -1), font_name), ("FONTSIZE", (0, 0), (-1, -1), 9), ("GRID", (0, 0), (-1, -1), 0.4, colors.Color(0.86, 0.89, 0.93)), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    elements.append(p("<b>WHOIS (champs clés)</b>"))
    elements.append(Spacer(1, 0.15 * cm))
    elements.append(who_tbl)

    doc.build(elements, onFirstPage=draw_header, onLaterPages=draw_header)

