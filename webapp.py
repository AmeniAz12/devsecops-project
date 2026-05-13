from __future__ import annotations

import secrets
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Form, Request
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from osint_reporter.collect import collect_all
from osint_reporter.exporters import export_pdf, export_txt
from osint_reporter.pentest_passive import passive_web_audit


BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"
REPORTS_DIR = BASE_DIR / "reports"

app = FastAPI(title="Domain OSINT (défensif)")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


def _ensure_dirs() -> None:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)


@app.get("/", response_class=HTMLResponse)
def home(request: Request) -> HTMLResponse:
    _ensure_dirs()
    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "defaults": {
                "timeout": 15,
                "user_agent": "domain-osint/1.0",
            },
        },
    )


@app.post("/scan", response_class=HTMLResponse)
def scan(
    request: Request,
    target: str = Form(...),
    timeout: int = Form(15),
    user_agent: str = Form("domain-osint/1.0"),
    hibp_enabled: str | None = Form(None),
    hibp_api_key: str | None = Form(None),
    hibp_emails: str | None = Form(None),
) -> HTMLResponse:
    _ensure_dirs()

    extra_emails = []
    if hibp_emails:
        extra_emails = [x.strip() for x in hibp_emails.splitlines() if x.strip()]

    report = collect_all(
        target=target,
        timeout_s=max(1, int(timeout)),
        user_agent=user_agent.strip() or "domain-osint/1.0",
        hibp_enabled=bool(hibp_enabled),
        hibp_api_key=hibp_api_key.strip() if hibp_api_key else None,
        hibp_emails=extra_emails,
    )

    token = secrets.token_urlsafe(10)
    safe_name = report["input"]["registrable_domain"].replace(".", "_")
    prefix = f"{safe_name}__{token}"

    txt_path = REPORTS_DIR / f"{prefix}.txt"
    pdf_path = REPORTS_DIR / f"{prefix}.pdf"
    json_path = REPORTS_DIR / f"{prefix}.json"

    export_txt(report, txt_path)
    export_pdf(report, pdf_path)
    json_path.write_text(__import__("json").dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    return templates.TemplateResponse(
        request,
        "result.html",
        {
            "report": report,
            "files": {
                "txt": txt_path.name,
                "pdf": pdf_path.name,
                "json": json_path.name,
            },
        },
    )


@app.get("/pentest", response_class=HTMLResponse)
def pentest_page(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "pentest.html",
        {
            "audit": None,
            "defaults": {
                "timeout": 15,
                "user_agent": "soc-passive-audit/1.0",
                "target": "https://example.com",
            },
        },
    )


@app.post("/pentest/check", response_class=HTMLResponse)
def pentest_check(
    request: Request,
    target: str = Form(...),
    timeout: int = Form(15),
    user_agent: str = Form("soc-passive-audit/1.0"),
) -> HTMLResponse:
    audit = passive_web_audit(
        target.strip(),
        float(max(1, min(120, int(timeout)))),
        user_agent.strip() or "soc-passive-audit/1.0",
    )
    return templates.TemplateResponse(
        request,
        "pentest.html",
        {
            "audit": audit,
            "defaults": {
                "timeout": max(1, min(120, int(timeout))),
                "user_agent": user_agent.strip() or "soc-passive-audit/1.0",
                "target": target.strip(),
            },
        },
    )


@app.get("/download/{filename}")
def download(request: Request, filename: str) -> Any:
    _ensure_dirs()
    path = (REPORTS_DIR / filename).resolve()
    if REPORTS_DIR.resolve() not in path.parents:
        return RedirectResponse("/", status_code=303)
    if not path.exists():
        return RedirectResponse("/", status_code=303)
    return FileResponse(path)

