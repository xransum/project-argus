"""Main FastAPI application for the Lambda-backed web UI."""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .api import domain, http, ip, jobs, proxy

logger = logging.getLogger(__name__)

_debug = os.getenv("DEBUG", "").lower() in ("1", "true", "yes")
logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s %(levelname)-8s %(name)s - %(message)s",
    datefmt="%H:%M:%S",
)
logging.getLogger("project_argus").setLevel(logging.DEBUG if _debug else logging.INFO)

PACKAGE_ROOT = Path(__file__).resolve().parent.parent
TEMPLATES_DIR = PACKAGE_ROOT / "templates"
STATIC_DIR = PACKAGE_ROOT / "static"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

app = FastAPI(
    title="Project Argus API",
    version="2.0.0",
    description="Bulk intelligence-gathering API for URLs, domains, IPs, and proxies",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

app.include_router(http.router, prefix="/api/http")
app.include_router(domain.router, prefix="/api/domain")
app.include_router(ip.router, prefix="/api/ip")
app.include_router(proxy.router, prefix="/api/proxy")
app.include_router(jobs.router, prefix="/api/jobs")


def _ep(path: str, label: str, desc: str, param: str, placeholder: str) -> dict:
    return {
        "path": path,
        "label": label,
        "desc": desc,
        "params": [{"name": param, "placeholder": placeholder}],
    }


_ENDPOINTS = {
    "v2": {
        "HTTP": {
            "status": _ep(
                "/api/http/status",
                "HTTP Status Check",
                "Fetch the final HTTP status and redirect chain for each URL.",
                "urls",
                "https://example.com\nhttps://google.com",
            ),
            "headers": _ep(
                "/api/http/headers",
                "HTTP Headers",
                "Fetch response headers for each URL.",
                "urls",
                "https://example.com\nhttps://google.com",
            ),
        },
        "Domain": {
            "info": _ep(
                "/api/domain/info",
                "Domain Info",
                "Registrar and lifecycle details.",
                "domains",
                "example.com\nopenai.com",
            ),
            "dns": _ep(
                "/api/domain/dns",
                "DNS",
                "Lookup DNS records for each domain.",
                "domains",
                "example.com\nopenai.com",
            ),
            "whois": _ep(
                "/api/domain/whois",
                "WHOIS",
                "Fetch WHOIS details for each domain.",
                "domains",
                "example.com\nopenai.com",
            ),
            "geoip": _ep(
                "/api/domain/geoip",
                "GeoIP",
                "Resolve GeoIP details for each domain.",
                "domains",
                "example.com\nopenai.com",
            ),
            "reputation": _ep(
                "/api/domain/reputation",
                "Reputation",
                "Check reputation for each domain.",
                "domains",
                "example.com\nopenai.com",
            ),
            "blacklist": _ep(
                "/api/domain/blacklist",
                "Blacklist",
                "Check blacklist status for each domain.",
                "domains",
                "example.com\nopenai.com",
            ),
            "ssl": _ep(
                "/api/domain/ssl",
                "SSL",
                "Check certificate validity for each domain.",
                "domains",
                "example.com\nopenai.com",
            ),
            "ssl-certificate": _ep(
                "/api/domain/ssl-certificate",
                "SSL Certificate",
                "Fetch certificate details for each domain.",
                "domains",
                "example.com\nopenai.com",
            ),
            "subdomains": _ep(
                "/api/domain/subdomains",
                "Subdomains",
                "Enumerate common subdomains.",
                "domains",
                "example.com\nopenai.com",
            ),
            "hosting": _ep(
                "/api/domain/hosting",
                "Hosting",
                "Fetch IP and hosting metadata.",
                "domains",
                "example.com\nopenai.com",
            ),
        },
        "IP": {
            "info": _ep(
                "/api/ip/info", "IP Info", "Resolve IP metadata.", "ips", "1.1.1.1\n8.8.8.8"
            ),
            "dns": _ep(
                "/api/ip/dns",
                "Reverse DNS",
                "Lookup reverse DNS for each IP.",
                "ips",
                "1.1.1.1\n8.8.8.8",
            ),
            "whois": _ep(
                "/api/ip/whois", "WHOIS", "Fetch IP WHOIS details.", "ips", "1.1.1.1\n8.8.8.8"
            ),
            "geoip": _ep(
                "/api/ip/geoip",
                "GeoIP",
                "Resolve GeoIP data for each IP.",
                "ips",
                "1.1.1.1\n8.8.8.8",
            ),
            "reputation": _ep(
                "/api/ip/reputation",
                "Reputation",
                "Check reputation for each IP.",
                "ips",
                "1.1.1.1\n8.8.8.8",
            ),
            "blacklist": _ep(
                "/api/ip/blacklist",
                "Blacklist",
                "Check blacklist status for each IP.",
                "ips",
                "1.1.1.1\n8.8.8.8",
            ),
        },
        "Proxy": {
            "check": _ep(
                "/api/proxy/check",
                "Proxy Check",
                "Probe HTTP, HTTPS, SOCKS4, and SOCKS5 support.",
                "proxies",
                "203.0.113.1:8080\n203.0.113.2:3128",
            ),
        },
    }
}


@app.get("/", response_class=HTMLResponse)
async def index(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("index.html", {"request": request, "endpoints": _ENDPOINTS})


@app.get("/api")
async def api_root() -> dict[str, Any]:
    return {
        "message": "Project Argus API",
        "version": "2.0.0",
        "documentation": "/docs",
        "endpoints": {
            "http": ["/api/http/status", "/api/http/headers"],
            "domain": [
                "/api/domain/info",
                "/api/domain/dns",
                "/api/domain/whois",
                "/api/domain/geoip",
                "/api/domain/reputation",
                "/api/domain/blacklist",
                "/api/domain/ssl",
                "/api/domain/ssl-certificate",
                "/api/domain/subdomains",
                "/api/domain/hosting",
            ],
            "ip": [
                "/api/ip/info",
                "/api/ip/dns",
                "/api/ip/whois",
                "/api/ip/geoip",
                "/api/ip/reputation",
                "/api/ip/blacklist",
            ],
            "proxy": ["/api/proxy/check"],
        },
        "jobs": {
            "status": "/api/jobs/{job_id}",
            "results": "/api/jobs/{job_id}/results",
        },
    }


@app.get("/health")
async def health_check() -> dict[str, str]:
    return {"status": "healthy"}
