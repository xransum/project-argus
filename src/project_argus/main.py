"""Main FastAPI application for Project Argus"""

import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncIterator, Dict

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .api import blacklist, dns, domain, geoip, http, ip, jobs, proxy, reputation, ssl, whois
from .db import init_db

logger = logging.getLogger(__name__)

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
STATIC_DIR = Path(__file__).resolve().parent / "static"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


# ---------------------------------------------------------------------------
# Lifespan — initialise SQLite schema on startup
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    await init_db()
    logger.info("Database initialised")
    yield


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Project Argus API",
    version="1.0.0",
    description="Bulk intelligence-gathering API for URLs, Domains, and IPs",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# HTTP/URL checks
app.include_router(http.router, prefix="/api/http")

# Unified (domain + IP) checks
app.include_router(dns.router, prefix="/api/dns")
app.include_router(whois.router, prefix="/api/whois")
app.include_router(geoip.router, prefix="/api/geoip")
app.include_router(reputation.router, prefix="/api/reputation")
app.include_router(blacklist.router, prefix="/api/blacklist")

# SSL — domain-specific
app.include_router(ssl.router, prefix="/api/ssl")

# Domain-specific
app.include_router(domain.router, prefix="/api/domain")

# IP-specific
app.include_router(ip.router, prefix="/api/ip")

# Proxy checker
app.include_router(proxy.router, prefix="/api/proxy")

# Job management
app.include_router(jobs.router, prefix="/api/jobs")


# ---------------------------------------------------------------------------
# Utility routes
# ---------------------------------------------------------------------------


def _ep(path: str, label: str, desc: str, param: str, placeholder: str) -> dict:
    return {
        "path": path,
        "label": label,
        "desc": desc,
        "params": [
            {
                "name": param,
                "label": label,
                "placeholder": placeholder,
                "required": True,
                "default": None,
            }
        ],
    }


_ENDPOINTS = {
    "v1": {
        "HTTP": {
            "status": _ep(
                "/api/http/status",
                "HTTP Status Check",
                "Fetch the HTTP status code returned by each URL.",
                "urls",
                "https://example.com\nhttps://google.com",
            ),
            "headers": _ep(
                "/api/http/headers",
                "HTTP Headers",
                "Retrieve the full set of HTTP response headers for each URL.",
                "urls",
                "https://example.com\nhttps://google.com",
            ),
        },
        "DNS": {
            "lookup": _ep(
                "/api/dns/lookup",
                "DNS Lookup",
                "Perform DNS lookups for domains (forward) or IPs (reverse PTR).",
                "targets",
                "example.com\n1.1.1.1",
            ),
        },
        "WHOIS": {
            "lookup": _ep(
                "/api/whois/lookup",
                "WHOIS Lookup",
                "Fetch WHOIS registration data for domains or IPs.",
                "targets",
                "example.com\n1.1.1.1",
            ),
        },
        "GeoIP": {
            "lookup": _ep(
                "/api/geoip/lookup",
                "GeoIP Location",
                "Resolve the geographic location of domains or IPs.",
                "targets",
                "example.com\n1.1.1.1",
            ),
        },
        "Reputation": {
            "check": _ep(
                "/api/reputation/check",
                "Reputation Score",
                "Check the threat-intelligence reputation score for domains or IPs.",
                "targets",
                "example.com\n1.1.1.1",
            ),
        },
        "Blacklist": {
            "check": _ep(
                "/api/blacklist/check",
                "Blacklist Check",
                "Test whether domains or IPs appear on known blacklists.",
                "targets",
                "example.com\n1.1.1.1",
            ),
        },
        "SSL": {
            "info": _ep(
                "/api/ssl/info",
                "SSL Check",
                "Verify whether each domain has a valid, unexpired SSL certificate.",
                "domains",
                "example.com\ngoogle.com",
            ),
            "certificate": _ep(
                "/api/ssl/certificate",
                "SSL Certificate Details",
                "Retrieve the full SSL certificate chain and details for each domain.",
                "domains",
                "example.com\ngoogle.com",
            ),
        },
        "Domain": {
            "info": _ep(
                "/api/domain/info",
                "Domain Info",
                "Look up registrar, registration date, and expiry for each domain.",
                "domains",
                "example.com\ngoogle.com",
            ),
            "subdomains": _ep(
                "/api/domain/subdomains",
                "Subdomain Enumeration",
                "Discover known subdomains for each domain.",
                "domains",
                "example.com\ngoogle.com",
            ),
            "hosting": _ep(
                "/api/domain/hosting",
                "Hosting & ASN Info",
                "Identify the hosting provider and autonomous system for each domain.",
                "domains",
                "example.com\ngoogle.com",
            ),
        },
        "IP": {
            "info": _ep(
                "/api/ip/info",
                "IP Info",
                "Retrieve host and autonomous system information for each IP address.",
                "ips",
                "1.1.1.1\n8.8.8.8",
            ),
        },
        "Proxy": {
            "check": _ep(
                "/api/proxy/check",
                "Proxy Check",
                "Test whether each proxy is reachable via HTTP, HTTPS, SOCKS4, and SOCKS5.",
                "proxies",
                '{"ip": "1.2.3.4", "port": 8080}',
            ),
        },
    }
}


@app.get("/", response_class=HTMLResponse)
async def index(request: Request) -> HTMLResponse:
    """Serve the API dashboard."""
    return templates.TemplateResponse("index.html", {"request": request, "endpoints": _ENDPOINTS})


@app.get("/api")
async def api_root() -> Dict[str, Any]:
    """JSON API discovery endpoint."""
    return {
        "message": "Project Argus API",
        "version": "1.0.0",
        "documentation": "/docs",
        "endpoints": {
            "http": ["/api/http/status", "/api/http/headers"],
            "dns": ["/api/dns/lookup"],
            "whois": ["/api/whois/lookup"],
            "geoip": ["/api/geoip/lookup"],
            "reputation": ["/api/reputation/check"],
            "blacklist": ["/api/blacklist/check"],
            "ssl": ["/api/ssl/info", "/api/ssl/certificate"],
            "domain": [
                "/api/domain/info",
                "/api/domain/subdomains",
                "/api/domain/hosting",
            ],
            "ip": ["/api/ip/info"],
            "proxy": ["/api/proxy/check"],
        },
        "jobs": {
            "status": "/api/jobs/{job_id}",
            "results": "/api/jobs/{job_id}/results",
            "results_paginated": "/api/jobs/{job_id}/results?nextToken={token}",
        },
    }


@app.get("/health")
async def health_check() -> Dict[str, str]:
    return {"status": "healthy"}
