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

from .api import domain, ip, jobs, url
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

app.include_router(url.router, prefix="/api/url")
app.include_router(domain.router, prefix="/api/domain")
app.include_router(ip.router, prefix="/api/ip")
app.include_router(jobs.router, prefix="/jobs")


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
        "URL": {
            "status": _ep(
                "/api/url/status",
                "HTTP Status Check",
                "Fetch the HTTP status code returned by each URL.",
                "urls",
                "https://example.com\nhttps://google.com",
            ),
            "headers": _ep(
                "/api/url/headers",
                "HTTP Headers",
                "Retrieve the full set of HTTP response headers for each URL.",
                "urls",
                "https://example.com\nhttps://google.com",
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
            "ssl": _ep(
                "/api/domain/ssl",
                "SSL Check",
                "Verify whether each domain has a valid, unexpired SSL certificate.",
                "domains",
                "example.com\ngoogle.com",
            ),
            "dns": _ep(
                "/api/domain/dns",
                "DNS Records",
                "Retrieve DNS records (A, MX, TXT, etc.) for each domain.",
                "domains",
                "example.com\ngoogle.com",
            ),
            "whois": _ep(
                "/api/domain/whois",
                "WHOIS Lookup",
                "Fetch raw WHOIS registration data for each domain.",
                "domains",
                "example.com\ngoogle.com",
            ),
            "geoip": _ep(
                "/api/domain/geoip",
                "GeoIP Location",
                "Resolve the geographic location of the server behind each domain.",
                "domains",
                "example.com\ngoogle.com",
            ),
            "reputation": _ep(
                "/api/domain/reputation",
                "Reputation Score",
                "Check the threat-intelligence reputation score for each domain.",
                "domains",
                "example.com\ngoogle.com",
            ),
            "blacklist": _ep(
                "/api/domain/blacklist",
                "Blacklist Check",
                "Test whether each domain appears on known blacklists.",
                "domains",
                "example.com\ngoogle.com",
            ),
            "ssl-certificate": _ep(
                "/api/domain/ssl-certificate",
                "SSL Certificate Details",
                "Retrieve the full SSL certificate chain and details for each domain.",
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
            "dns": _ep(
                "/api/ip/dns",
                "Reverse DNS",
                "Perform a reverse DNS (PTR record) lookup for each IP address.",
                "ips",
                "1.1.1.1\n8.8.8.8",
            ),
            "geoip": _ep(
                "/api/ip/geoip",
                "GeoIP Location",
                "Resolve the geographic location associated with each IP address.",
                "ips",
                "1.1.1.1\n8.8.8.8",
            ),
            "reputation": _ep(
                "/api/ip/reputation",
                "Reputation Score",
                "Check the threat-intelligence reputation score for each IP address.",
                "ips",
                "1.1.1.1\n8.8.8.8",
            ),
            "blacklist": _ep(
                "/api/ip/blacklist",
                "Blacklist Check",
                "Test whether each IP address appears on known blacklists.",
                "ips",
                "1.1.1.1\n8.8.8.8",
            ),
            "whois": _ep(
                "/api/ip/whois",
                "WHOIS Lookup",
                "Fetch raw WHOIS registration data for each IP address.",
                "ips",
                "1.1.1.1\n8.8.8.8",
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
            "url": ["/api/url/status", "/api/url/headers"],
            "domain": [
                "/api/domain/info",
                "/api/domain/ssl",
                "/api/domain/dns",
                "/api/domain/whois",
                "/api/domain/geoip",
                "/api/domain/reputation",
                "/api/domain/blacklist",
                "/api/domain/ssl-certificate",
                "/api/domain/subdomains",
                "/api/domain/hosting",
            ],
            "ip": [
                "/api/ip/info",
                "/api/ip/dns",
                "/api/ip/geoip",
                "/api/ip/reputation",
                "/api/ip/blacklist",
                "/api/ip/whois",
            ],
        },
        "jobs": {
            "status": "/jobs/{job_id}/status",
            "results": "/jobs/{job_id}/results",
            "results_paginated": "/jobs/{job_id}/results?nextToken={token}",
        },
    }


@app.get("/health")
async def health_check() -> Dict[str, str]:
    return {"status": "healthy"}
