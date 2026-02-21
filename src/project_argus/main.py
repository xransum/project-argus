"""Main FastAPI application for Project Argus"""

from collections import defaultdict
from typing import Any, Dict, List, Tuple

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .api.v1 import domain, ip, url

app = FastAPI(
    title="Project Argus API",
    version="1.0.0",
    description="API for URL, Domain, and IP intelligence gathering",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# V1 Routes
app.include_router(url.router, prefix="/api/v1/url", tags=["V1 - URL"])
app.include_router(domain.router, prefix="/api/v1/domain", tags=["V1 - Domain"])
app.include_router(ip.router, prefix="/api/v1/ip", tags=["V1 - IP"])


def get_api_endpoints() -> Tuple[Dict[str, Dict[str, Dict[str, str]]], List[str]]:
    """Dynamically extract all API endpoints organized by version and category"""
    endpoints: Dict[str, Dict[str, Dict[str, str]]] = defaultdict(lambda: defaultdict(dict))
    api_versions = set()

    for route in app.routes:
        # Skip non-API routes
        if not hasattr(route, "path") or not route.path.startswith("/api/"):
            continue

        # Parse the path: /api/{version}/{category}/{endpoint}
        parts = route.path.split("/")
        if len(parts) >= 5:
            version = parts[2]  # e.g., 'v1'
            category = parts[3]  # e.g., 'url', 'domain', 'ip'
            endpoint = parts[4]  # e.g., 'status', 'headers'

            api_versions.add(version)

            # Store the full path
            if endpoint not in endpoints[version][category]:
                endpoints[version][category][endpoint] = route.path

    return dict(endpoints), sorted(api_versions)


@app.get("/")
async def root() -> Dict[str, Any]:
    endpoints, api_versions = get_api_endpoints()

    return {
        "message": "Project Argus API",
        "version": "1.0.0",
        "documentation": "/docs",
        "api_versions": api_versions,
        "endpoints": endpoints,
    }


@app.get("/health")
async def health_check() -> Dict[str, str]:
    return {"status": "healthy"}
