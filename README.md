# Project Argus

A bulk intelligence-gathering API for analyzing URLs, domains, and IP addresses. Built with FastAPI (async), backed by a SQLite job queue, and served with a jQuery UI dark-theme dashboard.

## Features

### URL Analysis
- **HTTP Status Check**: Verify reachability, response time, and full redirect chain
- **Redirect Chain Tracking**: Follows HTTP 3xx redirects, detects loops and cap limits, and identifies client-side redirects (`<meta http-equiv="refresh">` and `window.location` JS patterns)
- **Headers Inspection**: Fetch full HTTP response headers

### Domain Intelligence
- **Domain Info**: Registrar, creation/expiration dates
- **SSL Check**: Certificate validity and expiry
- **DNS Records**: A, AAAA, MX, TXT, CNAME, NS
- **WHOIS Lookup**: Raw registration data
- **GeoIP**: Geographic location of the domain's server
- **Reputation**: Threat-intelligence reputation score
- **Blacklist Check**: Known blacklist status
- **SSL Certificate Details**: Full certificate chain
- **Subdomain Enumeration**: Known subdomains
- **Hosting & ASN Info**: Hosting provider and autonomous system

### IP Address Analysis
- **IP Info**: Hostname, ASN, organization, ISP
- **Reverse DNS**: PTR record lookup
- **GeoIP**: Geographic location
- **Reputation**: Threat-intelligence reputation score
- **Blacklist Check**: DNSBL and threat feed status
- **WHOIS Lookup**: Network registration data

### Async Job System
All bulk endpoints enqueue a job and return immediately. Clients poll for status and paginated results.

## Installation

### Prerequisites

- Python 3.8+
- Node.js + npm (for frontend vendor assets)
- [uv](https://github.com/astral-sh/uv) package manager

### Install uv

```bash
# macOS/Linux
curl -LsSf https://astral.sh/uv/install.sh | sh

# Windows
powershell -c "irm https://astral.sh/uv/install.ps1 | iex"
```

### Clone and build

```bash
git clone https://github.com/yourusername/project-argus.git
cd project-argus

# Install Python deps + build frontend vendor assets
./scripts/build.sh
```

`scripts/build.sh` runs `npm install` and copies jQuery and jQuery UI (dark-hive theme) into `src/project_argus/static/vendor/`.

## Running the API

### Development (auto-reload)

```bash
./scripts/dev.sh
```

### Production

```bash
./scripts/start.sh
```

### Manual

```bash
uv run uvicorn src.project_argus.main:app --host 0.0.0.0 --port 8000
```

The app will be available at:

| URL | Description |
|-----|-------------|
| `http://localhost:8000/` | Dashboard UI |
| `http://localhost:8000/docs` | Swagger / interactive docs |
| `http://localhost:8000/redoc` | ReDoc |
| `http://localhost:8000/api` | JSON endpoint discovery |

## API Endpoints

All bulk endpoints accept **POST** with a JSON body. Responses are job references — poll `/jobs/{job_id}/status` and `/jobs/{job_id}/results` for output.

### URL

```
POST /api/url/status       { "urls": ["https://example.com", ...] }
POST /api/url/headers      { "urls": ["https://example.com", ...] }
```

### Domain

```
POST /api/domain/info              { "domains": ["example.com", ...] }
POST /api/domain/ssl               { "domains": [...] }
POST /api/domain/dns               { "domains": [...] }
POST /api/domain/whois             { "domains": [...] }
POST /api/domain/geoip             { "domains": [...] }
POST /api/domain/reputation        { "domains": [...] }
POST /api/domain/blacklist         { "domains": [...] }
POST /api/domain/ssl-certificate   { "domains": [...] }
POST /api/domain/subdomains        { "domains": [...] }
POST /api/domain/hosting           { "domains": [...] }
```

### IP

```
POST /api/ip/info         { "ips": ["1.1.1.1", ...] }
POST /api/ip/dns          { "ips": [...] }
POST /api/ip/geoip        { "ips": [...] }
POST /api/ip/reputation   { "ips": [...] }
POST /api/ip/blacklist    { "ips": [...] }
POST /api/ip/whois        { "ips": [...] }
```

### Jobs

```
GET /jobs/{job_id}/status
GET /jobs/{job_id}/results
GET /jobs/{job_id}/results?nextToken={token}   # paginated
```

### Utility

```
GET /         # Dashboard UI
GET /api      # JSON endpoint discovery
GET /health   # Health check
```

## Usage Examples

### cURL

```bash
# Submit a bulk URL status job
curl -s -X POST http://localhost:8000/api/url/status \
  -H "Content-Type: application/json" \
  -d '{"urls": ["https://example.com", "https://google.com"]}'

# Poll for results (replace <job_id>)
curl -s http://localhost:8000/jobs/<job_id>/status
curl -s http://localhost:8000/jobs/<job_id>/results
```

### Python

```python
import asyncio
import httpx

async def main():
    async with httpx.AsyncClient() as client:
        # Submit job
        r = await client.post(
            "http://localhost:8000/api/url/status",
            json={"urls": ["https://example.com"]},
        )
        job_id = r.json()["job_id"]

        # Poll until done
        while True:
            status = await client.get(f"http://localhost:8000/jobs/{job_id}/status")
            if status.json()["status"] in ("completed", "failed"):
                break
            await asyncio.sleep(1)

        results = await client.get(f"http://localhost:8000/jobs/{job_id}/results")
        print(results.json())

asyncio.run(main())
```

## URL Status Response

`/api/url/status` results include full redirect chain details:

```json
{
  "url": "http://example.com",
  "final_url": "https://example.com/landing",
  "status_code": 200,
  "is_reachable": true,
  "response_time_ms": 143.5,
  "redirect_count": 2,
  "redirect_loop": false,
  "redirect_limit_reached": false,
  "redirect_chain": [
    { "url": "http://example.com", "status_code": 301, "location": "https://example.com", "redirect_type": "http" },
    { "url": "https://example.com", "status_code": 200, "location": null, "redirect_type": "meta-refresh" }
  ]
}
```

`redirect_type` values: `"http"` (3xx), `"meta-refresh"` (`<meta http-equiv="refresh">`), `"js-location"` (`window.location` / `location.href`).

## Testing

```bash
# Run all tests
./scripts/test.sh

# Or directly
uv run pytest

# Specific file
uv run pytest tests/unit/test_url_service.py -v
```

### Test structure

```
tests/
├── unit/
│   ├── test_url_service.py     # redirect chain, loop/limit detection
│   ├── test_domain_service.py
│   └── utils/
│       └── test_validators.py
└── functional/
    ├── test_url_endpoints.py
    ├── test_domain_endpoints.py
    └── test_ip_endpoints.py
```

## Project Structure

```
project-argus/
├── package.json                          # npm deps (jQuery, jQuery UI)
├── scripts/
│   ├── build.sh                          # npm install + vendor copy
│   ├── dev.sh                            # build + uvicorn --reload
│   ├── start.sh                          # build + uvicorn prod
│   └── test.sh                           # pytest runner
├── src/project_argus/
│   ├── api/
│   │   ├── url.py                        # POST /api/url/*
│   │   ├── domain.py                     # POST /api/domain/*
│   │   ├── ip.py                         # POST /api/ip/*
│   │   └── jobs.py                       # GET /jobs/*
│   ├── models/
│   │   ├── url_models.py                 # URLStatusResponse, RedirectHop
│   │   └── job_models.py                 # JobCreatedResponse, JobStatusResponse
│   ├── services/
│   │   ├── url_service.py                # redirect chain + client-side detection
│   │   ├── domain_service.py
│   │   ├── ip_service.py
│   │   └── job_service.py                # async job queue + HANDLERS dispatch
│   ├── utils/
│   │   ├── http.py                       # USER_AGENT_LIST, DEFAULT_REQUEST_HEADERS, extract_client_redirect()
│   │   └── validators.py
│   ├── static/
│   │   └── js/app.js                     # dashboard JS (dropdown, auto-poll, syntax highlight)
│   ├── templates/
│   │   ├── _head.html                    # CSS design tokens + component styles
│   │   ├── _scripts.html                 # script tags
│   │   └── index.html                    # jQuery UI tabs dashboard
│   ├── db.py                             # SQLite init + helpers
│   └── main.py                           # FastAPI app, _ENDPOINTS registry, lifespan
├── tests/
└── pyproject.toml
```

## License

MIT License — see LICENSE file for details.
