# Project Argus

A comprehensive security investigation API for analyzing URLs, domains, and IP addresses. Built with FastAPI and designed for threat intelligence gathering and security research.

## Features

### URL Analysis
- **Status Check**: Verify URL accessibility and response times
- **Headers Inspection**: Extract and analyze HTTP headers

### Domain Intelligence
- **Domain Information**: WHOIS data, registrar, creation/expiration dates
- **SSL/TLS Analysis**: Certificate validation, expiry monitoring
- **DNS Records**: Query A, AAAA, MX, TXT, CNAME, NS records
- **WHOIS Lookup**: Detailed registration information
- **Geolocation**: IP geolocation of domain
- **Reputation Checking**: Domain reputation scoring
- **Blacklist Status**: Check against known blacklists
- **SSL Certificate Details**: Full certificate information and chain
- **Subdomain Discovery**: Enumerate subdomains
- **Hosting Information**: Identify hosting provider and infrastructure

### IP Address Analysis
- **IP Information**: Hostname, ASN, organization, ISP details
- **Reverse DNS**: PTR record lookups
- **Geolocation**: Geographic location data
- **Reputation Checking**: IP reputation scoring
- **Blacklist Status**: DNSBL and threat feed checks
- **WHOIS Lookup**: Network registration information

## Installation

### Prerequisites

- Python 3.8+
- [uv](https://github.com/astral-sh/uv) package manager
- [nox](https://nox.thea.codes/) for automation

### Install uv

```bash
# macOS/Linux
curl -LsSf https://astral.sh/uv/install.sh | sh

# Windows
powershell -c "irm https://astral.sh/uv/install.ps1 | iex"
```

### Clone and Install

```bash
# Clone the repository
git clone https://github.com/yourusername/project-argus.git
cd project-argus

# Install dependencies
uv sync --all-extras
```

## Development Setup

### Using Nox (Recommended)

Nox automates testing, linting, type checking, and more:

```bash
# Install nox
uv tool install nox

# Set up development environment (installs pre-commit hooks)
nox -s dev

# Run all quality checks
nox

# Run specific sessions
nox -s lint          # Lint with ruff
nox -s mypy          # Type check with mypy
nox -s tests         # Run tests
nox -s coverage      # Run tests with coverage
nox -s typeguard     # Runtime type checking
nox -s pre-commit    # Run pre-commit hooks

# Run tests on all Python versions
nox -s tests

# List all available sessions
nox --list
```

### Manual Setup

```bash
# Install dev dependencies
uv sync --group dev

# Install pre-commit hooks
uv run pre-commit install
```

## Running the API

### Development Server

```bash
# Using uv
uv run uvicorn src.project_argus.main:app --reload --host 0.0.0.0 --port 8000
```

The API will be available at:
- **API Root**: http://localhost:8000
- **Interactive Docs**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

### Production Server

```bash
# Using uv with production settings
uv run uvicorn src.project_argus.main:app --host 0.0.0.0 --port 8000 --workers 4
```

## Testing

### Using Nox

```bash
# Run all tests
nox -s tests

# Run tests with coverage
nox -s coverage

# Run tests with runtime type checking
nox -s typeguard

# Run tests on specific Python version
nox -s tests-3.11
```

### Using pytest directly

```bash
# Run all tests
uv run pytest

# Run with coverage
uv run pytest --cov=src/project_argus --cov-report=html

# Run specific test file
uv run pytest tests/test_url_endpoints.py

# Run specific test
uv run pytest tests/test_url_endpoints.py::test_url_status_endpoint

# Verbose output
uv run pytest -v

# Stop on first failure
uv run pytest -x
```

## Code Quality

### Linting and Formatting

```bash
# Using nox
nox -s lint

# Using ruff directly
uv run ruff check src/ tests/ --fix
uv run ruff format src/ tests/
```

### Type Checking

```bash
# Using nox
nox -s mypy

# Using mypy directly
uv run mypy src/project_argus
```

### Pre-commit Hooks

```bash
# Run all pre-commit hooks
nox -s pre-commit

# Or directly
uv run pre-commit run --all-files
```

## API Endpoints

### Root Endpoints

```
GET /                  # API information and endpoint listing
GET /health           # Health check endpoint
```

### URL Endpoints

```
GET /api/v1/url/status?url=<url>       # Check URL status
GET /api/v1/url/headers?url=<url>      # Fetch URL headers
```

### Domain Endpoints

```
GET /api/v1/domain/info?domain=<domain>
GET /api/v1/domain/ssl?domain=<domain>
GET /api/v1/domain/dns?domain=<domain>&record_type=A
GET /api/v1/domain/whois?domain=<domain>
GET /api/v1/domain/geoip?domain=<domain>
GET /api/v1/domain/reputation?domain=<domain>
GET /api/v1/domain/blacklist?domain=<domain>
GET /api/v1/domain/ssl-certificate?domain=<domain>
GET /api/v1/domain/subdomains?domain=<domain>
GET /api/v1/domain/hosting?domain=<domain>
```

### IP Endpoints

```
GET /api/v1/ip/info?ip=<ip>
GET /api/v1/ip/dns?ip=<ip>
GET /api/v1/ip/geoip?ip=<ip>
GET /api/v1/ip/reputation?ip=<ip>
GET /api/v1/ip/blacklist?ip=<ip>
GET /api/v1/ip/whois?ip=<ip>
```

## Usage Examples

### cURL

```bash
curl "http://localhost:8000/api/v1/url/status?url=https://example.com"
curl "http://localhost:8000/api/v1/domain/whois?domain=example.com"
curl "http://localhost:8000/api/v1/ip/reputation?ip=8.8.8.8"
```

### Python

```python
import httpx

async with httpx.AsyncClient() as client:
    response = await client.get(
        "http://localhost:8000/api/v1/url/status",
        params={"url": "https://example.com"}
    )
    print(response.json())
```

## Project Structure

```
project-argus/
├── src/project_argus/
│   ├── api/v1/              # API endpoints
│   ├── models/              # Pydantic models
│   ├── services/            # Business logic
│   ├── utils/               # Utilities (validators, etc.)
│   └── main.py              # FastAPI app
├── tests/                   # Test suite
├── noxfile.py              # Nox configuration
├── pyproject.toml          # Project metadata
└── .pre-commit-config.yaml # Pre-commit hooks
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Run `nox -s dev` to set up development environment
4. Make your changes
5. Run `nox` to ensure all checks pass
6. Submit a pull request

## License

MIT License - See LICENSE file for details
