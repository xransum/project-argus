# Project Argus

Project Argus is a bulk intelligence-gathering API for URLs, domains, IP addresses, and proxies.

This repo now runs as a local-first AWS-style stack:

- FastAPI + Jinja web app in the same repo
- Lambda handlers in the same repo
- DynamoDB for job metadata and live progress
- S3 for one final JSON result per job
- SQS between the orchestrator Lambda and executor Lambdas
- LocalStack for local AWS emulation

This README is written as a clone-to-running guide for a fresh machine.

## Copy/Paste Quickstart

```bash
git clone https://github.com/xransum/project-argus.git
cd project-argus

./scripts/build.sh

docker info
docker compose -f infra/local/docker-compose.yml up --build -d
bash infra/local/bootstrap.sh

curl -s http://localhost:8000/health
curl -s http://localhost:8000/api
```

Submit a real test job:

```bash
curl -s -X POST http://localhost:8000/api/domain/dns \
  -H "Content-Type: application/json" \
  -d '{"domains": ["example.com"]}'
```

Then poll with the returned `job_id`:

```bash
curl -s http://localhost:8000/api/jobs/<job_id>
curl -s http://localhost:8000/api/jobs/<job_id>/results
```

## What Works Today

Verified locally with Docker + LocalStack:

- `POST /api/http/status`
- `POST /api/domain/dns`
- `POST /api/ip/geoip`
- `POST /api/proxy/check`
- `GET /api/jobs/{job_id}`
- `GET /api/jobs/{job_id}/results`

Verified flow:

1. Web app accepts the request.
2. Web app invokes the orchestrator Lambda.
3. Orchestrator writes a DynamoDB job record.
4. Orchestrator sends the job to the family SQS queue.
5. Family executor Lambda consumes the queue message.
6. Executor writes live progress back to DynamoDB.
7. Executor writes one final JSON result to S3.
8. Jobs and job_results Lambdas serve polling reads.

## Repository Layout

```text
src/project_argus/
  lambdas/         Lambda handlers
  shared/          AWS config, boto3 clients, job contracts, storage, orchestration
  web/             Active FastAPI app and family-based routes
  models/          Request and response models
  services/        Reused domain, IP, proxy, and URL service logic
  templates/       Jinja templates
  static/          Frontend assets

infra/local/
  docker-compose.yml
  bootstrap.sh

scripts/
  build.sh
  build-lambdas.sh
  dev.sh
  start.sh
  test.sh
```

## API Surface

### HTTP

```text
POST /api/http/status
POST /api/http/headers
```

Body:

```json
{"urls": ["https://example.com"]}
```

### Domain

```text
POST /api/domain/info
POST /api/domain/ssl
POST /api/domain/dns
POST /api/domain/whois
POST /api/domain/geoip
POST /api/domain/reputation
POST /api/domain/blacklist
POST /api/domain/ssl-certificate
POST /api/domain/subdomains
POST /api/domain/hosting
```

Body:

```json
{"domains": ["example.com"]}
```

### IP

```text
POST /api/ip/info
POST /api/ip/dns
POST /api/ip/whois
POST /api/ip/geoip
POST /api/ip/reputation
POST /api/ip/blacklist
```

Body:

```json
{"ips": ["1.1.1.1"]}
```

### Proxy

```text
POST /api/proxy/check
```

Body:

```json
{"proxies": ["1.1.1.1:8080"]}
```

### Jobs

```text
GET /api/jobs/{job_id}
GET /api/jobs/{job_id}/results
```

## Prerequisites

Install these on a fresh machine:

- Git
- Python 3.11
- Node.js and npm
- `uv`
- Docker Engine or Docker Desktop
- Docker Compose plugin

The project also uses:

- LocalStack via Docker
- AWS CLI only inside the LocalStack container through `awslocal`

## Supported Local Environments

Verified:

- Linux host with Docker Engine and Docker Compose
- Linux VM with enough CPU, RAM, and disk for Docker + LocalStack

Expected to work, but not verified in this repo yet:

- Docker Desktop on macOS
- Docker Desktop on Windows with a Linux container backend

If you run this outside Linux, the application stack should still be portable, but Docker socket behavior, filesystem mounts, and LocalStack Lambda execution may differ enough that you should treat it as best effort until you verify it on your machine.

## Clone And Prepare

```bash
git clone https://github.com/xransum/project-argus.git
cd project-argus
```

Optional sanity checks:

```bash
python --version
node --version
npm --version
uv --version
docker --version
docker compose version
```

## Linux Docker Permissions

If `docker info` fails with:

```text
permission denied while trying to connect to the docker API at unix:///var/run/docker.sock
```

add your user to the `docker` group:

```bash
sudo usermod -aG docker $USER
newgrp docker
docker info
```

If that still does not work, log out and log back in, then run:

```bash
docker info
```

This applies across common Linux distros, including Fedora, Debian, Ubuntu, and CentOS.

## Installing Docker On Debian

Debian's default apt repositories ship an older `docker.io` package and the
standalone `docker-compose` v1. Neither includes the Compose v2 plugin that
this project requires (`docker compose`, not `docker-compose`).

If `docker compose version` fails or is not recognized, install Docker Engine
from Docker's official repository instead:

```bash
# Remove distro-packaged versions
sudo apt-get remove -y docker docker-engine docker.io containerd runc docker-compose

# Add Docker's official apt repo
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/debian \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install Docker Engine and Compose v2 plugin
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

Verify:

```bash
docker --version
docker compose version
```

## SELinux Notes

If your distro enforces SELinux, this repo already includes the compose settings needed for bind mounts and LocalStack's Docker socket access:

- bind mounts use SELinux relabel flags
- LocalStack runs with `security_opt: label=disable`
- LocalStack runs as `root` so it can use `/var/run/docker.sock`

On distros without SELinux enabled by default, this section is mostly irrelevant and the same compose file should still work.

You should not need to disable SELinux globally.

## First-Time Local Build

This installs Python deps, npm deps, and frontend vendor assets:

```bash
./scripts/build.sh
```

## Web App Only

Hot reload mode outside Docker:

```bash
./scripts/dev.sh
```

Production-style local run outside Docker:

```bash
./scripts/start.sh
```

## Full Local AWS Stack

### 1. Start Docker services

```bash
docker compose -f infra/local/docker-compose.yml up --build -d
```

Check status:

```bash
docker compose -f infra/local/docker-compose.yml ps -a
```

Expected services:

- `project-argus-localstack`
- `local-web-1`

### 2. Bootstrap local AWS resources and Lambdas

```bash
bash infra/local/bootstrap.sh
```

This script will:

- wait for LocalStack
- create DynamoDB table `project-argus-jobs`
- enable DynamoDB TTL on `expires_at`
- create S3 bucket `project-argus-results`
- create SQS queues and DLQs for `http`, `domain`, `ip`, and `proxy`
- build a Lambda-compatible zip in `.build/lambdas/`
- deploy all Lambda functions into LocalStack
- wire SQS event source mappings to family executors

### 3. Open the app

```text
http://localhost:8000
```

### 4. Health checks

```bash
curl -s http://localhost:8000/health
curl -s http://localhost:8000/api
```

## Fresh Machine Quickstart

If you just want the shortest path from clone to running:

```bash
git clone https://github.com/xransum/project-argus.git
cd project-argus
./scripts/build.sh
docker info
docker compose -f infra/local/docker-compose.yml up --build -d
bash infra/local/bootstrap.sh
curl -s http://localhost:8000/health
```

## Example End-To-End Checks

### HTTP

```bash
curl -s -X POST http://localhost:8000/api/http/status \
  -H "Content-Type: application/json" \
  -d '{"urls": ["https://example.com"]}'
```

### Domain

```bash
curl -s -X POST http://localhost:8000/api/domain/dns \
  -H "Content-Type: application/json" \
  -d '{"domains": ["example.com"]}'
```

### IP

```bash
curl -s -X POST http://localhost:8000/api/ip/geoip \
  -H "Content-Type: application/json" \
  -d '{"ips": ["1.1.1.1"]}'
```

### Proxy

```bash
curl -s -X POST http://localhost:8000/api/proxy/check \
  -H "Content-Type: application/json" \
  -d '{"proxies": ["1.1.1.1:8080"]}'
```

Each request returns a payload like:

```json
{
  "job_id": "...",
  "job_type": "http/status",
  "status": "pending",
  "total": 1,
  "message": "Job enqueued. Poll /api/jobs/{job_id} for progress."
}
```

Then poll:

```bash
curl -s http://localhost:8000/api/jobs/<job_id>
curl -s http://localhost:8000/api/jobs/<job_id>/results
```

Note:

- the first poll may still show `pending`
- that is normal when LocalStack is cold-starting Lambda runtime containers
- poll again after a few seconds

## Logs And Debugging

Show service status:

```bash
docker compose -f infra/local/docker-compose.yml ps -a
```

Show web logs:

```bash
docker compose -f infra/local/docker-compose.yml logs -f web
```

Show LocalStack logs:

```bash
docker compose -f infra/local/docker-compose.yml logs -f localstack
```

Check DynamoDB jobs directly:

```bash
docker compose -f infra/local/docker-compose.yml exec -T localstack \
  awslocal dynamodb scan --table-name project-argus-jobs
```

Check Lambda mappings:

```bash
docker compose -f infra/local/docker-compose.yml exec -T localstack \
  awslocal lambda list-event-source-mappings
```

Check queue depth:

```bash
docker compose -f infra/local/docker-compose.yml exec -T localstack \
  awslocal sqs get-queue-attributes \
  --queue-url http://localhost:4566/000000000000/project-argus-http-queue \
  --attribute-names ApproximateNumberOfMessages ApproximateNumberOfMessagesNotVisible
```

## Rebuild And Reset

Rebuild just the web container:

```bash
docker compose -f infra/local/docker-compose.yml up --build -d web
```

Redeploy Lambdas and local AWS resources:

```bash
bash infra/local/bootstrap.sh
```

Stop services:

```bash
docker compose -f infra/local/docker-compose.yml down
```

Blow away LocalStack state and rebuilt artifacts:

```bash
docker compose -f infra/local/docker-compose.yml down
rm -rf .build .localstack
docker compose -f infra/local/docker-compose.yml up --build -d
bash infra/local/bootstrap.sh
```

## Tests

Run all tests:

```bash
./scripts/test.sh
```

Run the focused migrated route suite:

```bash
uv run pytest tests/integration/test_main.py tests/integration/test_routes.py tests/unit/utils/test_validators.py
```

## Known Behavior

- `http/status` can complete with SSL verification errors for some outbound HTTPS checks in the Lambda runtime
- that does not break the queue/job/result pipeline
- if needed, CA trust handling inside Lambda packaging is the next improvement

## Running In A VM

Yes, this should work in a VM.

The stack is not tiny, but it is reasonable if the VM has enough headroom for:

- Docker Engine
- LocalStack
- one web container
- short-lived Lambda runtime containers
- Python and npm tooling during builds

Practical recommendation:

- 4 vCPU minimum
- 8 GB RAM minimum
- 12 to 16 GB RAM preferred if you do repeated rebuilds and keep browser/tools open
- 20+ GB free disk space for images, build artifacts, npm cache, and Docker layers

If the VM is too small, the pain points will be:

- slow Docker image builds
- slow Lambda cold starts
- LocalStack becoming sluggish under repeated redeploys
- host swap pressure during `docker compose up --build` and `bootstrap.sh`

If you plan to run this in a VM regularly, I would treat this as the comfortable floor:

- 4 vCPU
- 12 GB RAM
- SSD-backed storage

If you want the most reliable experience, a normal Linux install or a well-provisioned VM is fine. A tiny VM with 2 cores and 4 GB RAM will be frustrating.
