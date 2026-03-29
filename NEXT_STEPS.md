# Next Steps

This file tracks the highest-value follow-up work after the local AWS-style migration.

## Current State

Verified locally with Docker + LocalStack:

- web -> orchestrator Lambda -> SQS -> executor Lambda -> DynamoDB/S3 -> jobs/job_results Lambdas
- `http/status`
- `domain/dns`
- `ip/geoip`
- `proxy/check`

## Priority Follow-Ups

### 1. Fix CA trust inside Lambda runtimes

Why:

- the Lambda pipeline works
- some outbound HTTPS checks can still fail with certificate verification errors
- this affects result quality, not job orchestration

What to look at:

- Lambda packaging in `scripts/build-lambdas.sh`
- HTTP client configuration used by the executor services
- CA bundle availability inside the Lambda runtime package

### 2. Smooth first-poll cold start behavior

Why:

- an immediate first `GET /api/jobs/{job_id}` can still show `pending`
- this is usually LocalStack cold start time, not a broken queue or executor

Possible fixes:

- small frontend polling backoff
- slightly clearer progress messaging while the first executor starts
- optional initial delay before the first automatic poll

### 3. Expand LocalStack end-to-end coverage

Why:

- the main vertical slices are proven
- more route families should be exercised with real local requests over time

Good candidates:

- more `domain/*` operations
- more `ip/*` operations
- `http/headers`

### 4. Add more operational docs if needed

Why:

- the README now covers fresh-machine setup and rerun flow
- if repeated setup pain shows up on the VM, add those lessons back into the docs

Good candidates:

- common failure signatures
- recovery commands
- platform-specific notes if a new host differs from the current Linux setup

## Commit Readiness

The migration is in a state where it makes sense to commit and clone onto another machine.

Known caveats to keep in mind after cloning:

- Docker must be working before `docker compose` and LocalStack will succeed
- on Linux, Docker socket permissions may need the `docker` group fix
- on SELinux-enforcing systems, the existing compose settings are important
- first poll after submit may briefly stay `pending` during Lambda cold start
