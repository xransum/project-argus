#!/usr/bin/env bash

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LAMBDA_BUILD_DIR="$ROOT/.build/lambdas"
LAMBDA_ZIP="$LAMBDA_BUILD_DIR/project-argus-lambda.zip"
CONTAINER_LAMBDA_ZIP="/tmp/project-argus-lambda.zip"

aws_local() {
  docker compose -f "$ROOT/infra/local/docker-compose.yml" exec -T localstack \
    awslocal --region us-east-1 "$@"
}

copy_lambda_zip() {
  docker cp "$LAMBDA_ZIP" project-argus-localstack:"$CONTAINER_LAMBDA_ZIP" >/dev/null
}

export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=us-east-1

LAMBDA_ENV_VARS="$({
  printf '{"Variables":{'
  printf '"AWS_REGION":"us-east-1",'
  printf '"AWS_DEFAULT_REGION":"us-east-1",'
  printf '"AWS_ENDPOINT_URL":"http://localstack:4566",'
  printf '"AWS_ACCESS_KEY_ID":"test",'
  printf '"AWS_SECRET_ACCESS_KEY":"test",'
  printf '"ARGUS_JOBS_TABLE":"project-argus-jobs",'
  printf '"ARGUS_RESULTS_BUCKET":"project-argus-results",'
  printf '"ARGUS_ORCHESTRATOR_FUNCTION":"project-argus-orchestrator",'
  printf '"ARGUS_JOBS_FUNCTION":"project-argus-jobs",'
  printf '"ARGUS_JOB_RESULTS_FUNCTION":"project-argus-job-results",'
  printf '"ARGUS_HTTP_QUEUE_URL":"http://localstack:4566/000000000000/project-argus-http-queue",'
  printf '"ARGUS_DOMAIN_QUEUE_URL":"http://localstack:4566/000000000000/project-argus-domain-queue",'
  printf '"ARGUS_IP_QUEUE_URL":"http://localstack:4566/000000000000/project-argus-ip-queue",'
  printf '"ARGUS_PROXY_QUEUE_URL":"http://localstack:4566/000000000000/project-argus-proxy-queue"'
  printf '}}'
})"

echo "==> Waiting for LocalStack"
until aws_local dynamodb list-tables >/dev/null 2>&1; do
  sleep 2
done

echo "==> Creating DynamoDB table"
if ! aws_local dynamodb describe-table --table-name project-argus-jobs >/dev/null 2>&1; then
  aws_local dynamodb create-table \
    --table-name project-argus-jobs \
    --attribute-definitions AttributeName=job_id,AttributeType=S \
    --key-schema AttributeName=job_id,KeyType=HASH \
    --billing-mode PAY_PER_REQUEST
  aws_local dynamodb update-time-to-live \
    --table-name project-argus-jobs \
    --time-to-live-specification Enabled=true,AttributeName=expires_at
fi

echo "==> Creating S3 bucket"
aws_local s3api create-bucket --bucket project-argus-results >/dev/null 2>&1 || true

create_queue_pair() {
  local queue_name="$1"
  local dlq_name="$2"
  local visibility_timeout="${3:-300}"

  local dlq_url
  dlq_url="$(aws_local sqs create-queue --queue-name "$dlq_name" --query QueueUrl --output text)"
  local dlq_arn
  dlq_arn="$(aws_local sqs get-queue-attributes --queue-url "$dlq_url" --attribute-names QueueArn --query 'Attributes.QueueArn' --output text)"
  local attributes
  attributes="$(printf '{"RedrivePolicy":"{\\"deadLetterTargetArn\\":\\"%s\\",\\"maxReceiveCount\\":\\"3\\"}","VisibilityTimeout":"%s"}' "$dlq_arn" "$visibility_timeout")"
  aws_local sqs create-queue --queue-name "$queue_name" --attributes "$attributes" >/dev/null
}

echo "==> Creating SQS queues and DLQs"
create_queue_pair project-argus-http-queue project-argus-http-dlq
create_queue_pair project-argus-domain-queue project-argus-domain-dlq
create_queue_pair project-argus-ip-queue project-argus-ip-dlq
create_queue_pair project-argus-proxy-queue project-argus-proxy-dlq

echo "==> Building Lambda packages"
bash "$ROOT/scripts/build-lambdas.sh"

echo "==> Copying Lambda package into LocalStack"
copy_lambda_zip

create_or_update_lambda() {
  local function_name="$1"
  local handler="$2"
  local zip_path="$3"

  if aws_local lambda get-function --function-name "$function_name" >/dev/null 2>&1; then
    aws_local lambda update-function-code --function-name "$function_name" --zip-file "fileb://$CONTAINER_LAMBDA_ZIP" >/dev/null
    aws_local lambda update-function-configuration \
      --function-name "$function_name" \
      --environment "$LAMBDA_ENV_VARS" >/dev/null
    return
  fi

  aws_local lambda create-function \
    --function-name "$function_name" \
    --runtime python3.11 \
    --handler "$handler" \
    --role arn:aws:iam::000000000000:role/lambda-role \
    --environment "$LAMBDA_ENV_VARS" \
    --zip-file "fileb://$CONTAINER_LAMBDA_ZIP" >/dev/null
}

echo "==> Creating Lambda functions"
create_or_update_lambda project-argus-orchestrator project_argus.lambdas.orchestrator.handler.handler "$LAMBDA_ZIP"
create_or_update_lambda project-argus-http project_argus.lambdas.http.handler.handler "$LAMBDA_ZIP"
create_or_update_lambda project-argus-domain project_argus.lambdas.domain.handler.handler "$LAMBDA_ZIP"
create_or_update_lambda project-argus-ip project_argus.lambdas.ip.handler.handler "$LAMBDA_ZIP"
create_or_update_lambda project-argus-proxy project_argus.lambdas.proxy.handler.handler "$LAMBDA_ZIP"
create_or_update_lambda project-argus-jobs project_argus.lambdas.jobs.handler.handler "$LAMBDA_ZIP"
create_or_update_lambda project-argus-job-results project_argus.lambdas.job_results.handler.handler "$LAMBDA_ZIP"

queue_arn() {
  local queue_name="$1"
  local queue_url
  queue_url="$(aws_local sqs get-queue-url --queue-name "$queue_name" --query QueueUrl --output text)"
  aws_local sqs get-queue-attributes --queue-url "$queue_url" --attribute-names QueueArn --query 'Attributes.QueueArn' --output text
}

ensure_mapping() {
  local function_name="$1"
  local source_arn="$2"
  local current
  current="$(aws_local lambda list-event-source-mappings --function-name "$function_name" --event-source-arn "$source_arn" --query 'EventSourceMappings[0].UUID' --output text 2>/dev/null || true)"
  if [ -z "$current" ] || [ "$current" = "None" ]; then
    aws_local lambda create-event-source-mapping --function-name "$function_name" --event-source-arn "$source_arn" --batch-size 1 >/dev/null
  fi
}

echo "==> Wiring SQS triggers"
ensure_mapping project-argus-http "$(queue_arn project-argus-http-queue)"
ensure_mapping project-argus-domain "$(queue_arn project-argus-domain-queue)"
ensure_mapping project-argus-ip "$(queue_arn project-argus-ip-queue)"
ensure_mapping project-argus-proxy "$(queue_arn project-argus-proxy-queue)"

echo "==> LocalStack bootstrap complete"
