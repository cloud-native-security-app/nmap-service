# Feature: sqs-sns-adapter (nmap-service)

Self-contained: any AI agent can start from this file with no prior context.

- Feature id: `sqs-sns-adapter` | Engram topic: `odd/sqs-sns-adapter/tasks` (project: nmap-service; mirror pending) | Branch: `v1`
- Master plan: repo `infra`, path `odd/tasks/cloud-native-deploy.md`
- Topology and contract (Proposed): repo `broker`, path `odd/tasks/sqs-sns-migration.md` (MSG-01 sign-off gates this feature)
- Counterpart: repo `gateway`, path `odd/tasks/sqs-sns-adapter.md`
- Decision date: 2026-10-17 (RabbitMQ replaced by SNS + SQS)

## Objective

Replace the `lapin` (AMQP) adapter in `nmap-service` (feature `broker_adapter`, module `src/messaging/rabbitmq.rs`) with the AWS SDK
for Rust: consume `ms-nmap-scan-requests` and `ms-nmap-scan-cancellations` from SQS, publish scan outcomes to the `scan-outcomes` SNS topic.

## Problem

`src/messaging/rabbitmq.rs` consumes queues `ms-nmap.scan-requests` and `ms-nmap.scan-cancellations` (ack, `nack(requeue=false)` on
malformed bodies) and publishes to exchange `scan.outcomes` with routing keys `scan.outcome.started|completed|failed`. Config
(`src/config.rs`) requires `MS_NMAP_BROKER_ENDPOINT`, `MS_NMAP_BROKER_CREDENTIAL` and `MS_NMAP_BROKER_VHOST`; the Dockerfile bakes a lab CA.

## Why

Amazon MQ is denied in the Learner Lab; the user chose SNS + SQS. SQS/SNS use public-CA HTTPS, so the lab CA is no longer needed.

## Scope

In:
- Config: region, two queue URLs, outcomes topic ARN, optional endpoint override for LocalStack (proposed names below). Remove `MS_NMAP_BROKER_*`.
- Consumers on SQS with long polling; **visibility timeout handling for long scans** (heartbeat `ChangeMessageVisibility` or a ceiling, broker Q1).
- Publisher on SNS with the `routing_key` String attribute.
- Remove `lapin` and companions, the `broker_adapter` AMQP code and the baked lab CA (Dockerfile stage, `SSL_CERT_FILE`).
- Tests against LocalStack (real container, no mocks); compose gains LocalStack.

Out:
- Scanning logic and `docs/security-scope.md` limits; message contracts (unchanged).
- Topology and Terraform (`broker` design, `infra` TF-10).

## Constraints

- Strict TDD: observe RED before implementing. Runner: `cargo test`; integration (`-- --ignored`, Docker) uses LocalStack.
- Credentials from the default AWS provider chain (ECS task role = shared `LabRole`); no static keys.
- At-least-once delivery: a duplicate `ScanRequest` must not start a second scan for the same `scan_id` (idempotency design in MSG-NM-02).
- `ScanRequest` bodies hold real SSH credentials: never log bodies; encryption and short retention come from the topology (broker Q4).
- Proposed env vars (confirm at MSG-NM-01): `AWS_REGION`, `AWS_ENDPOINT_URL` (LocalStack only), `MS_NMAP_SCAN_REQUESTS_QUEUE_URL`,
  `MS_NMAP_SCAN_CANCELLATIONS_QUEUE_URL`, `MS_NMAP_SCAN_OUTCOMES_TOPIC_ARN`.
- Planning heuristic about 400 authored changed lines per task; not a cap.
- Conventional Commits, no AI attribution; push/PR/merge are user decisions. Existing Spanish docs keep being edited in Spanish.

## Checklist

- [x] MSG-NM-01 Config: SQS/SNS variables with typed errors; RED: config tests first. Removing `MS_NMAP_BROKER_*` moves to MSG-NM-04 so the build stays green (same sequencing as the gateway).
- [ ] MSG-NM-02 Request and cancellation consumers on `aws-sdk-sqs`: long poll, delete after success, malformed handling, fixed visibility timeout set by Terraform (SSH connect + command timeout + 60 s, broker decision Q1; no ChangeMessageVisibility heartbeat), idempotency by `scan_id`; LocalStack tests including redrive to DLQ after 3 receives.
- [ ] MSG-NM-03 Outcome publisher on `aws-sdk-sns` with `routing_key` attribute; LocalStack test verifies the filters (Gateway gets `started`/`completed`/`failed`, the `ms-analisis` filter check is deferred until that queue exists, see broker sqs-sns-migration Q7).
- [ ] MSG-NM-04 Wiring and cleanup: update `src/wiring.rs`, remove `lapin` and the `broker_adapter` AMQP module, LocalStack in compose and README, `make verify` green.
- [ ] MSG-NM-05 Drop the baked lab CA (Dockerfile CA stage, `SSL_CERT_FILE`, `tls` build context); the image then builds with no cross-repo context.

## Acceptance criteria

- `nmap-service` consumes requests and cancellations and publishes outcomes through SNS + SQS on LocalStack and on AWS.
- Long scans are not redelivered while running; duplicates do not start a second scan; failures end in the DLQ after 3 receives.
- No `lapin`, AMQP configuration or lab CA remains; `make verify` passes; image builds without the `broker` repo.

## Checks

`cargo test`; `cargo test -- --ignored` (LocalStack); `make verify`; `docker build` without extra build contexts.

## Progress

Planned. Blocked on broker MSG-01 (topology sign-off, including the visibility-timeout question) and on MSG-02 for the AWS run.

## MSG-NM-01 evidence

- Route: delegated writer (single bounded writer, inline-verified by parent afterwards). Checkbox intentionally not ticked.
- RED: `cargo test --lib config::` -> compile failure (`E0425`/`E0599`/`E0609`, 32 errors: missing `AWS_REGION_VAR` etc., `ConfigError::InvalidUrl`/`InvalidArn`, new `Config` fields).
- GREEN: `cargo test --lib config::` -> `36 passed; 0 failed` (9 new tests). `cargo test` -> lib `155 passed; 0 failed`, integration suites only `ignored` (Docker).
- Change: `src/config.rs` adds `AWS_REGION`, optional `AWS_ENDPOINT_URL`, four queue URLs and `MS_NMAP_SCAN_OUTCOMES_TOPIC_ARN` (typed `MissingVar`, `InvalidUrl`, `InvalidArn` without echoing the value); `url = "2"` added to `Cargo.toml` (already in the lock). README env table lists the 7 vars. `MS_NMAP_BROKER_*` and `SSL_CERT_FILE` untouched (MSG-NM-04/05).
- Note: `Config::from_env` now requires the new vars at runtime, so local runs/compose must set them until MSG-NM-04 wires LocalStack.

## Next step

MSG-NM-01 once broker MSG-01 is signed off.

## Decisions for MSG-NM-02 (2026-10-19)

- Delete after handle (same as the gateway, user decision A): a request message is deleted only after the scan finished AND its terminal outcome was published. `process_one` returns whether the terminal publish succeeded; on failure the message stays and SQS redelivers it.
- Idempotency by `correlation_id` (user decision A): before scanning, look up Mongo for a finished scan with that `correlation_id`; if found, republish its terminal outcome and delete the message without rescanning. If the same `correlation_id` is already in flight in this replica, skip the duplicate without deleting it. `MongoRepository::save` becomes an upsert keyed by `correlation_id` with a unique index, so a redelivery never creates a second document.
- Known limitation (accepted, documented): cancellations are in-process. With more than one replica a cancellation can be consumed by a replica that is not running the scan and is lost; a cancellation that arrives before its request is also lost. Today the service runs one replica (`desired_count = 1`). The same limitation existed with RabbitMQ.
