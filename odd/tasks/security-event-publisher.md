# security-event-publisher (KAP-07)

- Engram topic: `odd/security-event-publisher/tasks` (project: `nmap-service`)
- Branch: `feature/security_event_publisher` (off origin/develop c267ff8)
- Status: in progress
- Master plan: repo `infra`, `odd/tasks/kinesis-admin-panel.md` (task KAP-07). Mirror of the gateway work (KAP-06, `gateway/odd/tasks/security-event-publisher.md`).

## Objective

ms-nmap publishes `scan.started`, `scan.completed`, `scan.failed` and `finding.critical` security events to the Kinesis stream `security-events` through a `SecurityEventPublisher` port, without ever failing or delaying the scan pipeline or the SNS outcome publish.

## Scope

- Port `SecurityEventPublisher`, envelope `SecurityEvent` (source `nmap-service`) with typed constructors that return `Err` for schema-invalid values; partition key `scan_id`.
- Adapters: Kinesis (`aws-sdk-kinesis`, honors `AWS_ENDPOINT_URL`), no-op, in-memory recorder.
- Config `SECURITY_EVENTS_STREAM_NAME` (optional; unset/blank = no-op + one startup info log; invalid = startup config error).
- Emission next to the SNS outcome publish, contract parity tests against `../broker/contracts`, LocalStack Kinesis test.
- Out of scope: user-service events (KAP-08), the gateway consumer (KAP-09), retries/outbox, changing the scan-outcome contract.

## Constraints

- Kinesis failures never fail or delay the pipeline or the SNS publish; logs carry the event type only.
- Events carry no credentials, raw scan output, error text or IPs of targets.
- Every emitted event validates against `broker/contracts/security-event.schema.json`.
- Unit tests do not mutate the process environment and have no wall-clock waits.
- Code comments in neutral Spanish, identifiers in English, this doc in English.

## Tooling

- TDD mode: on (source: user global config "Strict TDD Mode: enabled"); runner `make verify`.
- Route: delegated direct, single writer. Review policy: decline (stored user policy).

## Checklist

- [x] SEP-01 Feature doc.
- [ ] SEP-02 Envelope, port, recorder/no-op adapters, `emit`, schema parity tests.
- [ ] SEP-03 Kinesis adapter, `SECURITY_EVENTS_STREAM_NAME`, wiring, LocalStack test.
- [ ] SEP-04 Emission points in the pipeline, each with a failing-publisher test.
- [ ] SEP-05 `docs/architecture.md`, README env table, this doc closed.

## Next step

SEP-02.
