# Feature: failed-outcome-on-rejected-request (nmap-service)

- **Branch:** `fix/failed_outcome_on_rejected_request`
- **Status:** implemented locally; `make verify` run before closing

## Objective

A scan request that is valid JSON but fails `ScanRequest` validation must close
in the gateway with a `Failed` outcome instead of staying "pendiente" forever.

## Cause

Observed live 2026-10-20: `"ip": "172.31.86.37/32"` -> "invalid IP address
syntax". `SqsScanRequestSource` sent the body to the DLQ and deleted it, and
`next_valid_request` only logged the `ConsumeError`; no outcome was published,
so the gateway kept the scan pending and a later cancellation was a no-op
("escaneo desconocido").

## Fix

- `parse_scan_request` returns the new `ConsumeError::RejectedRequest
  { correlation_id, detail }` when the JSON carries a non-empty string
  `correlation_id`; otherwise `InvalidSchema` / `MalformedPayload` as before.
- `next_valid_request` (pipeline) publishes
  `ScanOutcome::failed(correlation_id, REJECTED_REQUEST_REASON)` through
  `ServicePorts.sink` (best-effort) and keeps consuming. DLQ send + delete are
  unchanged (the DLQ copy stays for diagnosis).
- The reason is a fixed Spanish string; no IP, credentials or serde detail leave
  the service (`detail` is only logged, credential redacted). Ports stay
  transport-neutral.

## Tasks

- [x] T1 unit: correlation_id extraction (bad IP, non-JSON, missing/non-string/empty id), reason has no payload values
- [x] T2 pipeline stubs: rejected + id -> one Failed, loop continues; no id -> nothing; sink failure does not stop consumption
- [x] T3 LocalStack e2e (`messaging_e2e_localstack`): DLQ copy + `scan.outcome.failed` on a raw-subscribed queue
- [x] T4 docs (`docs/architecture.md`)

## Evidence

- RED (unit): with id extraction disabled, `cargo test --lib` -> 4 failed
  (`invalid_ip_with_correlation_id_is_rejected_request_without_echoing_values`,
  `missing_required_field_is_invalid_schema`,
  `invalid_schema_error_redacts_credential_with_unexpected_type`,
  `rejected_request_with_correlation_id_publishes_one_failed_outcome_and_continues`).
- GREEN: `cargo test --lib` -> 174 passed; e2e `rejected_scan_request_goes_to_the_dlq_and_publishes_a_failed_outcome` passed.
