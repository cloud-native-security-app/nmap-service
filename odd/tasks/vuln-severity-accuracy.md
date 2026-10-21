# vuln-severity-accuracy

- Engram topic: `odd/vuln-severity-accuracy/tasks` (project: `nmap-service`)
- Branch: `fix/vuln_severity_per_cve` (VSA-01); VSA-02 not started
- Status: VSA-01 done (2026-10-21), uncommitted

## Objective

Each reported vulnerability carries its own, honest severity, and version-based guesses are distinguishable from confirmed findings.

## Problem (observed live, 2026-10-21)

A scan of a fresh Amazon Linux 2023 EC2 (only port 22/ssh) returned dozens of findings, all `critical`.

1. Bug: the `vulners` NSE script lists many CVEs for one service, each with its own CVSS. `parse` (`src/parser.rs`, the script handling around `classify_severity`) computes the maximum CVSS over the whole script output and assigns that single severity to every CVE (one 9.8 makes all of them critical). The unit test at `src/parser.rs:660` encodes that behavior.
2. Limitation: `vulners` matches CVEs by product version (CPE). Amazon Linux / RHEL backport security fixes without bumping the upstream version, so many listed CVEs are already fixed in the distro package (false positives).

## Tasks

- [x] VSA-01 Per-CVE severity: when a script output carries per-entry CVSS values (vulners `<table>` entries with `id`/`cvss`), classify each CVE with its own score; keep the script-level rules (risk factor / state VULNERABLE) for single-finding scripts. Update the test that encodes the old behavior.
- [ ] VSA-02 Version-based confidence: mark findings that come only from version matching (vulners) as `confidence: "version_match"` (additive, optional field in the outcome JSON) so the front can show them as "posible"; document the backport caveat. Cross-repo: gateway passes the field through untouched (ScanResult is relayed as JSON), user-service stores it verbatim, front `report-readability` RRD-06 displays it.

## Acceptance criteria

- A vulners output with CVEs of CVSS 9.8, 7.5 and 5.0 yields critical, high and medium respectively.
- Single-finding scripts keep their current classification.

## Checks

Strict TDD with real nmap XML fixtures (`cargo test`), `make verify`.

## Evidence

### VSA-01
- Route: delegated writer (single bounded writer), Strict TDD. Runner: `cargo test --lib parser`.
- RED: `cargo test --lib parser` -> 12 passed, 2 failed (`vulners_classifies_each_cve_with_its_own_cvss` got Critical for the 7.5 CVE; `vulners_dedupes_cves_keeping_highest_cvss_and_skips_non_cve_entries` description repeated the whole dump). `script_without_cvss_keeps_text_based_classification` passed already (regression guard).
- GREEN: `make verify` -> exit 0; lib 177 passed, 0 failed; integration suites passed (Docker ones included).
- Fixture: `tests/fixtures/vulners_multi_cve.xml` (CVSS 9.8, 7.5, 5.0, 2.1, a duplicate CVE at 4.3, one PACKETSTORM entry). Single-finding behavior covered by the existing `vuln_findings.xml` test (ftp-vsftpd-backdoor High; vulners CVE-2011-2523 Critical at its own 10.0).
- Decision on non-CVE entries: skipped as separate findings (no `PACKETSTORM:`/`EDB-ID:`/`1337DAY` findings) and not attached as references, because nmap data does not link them to a specific CVE. Duplicates by CVE id keep the highest CVSS.
- Per-entry findings get a short description (`<CVE>: CVSS x.y, reportado por <script> (<cpe/product>)`) instead of the full dump. Scripts without per-entry `id`+`cvss` tables use the unchanged script-level path.
