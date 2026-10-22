# dedupe-version-match-findings

- Engram topic: `odd/dedupe-version-match-findings/tasks` (project: `nmap-service`)
- Branch: not created yet
- Status: backlog (planned 2026-10-21, deferred by the user)

## Objective

Reduce the noise of "posibles" (version_match) findings in a report without hiding real signal, so the document is rigorous and readable.

## Problem (observed)

The `vulners` NSE script lists dozens of CVEs per service matched by product version (CPE). For a single OpenSSH/nginx version that is many `version_match` findings, several of which are the same underlying issue or already backported-fixed by the distro. The front already groups them as collapsible "Posibles" (feature `report-readability`, RRD), but the underlying list is still long and partly redundant.

## Scope / options

- Option A (parser, nmap-service): dedupe `version_match` findings by CVE id keeping the highest CVSS (VSA-01 already dedupes exact-id duplicates; extend/confirm the rule covers cross-entry duplicates), and optionally collapse near-identical descriptions.
- Option B (front, display-only): keep all findings in the data, but de-emphasize/paginate `version_match` beyond a threshold. Non-destructive; no contract change.
- Decision to take: where dedup belongs — the producer (nmap-service, loses data) vs the consumer (front, keeps data). Likely B for display + a conservative A for exact duplicates only.

## Tasks

- [ ] DVM-01 Decide producer vs consumer dedup (product decision).
- [ ] DVM-02 Implement the chosen approach with tests (real vulners fixture with duplicate CVEs across entries).
- [ ] DVM-03 Confirm `confirmed` findings are never deduped away and counts stay honest.

## Acceptance criteria

- A vulners output with the same CVE in two entries yields one finding; confirmed findings are untouched; the report's severity counts remain accurate.

## Checks

Strict TDD; `make verify` (nmap-service) and/or `npm run verify` (front) depending on the chosen layer.
