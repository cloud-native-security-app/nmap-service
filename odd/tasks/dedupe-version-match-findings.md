# dedupe-version-match-findings

- Engram topic: `odd/dedupe-version-match-findings/tasks` (project: `nmap-service`)
- Branch: `test/dvm_dedup_coverage` (doc only); front `fix/confirmed_hides_possible_duplicate`
- Status: done 2026-11-26

## Objective

Reduce the noise of "posibles" (version_match) findings in a report without hiding real signal, so the document is rigorous and readable.

## Problem (observed)

The `vulners` NSE script lists dozens of CVEs per service matched by product version (CPE). For a single OpenSSH/nginx version that is many `version_match` findings, several of which are the same underlying issue or already backported-fixed by the distro. The front already groups them as collapsible "Posibles" (feature `report-readability`, RRD), but the underlying list is still long and partly redundant.

## Scope / options

- Option A (parser, nmap-service): dedupe `version_match` findings by CVE id keeping the highest CVSS (VSA-01 already dedupes exact-id duplicates; extend/confirm the rule covers cross-entry duplicates), and optionally collapse near-identical descriptions.
- Option B (front, display-only): keep all findings in the data, but de-emphasize/paginate `version_match` beyond a threshold. Non-destructive; no contract change.
- Decision to take: where dedup belongs — the producer (nmap-service, loses data) vs the consumer (front, keeps data). Likely B for display + a conservative A for exact duplicates only.

## Tasks

- [x] DVM-01 Decide producer vs consumer dedup (product decision). User decision 2026-11-26: close as covered, no data dropped in the producer. Exact duplicates are already handled: `vulns_from_cvss_entries` (`src/parser.rs`) keeps one finding per CVE with the highest CVSS within a vulners script, and the front (`ReportDetails.tsx`, `dedupeById`) merges "posibles" by id across the report for display only.
- [x] DVM-02 Implement the chosen approach with tests. Already covered by `vulners_dedupes_cves_keeping_highest_cvss_and_skips_non_cve_entries` (fixture `tests/fixtures/vulners_multi_cve.xml`, CVE-2020-14145 at 5.0 and 4.3 yields one finding) and the front "posibles dedup" tests. No new code in nmap-service.
- [x] DVM-03 Confirm `confirmed` findings are never deduped away and counts stay honest. Gap found: the same CVE confirmed by an NSE script and listed by vulners (vsftpd 2.3.4: `ftp-vsftpd-backdoor` confirmed High plus `vulners` version_match Critical, expected by the parser test at `src/parser.rs` line 821) was shown and counted twice. User decision 2026-11-26: fix it in the front, display only. Front `de77051`: a "posible" whose id is already confirmed (and not dismissed by backport) is not shown or counted, and a note says how many; the JSON export and nmap-service are unchanged. Confirmed findings are still never merged (`las_confirmadas_no_se_deduplican`). Strict TDD RED: 2 new tests failed (the CVE shown twice, Crítica counted); the backport case passed before (characterization). `npm run verify` rc 0 (531 unit, 81 e2e).

## Acceptance criteria

- A vulners output with the same CVE in two entries yields one finding; confirmed findings are untouched; the report's severity counts remain accurate.

## Checks

Strict TDD; `make verify` (nmap-service) and/or `npm run verify` (front) depending on the chosen layer.
