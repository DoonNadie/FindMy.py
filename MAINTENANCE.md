# Maintained fork: maintenance plan

Owner: DoonNadie. Operational maintainer: BobNadie, a supervised AI service account.
Date: 2026-11-16. This is an experimental maintained fork, not an audited product.

## Cadence

- **Monthly:** review upstream changes, dependency advisories, integrity, permissions and test results. Our owner-specific deployment shares the existing monthly FindMy/exporter review (day 1, 10:30 Europe/Madrid); cloning this repository does not install or schedule anything.
- **Before any update:** review the exact diff, requirements/build hooks, licences, new network destinations and known advisories. No automatic dependency updates, rebases or release deployments.
- **After platform/protocol changes or an incident:** diagnose narrowly. A stale location report is not by itself a broken session. No location polling or Apple login is part of the scheduled review.

## Routine review

1. Compare upstream malmeloo/FindMy.py and Anisette changes with accepted code/dependency versions; preserve useful upstream fixes rather than diverging needlessly.
2. Query current advisories with existing tools; public package names/versions may be submitted to OSV, never account data or private source/state.
3. Verify pinned runtime and helper/resource hashes against the accepted baseline. Unexpected changes are an incident, not a reason to regenerate pins.
4. Check sensitive-file modes and paths by metadata only. Do not decrypt state or invoke a Keychain helper for a routine review.
5. Run targeted offline fork/storage tests on reviewed code and record date, source commit, Python/dependency versions and failures. Tests never need Apple credentials or an accessory export.
6. Record a dated report and concise owner summary. State which checks were unavailable; do not carry forward an old clean scan as a current result.

## Change and acceptance gate

1. Define the defect/risk, scope and acceptance criterion.
2. Work in a separate checkout/environment. Preserve known-working code from this maintained fork and encrypted recovery material; exclude all private state from Git.
3. Review source/dependencies before any installation. The owner explicitly approves new third-party installations/updates under the deployment's policy.
4. Run the relevant offline regressions, including password exclusion, invalid tokens, delegate response handling, TLS/redirect policy, header validation and ciphertext/path manipulation.
5. If needed for this specific query-library change, perform one owner-authorized query with the existing session. Do not force fresh login/2FA, exporter runs or changes to iCloud trust to test maintenance.
6. Compare output format, session serialization compatibility, reports and permissions. Fresh login and all supported platforms are separate acceptance scopes, not implied by a saved-session test.
7. Deploy an explicit versioned snapshot, not a mutable branch. Validate its manifest/import origin and preserve an accepted version of this maintained fork when needed for recovery.
8. Verify the normal entrypoint after switching. Update version record, changelog, operation notes and recovery instructions.

## Failure handling and rollback

- **401 / rejected session:** fail clearly; no password-saving workaround, unattended login or retry loop. Apple may require interactive credentials/2FA.
- **Keychain unavailable / bad hash / authentication tag failure:** stop. No plaintext fallback or automatic re-pinning.
- **Network/protocol error:** keep previous state/results separate from the failed new query; never present cached coordinates as a current report.
- **Applicable critical vulnerability:** evaluate actual exposure promptly during the review/incident; stop only the affected component when no safe mitigation exists. This plan is not continuous CVE monitoring.
- Recovery uses a reviewed accepted version of **this maintained fork**, not an automatic fallback to the original upstream client. Change code and routing only, not tokens, provisioning or trust-circle records automatically. Keep the current encrypted state if compatible. Restore old secret state only through a deliberate reviewed recovery procedure.
- Keep the official Find My application as an alternative. Never weaken TLS or disable SIP to make the unofficial client work.

## Ownership and boundaries

Keep MIT copyright and upstream attribution. Preserve reviewable history and identify AI-assisted contributions transparently. Do not publish tokens, passwords, accessory identifiers/locations, exported keys, provisioning, proprietary Apple libraries or private deployment paths.

Anisette 1.2.4 is pinned because the no-download adapter uses a private API; a dependency bump must review that adapter and exercise its fail-closed test. The upstream lock archived under docs/fork is historical, not an up-to-date fork lock. Review current resolution/supply chain for new environments.

Encrypted storage protects at rest, not against the same user/root, malicious filesystem races, rollback/deletion or loss of both ciphertext and key. Copies are not a recovery plan unless the key is recoverable too. This fork's optional encrypted store is not an automatic migration of another application's vault.

GitHub Actions remain disabled in this fork. The plan does not authorize automatic publication, PyPI releases or arbitrary public changes.

## Owner deployment policy update — 2026-11-16

The owner chose to retire the previous upstream client and its rollback entrypoint. The deployment now installs this maintained fork, while the query entrypoint still verifies an explicit source snapshot. Shared dependencies, encrypted state and recovery data are retained. If a defect appears, reproduce it, add a regression and repair the maintained fork; do not automatically reinstall the retired client. Historical Git provenance and MIT attribution remain intact.
