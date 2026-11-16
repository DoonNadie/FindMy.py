# Maintained fork: scope and operation

Version `0.10.2+doonnadie.1`, based on upstream `22e4879` (0.10.2).

## Implemented changes

- Raw account passwords are never included by `to_json` and are ignored when restoring old states. Tokens and provisioning data remain sensitive. In-memory passwords can be dropped with `forget_password`; no promise of secure memory erasure.
- Saved-token rejection without a password raises `ReauthenticationRequiredError` (an `UnauthorizedError` subtype), rather than silently retrying missing credentials. Persistence is not a promise of perpetual access or no future 2FA.
- Account requests require certificate-verified HTTPS, no userinfo/fragments/control characters, port 443 and Apple/icloud domain boundaries. Redirects are rejected, not followed; bodies have a 64 MiB default limit. Transport errors and selected protocol errors omit remote text, URLs and bodies.
- Numeric zero delegate status is preserved. Delegate structure and a nonempty searchPartyToken are checked before marking login successful.
- `ExternalAnisetteProvider` accepts an explicitly supplied async loader, validates an allowlist of headers, rejects duplicates, empty values and control characters, and preserves the loader's coherent LU/device/client identity. No shell commands or servers are created by this class. It must be supplied explicitly on restore.
- Local Anisette requires a reviewed local file and has a fail-closed filesystem fallback. It does not download missing binary libraries or overwrite the supplied file. The private dependency adapter is bound to **Anisette 1.2.4** and must be reviewed before changing that pin.
- Optional `EncryptedStateStore` stores JSON using AES-256-GCM with version/name-authenticated data, random nonces, 0700/0600, atomic writes and symlink/hardlink checks. The application supplies a 32-byte key; the library never saves that key. `AsyncAppleAccount.save_encrypted` uses this store.
- Package discovery includes all `findmy.*` subpackages.

## Intentional compatibility changes

Plain HTTP to remote Anisette is rejected by the default transport; use reviewed HTTPS or an explicit local loader. The legacy `allow_unverified_https` opt-in still exists for a caller-owned remote provider only; **do not enable it for normal use**. It never weakens the separate account transport.

Local binary auto-download is removed. Missing/invalid local libraries fail rather than fetching replacements. Original examples that relied on a download must supply `libs_path`.

Legacy `account.to_json(path)` still writes **plaintext token JSON** for API compatibility, despite excluding the password. Prefer `save_encrypted`. Older state files may still contain passwords: loading them does not erase those files or old backups. The optional store has its own format; it does not migrate another application's encrypted files automatically.

The prior upstream `uv.lock` is preserved as `docs/fork/upstream-uv.lock` **for provenance only**. It is not a current fork lock. `dependency-review.json` records versions of the pre-existing test environment, including the installed upstream distribution used for dependencies; the fork itself was loaded from this checkout. Resolve/review dependencies for a new environment before installing; no automated update or PyPI publication is configured.

## Encrypted state example

The application retrieves a persistent 32-byte key from its reviewed secret store (e.g. macOS Keychain). Never hard-code it or generate a different key each time.

```python
from pathlib import Path
from findmy.storage import EncryptedStateStore
from findmy.reports.account import AsyncAppleAccount

# key = your_reviewed_keychain_adapter.read_key()  # exactly 32 bytes
# provider = your_explicit_anisette_provider
store = EncryptedStateStore(Path.home() / "private-findmy-state", key)
# After an authorized interactive login, or after a successful token refresh:
account.save_encrypted(store, "account.json")
# Restore with the same key and explicit provider:
restored = AsyncAppleAccount(provider, state_info=store.read_json("account.json"))
```

This is a sketch: `key`, `provider` and `account` are supplied by your application, not secrets shipped with this repository. The parent directory must already exist, be trusted and have no symlink components. Existing insecure state directories/files are refused rather than silently chmodded. The store is POSIX-only, last-writer-wins and not a sandbox against the same user/root, malicious concurrent path changes, rollback or deletion. Arrange backups of both encrypted state and a recoverable key separately.

For a macOS application-level Keychain integration and explicit local resource review see the separate companion [findmy-local-tools](https://github.com/DoonNadie/findmy-local-tools). It is not installed or automatically modified by this fork.

## Verification performed on 2026-11-16

- 22 offline fork-security tests plus 10 encrypted-store tests, using unittest and the already present isolated Python 3.14 environment. No new test packages were installed.
- The offline tests also exercise 100 generated keypairs and TLS root/default verification checks. The upstream pytest suite was **not run as pytest** (pytest is not installed in this environment); these are targeted fork regressions, not a claim of all upstream test configurations passing.
- OSV query of 32 installed test-environment packages returned no known advisories at review time. This is not a dependency/code audit, signed supply-chain guarantee or future safety claim.
- The fork's actual source, default account class and external identity provider successfully queried/decrypted reports for **two owner-controlled accessories**, using existing encrypted tokens/keys and a reviewed local loader. No password, new login, 2FA, trust-circle mutation or production package replacement occurred.
- Fresh login/2FA, token expiry over time, another Mac/account, the new store with real production data, and every supported Python/platform combination remain unverified. Synthetic tests cover delegate negotiation; a fresh Apple login was intentionally not repeated.

Reproduce the offline tests after reviewing/installing the declared dependencies in an isolated environment:

```sh
python -m unittest discover -s tests -p 'test_fork_security.py' -v
python -m unittest discover -s tests -p 'test_storage.py' -v
```

## Maintenance and recovery

Keep `upstream` pointing to malmeloo/FindMy.py and compare upstream security/protocol changes before merging. Do not run blanket updates or change the Anisette adapter pin without reviewing source and rerunning tests. Keep a known-working production package separate; test upgrades against isolated data before migration and keep a rollback copy. Never run an accessory exporter to test this query library.

There is no promise of continuous autonomous maintenance. The owner-specific monthly exporter review has been extended to include this fork under the same scheduled job; this does not schedule anything for other users. See [the maintenance plan](../../MAINTENANCE.md). Do not store passwords as a shortcut to renewal; interactive Apple checks may remain necessary. Never publish private state, locations, identifiers or proprietary Apple libraries. Preserve upstream MIT licensing and attribution in all redistributions.
