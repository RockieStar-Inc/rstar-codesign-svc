---
name: setup-signing-host
description: Set up a Mac as a codesign-svc signing host - dedicated user, signing keychain, Developer ID certificate, notary credentials, config, LaunchAgent, tunnel, smoke test, access keys. Use when an operator installs or repairs codesign-svc.
---

# Set up a codesign-svc signing host

Goal: a Mac that signs and notarizes macOS apps for CI, unattended, after a
reboot. Do each step in order. Stop and report if a check fails.

Inputs you need from the operator:

- The Developer ID Application certificate as a `.p12` and its password.
- An App Store Connect API key (`AuthKey_<KEYID>.p8`), its key id and
  issuer id. Role: Developer is enough for notarization.
- The public hostname for the service, if it will be exposed.
- The repos, refs and bundle ids to allow.

Never print or commit passwords, the `.p12`, or the `.p8`.

## 1. Dedicated user and session

1. Create a standard user, for example `signer`. Do not install CI runners
   on this Mac.
2. Turn on automatic login for `signer` (System Settings, Users & Groups).
   FileVault blocks automatic login; if FileVault is on, someone must log in
   once after each reboot. Tell the operator.
3. Turn off sleep (System Settings, Energy) so the service stays reachable.

Why: `codesign` needs the user's GUI security session. The service runs as
a LaunchAgent in that session. A LaunchDaemon fails with
`errSecInternalComponent`.

## 2. Signing keychain

Run as `signer`:

```sh
KC=~/Library/Keychains/signing.keychain-db
security create-keychain -p "$KC_PASS" "$KC"
security set-keychain-settings "$KC"            # no -t: no auto-lock timeout
security import DeveloperID.p12 -k "$KC" -P "$P12_PASS" -T /usr/bin/codesign
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$KC_PASS" "$KC"
security list-keychains -d user -s "$KC" ~/Library/Keychains/login.keychain-db
security find-identity -v -p codesigning "$KC"
```

Check: `find-identity` lists `Developer ID Application: <Name> (<TEAMID>)`.
Note the team id and the identity name (or SHA-1).

Unlock: either unlock after login, or write the keychain password to
`~/codesign-svc/keychain-password` (mode 0600) and set
`CODESIGN_KEYCHAIN_PASSWORD_FILE` in the LaunchAgent. The password must be
one line without `"` or `\`.

## 3. Notary credentials

Recommended: the API key file.

```sh
mkdir -p ~/codesign-svc && chmod 700 ~/codesign-svc
mv AuthKey_ABCDE12345.p8 ~/codesign-svc/
chmod 600 ~/codesign-svc/AuthKey_ABCDE12345.p8
```

Config: `notary: {api_key_path: ..., key_id: ABCDE12345, issuer_id: <uuid>}`.

Alternative: a keychain profile.

```sh
xcrun notarytool store-credentials example-notary \
  --key ~/codesign-svc/AuthKey_ABCDE12345.p8 --key-id ABCDE12345 \
  --issuer <uuid> --keychain ~/Library/Keychains/signing.keychain-db
```

Config: `notary: {keychain_profile: example-notary, keychain: <path>}`.

## 4. Build and configure

```sh
go build -o /usr/local/bin/codesign-svc ./cmd/codesign-svc
cp config.example.yaml ~/codesign-svc/config.yaml
```

Edit `~/codesign-svc/config.yaml`:

- `work_dir`, `audit_log` under `~/codesign-svc`. Disk: each job reserves
  upload + 3 x `max_expanded_bytes` (default 4 GiB) on top of
  `min_free_bytes` (default 20 GiB). Lower `max_expanded_bytes` to your
  largest unpacked app if disk is small.
- One `issuers` entry per CI provider, with the agreed `audience`.
- One `profiles` entry per signing setup: `identity`, `keychain`, `team_id`,
  `allowed_bundle_ids`, `entitlements`, `entitlement_overrides` (for helper
  apps), `notary`, `dmg`.
- Electron apps: set `inherit_entitlements` to the same plist as
  electron-builder's `entitlementsInherit`. It must contain
  `com.apple.security.cs.allow-jit`, or bundled Node/V8 binaries (for
  example `Contents/Resources/node/bin/node`) crash at start under the
  hardened runtime. After the first job, read `signing_report` in the job
  status: no executable should have a `warning`.
- One `allow` rule per repo: `issuer`, `repo`, `refs`, `profiles`. Keep
  `require_protected_ref` on. Add `workflow_refs` on GitHub when you can.

## 5. LaunchAgent

```sh
sed "s#/Users/signer#$HOME#g" deploy/codesign-svc.plist \
  > ~/Library/LaunchAgents/local.codesign-svc.plist
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/local.codesign-svc.plist
curl -s http://127.0.0.1:8787/healthz
tail ~/codesign-svc/codesign-svc.log
```

Check: `{"status":"ok"}`. If the service exits, the log says why (bad
config, `.p8` readable by others, work dir writable by others).

## 6. Tunnel

The service listens on `127.0.0.1` and has no TLS. Expose it with a tunnel,
for example a named Cloudflare Tunnel that maps `codesign.example.com` to
`http://127.0.0.1:8787`. Run the tunnel as its own LaunchAgent or service.
Uploads arrive in parts of `upload_part_bytes` (default 64 MiB, at most
95 MiB), so Cloudflare's 100 MB request body limit is not a problem.

## 7. Smoke test

1. From an allowed repo and protected ref, run the CI step (see the
   `install-github-action` or `install-gitlab-ci` skill). Check the result
   with `spctl -a -t exec -vv` and `xcrun stapler validate`.
2. From a branch that is not allowed, run it again. Expect `HTTP 403`.
3. Reboot the Mac. Without logging in by hand, sign again. Expect success.
4. Read `~/codesign-svc/audit.jsonl`: one line per job.

## 8. Access keys (only when OIDC is not possible)

```sh
# in config.yaml: access_keys: {enabled: true, file: /Users/signer/codesign-svc/access-keys.json}
codesign-svc keys create -config ~/codesign-svc/config.yaml \
  -name example-ci -profiles example-release -expires 90d
```

The key prints once. Give it to the CI owner through a secret store, not
chat. List with `keys list`, revoke with `keys revoke <id>`. Set a reminder
to rotate before expiry. Restarting the service is not needed.
