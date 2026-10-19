# codesign-svc

Developer ID code signing and notarization for macOS apps, as a self-hosted
HTTP service.

You run it on a Mac you control. That Mac holds the Developer ID certificate
and the notary credentials. CI jobs (GitHub Actions, GitLab CI) upload an
unsigned `.app` and get back a signed, notarized, stapled zip, and a DMG if
you want one. CI never holds Apple secrets.

```
CI job ── OIDC token + unsigned .app zip ──▶ tunnel ──▶ codesign-svc (LaunchAgent, 127.0.0.1:8787)
                                                        ├─ verify token and allowlist
                                                        ├─ safe unzip, check bundle ids
                                                        ├─ codesign inside-out (no --deep)
                                                        ├─ notarytool submit, poll, staple
                                                        ├─ optional DMG: sign, notarize, staple
                                                        └─ audit log (JSON lines)
CI job ◀── job token: poll status, download result ──
```

## Install with your agent

The `skills/` folder has [Agent Skills](https://agentskills.io) that walk a
coding agent through each setup:

| Skill | Use it to |
|---|---|
| [`setup-signing-host`](skills/setup-signing-host/SKILL.md) | Set up the signing Mac (operator). |
| [`install-github-action`](skills/install-github-action/SKILL.md) | Add a signing step to a GitHub Actions workflow. |
| [`install-gitlab-ci`](skills/install-gitlab-ci/SKILL.md) | Add a signing job to GitLab CI. |

Point your agent at the skill file, or copy the folder into its skills
directory.

## How it works

1. The CI job gets a short-lived OIDC token from its CI provider.
2. It sends `POST /v1/jobs` with the token, a profile name, and a zip that
   holds one `.app`.
3. The service checks the token (issuer, audience, expiry, signature), then
   the allowlist (repo, ref, protected ref, event, profile). It returns a job
   id and a job token. The OIDC token is not used again.
4. One worker runs jobs one at a time: unzip, check bundle ids, sign from the
   inside out, verify, notarize, staple, check with Gatekeeper, zip with
   `ditto`. If the profile says `dmg: true`, it also builds a DMG and signs,
   notarizes, staples and checks it.
5. The CI job polls `GET /v1/jobs/{id}` with the job token and downloads the
   results.

## API

| Method and path | Auth | Result |
|---|---|---|
| `POST /v1/jobs` | OIDC token or access key | `202 {"id", "job_token"}`. Multipart fields, in this order: `profile`, then `file` (a zip with one `.app` at its root). A `Content-Length` header is required. `401` bad or reused token, `403` not allowed, `408` upload stalled, `411` no `Content-Length`, `413` too big, `429` queue full, `503` low disk. |
| `POST /v1/uploads` | OIDC token or access key | Start a chunked upload. JSON `{"profile", "size", "sha256"}`. Same checks and admission as `POST /v1/jobs`. `201 {"upload_id", "upload_token", "part_size", "parts"}`. |
| `PUT /v1/uploads/{id}/parts/{n}` | upload token | Part `n` (0 to `parts`-1), exactly `part_size` bytes except the last. Re-sending a part overwrites it. `204`. |
| `POST /v1/uploads/{id}/complete` | upload token | Checks that all parts arrived and the size and SHA-256 match, then creates the job: `202 {"id", "job_token"}` like `POST /v1/jobs`. The upload token is dead after this. |
| `GET /v1/jobs/{id}` | job token | `{"id", "status", "error", "profile", "bundle_id", "artifacts": {"zip": {"sha256", "notary_id"}, "dmg": {...}}, "signing_report": [{"path", "type", "entitlements", "warning"}]}`. Status is `queued`, `signing`, `notarizing`, `done` or `failed`. |
| `GET /v1/jobs/{id}/artifact?kind=zip\|dmg` | job token | The file. |
| `GET /healthz` | none | `{"status":"ok"}` |
| `GET /client/sign.sh` | none | The client script for this server version. |

A wrong job token and an unknown job both return `404`. Job tokens expire
with the job (`result_ttl`).

**Chunked uploads.** Proxies such as Cloudflare Tunnel refuse request
bodies over 100 MB, and an app zip is often bigger. So the client uploads
in parts of `upload_part_bytes` (default 64 MiB, at most 95 MiB). The queue
slot and disk reservation are taken when the upload starts. An upload with
no activity for `upload_timeout` is dropped, with its slot, reservation and
file; a restart drops all unfinished uploads. `POST /v1/jobs` stays for
small uploads and direct connections. The client script always uses parts.

## Security model

- **Deny by default.** A request passes only when one `allow` rule matches
  the issuer, the repo, a ref glob, and the profile.
- **Protected refs only.** `require_protected_ref` is on by default. The
  token's `ref_protected` claim must be true.
- **No pull request contexts.** Allowed events default to `push`,
  `workflow_dispatch` and `release` on GitHub, and `push` and `web` on
  GitLab. `pull_request`, `pull_request_target`, `workflow_run` and
  `merge_request_event` are denied unless a rule lists them. A rule can also
  pin the workflow file with `workflow_refs`.
- **One token, one job.** The service remembers each token's `jti` until it
  expires and refuses reuse.
- **Server-side profiles.** The identity, keychain, team id, entitlements and
  allowed bundle ids live in the config. Clients only name a profile.
- **Bundle ids.** The top-level `CFBundleIdentifier` must match
  `allowed_bundle_ids`. Every nested `.app`, `.xpc` and `.appex` must have
  that id or one under it (`com.example.app.helper`).
- **Safe unzip.** Pure Go `archive/zip`, not `ditto -x`. It rejects absolute
  paths, `..`, names over 1024 bytes, symlinks that leave the root, and
  writes through symlinks. It caps file count and unpacked bytes, and counts
  real bytes, not header sizes.
- **Signing.** Inside-out, no `--deep`. Symlinks are never followed or
  signed. Entitlements go only to the main app, nested `.app`/`.xpc`/`.appex`
  bundles and standalone executables (`MH_EXECUTE`), never to frameworks,
  dylibs or plugins. After signing: `codesign --verify --deep --strict` and a
  team id check. The job status has a `signing_report` that lists every
  signed path, its Mach-O type and its entitlements file.
- **The service never runs uploaded code.** Run your app's binaries in the
  client's smoke check instead (see below).
- **Admission order.** Token, allowlist (repo, ref, event, protected ref,
  workflow) and replay are checked before a queue slot or disk is taken. The
  profile is checked when its form field arrives, before the file is read.
- **Bounds.** Bounded queue, one worker, a timeout on every external command,
  a per-job deadline, an upload size limit, an upload read deadline
  (`upload_timeout`), disk reservations (see below), a record-by-record
  walk of the zip central directory before the zip is opened (end-record
  counts are not trusted), and result cleanup after `result_ttl` or past
  `max_retained_jobs`.
- **Tokens are burned only on admission.** A `429` or `503` leaves the
  OIDC token usable for a retry.

### Disk sizing

Each admitted job reserves its upload size plus 3 x `max_expanded_bytes`
(default 4 GiB): the unpacked app, the notary and output zips, and the DMG
staging copy plus the DMG. A new job gets `503` when free disk minus all
reservations would fall below `min_free_bytes` (default 20 GiB). A
reservation ends when its job finishes. During extraction the service also
checks real free disk every 256 MiB and fails the job below
`min_free_bytes`.

So one job with the defaults needs about 20 + 12 GiB free, plus the
upload. Size the disk for `queue_size` jobs, or lower `max_expanded_bytes`
to fit your largest app.
- **Secrets stay off argv.** The optional keychain password goes to
  `security -i` on stdin. Job tokens and access keys are stored only as
  SHA-256 hashes.
- **Audit log.** One JSON line per job: issuer, repo, ref, commit, event, run
  URL, access key id, profile, bundle id, input and output SHA-256, result.

## Electron apps

Electron apps ship helper apps and often extra executables, such as a
bundled Node at `Contents/Resources/node/bin/node`. Under the hardened
runtime, a V8 or Node binary without `com.apple.security.cs.allow-jit`
crashes at start ("Failed to reserve virtual memory for CodeRange").

- Set `entitlements` to the plist you use for electron-builder's
  `entitlements`.
- Set `inherit_entitlements` to the plist you use for electron-builder's
  `entitlementsInherit`. It must include
  `com.apple.security.cs.allow-jit`. It applies to every nested
  `.app`/`.xpc`/`.appex` and every standalone executable.
- Use `entitlement_overrides` for single paths that need something else.
- Check `signing_report` in the job status. A `warning` marks an executable
  signed with the hardened runtime and no entitlements.
- Add a smoke command to the client so CI starts the signed binaries.

## Zip archives: use ditto

A `.framework` bundle uses symlinks (`Versions/Current`, top-level links).
Plain `zip -r` follows symlinks, stores copies, and breaks the bundle and
its signature. So:

- On macOS the client always uses `ditto -c -k --keepParent`.
- On other systems it uses `zip -r -y`, which keeps symlinks, and prints a
  warning. Never use `zip` without `-y` for an app.
- The service accepts both and rejects an archive whose frameworks lost
  their symlinks: "archive lost symlinks; create it with ditto -c -k
  --keepParent".
- Results are always made with `ditto -c -k --keepParent`.

## Host setup

Use a dedicated Mac (a Mac mini is enough) and a dedicated macOS user, for
example `signer`. Do not run CI runners on this Mac.

1. **User and session.** Create the `signer` user and turn on automatic login
   for it. The service must run as a LaunchAgent in that user's GUI session.
   A LaunchDaemon cannot use the keychain for `codesign` and fails with
   `errSecInternalComponent`. Note: with FileVault on, automatic login is not
   possible, so someone must log in once after each reboot.

2. **Signing keychain.** Use a separate keychain, not the login keychain:

   ```sh
   security create-keychain -p "$KC_PASS" ~/Library/Keychains/signing.keychain-db
   security set-keychain-settings ~/Library/Keychains/signing.keychain-db   # no auto-lock timeout
   security import DeveloperID.p12 -k ~/Library/Keychains/signing.keychain-db \
     -P "$P12_PASS" -T /usr/bin/codesign
   security set-key-partition-list -S apple-tool:,apple:,codesign: -s \
     -k "$KC_PASS" ~/Library/Keychains/signing.keychain-db
   security list-keychains -d user -s ~/Library/Keychains/signing.keychain-db \
     ~/Library/Keychains/login.keychain-db
   security find-identity -v -p codesigning ~/Library/Keychains/signing.keychain-db
   ```

   The keychain must be unlocked when a job runs. Unlock it after login, or
   set `CODESIGN_KEYCHAIN_PASSWORD_FILE` in the LaunchAgent to a file (mode
   0600) with the password; the service then unlocks the keychain before
   each job. The password never goes into argv or logs.

3. **Notary credentials.** Pick one per profile.
   - **Recommended:** an App Store Connect API key. Put the `.p8` file in the
     `signer` home, owned by `signer`, mode 0600. Set `notary.api_key_path`,
     `key_id` and `issuer_id`. The service refuses to start if the file is
     readable by others.
   - Or a notarytool keychain profile:
     `xcrun notarytool store-credentials example-notary --key AuthKey_X.p8
     --key-id X --issuer <uuid> --keychain ~/Library/Keychains/signing.keychain-db`,
     then set `notary.keychain_profile` and `notary.keychain`.

4. **Config.** Copy `config.example.yaml` to
   `~/codesign-svc/config.yaml` and edit it. Keep `listen` on `127.0.0.1`.

5. **Install and start.**

   ```sh
   go build -o /usr/local/bin/codesign-svc ./cmd/codesign-svc
   cp deploy/codesign-svc.plist ~/Library/LaunchAgents/local.codesign-svc.plist
   launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/local.codesign-svc.plist
   curl -s http://127.0.0.1:8787/healthz
   ```

6. **Expose it.** Use a tunnel, for example Cloudflare Tunnel
   (`cloudflared tunnel --url http://127.0.0.1:8787`, or a named tunnel with a
   hostname). The service has no TLS of its own. Uploads go up in parts of
   at most 95 MiB, so the 100 MB body limit of Cloudflare does not apply.

7. **Smoke test.** Sign a known app from an allowed repo and ref. Then call
   from a repo or branch that is not allowed and check that you get `403`.
   Reboot the Mac and sign again without touching it.

## Auth: OIDC first, access keys as fallback

Use OIDC when your CI supports it. Tokens are short-lived and name the repo
and ref, so the allowlist can check them.

Access keys are for CI without OIDC, or for local use. They are off by
default. Turn them on with `access_keys.enabled: true` and a `file` path,
then:

```sh
codesign-svc keys create -config config.yaml -name ci-example -profiles example-release -expires 90d
codesign-svc keys list   -config config.yaml
codesign-svc keys revoke -config config.yaml <id>
```

`create` prints the key (`csk_<id>_<secret>`) once. The service stores only
a SHA-256 of the secret. A key can use only the profiles it was made with;
`allow` rules do not apply to keys, so keep the profile list short. Always
set an expiry and rotate keys before they expire. The audit log records the
key id and name.

## Clients

Both clients use [`clients/sign.sh`](clients/sign.sh) (POSIX `sh`, `curl`
and `dd`). It uploads in parts and retries a part up to 3 times after a
network error or a 5xx; any other error fails the step. Every `curl` call has a connect timeout and a time limit inside the
overall deadline (`timeout-minutes`).

After download, on macOS, the client checks the result:
`codesign --verify --deep --strict`, `spctl -a -t exec` and
`stapler validate` for the app, and `spctl -a -t open --context
context:primary-signature` and `stapler validate` for the DMG. Set `verify`
to `0` to skip this.

An optional smoke command then runs on macOS with `$APP` set to the signed
`.app`. A non-zero exit fails the step. It may run for `smoke-timeout`
seconds (default 300, never past the overall deadline); then it and every
process it started are killed and the step fails. It runs headless: do not
use `open -W -n`. Electron example:

```yaml
smoke-command: |
  "$APP/Contents/Resources/node/bin/node" --version
  ELECTRON_RUN_AS_NODE=1 "$APP/Contents/MacOS/Example" --version
```

GitHub Actions:

```yaml
permissions:
  contents: read
  id-token: write
steps:
  - uses: <owner>/<repo>/clients/github@<tag>
    id: sign
    with:
      url: https://codesign.example.com
      profile: example-release
      path: dist/mac-universal/Example.app
      smoke-command: '"$APP/Contents/Resources/node/bin/node" --version'
  - run: echo "${{ steps.sign.outputs.zip }}"
```

GitLab CI:

```yaml
include:
  - remote: https://raw.githubusercontent.com/<owner>/<repo>/<tag>/clients/gitlab/sign.gitlab-ci.yml
sign-macos:
  extends: .codesign
  variables:
    CODESIGN_URL: https://codesign.example.com
    CODESIGN_PROFILE: example-release
    CODESIGN_PATH: dist/Example.app
```

Run the GitHub step on a macOS runner to get the checks and the smoke
command. On Linux runners they are skipped (a smoke command then fails the
step). Check a result by hand on any Mac:

```sh
ditto -x -k signed/Example.zip /tmp/check
spctl -a -t exec -vv /tmp/check/Example.app
xcrun stapler validate /tmp/check/Example.app
```

## Development

```sh
go vet ./...
go test ./...
gofmt -l .
shellcheck -s sh clients/sign.sh
```

Tests never run the real `codesign` or `notarytool`; they use a fake command
runner. For a local run without OIDC, set `dev_mode.enabled: true`, export
the token in `CODESIGN_DEV_TOKEN`, and add an allow rule with
`issuer: dev`. Never enable dev mode on a real signing host.

## Not in scope

`.pkg` signing, Windows, more than one worker, a web UI, metrics.

## License

MIT
