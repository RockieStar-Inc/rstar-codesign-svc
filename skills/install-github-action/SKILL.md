---
name: install-github-action
description: Add a codesign-svc signing and notarization step to a GitHub Actions workflow that builds a macOS .app. Use when a repo must ship a Developer ID signed, notarized app and a codesign-svc host exists.
---

# Add codesign-svc to a GitHub Actions workflow

Goal: the workflow uploads the unsigned `.app` to codesign-svc and gets back
a signed, notarized, stapled zip (and a DMG if the profile builds one). The
repo stores no Apple certificate or password.

## Before you start

Get these from the service operator. Do not guess them.

- Service URL, for example `https://codesign.example.com`.
- Profile name, for example `example-release`.
- OIDC audience the service expects (default `codesign`).

## Steps

1. Find the job that builds the `.app` and the path of the `.app`.

2. Give the signing job OIDC permission. Add at job or workflow level:

   ```yaml
   permissions:
     contents: read
     id-token: write
   ```

3. Run the step on a macOS runner (`runs-on: macos-latest`): the action
   then zips with `ditto`, checks the result with `codesign`, `spctl` and
   `stapler`, and runs the smoke command. Never zip the app with plain
   `zip -r`; it breaks frameworks.

   Add the step after the build. Pin `@<tag>` to a release of codesign-svc.

   ```yaml
   - uses: <owner>/<repo>/clients/github@<tag>
     id: sign
     with:
       url: https://codesign.example.com
       profile: example-release
       path: dist/Example.app        # or a .zip with one .app at its root
       # audience: codesign
       # output-dir: signed
       # Runs on macOS after download with $APP set; non-zero fails the step.
       smoke-command: |
         "$APP/Contents/MacOS/Example" --version
       # smoke-timeout: 300   # seconds; the command and its children are killed after this
   - uses: actions/upload-artifact@v4
     with:
       name: signed-macos
       path: signed/
   ```

   Outputs: `steps.sign.outputs.zip`, `steps.sign.outputs.dmg`,
   `steps.sign.outputs.job-id`.

4. Run the step only on refs the service allows, for example:

   ```yaml
   on:
     push:
       tags: ["v*"]
   ```

   The service denies `pull_request`, `pull_request_target` and
   `workflow_run` by default, and requires a protected ref. Protect the
   branch or tag in repo settings (Settings, Rules), or the token claim
   `ref_protected` is false and the request gets `403`.

5. Ask the operator to add an allow rule. Send them this, filled in:

   ```yaml
   - issuer: https://token.actions.githubusercontent.com
     repo: example-org/example-app
     refs: [refs/tags/v*]
     profiles: [example-release]
     workflow_refs:
       - example-org/example-app/.github/workflows/release.yml@refs/tags/v*
   ```

## No OIDC available

If the operator gives you an access key instead, store it as a secret
`CODESIGN_ACCESS_KEY` and add `access-key: ${{ secrets.CODESIGN_ACCESS_KEY }}`
to `with:`. Then `id-token: write` is not needed. Prefer OIDC.

## Check the result

On a Mac:

```sh
ditto -x -k signed/Example.zip /tmp/check
spctl -a -t exec -vv /tmp/check/Example.app      # "source=Notarized Developer ID"
xcrun stapler validate /tmp/check/Example.app    # "The validate action worked!"
# DMG, if built:
spctl -a -t open --context context:primary-signature -vv signed/Example.dmg
xcrun stapler validate signed/Example.dmg
```

## Electron apps

Ask the operator to set `inherit_entitlements` on the profile to your
electron-builder `entitlementsInherit` plist (with
`com.apple.security.cs.allow-jit`). Add a smoke command that starts every
bundled executable with `--version`, for example:

```yaml
smoke-command: |
  "$APP/Contents/Resources/node/bin/node" --version
  ELECTRON_RUN_AS_NODE=1 "$APP/Contents/MacOS/Example" --version
```

Do not use `open -W -n`; the smoke command runs headless.

## Errors

- `HTTP 401`: no `id-token: write`, wrong audience, or the token was reused.
- `HTTP 403`: the reason names the failed check (ref, protected ref, event,
  workflow, profile). Fix the trigger or ask for a rule change.
- `smoke test failed`: a signed binary does not start. Look for a
  `warning` in the signing report (missing entitlements).
- `archive lost symlinks`: the zip was made with plain `zip -r`. Pass the
  `.app` path instead, or zip with `ditto -c -k --keepParent`.
- `job failed: ... bundle id`: the app's `CFBundleIdentifier` is not in the
  profile, or a nested helper id is not under the main id.
- `job failed: notarization ... Invalid`: the error lists Apple's notary log
  issues.
