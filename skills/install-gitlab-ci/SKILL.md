---
name: install-gitlab-ci
description: Add a codesign-svc signing and notarization job to GitLab CI for a macOS .app. Use when a GitLab project must ship a Developer ID signed, notarized app and a codesign-svc host exists.
---

# Add codesign-svc to GitLab CI

Goal: a CI job uploads the unsigned `.app` to codesign-svc and gets back a
signed, notarized, stapled zip (and a DMG if the profile builds one). The
project stores no Apple certificate or password.

## Before you start

Get these from the service operator. Do not guess them.

- Service URL, for example `https://codesign.example.com`.
- Profile name, for example `example-release`.
- OIDC audience the service expects (default `codesign`).

## Steps

1. Find the job that builds the `.app` and the artifact path of the `.app`.

2. Include the template and add a job. Pin `<tag>` to a release of
   codesign-svc.

   ```yaml
   include:
     - remote: https://raw.githubusercontent.com/<owner>/<repo>/<tag>/clients/gitlab/sign.gitlab-ci.yml

   sign-macos:
     extends: .codesign
     stage: deploy
     needs: [build-macos]
     variables:
       CODESIGN_URL: https://codesign.example.com
       CODESIGN_PROFILE: example-release
       CODESIGN_PATH: dist/Example.app     # or a .zip with one .app at its root
     rules:
       - if: $CI_COMMIT_TAG =~ /^v/
   ```

   The template sets:

   ```yaml
   id_tokens:
     CODESIGN_ID_TOKEN:
       aud: codesign
   ```

   If the service uses another audience, override `id_tokens` in your job.

3. The job image needs `sh` and `curl`. Prefer a macOS runner: the script
   then zips with `ditto`, checks the result with `codesign`, `spctl` and
   `stapler`, and can run `CODESIGN_SMOKE_CMD` (with `$APP` set to the
   signed app). On Linux it uses `zip -r -y` (keep symlinks) and skips the
   checks; a smoke command fails there. Never zip the app with plain
   `zip -r`. Results land in `signed/` and are saved as job artifacts.
   For Electron apps, set `CODESIGN_SMOKE_CMD` to start each bundled
   executable with `--version`. `CODESIGN_SMOKE_TIMEOUT` (default 300 s)
   limits it.

4. Run the job only on protected refs. The service requires the token claim
   `ref_protected` to be true. Protect the tag pattern (`v*`) or branch in
   Settings, Repository, Protected tags / Protected branches. The service
   allows the pipeline sources `push` and `web` by default and denies
   `merge_request_event` and `external_pull_request_event`.

5. Ask the operator to add an allow rule. Send them this, filled in:

   ```yaml
   - issuer: https://gitlab.com            # or your self-hosted GitLab URL
     repo: example-group/example-app       # project_path
     refs: [refs/tags/v*]
     profiles: [example-release]
   ```

## No OIDC available

If the operator gives you an access key instead, store it as a masked,
protected CI/CD variable `CODESIGN_ACCESS_KEY`. The script uses it before
the ID token. Prefer OIDC.

## Check the result

On a Mac:

```sh
ditto -x -k signed/Example.zip /tmp/check
spctl -a -t exec -vv /tmp/check/Example.app      # "source=Notarized Developer ID"
xcrun stapler validate /tmp/check/Example.app
# DMG, if built:
spctl -a -t open --context context:primary-signature -vv signed/Example.dmg
xcrun stapler validate signed/Example.dmg
```

## Errors

- `HTTP 401`: wrong audience, unknown issuer, or a reused token.
- `HTTP 403`: the reason names the failed check (ref, protected ref,
  pipeline source, profile).
- `job failed: ...`: read the error; notarization errors include Apple's
  notary log issues.
