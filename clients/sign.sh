#!/bin/sh
# Client for codesign-svc. Uploads an unsigned macOS .app, waits for the
# signed and notarized result, downloads it, and on macOS verifies it.
#
# Environment:
#   CODESIGN_URL          service base URL (required)
#   CODESIGN_PROFILE      signing profile name (required)
#   CODESIGN_PATH         path to the .app, or a .zip with one .app at its root (required)
#   CODESIGN_OUTPUT_DIR   where results go (default: signed)
#   CODESIGN_TIMEOUT_MIN  how long the whole run may take (default: 90)
#   CODESIGN_VERIFY       1 (default) runs codesign/spctl/stapler checks on macOS; 0 skips them
#   CODESIGN_SMOKE_CMD    optional shell command run on macOS after download,
#                         with $APP set to the signed .app; non-zero fails
#   CODESIGN_SMOKE_TIMEOUT  seconds the smoke command may run (default: 300)
# Credentials, first match wins:
#   CODESIGN_ACCESS_KEY   access key (csk_...) from the service operator
#   CODESIGN_ID_TOKEN     OIDC token (GitLab: from id_tokens)
#   ACTIONS_ID_TOKEN_REQUEST_URL/TOKEN  GitHub Actions; needs id-token: write
#   CODESIGN_AUDIENCE     audience for the GitHub token (default: codesign)
#
# The OIDC token or access key is used only to create the job. Status and
# downloads use the job token the service returns. No token is printed.
set -eu
set +x

die() { echo "codesign: $*" >&2; exit 1; }
note() { echo "codesign: $*"; }

: "${CODESIGN_URL:?CODESIGN_URL is required}"
: "${CODESIGN_PROFILE:?CODESIGN_PROFILE is required}"
: "${CODESIGN_PATH:?CODESIGN_PATH is required}"
OUT_DIR=${CODESIGN_OUTPUT_DIR:-signed}
TIMEOUT_MIN=${CODESIGN_TIMEOUT_MIN:-90}
AUDIENCE=${CODESIGN_AUDIENCE:-codesign}
VERIFY=${CODESIGN_VERIFY:-1}
SMOKE=${CODESIGN_SMOKE_CMD:-}
SMOKE_TIMEOUT=${CODESIGN_SMOKE_TIMEOUT:-300}
BASE=${CODESIGN_URL%/}
case "$TIMEOUT_MIN" in '' | *[!0-9]*) die "CODESIGN_TIMEOUT_MIN must be a number" ;; esac
case "$SMOKE_TIMEOUT" in '' | *[!0-9]*) die "CODESIGN_SMOKE_TIMEOUT must be a number" ;; esac

command -v curl >/dev/null 2>&1 || die "curl is required"
IS_MAC=0
[ "$(uname -s)" = Darwin ] && IS_MAC=1
[ -z "$SMOKE" ] || [ "$IS_MAC" = 1 ] || die "CODESIGN_SMOKE_CMD needs macOS; run this step on a macOS runner"

DEADLINE=$(($(date +%s) + TIMEOUT_MIN * 60))
# remaining prints the seconds left before the deadline, or fails.
remaining() {
	left=$((DEADLINE - $(date +%s)))
	[ "$left" -gt 0 ] || die "timed out after $TIMEOUT_MIN minutes"
	echo "$left"
}
# Every curl call has a connect timeout and a total time limit that never
# passes the deadline. MAX_SECONDS 0 means all remaining time.
fetch() { # fetch MAX_SECONDS curl-args...
	max=$1
	shift
	left=$((DEADLINE - $(date +%s)))
	if [ "$left" -le 0 ]; then
		echo "codesign: timed out after $TIMEOUT_MIN minutes" >&2
		return 124
	fi
	if [ "$max" = 0 ] || [ "$max" -gt "$left" ]; then max=$left; fi
	curl -sS --connect-timeout 30 --max-time "$max" "$@"
}

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT INT TERM
umask 077

# Headers go through a file so tokens never appear in argv.
header_file() {
	printf 'Authorization: Bearer %s\n' "$1" >"$TMP/auth.$2"
	echo "$TMP/auth.$2"
}

json_field() { # json_field NAME < json  (flat string fields only)
	sed -n "s/.*\"$1\":\"\([^\"]*\)\".*/\1/p"
}

json_num() { # json_num NAME < json  (flat integer fields only)
	sed -n "s/.*\"$1\":\([0-9][0-9]*\).*/\1/p"
}

credential() {
	if [ -n "${CODESIGN_ACCESS_KEY:-}" ]; then
		printf '%s' "$CODESIGN_ACCESS_KEY"
	elif [ -n "${CODESIGN_ID_TOKEN:-}" ]; then
		printf '%s' "$CODESIGN_ID_TOKEN"
	elif [ -n "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" ] && [ -n "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}" ]; then
		fetch 60 -f -H "@$(header_file "$ACTIONS_ID_TOKEN_REQUEST_TOKEN" gh)" \
			"${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=${AUDIENCE}" | json_field value
	else
		die "no credential: set CODESIGN_ACCESS_KEY, CODESIGN_ID_TOKEN, or grant id-token: write on GitHub"
	fi
}

# kill_group sends TERM to a process group, waits up to 5 s for it to empty,
# then sends KILL. It returns only after the KILL step.
kill_group() {
	kill -TERM -- "-$1" 2>/dev/null || return 0
	i=0
	while [ "$i" -lt 5 ] && kill -0 -- "-$1" 2>/dev/null; do
		sleep 1
		i=$((i + 1))
	done
	kill -KILL -- "-$1" 2>/dev/null || true
}

sha256() {
	if command -v shasum >/dev/null 2>&1; then
		shasum -a 256 "$1" | cut -d' ' -f1
	else
		sha256sum "$1" | cut -d' ' -f1
	fi
}

# 1. Package the app. Plain `zip -r` follows symlinks and breaks .framework
# bundles, so macOS always uses ditto and other systems use `zip -r -y`.
case "$CODESIGN_PATH" in
*.zip)
	[ -f "$CODESIGN_PATH" ] || die "$CODESIGN_PATH not found"
	ZIP=$CODESIGN_PATH
	NAME=$(basename "$CODESIGN_PATH" .zip)
	;;
*.app | *.app/)
	APP_IN=${CODESIGN_PATH%/}
	[ -d "$APP_IN" ] || die "$APP_IN is not a directory"
	NAME=$(basename "$APP_IN" .app)
	ZIP=$TMP/$NAME.zip
	if [ "$IS_MAC" = 1 ]; then
		ditto -c -k --keepParent "$APP_IN" "$ZIP"
	else
		command -v zip >/dev/null 2>&1 || die "zip is required"
		note "WARNING: not on macOS; zipping with 'zip -r -y'. macOS with ditto is recommended."
		(cd "$(dirname "$APP_IN")" && zip -q -r -y "$ZIP" "$(basename "$APP_IN")")
	fi
	;;
*) die "CODESIGN_PATH must be a .app directory or a .zip" ;;
esac

# 2. Upload in parts, then create the job. Proxies such as Cloudflare refuse
# request bodies over 100 MB, so the zip goes up in parts of part_size bytes.
case "$CODESIGN_PROFILE" in *[!A-Za-z0-9._-]*) die "CODESIGN_PROFILE may hold only letters, digits, '.', '_' and '-'" ;; esac
SIZE=$(wc -c <"$ZIP" | tr -d ' ')
ZIP_SHA=$(sha256 "$ZIP")
CRED=$(credential)
[ -n "$CRED" ] || die "could not get a credential"
note "uploading $NAME ($SIZE bytes) to $BASE (profile $CODESIGN_PROFILE)"
code=$(fetch 60 -o "$TMP/upload.json" -w '%{http_code}' -X POST \
	-H "@$(header_file "$CRED" cred)" -H 'Content-Type: application/json' \
	--data "{\"profile\":\"$CODESIGN_PROFILE\",\"size\":$SIZE,\"sha256\":\"$ZIP_SHA\"}" \
	"$BASE/v1/uploads") || die "start upload failed"
CRED=
rm -f "$TMP/auth.cred" "$TMP/auth.gh"
[ "$code" = 201 ] || die "start upload: HTTP $code: $(cat "$TMP/upload.json")"
UP_ID=$(json_field upload_id <"$TMP/upload.json")
UP_TOKEN=$(json_field upload_token <"$TMP/upload.json")
PART_SIZE=$(json_num part_size <"$TMP/upload.json")
PARTS=$(json_num parts <"$TMP/upload.json")
rm -f "$TMP/upload.json"
case "$UP_ID" in *[!0-9a-f]* | "") die "bad upload id from service" ;; esac
case "$PART_SIZE$PARTS" in *[!0-9]* | "") die "bad part size from service" ;; esac
[ "$PART_SIZE" -gt 0 ] && [ -n "$UP_TOKEN" ] || die "bad upload reply from service"
UP_HDR=$(header_file "$UP_TOKEN" up)

# put_part N uploads $TMP/part as part N. Network errors and 5xx are retried
# up to 3 times; any other status fails the run.
put_part() {
	attempt=1
	while :; do
		[ $((DEADLINE - $(date +%s))) -gt 0 ] || die "timed out after $TIMEOUT_MIN minutes"
		pcode=$(fetch 600 -o "$TMP/part.json" -w '%{http_code}' -T "$TMP/part" \
			-H "@$UP_HDR" -H 'Content-Type: application/octet-stream' \
			"$BASE/v1/uploads/$UP_ID/parts/$1") || pcode=000
		[ "$pcode" != 204 ] || return 0
		case "$pcode" in
		000 | 5??) ;;
		*) die "part $1: HTTP $pcode: $(cat "$TMP/part.json" 2>/dev/null)" ;;
		esac
		[ "$attempt" -le 3 ] || die "part $1: failed after $attempt attempts (last HTTP $pcode)"
		note "part $1: HTTP $pcode, retry $attempt of 3"
		sleep $((attempt * 2))
		attempt=$((attempt + 1))
	done
}

n=0
while [ "$n" -lt "$PARTS" ]; do
	dd if="$ZIP" of="$TMP/part" bs="$PART_SIZE" skip="$n" count=1 2>/dev/null || die "could not read part $n"
	put_part "$n"
	n=$((n + 1))
	note "uploaded part $n/$PARTS"
done
rm -f "$TMP/part" "$TMP/part.json"
code=$(fetch 0 -o "$TMP/create.json" -w '%{http_code}' -X POST -H "@$UP_HDR" \
	"$BASE/v1/uploads/$UP_ID/complete") || die "complete upload failed"
rm -f "$UP_HDR"
[ "$code" = 202 ] || die "complete upload: HTTP $code: $(cat "$TMP/create.json")"
JOB_ID=$(json_field id <"$TMP/create.json")
JOB_TOKEN=$(json_field job_token <"$TMP/create.json")
rm -f "$TMP/create.json"
case "$JOB_ID" in *[!0-9a-f]* | "") die "bad job id from service" ;; esac
[ -n "$JOB_TOKEN" ] || die "no job token from service"
JOB_HDR=$(header_file "$JOB_TOKEN" job)
note "job $JOB_ID"

# 3. Poll until done. remaining() ends the loop at the deadline.
delay=1
last=
while :; do
	code=$(fetch 60 -o "$TMP/status.json" -w '%{http_code}' -H "@$JOB_HDR" "$BASE/v1/jobs/$JOB_ID") || code=000
	if [ "$code" = 200 ]; then
		status=$(json_field status <"$TMP/status.json")
		[ "$status" = "$last" ] || note "$status"
		last=$status
		case "$status" in
		done) break ;;
		failed) die "job failed: $(cat "$TMP/status.json")" ;;
		esac
	elif [ "$code" != 000 ] && [ "$code" -lt 500 ]; then
		die "status: HTTP $code: $(cat "$TMP/status.json")"
	fi
	left=$(remaining)
	[ "$delay" -le "$left" ] || delay=$left
	sleep "$delay"
	[ "$delay" -ge 30 ] || delay=$((delay + 5))
done
if grep -q '"warning"' "$TMP/status.json"; then
	note "WARNING: the signing report has warnings (executables without entitlements):"
	tr '{' '\n' <"$TMP/status.json" | grep '"warning"' | sed -n 's/.*"path":"\([^"]*\)".*/  \1/p'
fi

# 4. Download and check each artifact.
mkdir -p "$OUT_DIR"
ZIP_OUT=
DMG_OUT=
for kind in zip dmg; do
	want=$(sed -n "s/.*\"$kind\":{\"sha256\":\"\([0-9a-f]*\)\".*/\1/p" "$TMP/status.json")
	[ -n "$want" ] || continue
	dst=$OUT_DIR/$NAME.$kind
	fetch 0 -f -H "@$JOB_HDR" -o "$dst" "$BASE/v1/jobs/$JOB_ID/artifact?kind=$kind" || die "download $kind failed"
	got=$(sha256 "$dst")
	[ "$got" = "$want" ] || die "$kind sha256 mismatch: got $got, want $want"
	note "$dst ($got)"
	if [ "$kind" = zip ]; then ZIP_OUT=$dst; else DMG_OUT=$dst; fi
	if [ -n "${GITHUB_OUTPUT:-}" ]; then
		echo "$kind=$dst" >>"$GITHUB_OUTPUT"
	fi
done
if [ -n "${GITHUB_OUTPUT:-}" ]; then
	echo "job-id=$JOB_ID" >>"$GITHUB_OUTPUT"
fi
[ -n "$ZIP_OUT" ] || die "the job has no zip artifact"

# 5. Verify on macOS. The service never runs uploaded code; this is where a
# broken signature or a crashing binary shows up.
if [ "$IS_MAC" = 0 ]; then
	note "not on macOS: skipped signature checks"
	exit 0
fi
mkdir "$TMP/check"
ditto -x -k "$ZIP_OUT" "$TMP/check"
APP=$(find "$TMP/check" -maxdepth 1 -name '*.app' -type d | head -n 1)
[ -n "$APP" ] || die "no .app in $ZIP_OUT"
if [ "$VERIFY" = 1 ]; then
	note "verifying $(basename "$APP")"
	codesign --verify --deep --strict --verbose=2 "$APP"
	spctl -a -t exec -vv "$APP"
	xcrun stapler validate "$APP"
	if [ -n "$DMG_OUT" ]; then
		spctl -a -t open --context context:primary-signature -vv "$DMG_OUT"
		xcrun stapler validate "$DMG_OUT"
	fi
fi
if [ -n "$SMOKE" ]; then
	limit=$(remaining)
	[ "$SMOKE_TIMEOUT" -le "$limit" ] || SMOKE_TIMEOUT=$limit
	note "smoke test (limit ${SMOKE_TIMEOUT}s): $SMOKE"
	export APP
	# Job control gives each background job its own process group, so the
	# whole group can be killed: the command and everything it started.
	set -m
	sh -c "$SMOKE" &
	smoke_pid=$!
	(
		sleep "$SMOKE_TIMEOUT"
		: >"$TMP/smoke-timeout"
		kill -TERM -- "-$smoke_pid" 2>/dev/null
		sleep 5
		kill -KILL -- "-$smoke_pid" 2>/dev/null
	) &
	watchdog=$!
	set +m
	rc=0
	wait "$smoke_pid" || rc=$?
	kill -KILL -- "-$watchdog" 2>/dev/null || true
	wait "$watchdog" 2>/dev/null || true
	# Whatever happened, clean the group: TERM, up to 5 s grace, then KILL.
	kill_group "$smoke_pid"
	[ ! -e "$TMP/smoke-timeout" ] || die "smoke test timed out after ${SMOKE_TIMEOUT}s"
	[ "$rc" = 0 ] || die "smoke test failed (exit $rc)"
	note "smoke test passed"
fi
