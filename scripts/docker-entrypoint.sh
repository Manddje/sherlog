#!/bin/sh
# Make the writable state directories owned by the runtime user, then drop
# privileges to it. This lets root-owned mounted volumes (e.g. a Coolify
# persistent volume at INBOX_DIR or JOBS_DIR) work without a manual chown on
# the host. Runs as root (the image's default user); execs uvicorn as appuser.
set -e

APP_UID=10001
JOBS_DIR="${JOBS_DIR:-/data/jobs}"

own() {
    [ -n "$1" ] || return 0
    mkdir -p "$1" 2>/dev/null || true
    # Non-recursive: only the mount/target dir needs the right owner so the
    # app can create job subdirs under it. Cheap even for a large inbox.
    chown "$APP_UID:$APP_UID" "$1" 2>/dev/null || true
}

own "$(dirname "$JOBS_DIR")"   # parent also holds the CSP-names cache
own "$JOBS_DIR"
own "$INBOX_DIR"

# setpriv ships with util-linux (no extra package) and preserves the env.
exec setpriv --reuid "$APP_UID" --regid "$APP_UID" --init-groups "$@"
