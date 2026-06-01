#!/usr/bin/env bash
set -euo pipefail

# Directory containing the test routes.
# You can override with: TARGET_DIR=./some/other/dir ./with-temp-test-routes.sh ...
TARGET_DIR="${TARGET_DIR:-./src/routes/tests}"

# Naming convention for the page files we want to toggle.
BASENAME="${BASENAME:-page}"
ACTIVE_PREFIX="${ACTIVE_PREFIX:-+}"
INACTIVE_PREFIX="${INACTIVE_PREFIX:-_}"

# Extensions to handle. Override with EXTENSIONS="svelte ts js" if you want custom.
EXTENSIONS="${EXTENSIONS:-svelte ts js}"

log() {
  printf '[with-temp-test-routes] %s\n' "$*" >&2
}

build_find_args_active() {
  # Builds: -name '+page.svelte' -o -name '+page.ts' ...
  set --  # clear "$@"
  local first=1 ext
  for ext in $EXTENSIONS; do
    if [ "$first" -eq 1 ]; then
      first=0
      set -- -name "${ACTIVE_PREFIX}${BASENAME}.${ext}"
    else
      set -- "$@" -o -name "${ACTIVE_PREFIX}${BASENAME}.${ext}"
    fi
  done
  printf '%s\n' "$@"
}

build_find_args_inactive() {
  # Builds: -name '_page.svelte' -o -name '_page.ts' ...
  set --  # clear "$@"
  local first=1 ext
  for ext in $EXTENSIONS; do
    if [ "$first" -eq 1 ]; then
      first=0
      set -- -name "${INACTIVE_PREFIX}${BASENAME}.${ext}"
    else
      set -- "$@" -o -name "${INACTIVE_PREFIX}${BASENAME}.${ext}"
    fi
  done
  printf '%s\n' "$@"
}

ignore_test_routes() {
  [ -d "$TARGET_DIR" ] || { log "Target dir '$TARGET_DIR' does not exist, skipping."; return 0; }

  log "Temporarily hiding ${ACTIVE_PREFIX}${BASENAME}.* files under $TARGET_DIR"

  # shellcheck disable=SC2046
  find "$TARGET_DIR" -type f \
    \( $(build_find_args_active) \) \
    -print0 |
  while IFS= read -r -d '' f; do
    dir=${f%/*}
    filename=${f##*/}
    ext=${filename##*.}
    dest="$dir/${INACTIVE_PREFIX}${BASENAME}.$ext"

    if [ -e "$dest" ]; then
      log "WARNING: destination already exists, skipping: $dest"
      continue
    fi

    mv -- "$f" "$dest"
  done
}

restore_test_routes() {
  [ -d "$TARGET_DIR" ] || return 0

  log "Restoring ${INACTIVE_PREFIX}${BASENAME}.* files under $TARGET_DIR"

  # shellcheck disable=SC2046
  find "$TARGET_DIR" -type f \
    \( $(build_find_args_inactive) \) \
    -print0 |
  while IFS= read -r -d '' f; do
    dir=${f%/*}
    filename=${f##*/}
    ext=${filename##*.}
    dest="$dir/${ACTIVE_PREFIX}${BASENAME}.$ext"

    if [ -e "$dest" ]; then
      log "WARNING: active file already exists, skipping: $dest"
      continue
    fi

    mv -- "$f" "$dest"
  done
}

usage() {
  cat >&2 <<EOF
Usage: $(basename "$0") command [args...]

Temporarily renames matching files (${ACTIVE_PREFIX}${BASENAME}.*) to
${INACTIVE_PREFIX}${BASENAME}.* under \$TARGET_DIR (default: ./src/routes/tests)
for the duration of the given command.

Environment variables:
  TARGET_DIR   Directory to search (default: ./src/routes/tests)
  BASENAME     Base filename (default: page)
  ACTIVE_PREFIX   Prefix for active files (default: +)
  INACTIVE_PREFIX Prefix for inactive files (default: _)
  EXTENSIONS   Space-separated list of extensions (default: "svelte ts js")
EOF
  exit 1
}

# --- Main wrapper logic ---

if [ "$#" -lt 1 ]; then
  usage
fi

ignore_test_routes

cleanup() {
  # Preserve the wrapped command's exit code
  local ec=$?
  restore_test_routes || true
  exit "$ec"
}
trap cleanup EXIT

# Run the wrapped command (e.g. vite build, pnpm build, etc.)
"$@"
