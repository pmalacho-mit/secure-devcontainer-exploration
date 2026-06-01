#!/usr/bin/env bash
#
# Script to populate a SvelteKit test route with demo files from the release directory.
#
# This script copies the necessary demo files into a SvelteKit project's routes
# directory to set up a working test route.

set -euo pipefail

DIRNAME="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Print usage information to stderr.
usage() {
  cat >&2 <<'USAGE'
Usage: populate-test-route.sh [OPTIONS]

Populate a SvelteKit project with test route files from the release directory.

Options:
  -d, --destination DIR   Destination SvelteKit project directory 
                          (or its corresponding routes directory).
                          Defaults to current directory (.).
                          Will automatically append 'src/routes/' if needed.
  -h, --help              Display this help and exit.

Notes:
  • The destination directory should be the root of a SvelteKit project 
    or its corresponding routes directory.
  • If the destination doesn't end with 'src/routes/', the script will
    automatically append it.
  • The script will copy demo files from the release directory into the
    target routes directory.

Example:
  populate-test-route.sh --destination /path/to/sveltekit-project
  populate-test-route.sh -d .
USAGE
}

# Initialize variables for argument parsing.
DESTINATION=""
DESTINATION_PROVIDED=false

# Process command line arguments.
while [[ $# -gt 0 ]]; do
  case "$1" in
    -d|--destination)
      DESTINATION="${2-}"
      DESTINATION_PROVIDED=true
      if [[ -z "$DESTINATION" ]]; then
        printf "Error: missing argument to %s\n" "$1" >&2
        usage
        exit 1
      fi
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      break
      ;;
    -*)
      printf "Unknown option: %s\n" "$1" >&2
      usage
      exit 1
      ;;
    *)
      printf "Error: unexpected positional argument '%s'\n" "$1" >&2
      usage
      exit 1
      ;;
  esac
done

# Set default destination to current directory if not provided.
if [[ -z "$DESTINATION" ]]; then
  DESTINATION="."
fi

# Expand the destination to an absolute path.
DESTINATION="$(cd "$DESTINATION" 2>/dev/null && pwd)" || {
  printf "Error: destination directory '%s' does not exist\n" "$DESTINATION" >&2
  exit 1
}

# Ensure destination ends with 'src/routes/' - add it if missing.
if [[ ! "$DESTINATION" =~ src/routes/?$ ]]; then
  DESTINATION="${DESTINATION%/}/src/routes"
fi

DESTINATION="${DESTINATION}/tests"

# Create the destination directory if it doesn't exist.
if [[ ! -d "$DESTINATION" ]]; then
  printf "Creating destination directory: %s\n" "$DESTINATION"
  mkdir -p "$DESTINATION"
fi


printf "Populating test route in: %s\n" "$DESTINATION"

cp -r "${DIRNAME}/+page.svelte" "$DESTINATION/"
mkdir -p "$DESTINATION/[...path]"
cp -r "${DIRNAME}/[...path]/+page.svelte" "$DESTINATION/[...path]/"
cp -r "${DIRNAME}/[...path]/+page.ts" "$DESTINATION/[...path]/"

printf "Done!\n"