#!/usr/bin/env bash

set -eo pipefail

DIR="$(CDPATH= cd "$(dirname "${0}")/../../.." && pwd)"
cd "${DIR}"

fail() {
  echo "error: $@" >&2
  exit 1
}

[ -n "${RELEASE_GO_BINARY}" ] || fail "RELEASE_GO_BINARY must be set."

if [ -n "${RELEASE_SKIP_SIGN}" ]; then
  SKIP_SIGN="--skip-sign"
elif [ -z "${RELEASE_MINISIGN_PRIVATE_KEY}" -o -z "${RELEASE_MINISIGN_PRIVATE_KEY_PASSWORD}" ]; then
  fail "RELEASE_MINISIGN_PRIVATE_KEY and RELEASE_MINISIGN_PRIVATE_KEY_PASSWORD must be set."
fi

[ -z "${RELEASE_SKIP_VALIDATE}" ] || SKIP_VALIDATE="--skip-validate"

RELEASE_DIR=".build/release/buf"
ASSETS_DIR="${RELEASE_DIR}/assets"
WORKSPACE_DIR="${RELEASE_DIR}/workspace"
DIST_DIR="${WORKSPACE_DIR}/dist"

rm -rf "${RELEASE_DIR}"
mkdir -p "${ASSETS_DIR}" "${WORKSPACE_DIR}"
trap "rm -rf $WORKSPACE_DIR" EXIT

test -f "${GOBIN}/${RELEASE_GO_BINARY}" || go install "golang.org/dl/${RELEASE_GO_BINARY}"@latest
"${GOBIN}/${RELEASE_GO_BINARY}" download 2>/dev/null

ln -s "${GOBIN}/${RELEASE_GO_BINARY}" "${RELEASE_DIR}/go"

echo "${RELEASE_MINISIGN_PRIVATE_KEY}" >"${WORKSPACE_DIR}/minisignsecret"
echo "${RELEASE_MINISIGN_PRIVATE_KEY_PASSWORD}" >"${WORKSPACE_DIR}/minisignpass"

mkdir -p "${WORKSPACE_DIR}/etc/bash_completion.d" \
  "${WORKSPACE_DIR}/share/fish/vendor_completions.d" \
  "${WORKSPACE_DIR}/share/zsh/site-functions"

"${GOBIN}/buf" bash-completion >"${WORKSPACE_DIR}/etc/bash_completion.d/buf"
"${GOBIN}/buf" fish-completion >"${WORKSPACE_DIR}/share/fish/vendor_completions.d/buf.fish"
"${GOBIN}/buf" zsh-completion >"${WORKSPACE_DIR}/share/zsh/site-functions/_buf"

"${RELEASE_DIR}/go" mod verify
env -i PATH="$PATH" HOME="$HOME" GOMODCACHE="$GOMODCACHE" GOCACHE="$GOCACHE" "$CACHE/bin/goreleaser" release ${SKIP_SIGN} ${SKIP_VALIDATE}

echo Upload all the files in this directory to GitHub: open "${ASSETS_DIR}"
