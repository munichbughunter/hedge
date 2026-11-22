#!/bin/sh
# Entrypoint of the Hedge image.
#
# Before the proxy starts, create what is secret and therefore never comes
# from the config: the witness signing key and the control token. They are
# written to the paths the config names (on the volume) and only if they do
# not exist yet – an existing key is never touched.
set -eu

if [ "${1:-run}" = "run" ]; then
  if [ ! -f "${HEDGE_CONFIG:-/etc/hedge/hedge.toml}" ]; then
    echo "hedge: no config at ${HEDGE_CONFIG:-/etc/hedge/hedge.toml} – mount one (see docs/operations.md)" >&2
    exit 78
  fi
  hedge init --keys-only
fi

exec hedge "$@"
