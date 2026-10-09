#!/bin/sh
set -eu
if [ "$#" -eq 0 ]; then
    set -- serve --config /config/freelay.toml
fi
exec freelay "$@"
