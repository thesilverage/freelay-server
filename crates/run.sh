#!/bin/sh
set -eu
# Configuration is explicit; transport/VPN services are administered separately.
if [ "$#" -eq 0 ]; then
    set -- serve --config /config/freelay.toml
fi
exec freelay "$@"
