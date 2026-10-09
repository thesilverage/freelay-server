#!/usr/bin/env bash
# Run from any directory, after building the image. No host data/network mounts.
set -euo pipefail
smoke_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
image="${1:-freelay-validation:20261008}"
docker run --rm --network none --read-only \
  --tmpfs /data:rw,uid=10001,gid=10001 --tmpfs /tmp:rw \
  --mount "type=bind,source=$smoke_dir/container-smoke.toml,target=/config/freelay.toml,readonly" \
  --entrypoint bash "$image" -eu -c '
    test "$(id -u)" = 10001
    freelay version
    freelay serve --config /config/freelay.toml &
    server_pid=$!
    trap '\''kill -TERM "$server_pid" 2>/dev/null || true; wait "$server_pid" || true'\'' EXIT
    ready=false
    for attempt in {1..50}; do
      kill -0 "$server_pid"
      if (exec 3<>/dev/tcp/127.0.0.1/8080) 2>/dev/null; then ready=true; break; fi
      sleep 0.1
    done
    test "$ready" = true
    exec 3<>/dev/tcp/127.0.0.1/8080
    printf "GET /base/ready HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n" >&3
    IFS= read -r status <&3
    case "$status" in "HTTP/1.1 200 OK"*) ;; *) printf "Unexpected readiness response: %s\n" "$status"; exit 1;; esac
    test "$(freelay control --config /config/freelay.toml list)" = "[]"
    freelay control --config /config/freelay.toml gc --dry-run
    printf "Container smoke test passed.\n"
  '
