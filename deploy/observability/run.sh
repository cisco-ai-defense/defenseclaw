#!/usr/bin/env bash
# Helper wrapper around docker compose for the DefenseClaw observability
# stack. Drops you into the same env the sidecar expects.
#
# Usage:
#   ./run.sh up        — start the stack in the background
#   ./run.sh down      — stop and remove containers (keeps volumes)
#   ./run.sh reset     — stop + wipe volumes (fresh dashboards / TSDB)
#   ./run.sh logs      — tail every service
#   ./run.sh env       — print the env vars you should export to point
#                        defenseclaw at this stack
#
# Any other arg is passed straight through to `docker compose`.

set -euo pipefail

cd "$(dirname "$0")"

cmd="${1:-up}"
shift || true

case "$cmd" in
  up)
    docker compose up -d "$@"
    echo
    echo "DefenseClaw observability stack is up."
    echo "  Grafana:    http://localhost:3000  (admin / admin)"
    echo "  Prometheus: http://localhost:9090"
    echo "  Tempo API:  http://localhost:3200"
    echo "  Loki API:   http://localhost:3100"
    echo "  OTLP gRPC:  localhost:4317"
    echo "  OTLP HTTP:  localhost:4318"
    echo
    echo "To send telemetry from a local gateway run:"
    echo '  eval "$(./run.sh env)"'
    echo '  go run ./cmd/defenseclaw gateway'
    ;;
  down)
    docker compose down "$@"
    ;;
  reset)
    docker compose down -v "$@"
    ;;
  logs)
    docker compose logs -f "$@"
    ;;
  env)
    cat <<'EOF'
export DEFENSECLAW_TELEMETRY_ENABLED=1
export OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4317
export OTEL_EXPORTER_OTLP_PROTOCOL=grpc
export OTEL_SERVICE_NAME=defenseclaw
export OTEL_RESOURCE_ATTRIBUTES=service.namespace=defenseclaw,deployment.environment=local-dev
EOF
    ;;
  *)
    docker compose "$cmd" "$@"
    ;;
esac
