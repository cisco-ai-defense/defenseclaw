#!/usr/bin/env bash
# End-to-end harness for the custom-provider routing path.
#
# Stands up a Python HTTPS server backed by a self-signed cert, writes
# a matching ~/.defenseclaw/custom-providers.json entry, configures
# `defenseclaw setup llm` with `--instance-name`, and asserts the
# request lands on the fake endpoint's access log.
#
# Run locally:
#   bash scripts/test-e2e-custom-provider.sh
#
# Exits non-zero on any assertion failure. Designed to be safe to run
# repeatedly against a throwaway DEFENSECLAW_HOME.

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

PORT=${DEFENSECLAW_E2E_PORT:-18443}
INSTANCE_NAME=${DEFENSECLAW_E2E_INSTANCE:-acme-internal-llm}
MODEL=${DEFENSECLAW_E2E_MODEL:-acme-internal/gpt-4o-test}

TMP_DIR=$(mktemp -d -t defenseclaw-e2e-XXXXXX)
LOG_FILE="${TMP_DIR}/access.log"
CERT_PEM="${TMP_DIR}/server.pem"
KEY_PEM="${TMP_DIR}/server.key"

DEFENSECLAW_HOME="${TMP_DIR}/home"
mkdir -p "${DEFENSECLAW_HOME}"
export DEFENSECLAW_HOME

cleanup() {
  if [[ -n "${SERVER_PID:-}" ]]; then
    kill "${SERVER_PID}" 2>/dev/null || true
    wait "${SERVER_PID}" 2>/dev/null || true
  fi
  if [[ "${DEFENSECLAW_E2E_KEEP:-0}" != "1" ]]; then
    rm -rf "${TMP_DIR}"
  else
    echo "Kept temporary dir: ${TMP_DIR}"
  fi
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Generate a self-signed cert
# ---------------------------------------------------------------------------

echo "==> Generating self-signed cert at ${CERT_PEM}"
openssl req \
  -x509 \
  -newkey rsa:2048 \
  -keyout "${KEY_PEM}" \
  -out "${CERT_PEM}" \
  -days 1 \
  -nodes \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  >/dev/null 2>&1

# ---------------------------------------------------------------------------
# Spin up a fake OpenAI-shaped HTTPS server
# ---------------------------------------------------------------------------

cat > "${TMP_DIR}/server.py" <<'PY'
import json
import os
import ssl
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

LOG_FILE = os.environ["E2E_LOG_FILE"]


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(length) if length else b""
        with open(LOG_FILE, "a", encoding="utf-8") as fh:
            fh.write(f"POST {self.path} {len(body)}\n")
        response = {
            "id": "chatcmpl-e2e",
            "object": "chat.completion",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "ok"},
                    "finish_reason": "stop",
                }
            ],
        }
        payload = json.dumps(response).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_args, **_kwargs):  # silence stderr noise
        pass


if __name__ == "__main__":
    addr = ("127.0.0.1", int(os.environ["E2E_PORT"]))
    httpd = HTTPServer(addr, Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=os.environ["E2E_CERT"], keyfile=os.environ["E2E_KEY"])
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    print(f"listening on https://127.0.0.1:{addr[1]}", flush=True)
    httpd.serve_forever()
PY

E2E_LOG_FILE="${LOG_FILE}" \
E2E_PORT="${PORT}" \
E2E_CERT="${CERT_PEM}" \
E2E_KEY="${KEY_PEM}" \
  python3 "${TMP_DIR}/server.py" &
SERVER_PID=$!

echo "==> Fake LLM endpoint pid=${SERVER_PID} (https://127.0.0.1:${PORT})"

# Wait for the server to come up.
for _ in $(seq 1 50); do
  if curl --cacert "${CERT_PEM}" --silent --output /dev/null "https://127.0.0.1:${PORT}/healthz"; then
    break
  fi
  if curl --cacert "${CERT_PEM}" --silent --max-time 0.5 --output /dev/null "https://127.0.0.1:${PORT}/" || true; then
    break
  fi
  sleep 0.1
done

# ---------------------------------------------------------------------------
# Write the overlay entry with the cert inline
# ---------------------------------------------------------------------------

OVERLAY="${DEFENSECLAW_HOME}/custom-providers.json"
# Export everything the Python heredoc reads as os.environ so the
# `<<'PY'` (quoted) heredoc body can stay literal — using an unquoted
# heredoc would let `set -u` blow up on the Python expression syntax
# inside ${} (which shell would otherwise try to interpret).
export E2E_CA_PEM
E2E_CA_PEM=$(<"${CERT_PEM}")
export E2E_INSTANCE_NAME="${INSTANCE_NAME}"
export E2E_PORT="${PORT}"
export E2E_MODEL="${MODEL}"
export E2E_OVERLAY="${OVERLAY}"
python3 - <<'PY'
import json
import os
import pathlib

overlay = {
    "providers": [
        {
            "name": os.environ["E2E_INSTANCE_NAME"],
            "base_provider_type": "openai",
            "base_url": f"https://127.0.0.1:{os.environ['E2E_PORT']}",
            "allowed_requests": ["chat"],
            "available_models": [os.environ["E2E_MODEL"]],
            "tls": {
                "ca_cert_pem": os.environ["E2E_CA_PEM"],
            },
            "env_keys": ["DEFENSECLAW_LLM_KEY"],
        }
    ]
}
pathlib.Path(os.environ["E2E_OVERLAY"]).write_text(
    json.dumps(overlay, indent=2), encoding="utf-8",
)
PY

# ---------------------------------------------------------------------------
# Configure DefenseClaw to route through the instance
# ---------------------------------------------------------------------------

defenseclaw setup llm \
  --non-interactive \
  --provider acme-internal \
  --instance-name "${INSTANCE_NAME}" \
  --model "${MODEL}"

# ---------------------------------------------------------------------------
# Issue a probe request via `defenseclaw doctor` (which calls llm.ping())
# ---------------------------------------------------------------------------

if defenseclaw doctor 2>&1 | tee "${TMP_DIR}/doctor.out"; then
  echo "==> defenseclaw doctor: OK"
else
  echo "==> defenseclaw doctor: WARNING (exit nonzero, continuing)"
fi

# ---------------------------------------------------------------------------
# Assert the fake endpoint actually saw a request.
# ---------------------------------------------------------------------------

if grep -q "POST" "${LOG_FILE}"; then
  echo "==> Fake endpoint access log:"
  cat "${LOG_FILE}" | sed 's/^/    /'
  echo "==> PASS"
  exit 0
else
  echo "!! Fake endpoint never received a request:"
  cat "${LOG_FILE}" || true
  echo "!! doctor stdout:"
  cat "${TMP_DIR}/doctor.out" || true
  echo "!! FAIL"
  exit 1
fi
