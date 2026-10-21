# Edge Connector on Raspberry Pi

This guide checks the Linux C engine and PicoClaw hook on a Raspberry Pi using an explicitly local development build. For a production Fleet deployment, follow [INSTALL.md](INSTALL.md) for mbedTLS 3.x, MQTT TLS, per-device keys, broker ACLs, signed OTA, audit and flash storage, and the service unit. A development build must not be used as a production gateway or device.

## Build and test locally

On a 64-bit Raspberry Pi OS or Debian host:

```bash
sudo apt update
sudo apt install -y build-essential cmake python3 python3-venv git
git clone https://github.com/cisco-ai-defense/defenseclaw.git
cd defenseclaw
cmake -S edge-connector -B edge-connector/build-rpi-dev \
  -DDCLAW_PROFILE=STANDARD -DDCLAW_DEV_MODE=ON -DDCLAW_BUILD_TESTS=ON
cmake --build edge-connector/build-rpi-dev -j4
ctest --test-dir edge-connector/build-rpi-dev --output-on-failure
```

The test count and latency depend on the checkout and Pi model. Run `edge-connector/build-rpi-dev/tests/bench_latency` if you need measurements on your own hardware; the benchmark is not a production latency guarantee.

## Check the hook without a broker

Without a daemon, the hook only uses the C shared library in process when `DCLAW_ALLOW_FFI=1` is set. Give the development build a writable, disposable flash file and an audit key. A fresh device starts at `DCLAW_POLICY_VERSION=0`; the engine rejects a claimed nonzero accepted policy without a verified on-flash OTA blob.

```bash
export DCLAW_ALLOW_FFI=1
export DCLAW_SOCKET_PATH=/nonexistent/defenseclaw.sock
export DCLAW_LIB_PATH="$PWD/edge-connector/build-rpi-dev/libdclaw_core.so"
export DCLAW_FLASH_PATH="$(mktemp -d)/flash.bin"
export DCLAW_AUDIT_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
export DCLAW_LOG_PATH="${DCLAW_FLASH_PATH%.bin}.log"
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"hook.hello","params":{}}' \
  '{"jsonrpc":"2.0","id":2,"method":"hook.before_tool","params":{"tool":"unreviewed_tool","arguments":{}}}' \
  '{"jsonrpc":"2.0","id":3,"method":"hook.before_tool","params":{"tool":"web_fetch","arguments":{"url":"http://127.0.0.1/"}}}' \
  | python3 edge-connector/tools/picoclaw_hook.py
```

The first response has `ok: true`. The unknown tool is denied with `INVALID_INPUT`; the private network destination is denied with `SSRF_BLOCK`. This tests the local hook and C library only. It does not prove a PicoClaw agent is configured to intercept every real tool call. Confirm that integration separately against your installed PicoClaw version and check its hook logs.

The C engine trusts only its reviewed tool-name-to-capability table in `src/decision/policy_table.c`. An adapter's Python `TOOL_CAP_MAP` cannot authorize a custom name in C. Unknown tools fail closed, even if the caller supplies a different capability flag. Add a reviewed C mapping and test it before using a custom PicoClaw tool.

## Compile a policy example

The shipped [`strict.yaml`](policies/strict.yaml) has an allowlist of public numeric IP examples. Replace them with approved public service IPs. The current guard blocks hostnames, wildcard domains, private addresses and numeric aliases for network tools; it has no DNS egress proxy. The compiler accepts `capability_sequences`, `destination_allowlist` and `canary`, and rejects unsupported `rate_limits`, `escalation_mode`, `content_inspection` and `ssrf_protection` keys. Runtime rate limits are built in (60 tool calls, 30 network requests, 10 actuations per minute), and production uses synchronous Fleet escalation by default.

```bash
python3 -m venv .edge-policy-venv
. .edge-policy-venv/bin/activate
python -m pip install PyYAML
python edge-connector/tools/policy_compiler.py \
  --input edge-connector/policies/strict.yaml --profile standard --version 1 \
  --output-header policy_tables.h --output-binary policy.bin
```

The `policy.bin` output from this command has a development stub signature. Production devices reject it. Use the authenticated Fleet policy-push API with an explicit shared `DCLAW_OTA_HMAC_KEY` and a C production build compiled with `-DDCLAW_ALLOW_HMAC_OTA=ON`. The optional compiler Ed25519 output is not accepted by this C receiver. Policy versions must be monotonic and at most 65534; 65535 is reserved.

The device's signed registration and heartbeat wire format is 72 bytes (40-byte body with boot counter and last-applied emergency sequence, then 32-byte HMAC). Upgrade the Fleet gateway and C devices together; old 64- and 68-byte keyed frames are rejected. See [INSTALL.md](INSTALL.md) for production provisioning and upgrade steps.
