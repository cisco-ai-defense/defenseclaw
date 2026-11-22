// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import "strings"

// Side transports of a Substrate render: everything besides the hooks that
// talks to DefenseClaw from inside the sandbox (native OTLP exporters, the
// Claude Code otelHeadersHelper, the Codex notify bridge). Under OpenShell
// they post to http://<ingress> with the binding token; in an Agent
// Substrate actor there is no binding token, so they send
// SandboxActorHeader: SandboxActorPlaceholder, which Substrate egress
// replaces with the actor JWT, and no Authorization header. OpenShell
// renders are unchanged.

// otlpBase is the scheme and authority the native OTLP exporters post to.
func (rt resolvedSandboxTarget) otlpBase() string {
	if rt.ingress.Substrate() {
		return substrateOrigin(rt.ingress)
	}
	return "http://" + rt.ingressAddr
}

// substrateOrigin is in's scheme://host, with the port only when it is not
// the scheme's default, so the Host header is the bare Service name the
// actor's EgressPolicy rule lists.
func substrateOrigin(in SandboxIngress) string {
	scheme := in.Scheme
	if scheme == "" {
		scheme = "http"
	}
	if (scheme == "http" && in.Port == 80) || (scheme == "https" && in.Port == 443) {
		return scheme + "://" + in.Host
	}
	return scheme + "://" + in.Addr()
}

// substrateOTLPEndpoint moves an endpoint the native OTLP spec built on
// http://<ingress addr> to the Substrate ingress origin.
func (rt resolvedSandboxTarget) substrateOTLPEndpoint(v string) string {
	if !rt.ingress.Substrate() {
		return v
	}
	old := "http://" + rt.ingressAddr
	if strings.HasPrefix(v, old) {
		return rt.otlpBase() + strings.TrimPrefix(v, old)
	}
	return v
}

// claudeCodeSubstrateOtelHelper is the otelHeadersHelper of a Substrate
// render: the actor header placeholder, never a token.
const claudeCodeSubstrateOtelHelper = `#!/bin/sh
# defenseclaw-managed-hook v1
# DefenseClaw Claude Code otelHeadersHelper (Agent Substrate actor images).
# Prints the OTLP exporter headers for the DefenseClaw actor listener.
# Substrate egress replaces the actor header placeholder with the actor JWT.
printf '{"` + SandboxActorHeader + `":"` + SandboxActorPlaceholder + `","x-defenseclaw-source":"claudecode","x-defenseclaw-client":"claudecode-otel/1.0"}\n'
`

// codexSubstrateNotifyPath is the actor listener's Codex notify route.
const codexSubstrateNotifyPath = "/api/v1/substrate/notify/codex"

// renderCodexSubstrateNotifyBridge is the notify bridge of a Substrate
// render: Codex's JSON goes to the actor listener in the kit envelope with
// the actor header placeholder. Best-effort, like the OpenShell bridge.
func renderCodexSubstrateNotifyBridge(rt resolvedSandboxTarget) []byte {
	cacert := ""
	if rt.ingress.CAFile != "" {
		cacert = "  --cacert " + shellSingleQuote(rt.ingress.CAFile) + " \\\n"
	}
	return []byte(`#!/bin/bash -p
# defenseclaw-managed-hook v1
# DefenseClaw Codex notify bridge (Agent Substrate actor images, root-owned).
# Forwards Codex's agent-turn-complete JSON to the DefenseClaw actor listener
# in the kit envelope. Substrate egress replaces the actor header
# placeholder with the actor JWT. Best-effort: never blocks or prints.
set -u
PATH=` + SandboxHookPATH + `
export PATH
unset LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT BASH_ENV ENV CURL_HOME
JSON="${1:-}"
[ -n "$JSON" ] || exit 0
printf '{"v":"1","connector":"codex","event":"agent-turn-complete","mode":"interactive","kit_version":"shell","payload":%s}' "$JSON" |
  curl -q -s --noproxy '*' -o /dev/null \
  --connect-timeout 2 --max-time 5 \
` + cacert + `  -X POST ` + shellSingleQuote(substrateOrigin(rt.ingress)+codexSubstrateNotifyPath) + ` \
  -H 'Content-Type: application/json' \
  -H 'X-DefenseClaw-Client: codex-notify/1.0' \
  -H 'x-defenseclaw-source: codex-notify' \
  -H ` + shellSingleQuote(SandboxActorHeader+": "+SandboxActorPlaceholder) + ` \
  --data-binary @- >/dev/null 2>&1 || true
exit 0
`)
}
