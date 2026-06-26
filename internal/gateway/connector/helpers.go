// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
)

// userHomeDir returns the current user's home directory in a cross-platform
// way. It prefers os.UserHomeDir() (which uses USERPROFILE on Windows,
// HOME on Unix) and falls back to os.Getenv("HOME") for legacy compatibility.
func userHomeDir() string {
	if h, err := os.UserHomeDir(); err == nil && h != "" {
		return h
	}
	return os.Getenv("HOME")
}

// nativeHookFlag is the distinctive argument fragment that marks a command as
// the DefenseClaw native Go hook entrypoint (`defenseclaw-gateway hook
// --connector <name>`). It is used both when writing an agent's hook command on
// Windows and when recognizing DefenseClaw-owned hooks during teardown.
const nativeHookFlag = "hook --connector "

// hookInvocationCommand returns the command string an agent runtime is
// configured to run for a DefenseClaw hook.
//
// On Unix the agent runs the bundled .sh hook through its shell, so the command
// is the script path (unixCommand) the caller already resolved.
//
// On Windows there is no Bash/.cmd/jq/PATH-restore chain: the agent invokes the
// DefenseClaw binary's hidden `hook` subcommand directly. The Windows command
// deliberately carries no per-install volatile values — the gateway address,
// token, and fail mode are resolved at runtime from the hook sidecar
// (hooks/.hookcfg, hooks/.token) and the environment. Keeping the command
// byte-identical across setup and teardown is required so Codex's trust-hash
// recognition and the JSON/YAML hook removers (which match on the exact command
// string) still find the entries DefenseClaw inserted.
func hookInvocationCommand(connector, unixCommand string) string {
	return hookInvocationCommandFor(runtime.GOOS, connector, unixCommand)
}

// hookInvocationCommandFor is the OS-parameterized core of
// hookInvocationCommand, split out so the Windows command string can be
// exercised by tests on any host.
func hookInvocationCommandFor(goos, connector, unixCommand string) string {
	if goos != "windows" {
		return unixCommand
	}
	return windowsQuoteExe(defenseclawHookBinary()) + " " + nativeHookFlag + connector
}

// defenseclawHookBinary returns the path to the running gateway binary, which
// also hosts the hidden `hook` subcommand. Falls back to the bare binary name
// (resolved via PATH by the agent) when the path cannot be determined.
func defenseclawHookBinary() string {
	if exe, err := os.Executable(); err == nil && strings.TrimSpace(exe) != "" {
		return exe
	}
	return "defenseclaw-gateway"
}

// windowsQuoteExe wraps an executable path in double quotes so cmd.exe and agent
// runtimes treat a path containing spaces (e.g. "C:\Program Files\...") as a
// single token. Backslashes are preserved verbatim inside double quotes.
func windowsQuoteExe(p string) string {
	return `"` + p + `"`
}

// isNativeHookCommand reports whether cmd is the DefenseClaw native Go hook
// entrypoint invocation written on Windows. Used by teardown ownership
// recognition, which otherwise keys on a hooks-dir path / script marker that a
// native (non-file) command does not carry.
func isNativeHookCommand(cmd string) bool {
	return strings.Contains(cmd, nativeHookFlag)
}

// SecureTokenMatch compares two token strings in constant time to prevent
// timing-based token extraction attacks.
func SecureTokenMatch(a, b string) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// ExtractBearerKey extracts the API key from an Authorization header value,
// stripping the "Bearer " prefix. Returns empty string if no key found.
func ExtractBearerKey(value string) string {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "Bearer ") {
		return strings.TrimSpace(value[7:])
	}
	if strings.HasPrefix(value, "bearer ") {
		return strings.TrimSpace(value[7:])
	}
	return value
}

// ExtractAPIKey extracts the upstream API key from an HTTP request using a
// priority chain common across connectors. Returns the raw key (no "Bearer "
// prefix).
//
// Priority:
//  1. X-AI-Auth header (OpenClaw fetch interceptor, normalized to "Bearer <key>")
//  2. api-key header (Azure)
//  3. x-api-key header (Anthropic)
//  4. Authorization header
//
// Keys prefixed with "sk-dc-" (DefenseClaw master keys) are skipped so they
// don't leak upstream.
func ExtractAPIKey(r *http.Request) string {
	if aiAuth := r.Header.Get("X-AI-Auth"); aiAuth != "" {
		key := ExtractBearerKey(aiAuth)
		if !strings.HasPrefix(key, "sk-dc-") {
			return key
		}
	}
	if azKey := r.Header.Get("api-key"); azKey != "" {
		return azKey
	}
	if xKey := r.Header.Get("x-api-key"); xKey != "" {
		return xKey
	}
	if auth := r.Header.Get("Authorization"); auth != "" {
		key := ExtractBearerKey(auth)
		if !strings.HasPrefix(key, "sk-dc-") {
			return key
		}
	}
	return ""
}

// chatBody is the minimal shape of an OpenAI/Anthropic chat request body
// used by ParseModelFromBody and ParseStreamFromBody.
type chatBody struct {
	Model  string `json:"model"`
	Stream *bool  `json:"stream,omitempty"`
}

// ParseModelFromBody extracts the "model" field from a JSON request body.
func ParseModelFromBody(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	var b chatBody
	if err := json.Unmarshal(body, &b); err != nil {
		return ""
	}
	return b.Model
}

// ParseStreamFromBody extracts the "stream" field from a JSON request body.
// Returns false if the field is absent or unparseable.
func ParseStreamFromBody(body []byte) bool {
	if len(body) == 0 {
		return false
	}
	var b chatBody
	if err := json.Unmarshal(body, &b); err != nil {
		return false
	}
	if b.Stream == nil {
		return false
	}
	return *b.Stream
}

// IsLoopback returns true when the request originates from a loopback address.
func IsLoopback(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return host == "localhost"
}

// isChatPath returns true for paths that are OpenAI/Anthropic chat completions.
func isChatPath(path string) bool {
	return strings.Contains(path, "/chat/completions") ||
		strings.Contains(path, "/messages") ||
		strings.Contains(path, "/responses")
}

// AcceptLoopbackWithWarning centralizes the "trust loopback because the
// vendor CLI is a native binary with no seam to inject X-DC-Auth" carve-
// out used today by the Codex connector. Centralizing the pattern means
// any future connector that needs the same exception must opt in
// explicitly (callers pass their own warned *sync.Once + reason) and the
// [SECURITY] line wording stays uniform across connectors so operators
// grepping audit/console output recognize the bypass immediately.
//
// Usage:
//
//	type FooConnector struct {
//	    gatewayToken string
//	    warned       sync.Once
//	}
//	func (c *FooConnector) Authenticate(r *http.Request) bool {
//	    if connector.AcceptLoopbackWithWarning(r, c.gatewayToken,
//	        "foo", "foo-cli has no header-injection seam", &c.warned) {
//	        return true
//	    }
//	    // ... fall back to header-based auth checks ...
//	    return false
//	}
//
// The helper:
//
//   - returns false (no trust) when r is not a loopback request, so the
//     caller falls through to its real auth path;
//   - returns true when r IS loopback;
//   - emits a single `[SECURITY] <connector>: loopback request accepted
//     without X-DC-Auth — DEFENSECLAW_GATEWAY_TOKEN is set but the
//     <connector> native binary has no seam to inject it. <reason>` line
//     to stderr the FIRST time it returns true while gatewayToken is
//     non-empty (subsequent calls suppress the warning via warned).
//   - never logs when gatewayToken is empty — that is the "no gateway
//     auth configured at all" case where loopback trust is the explicit
//     operator default.
//
// # SECURITY MODEL — IMPORTANT
//
// This helper is the only sanctioned way to take the loopback carve-out
// in the codebase. Anyone reviewing a connector PR can grep for
// `AcceptLoopbackWithWarning` and immediately see every connector that
// elects to trust loopback unconditionally, alongside the human-readable
// `reason` string explaining why. Adding the carve-out by writing
// `if IsLoopback(r) { return true }` directly in a connector is a
// security regression and should be rejected at code review.
//
// connectorName is the connector's short name. Today there is exactly
// one authorised caller (Codex). If you are about to call this from a
// second connector, you must:
//
//  1. document the reason that connector cannot inject X-DC-Auth in the
//     connector's Authenticate() godoc, AND
//  2. add a test asserting the [SECURITY] line is emitted exactly once
//     per process for that new caller.
func AcceptLoopbackWithWarning(r *http.Request, gatewayToken, connectorName, reason string, warned *sync.Once) bool {
	if !IsLoopback(r) {
		return false
	}
	// SECURITY: the warned argument is REQUIRED — passing nil
	// would silently suppress the [SECURITY] log line that
	// announces every loopback bypass, recreating the silent-trust
	// vulnerability this helper was built to prevent. We panic
	// here instead of returning true-without-warn so the misuse is
	// caught at first call (typically immediately after a
	// connector's Authenticate is wired up), not in production
	// where the missing warning would only surface during an
	// audit.
	if warned == nil {
		panic("connector.AcceptLoopbackWithWarning: warned argument must not be nil (would silently suppress the [SECURITY] loopback-bypass log)")
	}
	connectorName = strings.TrimSpace(connectorName)
	if connectorName == "" {
		connectorName = "unknown"
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "vendor CLI has no header-injection seam"
	}
	// Only emit the warning when the operator has actually
	// configured a token; without a token there is no "bypass"
	// (the gateway accepts unauthenticated loopback by default).
	// We keep the warning at WARN-only because the carve-out is a
	// deliberate trust decision documented in INFO.md, not an
	// unexpected configuration.
	if strings.TrimSpace(gatewayToken) != "" {
		warned.Do(func() {
			fmt.Fprintf(os.Stderr,
				"[SECURITY] %s: loopback request accepted without X-DC-Auth — "+
					"DEFENSECLAW_GATEWAY_TOKEN is set but the %s native binary "+
					"has no seam to inject it. %s. Any process on this host "+
					"can route through this connector's API with no further "+
					"authentication.\n",
				connectorName, connectorName, reason)
		})
	}
	return true
}

func authenticateHookBridgeRequest(r *http.Request, gatewayToken, masterKey, connectorName, loopbackReason string, warned *sync.Once) bool {
	provided := ExtractBearerKey(r.Header.Get("Authorization"))
	if gatewayToken != "" && SecureTokenMatch(provided, gatewayToken) {
		return true
	}
	if masterKey != "" && SecureTokenMatch(provided, masterKey) {
		return true
	}
	return AcceptLoopbackWithWarning(r, gatewayToken, connectorName, loopbackReason, warned)
}
