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

// Package hookexec runs DefenseClaw agent hooks natively in Go instead of via
// the bundled Bash hook scripts. It is the execution path used on Windows,
// where agents invoke the DefenseClaw binary directly (no Git Bash, no .cmd
// wrapper, no jq, and no PATH lockdown — because Go never shells out).
//
// The behavior here intentionally mirrors the .sh hooks under
// internal/gateway/connector/hooks line-for-line: the same gateway endpoint
// per connector, the same per-connector stdout shape and exit code, and the
// same fail-open-on-outage / fail-closed-on-misconfig policy. Unix keeps using
// the .sh hooks unchanged; this package is the parity implementation so the
// two paths cannot drift (the golden tests pin the contract on every OS).
package hookexec

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// blockExit is the POSIX exit code every supported agent treats as "this hook
// blocked the action" (Claude Code, Codex, Cursor, Windsurf, OpenHands, ...).
const blockExit = 2

// defaultMaxBody caps how many bytes of the agent's hook payload we read from
// stdin before refusing it, matching DEFENSECLAW_HOOK_MAX_BODY in the .sh
// hooks (1 MiB). A 1 MiB+ hook event is well outside any legitimate payload
// and silently truncating it would yield a confusing downstream parse error.
const defaultMaxBody int64 = 1 << 20

// Options configures a single hook invocation. The CLI entrypoint fills these
// from flags + environment; tests construct them directly so the full decision
// matrix can be exercised without a real gateway or agent.
type Options struct {
	// Connector is the logical connector name, e.g. "claudecode", "codex".
	Connector string
	// Event is the agent hook event (informational; recorded in failure logs).
	Event string
	// APIAddr is the gateway "host:port" the hook posts to.
	APIAddr string
	// FailMode is "open" or "closed"; it governs response-layer failures
	// (4xx / bad JSON) and transport failures. StrictAvailability forces
	// closed independently. Empty defaults to "open".
	FailMode string

	// Home is DEFENSECLAW_HOME (default ~/.defenseclaw). If it does not exist
	// or contains a .disabled file the hook is a no-op (exit 0).
	Home string
	// HookDir holds connector-scoped and legacy token sidecars (default Home/hooks).
	HookDir string
	// Token, when set, is the resolved gateway token (e.g. from the
	// DEFENSECLAW_GATEWAY_TOKEN env var). A connector-scoped token file takes
	// precedence so an inherited generic gateway token cannot shadow the
	// narrower credential; Token still precedes the legacy .token fallback.
	Token string

	// StrictAvailability mirrors DEFENSECLAW_STRICT_AVAILABILITY: when true,
	// transport failures and a missing token fail closed instead of open.
	StrictAvailability bool

	// MaxBody overrides the stdin cap in bytes (default defaultMaxBody).
	MaxBody int64

	// TraceParent / TraceState are W3C trace-context candidates forwarded to
	// the gateway after validation (invalid values are dropped, never sent).
	TraceParent string
	TraceState  string

	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer

	// HTTPClient lets tests inject a stub transport. When nil a client with
	// the same 2s-connect / 10s-total budget as the .sh `curl` call is used.
	HTTPClient *http.Client
	// Now is injectable for deterministic failure-log timestamps in tests.
	Now func() time.Time
}

// Run executes the hook described by opts and returns the process exit code
// (0 = allow / no-op, 2 = block / fail-closed). It never returns other codes
// so callers can pass the result straight to os.Exit.
func Run(ctx context.Context, opts Options) int {
	opts = withDefaults(opts)

	sp, ok := specFor(opts.Connector)
	if !ok {
		// Unknown connector is a wiring bug, not a policy decision. Fail loud
		// so it surfaces in tests / setup rather than silently disabling the
		// guardrail. The CLI validates --connector against the registry, so
		// this is unreachable in normal operation.
		fmt.Fprintf(opts.Stderr, "defenseclaw: unknown hook connector %q\n", opts.Connector)
		return blockExit
	}

	// DEFENSECLAW_HOME guard: if the data dir is gone or the operator dropped
	// a .disabled file, return the connector's explicit no-op response. Cursor
	// requires valid JSON even for an intentional allow; other connectors keep
	// their existing empty response because openAllow is unset for them.
	if info, err := os.Stat(opts.Home); err != nil || !info.IsDir() {
		return emit(opts.Stdout, sp.openAllow)
	}
	if _, err := os.Stat(filepath.Join(opts.Home, ".disabled")); err == nil {
		return emit(opts.Stdout, sp.openAllow)
	}

	failMode := normalizeFailMode(opts.FailMode)

	// Missing-token branch: only taken when BOTH the env token is empty AND
	// the resolved token sidecar is absent. (An empty token inside an existing
	// file is intentionally NOT a missing token — it selects the loopback
	// no-auth path, same as the .sh.)
	tokenFile, scopedTokenFile := hookTokenFile(opts.HookDir, opts.Connector)
	if opts.Token == "" && !fileExists(tokenFile) {
		return handleMissingToken(opts, sp, failMode)
	}

	payload, overflow, err := readCapped(opts.Stdin, opts.MaxBody)
	if err != nil {
		// stdin read error is treated like an oversized/unusable payload.
		overflow = true
	}
	if overflow {
		return handleOversized(opts, sp, failMode)
	}

	token := opts.Token
	if scopedTokenFile || token == "" {
		token = readTokenFile(tokenFile, scopedTokenFile)
	}

	return doRequest(ctx, opts, sp, failMode, payload, token)
}

// RunCodexNotify forwards the JSON payload Codex appends to its configured
// `notify` argv array. Notifications are telemetry-only and deliberately
// best-effort: every local/configuration/transport/response failure returns 0,
// matching the legacy Bash bridge's `curl ... || true` contract.
func RunCodexNotify(ctx context.Context, opts Options, payload []byte) int {
	opts = withDefaults(opts)
	if info, err := os.Stat(opts.Home); err != nil || !info.IsDir() {
		return 0
	}
	if _, err := os.Stat(filepath.Join(opts.Home, ".disabled")); err == nil {
		return 0
	}
	if len(payload) == 0 || int64(len(payload)) > opts.MaxBody {
		return 0
	}

	tokenFile := filepath.Join(opts.HookDir, ".token")
	if opts.Token == "" && !fileExists(tokenFile) {
		return 0
	}
	token := opts.Token
	if token == "" {
		token = readTokenFile(tokenFile, false)
	}

	notifyCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(notifyCtx, http.MethodPost,
		"http://"+opts.APIAddr+"/api/v1/codex/notify", bytes.NewReader(payload))
	if err != nil {
		return 0
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DefenseClaw-Client", "codex-notify/1.0")
	req.Header.Set("x-defenseclaw-source", "codex-notify")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if v := strings.TrimSpace(opts.TraceParent); v != "" && validTraceparent(v) {
		req.Header.Set("traceparent", v)
	}
	if v := strings.TrimSpace(opts.TraceState); v != "" && validTracestate(v) {
		req.Header.Set("tracestate", v)
	}

	resp, err := opts.HTTPClient.Do(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, defaultMaxBody))
	return 0
}

// doRequest performs the gateway POST and dispatches the response through the
// connector-specific decision logic, applying the transport vs response
// failure split exactly like the .sh hooks.
func doRequest(ctx context.Context, opts Options, sp spec, failMode string, payload []byte, token string) int {
	url := "http://" + opts.APIAddr + sp.endpoint
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return failResponse(opts, sp, failMode, "invalid request: "+err.Error())
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DefenseClaw-Client", sp.hookName+"/1.0")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if v := strings.TrimSpace(opts.TraceParent); v != "" && validTraceparent(v) {
		req.Header.Set("traceparent", v)
	}
	if v := strings.TrimSpace(opts.TraceState); v != "" && validTracestate(v) {
		req.Header.Set("tracestate", v)
	}

	resp, err := opts.HTTPClient.Do(req)
	if err != nil {
		return failUnreachable(opts, sp, failMode, "gateway unreachable")
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, defaultMaxBody))

	switch {
	case resp.StatusCode >= 500 && resp.StatusCode < 600:
		return failUnreachable(opts, sp, failMode, fmt.Sprintf("gateway returned HTTP %d", resp.StatusCode))
	case resp.StatusCode < 200 || resp.StatusCode >= 300:
		return failResponse(opts, sp, failMode, fmt.Sprintf("gateway returned HTTP %d", resp.StatusCode))
	}

	return sp.decide(opts, body)
}

// decide shapes the connector-native stdout + exit code from a 2xx gateway
// response body, returning a fail_response result if the body is not JSON.
func (sp spec) decide(opts Options, body []byte) int {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		return failResponse(opts, sp, normalizeFailMode(opts.FailMode), "invalid JSON response")
	}

	action, ok := rawString(fields, "action")
	if !ok || (action != "allow" && action != "block" && action != "confirm") {
		if sp.style == styleClaudeCode || sp.style == styleCodex || sp.style == styleActionStderr {
			return failResponse(opts, sp, normalizeFailMode(opts.FailMode), "invalid or missing action in gateway response")
		}
		action = "allow"
	}
	reason := rawStringOr(fields, "reason", "")
	output := compactField(fields, sp.outputField)

	switch sp.style {
	case styleClaudeCode:
		if output != "" {
			fmt.Fprintln(opts.Stdout, output)
		}
		if action == "block" {
			if output != "" {
				return 0
			}
			if reason == "" {
				reason = sp.defaultBlockReason
			}
			fmt.Fprintln(opts.Stderr, reason)
			return blockExit
		}
		return 0

	case styleCodex:
		if output != "" {
			fmt.Fprintln(opts.Stdout, output)
		}
		if action == "block" {
			if output != "" {
				return 0
			}
			if reason == "" {
				reason = sp.defaultBlockReason
			}
			// Emit minimal structured block JSON with exit 0: newer Codex
			// versions treat exit 2 on UserPromptSubmit as "hook failed",
			// not "hook blocked".
			fmt.Fprintf(opts.Stdout, "{\"decision\":\"block\",\"reason\":%s}\n", mustJSONString(reason))
			return 0
		}
		return 0

	case styleHookEcho:
		if output != "" {
			fmt.Fprintln(opts.Stdout, output)
		} else {
			return emit(opts.Stdout, sp.openAllow)
		}
		return 0

	case styleHookEchoDecision:
		if output != "" {
			fmt.Fprintln(opts.Stdout, output)
			if d := decodeDecision(output); d == "deny" || d == "block" {
				return blockExit
			}
		}
		return 0

	case styleActionStderr:
		if action == "block" {
			if reason == "" {
				reason = sp.defaultBlockReason
			}
			fmt.Fprintln(opts.Stderr, reason)
			return blockExit
		}
		return 0

	default:
		return 0
	}
}

// handleMissingToken mirrors defenseclaw_handle_missing_token: log the bypass,
// then allow (exit 0) by default or block (exit 2) under strict availability.
// No connector-specific JSON body is emitted on this path.
func handleMissingToken(opts Options, sp spec, failMode string) int {
	const reason = "missing gateway token (connector-scoped and legacy token sidecars absent; DEFENSECLAW_GATEWAY_TOKEN unset)"
	logHookFailure(opts, sp, reason, "transport", failMode)
	if opts.StrictAvailability || failMode == "closed" {
		fmt.Fprintf(opts.Stderr,
			"defenseclaw: %s, blocking %s (fail mode closed)\n", reason, sp.subject)
		return emit(opts.Stdout, sp.unreachableStrict)
	}
	return emit(opts.Stdout, sp.openAllow)
}

// handleOversized mirrors the per-connector oversized-payload branch.
func handleOversized(opts Options, sp spec, failMode string) int {
	logHookFailure(opts, sp, "stdin body exceeded cap", "transport", failMode)
	fmt.Fprintf(opts.Stderr, "defenseclaw: %s hook refusing oversized payload\n", sp.connector)
	if failMode == "closed" {
		return emit(opts.Stdout, sp.oversizedClosed)
	}
	return emit(opts.Stdout, sp.openAllow)
}

// failUnreachable applies the connector's effective fail mode to native hook
// transport failures. Strict availability remains an unconditional closed
// override for compatibility with existing deployments.
func failUnreachable(opts Options, sp spec, failMode, reason string) int {
	logHookFailure(opts, sp, reason, "transport", failMode)
	if opts.StrictAvailability || failMode == "closed" {
		fmt.Fprintf(opts.Stderr,
			"defenseclaw: gateway unreachable, blocking %s (fail mode closed): %s\n", sp.subject, reason)
		return emit(opts.Stdout, sp.unreachableStrict)
	}
	fmt.Fprintf(opts.Stderr, "defenseclaw: gateway unreachable, allowing %s: %s\n", sp.subject, reason)
	return emit(opts.Stdout, sp.openAllow)
}

func rawString(fields map[string]json.RawMessage, key string) (string, bool) {
	raw, ok := fields[key]
	if !ok {
		return "", false
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", false
	}
	return strings.ToLower(strings.TrimSpace(value)), true
}

// failResponse mirrors the response-layer failure path: honor FAIL_MODE.
func failResponse(opts Options, sp spec, failMode, reason string) int {
	reason = responseFailureReason(reason)
	logHookFailure(opts, sp, reason, "response", failMode)
	fmt.Fprintf(opts.Stderr, "defenseclaw: %s hook error: %s\n", sp.errLabel, reason)
	if failMode == "open" {
		return emit(opts.Stdout, sp.openAllow)
	}
	return emit(opts.Stdout, sp.responseClosed)
}

func responseFailureReason(reason string) string {
	if strings.Contains(reason, "HTTP 401") || strings.Contains(reason, "HTTP 403") {
		return reason + " (gateway auth failed; possible token drift. Run `defenseclaw doctor --fix` or `defenseclaw-gateway restart`.)"
	}
	return reason
}

// emit writes a fail-closed JSON body (if any) and returns its exit code.
func emit(out io.Writer, r failResult) int {
	if r.body != "" {
		fmt.Fprintln(out, r.body)
	}
	return r.exit
}

func withDefaults(o Options) Options {
	if o.Stdin == nil {
		o.Stdin = os.Stdin
	}
	if o.Stdout == nil {
		o.Stdout = os.Stdout
	}
	if o.Stderr == nil {
		o.Stderr = os.Stderr
	}
	if o.MaxBody <= 0 {
		o.MaxBody = defaultMaxBody
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Home == "" {
		if home, err := os.UserHomeDir(); err == nil {
			o.Home = filepath.Join(home, ".defenseclaw")
		}
	}
	if o.HookDir == "" {
		o.HookDir = filepath.Join(o.Home, "hooks")
	}
	if o.HTTPClient == nil {
		o.HTTPClient = defaultHTTPClient()
	}
	return o
}

// defaultHTTPClient matches the .sh `curl --connect-timeout 2 --max-time 10`.
//
// CheckRedirect refuses to follow redirects, mirroring `curl` without `-L`
// (the .sh hooks never passed -L). The gateway hook endpoints never legitimately
// redirect, so a 3xx is surfaced to doRequest as a non-2xx response (handled by
// FAIL_MODE) instead of being followed. This keeps the hook from chasing a
// redirect to a different host/port — which would otherwise widen the SSRF
// surface and could leak the gateway bearer token to an unintended target if the
// configured gateway address were ever tampered with.
func defaultHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{Timeout: 2 * time.Second}).DialContext,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func normalizeFailMode(m string) string {
	if strings.EqualFold(strings.TrimSpace(m), "closed") {
		return "closed"
	}
	return "open"
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func hookTokenFile(hookDir, connector string) (string, bool) {
	scoped := filepath.Join(hookDir, ".hook-"+strings.ToLower(strings.TrimSpace(connector))+".token")
	if fileExists(scoped) {
		return scoped, true
	}
	return filepath.Join(hookDir, ".token"), false
}

// readTokenFile parses DEFENSECLAW_GATEWAY_TOKEN out of a token sidecar,
// which setup writes as `DEFENSECLAW_GATEWAY_TOKEN="<token>"` (Go-quoted). An
// unreadable/empty file yields an empty token (loopback no-auth path).
func readTokenFile(path string, allowRaw bool) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		line = strings.TrimPrefix(line, "export ")
		const key = "DEFENSECLAW_GATEWAY_TOKEN="
		if !strings.HasPrefix(line, key) {
			continue
		}
		val := strings.TrimSpace(line[len(key):])
		if unq, err := strconv.Unquote(val); err == nil {
			return unq
		}
		return strings.Trim(val, `"'`)
	}
	if !allowRaw {
		return ""
	}
	raw := strings.TrimSuffix(string(data), "\n")
	if strings.ContainsAny(raw, "\r\n") {
		return ""
	}
	return raw
}

// rawStringOr returns the JSON string value at key, or def when the key is
// missing, null, or not a string (matching jq's `.key // "def"`).
func rawStringOr(m map[string]json.RawMessage, key, def string) string {
	raw, ok := m[key]
	if !ok {
		return def
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return def
	}
	if s == "" {
		return def
	}
	return s
}

// compactField returns the compact JSON of m[field], or "" when the field is
// missing or JSON null (matching jq's `.field // empty`).
func compactField(m map[string]json.RawMessage, field string) string {
	if field == "" {
		return ""
	}
	raw, ok := m[field]
	if !ok {
		return ""
	}
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return ""
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		return trimmed
	}
	return buf.String()
}

// decodeDecision pulls the `decision` string from an already-compact JSON
// object (the connector's hook_output) for the OpenHands deny/block path.
func decodeDecision(output string) string {
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(output), &m); err != nil {
		return ""
	}
	return rawStringOr(m, "decision", "")
}

// mustJSONString returns s as a JSON string literal (quoted + escaped).
func mustJSONString(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		return `""`
	}
	return string(b)
}
