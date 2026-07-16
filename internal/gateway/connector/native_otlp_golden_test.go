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
	"encoding/json"
	"net/url"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// fixedSetupOpts produces a deterministic SetupOpts so the shape
// checks below are stable across machines. We deliberately use a
// placeholder address and a short token: the renderers must not
// inject anything ENV-derived (hostname, USER, $HOME) into the OTLP
// payload.
func fixedSetupOpts(t *testing.T) SetupOpts {
	t.Helper()
	return SetupOpts{
		APIAddr:       "127.0.0.1:18970",
		APIToken:      "tok-test",
		OTLPPathToken: strings.Repeat("a", 64),
		DataDir:       t.TempDir(),
	}
}

func TestScopedOTLPEndpointRecognitionIsExact(t *testing.T) {
	token := strings.Repeat("a", 64)
	base := "http://127.0.0.1:18970/otlp/claudecode/" + token
	if !isScopedOTLPBaseEndpoint(base, "127.0.0.1:18970", OTLPScopeClaude) {
		t.Fatal("valid connector-scoped base endpoint was rejected")
	}
	if !isScopedOTLPEndpoint(base+"/v1/logs", "127.0.0.1:18970", OTLPScopeClaude, NativeOTLPSignalLogs) {
		t.Fatal("valid connector-scoped signal endpoint was rejected")
	}
	for _, endpoint := range []string{
		base + "/extra",
		base + "/v1/traces",
		"http://127.0.0.1:18970/otlp/codex/" + token,
		"http://localhost:18970/otlp/claudecode/" + token,
	} {
		if isScopedOTLPBaseEndpoint(endpoint, "127.0.0.1:18970", OTLPScopeClaude) {
			t.Errorf("foreign or malformed base endpoint accepted: %q", endpoint)
		}
	}
}

// TestNativeOTLPShape_Codex pins the codex [otel] table to the
// schema-required shape. Codex's deserializer is kebab-case and
// rejects missing keys, so this test guards the four documented
// top-level fields and the per-signal exporter sub-shape.
//
// Equally important: this test ASSERTS that we do not emit
// service_name / resource_attributes keys. Codex's documented
// schema does not define them (see codex config-reference) and
// the published schema is published as strict (see
// https://github.com/openai/codex/issues/17012). Writing them would
// risk codex rejecting the operator's config at startup.
func TestNativeOTLPShape_Codex(t *testing.T) {
	t.Parallel()
	opts := fixedSetupOpts(t)

	pathToken, err := EnsureOTLPPathToken(opts.DataDir, OTLPScopeCodex)
	if err != nil || pathToken == "" {
		t.Fatalf("mint scoped Codex OTLP token: present=%v err=%v", pathToken != "", err)
	}
	block, err := buildCodexOtelBlockWithPathToken(opts, pathToken)
	if err != nil {
		t.Fatalf("buildCodexOtelBlockWithPathToken: %v", err)
	}

	for _, want := range []string{"log_user_prompt", "exporter", "trace_exporter", "metrics_exporter"} {
		if _, ok := block[want]; !ok {
			t.Errorf("missing required codex [otel] key %q", want)
		}
	}

	// Guard against accidentally re-adding service_name /
	// resource_attributes — codex's [otel] schema does not accept
	// them. If a future contributor wants codex telemetry tagged
	// with defenseclaw resource attributes they have two options:
	// (1) wrap codex's launch with an OTEL_* env var injection
	// (out of scope for this connector — codex spawns its own
	// subshells), or (2) lobby the codex team to add support for
	// these keys in the [otel] schema.
	for _, banned := range []string{"service_name", "resource_attributes", "service.name", "resource.attributes"} {
		if _, present := block[banned]; present {
			t.Errorf("codex [otel] must NOT carry %q — schema does not define it; see HookProfile rationale", banned)
		}
	}

	// Each per-signal exporter must carry endpoint + protocol +
	// headers under the otlp-http sub-key. Drift here means the
	// codex CLI will refuse the config at startup with a
	// missing-field flavour error.
	for _, signal := range []string{"exporter", "trace_exporter", "metrics_exporter"} {
		exp, ok := block[signal].(map[string]interface{})
		if !ok {
			t.Errorf("%s: not a map", signal)
			continue
		}
		otlp, ok := exp["otlp-http"].(map[string]interface{})
		if !ok {
			t.Errorf("%s.otlp-http: not a map", signal)
			continue
		}
		if got, _ := otlp["protocol"].(string); got != "json" {
			t.Errorf("%s.otlp-http.protocol = %q; want \"json\"", signal, got)
		}
		wantSignal := map[string]string{
			"exporter":         "logs",
			"trace_exporter":   "traces",
			"metrics_exporter": "metrics",
		}[signal]
		ep, _ := otlp["endpoint"].(string)
		wantEndpoint := "http://" + opts.APIAddr + "/v1/" + wantSignal
		if ep != wantEndpoint {
			t.Errorf("%s.otlp-http.endpoint = %q; want %q", signal, ep, wantEndpoint)
		}
		if strings.Contains(ep, pathToken) || strings.Contains(ep, "/otlp/codex/") {
			t.Errorf("%s.otlp-http.endpoint leaked scoped Codex credential: %q", signal, ep)
		}
		if !strings.Contains(ep, "/v1/") {
			t.Errorf("%s.otlp-http.endpoint = %q; want standard OTLP signal path", signal, ep)
		}
		hdrs := toStringMap(otlp["headers"])
		if _, leaked := hdrs["x-defenseclaw-token"]; leaked {
			t.Errorf("%s.otlp-http.headers leaked the general API token: %v", signal, hdrs)
		}
		if hdrs["x-defenseclaw-source"] != "codex" {
			t.Errorf("%s.otlp-http.headers[x-defenseclaw-source] = %q; want \"codex\"", signal, hdrs["x-defenseclaw-source"])
		}
		if hdrs["x-defenseclaw-client"] == "" {
			t.Errorf("%s.otlp-http.headers[x-defenseclaw-client] missing (gateway CSRF gate would reject)", signal)
		}
		if got := hdrs["authorization"]; got != "Bearer "+pathToken {
			t.Errorf("%s.otlp-http.headers[authorization] = %q; want connector-scoped bearer", signal, got)
		}
	}
}

func TestCodexHookProfile_IsPureAndLeavesScopedTokenUnresolved(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	opts := SetupOpts{DataDir: dir, APIAddr: "127.0.0.1:18970", APIToken: "hook-credential"}
	tokenPath, err := OTLPPathTokenFilePath(dir, OTLPScopeCodex)
	if err != nil {
		t.Fatalf("OTLPPathTokenFilePath: %v", err)
	}

	profile := NewCodexConnector().HookProfile(opts)
	if profile.NativeOTLP == nil {
		t.Fatal("Codex HookProfile omitted NativeOTLP metadata")
	}
	if profile.NativeOTLP.PathToken != "" || profile.NativeOTLP.PathScope != "" {
		t.Fatal("Codex HookProfile resolved setup-owned path-token state")
	}
	if _, err := os.Lstat(tokenPath); !os.IsNotExist(err) {
		t.Fatal("Codex HookProfile touched the scoped token file")
	}

	// Rendering with an explicitly injected token is also pure: setup owns
	// minting, while this function only maps supplied state into TOML.
	if _, err := buildCodexOtelBlockWithPathToken(opts, strings.Repeat("a", 64)); err != nil {
		t.Fatalf("buildCodexOtelBlockWithPathToken: %v", err)
	}
	if _, err := os.Lstat(tokenPath); !os.IsNotExist(err) {
		t.Fatal("Codex OTLP renderer touched the scoped token file")
	}

	existingDir := t.TempDir()
	seeded, err := EnsureOTLPPathToken(existingDir, OTLPScopeCodex)
	if err != nil {
		t.Fatalf("seed existing scoped token: %v", err)
	}
	existingProfile := NewCodexConnector().HookProfile(SetupOpts{
		DataDir: existingDir,
		APIAddr: opts.APIAddr,
	})
	if existingProfile.NativeOTLP.PathToken != "" || existingProfile.NativeOTLP.PathScope != "" {
		t.Fatal("Codex HookProfile loaded an existing setup-owned token")
	}
	retained, err := LoadOTLPPathToken(existingDir, OTLPScopeCodex)
	if err != nil || retained != seeded {
		t.Fatalf("Codex HookProfile changed existing token state: retained=%v err=%v", retained == seeded, err)
	}
}

// TestNativeOTLPShape_ClaudeCode pins the claudecode env block to
// the shape the vendor's settings.json injects into the CLI process.
// Keys are matched explicitly because Claude Code's OTel SDK reads
// each one by name; OTEL_EXPORTER_OTLP_HEADERS / OTEL_RESOURCE_ATTRIBUTES
// values are parsed as unordered comma-separated key=value sets.
func TestNativeOTLPShape_ClaudeCode(t *testing.T) {
	t.Parallel()
	opts := fixedSetupOpts(t)

	env := buildClaudeCodeOtelEnv(opts)
	if len(env) == 0 {
		t.Fatal("buildClaudeCodeOtelEnv returned empty map; spec validation likely failed")
	}

	for _, want := range []string{
		"CLAUDE_CODE_ENABLE_TELEMETRY",
		"DEFENSECLAW_FAIL_MODE",
		"OTEL_EXPORTER_OTLP_ENDPOINT",
		"OTEL_EXPORTER_OTLP_HEADERS",
		"OTEL_EXPORTER_OTLP_PROTOCOL",
		"OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
		"OTEL_EXPORTER_OTLP_LOGS_HEADERS",
		"OTEL_EXPORTER_OTLP_LOGS_PROTOCOL",
		"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT",
		"OTEL_EXPORTER_OTLP_METRICS_HEADERS",
		"OTEL_EXPORTER_OTLP_METRICS_PROTOCOL",
		"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
		"OTEL_EXPORTER_OTLP_TRACES_HEADERS",
		"OTEL_EXPORTER_OTLP_TRACES_PROTOCOL",
		"OTEL_LOGS_EXPORTER",
		"OTEL_METRICS_EXPORTER",
		"OTEL_TRACES_EXPORTER",
		"OTEL_RESOURCE_ATTRIBUTES",
		"OTEL_SERVICE_NAME",
	} {
		if _, ok := env[want]; !ok {
			t.Errorf("missing required claudecode env var %q", want)
		}
	}

	if env["CLAUDE_CODE_ENABLE_TELEMETRY"] != "1" {
		t.Errorf("CLAUDE_CODE_ENABLE_TELEMETRY = %q; want \"1\"", env["CLAUDE_CODE_ENABLE_TELEMETRY"])
	}
	if env["OTEL_SERVICE_NAME"] != "claudecode" {
		t.Errorf("OTEL_SERVICE_NAME = %q; want \"claudecode\"", env["OTEL_SERVICE_NAME"])
	}
	if env["OTEL_EXPORTER_OTLP_PROTOCOL"] != "http/json" {
		t.Errorf("OTEL_EXPORTER_OTLP_PROTOCOL = %q; want \"http/json\"", env["OTEL_EXPORTER_OTLP_PROTOCOL"])
	}
	if env["OTEL_TRACES_EXPORTER"] != "none" {
		t.Errorf("OTEL_TRACES_EXPORTER = %q; want none", env["OTEL_TRACES_EXPORTER"])
	}
	if !strings.HasPrefix(env["OTEL_EXPORTER_OTLP_ENDPOINT"], "http://"+opts.APIAddr) {
		t.Errorf("OTEL_EXPORTER_OTLP_ENDPOINT = %q; want http://%s prefix",
			env["OTEL_EXPORTER_OTLP_ENDPOINT"], opts.APIAddr)
	}
	if strings.Contains(env["OTEL_EXPORTER_OTLP_ENDPOINT"], opts.OTLPPathToken) ||
		strings.Contains(env["OTEL_EXPORTER_OTLP_ENDPOINT"], "/otlp/claudecode/") {
		t.Errorf("OTEL_EXPORTER_OTLP_ENDPOINT leaked scoped Claude credential: %q", env["OTEL_EXPORTER_OTLP_ENDPOINT"])
	}

	headers := splitOTelHeader(env["OTEL_EXPORTER_OTLP_HEADERS"])
	wantHeaders := map[string]bool{
		"x-defenseclaw-source=claudecode":            true,
		"x-defenseclaw-client=claudecode-otel/1.0":   true,
		"authorization=Bearer " + opts.OTLPPathToken: true,
	}
	for _, h := range headers {
		delete(wantHeaders, h)
	}
	if len(wantHeaders) != 0 {
		t.Errorf("OTEL_EXPORTER_OTLP_HEADERS missing entries %v; got %v",
			wantHeaders, env["OTEL_EXPORTER_OTLP_HEADERS"])
	}
	if strings.Contains(env["OTEL_EXPORTER_OTLP_HEADERS"], "x-defenseclaw-token=") {
		t.Errorf("OTEL_EXPORTER_OTLP_HEADERS leaked the general API token: %s", env["OTEL_EXPORTER_OTLP_HEADERS"])
	}
	for _, signal := range []string{"LOGS", "METRICS", "TRACES"} {
		prefix := "OTEL_EXPORTER_OTLP_" + signal
		wantEndpoint := env["OTEL_EXPORTER_OTLP_ENDPOINT"] + "/v1/" + strings.ToLower(signal)
		if got := env[prefix+"_ENDPOINT"]; got != wantEndpoint {
			t.Errorf("%s_ENDPOINT = %q; want %q", prefix, got, wantEndpoint)
		}
		if got := env[prefix+"_PROTOCOL"]; got != "http/json" {
			t.Errorf("%s_PROTOCOL = %q; want http/json", prefix, got)
		}
		if got := env[prefix+"_HEADERS"]; got != env["OTEL_EXPORTER_OTLP_HEADERS"] {
			t.Errorf("%s_HEADERS = %q; want managed common headers", prefix, got)
		}
	}

	resAttrs := splitOTelHeader(env["OTEL_RESOURCE_ATTRIBUTES"])
	wantAttrs := map[string]bool{
		"service.name=claudecode":          true,
		"defenseclaw.connector=claudecode": true,
	}
	for _, a := range resAttrs {
		delete(wantAttrs, a)
	}
	if len(wantAttrs) != 0 {
		t.Errorf("OTEL_RESOURCE_ATTRIBUTES missing entries %v; got %v",
			wantAttrs, env["OTEL_RESOURCE_ATTRIBUTES"])
	}
}

func TestNativeOTLPShape_Copilot(t *testing.T) {
	t.Parallel()
	opts := fixedSetupOpts(t)

	spec := NewCopilotConnector().HookProfile(opts).NativeOTLP
	if spec == nil {
		t.Fatal("copilot NativeOTLP spec is nil")
	}
	env, err := spec.EnvBlock()
	if err != nil {
		t.Fatalf("copilot EnvBlock: %v", err)
	}

	for _, want := range []string{
		"COPILOT_OTEL_ENABLED",
		"OTEL_EXPORTER_OTLP_ENDPOINT",
		"OTEL_EXPORTER_OTLP_HEADERS",
		"OTEL_EXPORTER_OTLP_PROTOCOL",
		"OTEL_RESOURCE_ATTRIBUTES",
		"OTEL_SERVICE_NAME",
	} {
		if _, ok := env[want]; !ok {
			t.Errorf("missing required copilot env var %q", want)
		}
	}
	if env["COPILOT_OTEL_ENABLED"] != "true" {
		t.Errorf("COPILOT_OTEL_ENABLED = %q; want true", env["COPILOT_OTEL_ENABLED"])
	}
	if env["OTEL_SERVICE_NAME"] != "copilot" {
		t.Errorf("OTEL_SERVICE_NAME = %q; want copilot", env["OTEL_SERVICE_NAME"])
	}
	headers := splitOTelHeader(env["OTEL_EXPORTER_OTLP_HEADERS"])
	wantHeaders := map[string]bool{
		"x-defenseclaw-source=copilot":          true,
		"x-defenseclaw-client=copilot-otel/1.0": true,
		"x-defenseclaw-token=" + opts.APIToken:  true,
	}
	for _, h := range headers {
		delete(wantHeaders, h)
	}
	if len(wantHeaders) != 0 {
		t.Errorf("OTEL_EXPORTER_OTLP_HEADERS missing entries %v; got %v",
			wantHeaders, env["OTEL_EXPORTER_OTLP_HEADERS"])
	}
}

func TestNativeOTLPShape_Omnigent(t *testing.T) {
	t.Parallel()
	opts := fixedSetupOpts(t)

	spec := NewOmnigentConnector().HookProfile(opts).NativeOTLP
	if spec == nil {
		t.Fatal("omnigent NativeOTLP spec is nil")
	}
	env, err := spec.EnvBlock()
	if err != nil {
		t.Fatalf("omnigent EnvBlock: %v", err)
	}

	for _, want := range []string{
		"OTEL_EXPORTER_OTLP_ENDPOINT",
		"OTEL_EXPORTER_OTLP_PROTOCOL",
		"OTEL_EXPORTER_OTLP_HEADERS",
		"OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
		"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT",
		"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
		"OTEL_LOGS_EXPORTER",
		"OTEL_METRICS_EXPORTER",
		"OTEL_TRACES_EXPORTER",
		"OTEL_RESOURCE_ATTRIBUTES",
		"OTEL_SERVICE_NAME",
		"OMNIGENT_OTEL_CAPTURE_CONTENT",
	} {
		if _, ok := env[want]; !ok {
			t.Errorf("missing required omnigent env var %q", want)
		}
	}
	if env["OTEL_EXPORTER_OTLP_PROTOCOL"] != "http/protobuf" {
		t.Errorf("OTEL_EXPORTER_OTLP_PROTOCOL = %q; want http/protobuf", env["OTEL_EXPORTER_OTLP_PROTOCOL"])
	}
	if env["OTEL_SERVICE_NAME"] != "omnigent" {
		t.Errorf("OTEL_SERVICE_NAME = %q; want omnigent", env["OTEL_SERVICE_NAME"])
	}
	if env["OMNIGENT_OTEL_CAPTURE_CONTENT"] != "false" {
		t.Errorf("OMNIGENT_OTEL_CAPTURE_CONTENT = %q; want false", env["OMNIGENT_OTEL_CAPTURE_CONTENT"])
	}
	for _, signal := range []string{"LOGS", "METRICS", "TRACES"} {
		if got := env["OTEL_"+signal+"_EXPORTER"]; got != "otlp" {
			t.Errorf("OTEL_%s_EXPORTER = %q; want otlp", signal, got)
		}
		want := "http://" + opts.APIAddr + "/v1/" + strings.ToLower(signal)
		if got := env["OTEL_EXPORTER_OTLP_"+signal+"_ENDPOINT"]; got != want {
			t.Errorf("OTEL_EXPORTER_OTLP_%s_ENDPOINT = %q; want %q", signal, got, want)
		}
	}
	headers := splitOTelHeader(env["OTEL_EXPORTER_OTLP_HEADERS"])
	wantHeaders := map[string]bool{
		"x-defenseclaw-source=omnigent":          true,
		"x-defenseclaw-client=omnigent-otel/1.0": true,
		"x-defenseclaw-token=" + opts.APIToken:   true,
	}
	for _, header := range headers {
		delete(wantHeaders, header)
	}
	if len(wantHeaders) != 0 {
		t.Errorf("OTEL_EXPORTER_OTLP_HEADERS missing entries %v; got %v", wantHeaders, env["OTEL_EXPORTER_OTLP_HEADERS"])
	}
	attrs := splitOTelHeader(env["OTEL_RESOURCE_ATTRIBUTES"])
	wantAttrs := map[string]bool{
		"service.name=omnigent":          true,
		"defenseclaw.connector=omnigent": true,
	}
	for _, attr := range attrs {
		delete(wantAttrs, attr)
	}
	if len(wantAttrs) != 0 {
		t.Errorf("OTEL_RESOURCE_ATTRIBUTES missing entries %v; got %v", wantAttrs, env["OTEL_RESOURCE_ATTRIBUTES"])
	}
}

// TestNativeOTLPShape_GeminiCLI pins the Gemini CLI telemetry
// sub-object to the schema the vendor's settings.json loader
// requires: enabled/target/useCollector/otlpEndpoint/otlpProtocol/
// logPrompts, with the path-scoped endpoint that the gateway's
// tokenAuth middleware accepts for the gemini scope.
func TestNativeOTLPShape_GeminiCLI(t *testing.T) {
	t.Parallel()
	opts := fixedSetupOpts(t)
	const fixedToken = "test-gemini-token"

	spec := geminiCLINativeOTLPSpec(opts)
	if spec == nil {
		t.Fatal("geminiCLINativeOTLPSpec returned nil")
	}
	spec.PathToken = fixedToken
	got, err := spec.JSONBlock()
	if err != nil {
		t.Fatalf("spec.JSONBlock: %v", err)
	}

	want := map[string]interface{}{
		"enabled":      true,
		"target":       "local",
		"useCollector": true,
		"otlpEndpoint": "http://127.0.0.1:18970/otlp/geminicli/" + fixedToken,
		"otlpProtocol": "http",
		"logPrompts":   spec.LogUserPrompts,
	}

	if !reflect.DeepEqual(want, got) {
		t.Fatalf("geminicli telemetry block mismatch:\n  want=%s\n   got=%s",
			mustJSON(want), mustJSON(got))
	}
}

func TestSerializeOTLPHeadersRoundTripsThroughJavaScriptURIParser(t *testing.T) {
	t.Parallel()

	const value = "Bearer literal+plus,comma=equals%percent 雪"
	encoded := serializeOTLPHeaders(map[string]string{
		"Authorization": value,
	})
	if strings.Contains(encoded, "authorization=Bearer+") {
		t.Fatalf("space used form/query encoding instead of URI encoding: %q", encoded)
	}
	if !strings.Contains(encoded, "authorization=Bearer%20") {
		t.Fatalf("space was not percent-encoded for decodeURIComponent: %q", encoded)
	}

	got := splitOTelHeader(encoded)
	want := []string{"authorization=" + value}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("JavaScript-style header round-trip mismatch:\n  got=%q\n want=%q\nencoded=%q", got, want, encoded)
	}
}

// toStringMap canonicalizes header keys to lower-case so values
// produced by either map[string]string or map[string]interface{}
// renderers compare equal.
func toStringMap(v interface{}) map[string]string {
	out := map[string]string{}
	switch m := v.(type) {
	case map[string]interface{}:
		for k, vv := range m {
			out[strings.ToLower(k)], _ = vv.(string)
		}
	case map[string]string:
		for k, vv := range m {
			out[strings.ToLower(k)] = vv
		}
	}
	return out
}

// splitOTelHeader parses comma-separated key=value lists per the
// OTel spec, with the key half lower-cased so case differences from
// the renderer don't cause spurious mismatches.
func splitOTelHeader(v string) []string {
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		eq := strings.IndexByte(p, '=')
		if eq <= 0 {
			out = append(out, p)
			continue
		}
		// OpenTelemetry JS parses header components with decodeURIComponent,
		// whose relevant Go equivalent is PathUnescape: unlike query/form
		// decoding, a literal '+' remains a plus rather than becoming a space.
		key, _ := url.PathUnescape(p[:eq])
		value, _ := url.PathUnescape(p[eq+1:])
		out = append(out, strings.ToLower(key)+"="+value)
	}
	sort.Strings(out)
	return out
}

func mustJSON(v interface{}) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "<encode error: " + err.Error() + ">"
	}
	return string(b)
}
