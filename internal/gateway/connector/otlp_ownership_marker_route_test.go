// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"
)

// otlpMarkerRouteCase is one row of the second product-owned versus
// operator-owned table every native OTLP writer shares (Codex and Claude Code
// Setup and the managed per-user cleanup and Verify that Linux, macOS and the
// Windows module call). Each row keeps a released exporter's product marker
// headers and changes what the markers sit beside:
//
//   - moved: the operator removed the released bearer and retyped the route to
//     an unauthenticated local collector. Stale markers alone never claim a
//     route whose host DefenseClaw did not write, so the route stays and only
//     the markers go. A route on a host the product writes (127.0.0.1,
//     localhost) at a retired port is still the product's and is removed.
//   - unresolved: the released bearer stays beside the markers on a route
//     cleanup keeps, and the scoped credential cannot be read. Every writer
//     refuses and leaves the file as found, so the bearer neither stays
//     silently on a port DefenseClaw no longer owns nor is taken from an
//     operator collector. A remote collector was never a DefenseClaw port, so
//     its bearer stays the operator's there.
type otlpMarkerRouteCase struct {
	name     string
	route    string // logs route; {sig} is the signal for Codex's three tables
	bearer   string // "", "product" (the released token) or a literal value
	sidecar  bool   // the scoped token can still be read
	want     string // keep_route_strip_markers, remove_route, strip_bearer, refuse
	keepAuth bool   // the Authorization value stays: an operator shape, or a remote collector DefenseClaw never owned
	// claude overrides want for Claude Code, whose OTLP headers are not tied to
	// one route: removing a claimed logs route leaves its headers to the
	// generic collector, so an unresolved bearer there is refused too.
	claude string
}

func (c otlpMarkerRouteCase) wantFor(writer string) string {
	if writer == "claudecode" && c.claude != "" {
		return c.claude
	}
	return c.want
}

func otlpMarkerRouteCases() []otlpMarkerRouteCase {
	return []otlpMarkerRouteCase{
		{name: "moved_inet_aton_shorthand", route: "http://127.1:4318/v1/{sig}", want: "keep_route_strip_markers"},
		{name: "moved_hex_shorthand", route: "http://0x7f.1:4318/v1/{sig}", want: "keep_route_strip_markers"},
		{name: "moved_loopback_alias", route: "http://127.0.0.2:4318/v1/{sig}", want: "keep_route_strip_markers"},
		{name: "moved_unspecified", route: "http://0.0.0.0:4318/v1/{sig}", want: "keep_route_strip_markers"},
		{name: "moved_localhost_subdomain", route: "http://otel.localhost:4318/v1/{sig}", want: "keep_route_strip_markers"},
		{name: "moved_ipv4_mapped", route: "http://[::ffff:127.0.0.1]:4318/v1/{sig}", want: "keep_route_strip_markers"},
		{name: "retired_port_product_host", route: "http://127.0.0.1:4318/v1/{sig}", want: "remove_route"},
		{name: "retired_port_localhost", route: "http://localhost:4318/v1/{sig}", want: "remove_route"},
		{name: "unresolved_query_route", route: "http://127.0.0.1:19097/v1/{sig}?tenant=x", bearer: "product", want: "refuse"},
		{name: "unresolved_moved_local", route: "http://127.1:4318/v1/{sig}", bearer: "product", want: "refuse"},
		{name: "unresolved_remote_keeps_operator_route", route: "https://collector.example.test/v1/{sig}", bearer: "product", want: "keep_route_strip_markers", keepAuth: true},
		{name: "unresolved_scheme_spelling", route: "http://127.0.0.1:19097/v1/{sig}?tenant=x", bearer: "bearer-product", want: "refuse"},
		{name: "resolved_query_route", route: "http://127.0.0.1:19097/v1/{sig}?tenant=x", bearer: "product", sidecar: true, want: "strip_bearer"},
		{name: "operator_bearer_shape", route: "http://127.0.0.1:19097/v1/{sig}?tenant=x", bearer: "Bearer operator-collector-token", want: "keep_route_strip_markers", keepAuth: true},
		{name: "unresolved_on_product_route", route: "http://127.0.0.1:19097/v1/{sig}", bearer: "product", want: "remove_route", claude: "refuse"},
	}
}

func (c otlpMarkerRouteCase) endpoint(signal string) string {
	return strings.ReplaceAll(c.route, "{sig}", signal)
}

func (c otlpMarkerRouteCase) authorization(productToken string) string {
	switch c.bearer {
	case "":
		return ""
	case "product":
		return "Bearer " + productToken
	case "bearer-product":
		return "bearer " + productToken
	default:
		return c.bearer
	}
}

func TestOTLPProductRouteHostIsTheWrittenSpelling(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "localhost", "LOCALHOST.", "::1"} {
		if !otlpProductRouteHost(host, "") {
			t.Errorf("otlpProductRouteHost(%q) = false", host)
		}
	}
	for _, host := range []string{"127.1", "127.0.0.2", "0.0.0.0", "0x7f.1", "otel.localhost", "::ffff:127.0.0.1", "2130706433", ""} {
		if otlpProductRouteHost(host, "127.0.0.1:18970") {
			t.Errorf("otlpProductRouteHost(%q) = true", host)
		}
	}
	if !otlpProductRouteHost("127.0.0.5", "127.0.0.5:18970") {
		t.Error("the current API host is a product host")
	}
	product := strings.Repeat("a", 64)
	for _, tc := range []struct {
		values, known []string
		want          bool
	}{
		{[]string{"Bearer " + product}, nil, true},
		{[]string{"BEARER " + product}, nil, true},
		{[]string{"Bearer " + product}, []string{product}, false},
		{[]string{"Bearer operator-token"}, nil, false},
		{[]string{"Basic " + product}, nil, false},
		{nil, nil, false},
	} {
		if got := otlpUnresolvedProductBearer(tc.values, tc.known); got != tc.want {
			t.Errorf("otlpUnresolvedProductBearer(%q, %d known) = %t", tc.values, len(tc.known), got)
		}
	}
}

func codexMarkerRouteFixture(t *testing.T, release, goos string, c otlpMarkerRouteCase, productToken string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "codex_otel_"+release+"_product.toml"))
	if err != nil {
		t.Fatal(err)
	}
	body := strings.ReplaceAll(string(raw), "\r\n", "\n")
	body = strings.ReplaceAll(body, "fixture-os", goos)
	auth := ""
	if value := c.authorization(productToken); value != "" {
		auth = "authorization = '" + value + "'\n"
	}
	body = strings.ReplaceAll(body, "authorization = 'Bearer released-static-token'\n", auth)
	for _, signal := range []string{"logs", "metrics", "traces"} {
		body = strings.ReplaceAll(body, "'http://127.0.0.1:19081/v1/"+signal+"'", "'"+c.endpoint(signal)+"'")
	}
	if goos == "windows" {
		body = strings.ReplaceAll(body, "\n", "\r\n")
	}
	return body
}

// Codex: every writer reaches the row's outcome from a real released 1.0.2 or
// 1.0.3 exporter on Linux, macOS and Windows.
func TestCodexMarkerRouteOwnershipAcrossWriters(t *testing.T) {
	for _, release := range []string{"1.0.2", "1.0.3"} {
		for _, goos := range []string{"linux", "darwin", "windows"} {
			for _, c := range otlpMarkerRouteCases() {
				for _, path := range []string{"setup", "managed_cleanup"} {
					t.Run(release+"/"+goos+"/"+c.name+"/"+path, func(t *testing.T) {
						dir := t.TempDir()
						configPath := filepath.Join(dir, "config.toml")
						if err := os.WriteFile(configPath, []byte("model = 'gpt-5'\n"), 0o600); err != nil {
							t.Fatal(err)
						}
						prior := CodexConfigPathOverride
						CodexConfigPathOverride = configPath
						t.Cleanup(func() { CodexConfigPathOverride = prior })
						conn := NewCodexConnector()
						earlier := SetupOpts{DataDir: dir, APIAddr: "127.0.0.1:19081", APIToken: "test-hook-token", GOOS: goos, CodexOtelEnvironment: goos}
						if err := conn.Setup(context.Background(), earlier); err != nil {
							t.Fatalf("seed released setup: %v", err)
						}
						base, err := os.ReadFile(configPath)
						if err != nil {
							t.Fatal(err)
						}
						productToken, err := EnsureOTLPPathToken(dir, OTLPScopeCodex)
						if err != nil {
							t.Fatal(err)
						}
						fixture := codexMarkerRouteFixture(t, release, goos, c, productToken)
						if !c.sidecar {
							if err := RemoveOTLPPathToken(dir, OTLPScopeCodex); err != nil {
								t.Fatal(err)
							}
						}
						baseText := strings.ReplaceAll(string(base), "\r\n", "\n")
						if goos == "windows" {
							baseText = strings.ReplaceAll(baseText, "\n", "\r\n")
						}
						before := baseText + fixture
						if err := os.WriteFile(configPath, []byte(before), 0o600); err != nil {
							t.Fatal(err)
						}
						var parsed map[string]interface{}
						if err := toml.Unmarshal([]byte(before), &parsed); err != nil {
							t.Fatal(err)
						}
						verifyClean := strings.Join(codexOtelResidueFields(parsed["otel"], SetupOpts{DataDir: dir, APIAddr: "127.0.0.1:19082"}), "\n")
						_, verifyErr := UserNativeOTLPResidue("codex", SetupOpts{DataDir: dir, ManagedEnterprise: true})

						var runErr error
						if path == "setup" {
							upgrade := earlier
							upgrade.APIAddr = "127.0.0.1:19082"
							runErr = conn.Setup(context.Background(), upgrade)
						} else {
							_, runErr = RemoveUserNativeOTLP("codex", SetupOpts{DataDir: dir, ManagedEnterprise: true})
						}
						got, err := os.ReadFile(configPath)
						if err != nil {
							t.Fatal(err)
						}
						if c.want == "refuse" {
							if runErr == nil || !strings.Contains(runErr.Error(), "cannot be read") {
								t.Fatalf("%s accepted an exporter whose bearer owner is unresolved: %v", path, runErr)
							}
							if verifyErr == nil {
								t.Fatal("managed Verify passed an unresolved bearer")
							}
							if !strings.Contains(verifyClean, "owner is unresolved") {
								t.Fatalf("VerifyClean did not name the unresolved bearer: %q", verifyClean)
							}
							if string(got) != before {
								t.Fatal("refused cleanup changed config.toml")
							}
							return
						}
						if runErr != nil {
							t.Fatalf("%s: %v", path, runErr)
						}
						if verifyErr != nil {
							t.Fatalf("managed Verify: %v", verifyErr)
						}
						if !c.keepAuth && strings.Contains(string(got), productToken) {
							t.Fatal("product bearer survived")
						}
						if left := codexConfigResidue(t, dir, ""); len(left) != 0 {
							t.Fatalf("residue after %s: %v", path, left)
						}
						var after map[string]interface{}
						if err := toml.Unmarshal(got, &after); err != nil {
							t.Fatal(err)
						}
						otel, _ := after["otel"].(map[string]interface{})
						signals := map[string]string{"exporter": "logs", "metrics_exporter": "metrics", "trace_exporter": "traces"}
						for _, key := range codexOtelExporterKeys {
							exporter, kept := otel[key].(map[string]interface{})
							if c.want == "remove_route" {
								if kept {
									t.Fatalf("product exporter otel.%s survived on a retired port", key)
								}
								continue
							}
							http, _ := exporter["otlp-http"].(map[string]interface{})
							if http["endpoint"] != c.endpoint(signals[key]) || http["protocol"] != "json" {
								t.Fatalf("operator route otel.%s changed: endpoint=%v protocol=%v", key, http["endpoint"], http["protocol"])
							}
							headers, _ := http["headers"].(map[string]interface{})
							if len(otlpHeaderKeys(headers, "x-defenseclaw-source"))+len(otlpHeaderKeys(headers, "x-defenseclaw-client")) != 0 {
								t.Fatalf("product markers survived on otel.%s", key)
							}
							wantHeaders := 0
							if c.keepAuth {
								wantHeaders = 1
								if headers["authorization"] != c.authorization(productToken) {
									t.Fatalf("operator Authorization changed on otel.%s", key)
								}
							}
							if len(headers) != wantHeaders {
								t.Fatalf("otel.%s keeps %d headers, want %d", key, len(headers), wantHeaders)
							}
						}
					})
				}
			}
		}
	}
}

// Claude Code: the same rows on the logs route of the env block, beside the
// real T11 operator collector recorded on a published 1.0.2 upgrade subject
// (also the 1.0.3 shape), whose six values must stay byte-identical.
func TestClaudeMarkerRouteOwnershipAcrossWriters(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("testdata", "claudecode_operator_1.0.2_1.0.3.json"))
	if err != nil {
		t.Fatal(err)
	}
	var operator map[string]string
	if err := json.Unmarshal(fixture, &operator); err != nil {
		t.Fatal(err)
	}
	const markers = ",x-defenseclaw-source=claudecode,x-defenseclaw-client=claudecode-otel/1.0"
	for _, release := range []string{"1.0.2", "1.0.3"} {
		for _, goos := range []string{"linux", "darwin", "windows"} {
			for _, c := range otlpMarkerRouteCases() {
				for _, path := range []string{"setup", "managed_cleanup"} {
					t.Run(release+"/"+goos+"/"+c.name+"/"+path, func(t *testing.T) {
						dir := t.TempDir()
						pinClaudeUpgradeTestOwner(t, dir)
						settingsPath := filepath.Join(dir, "settings.json")
						prior := ClaudeCodeSettingsPathOverride
						ClaudeCodeSettingsPathOverride = settingsPath
						t.Cleanup(func() { ClaudeCodeSettingsPathOverride = prior })
						conn := NewClaudeCodeConnector()
						earlier := SetupOpts{DataDir: dir, APIAddr: "127.0.0.1:19081", GOOS: goos, sandboxNativeOTLP: true}
						if err := conn.Setup(context.Background(), earlier); err != nil {
							t.Fatalf("released %s setup: %v", release, err)
						}
						productToken, err := LoadOTLPPathToken(dir, OTLPScopeClaude)
						if err != nil || productToken == "" {
							t.Fatalf("released scoped token: present=%t err=%v", productToken != "", err)
						}
						if !c.sidecar {
							// The product credential cannot be established: the
							// sidecar is gone and the backup records no bearer.
							if err := RemoveOTLPPathToken(dir, OTLPScopeClaude); err != nil {
								t.Fatal(err)
							}
							scrubClaudeBackupRecordedHeaders(t, dir)
						}
						data, err := os.ReadFile(settingsPath)
						if err != nil {
							t.Fatal(err)
						}
						var settings map[string]interface{}
						if err := json.Unmarshal(data, &settings); err != nil {
							t.Fatal(err)
						}
						env := settings["env"].(map[string]interface{})
						for key, value := range operator {
							env[key] = value
						}
						for _, key := range []string{"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "OTEL_EXPORTER_OTLP_METRICS_HEADERS", "OTEL_EXPORTER_OTLP_TRACES_HEADERS"} {
							delete(env, key)
						}
						route := c.endpoint("logs")
						headers := "x-tenant=logs" + markers
						if value := c.authorization(productToken); value != "" {
							headers = "authorization=" + value + "," + headers
						}
						env["OTEL_EXPORTER_OTLP_LOGS_ENDPOINT"] = route
						env["OTEL_EXPORTER_OTLP_LOGS_HEADERS"] = headers
						env["OTEL_LOGS_EXPORTER"] = "otlp"
						writeClaudeUpgradeSettings(t, settingsPath, settings)
						before, err := os.ReadFile(settingsPath)
						if err != nil {
							t.Fatal(err)
						}
						_, verifyErr := UserNativeOTLPResidue("claudecode", SetupOpts{DataDir: dir, ManagedEnterprise: true})

						var runErr error
						if path == "setup" {
							upgrade := earlier
							upgrade.sandboxNativeOTLP = false
							upgrade.APIAddr = "127.0.0.1:19082"
							runErr = conn.Setup(context.Background(), upgrade)
						} else {
							_, runErr = RemoveUserNativeOTLP("claudecode", SetupOpts{DataDir: dir, ManagedEnterprise: true})
						}
						raw, err := os.ReadFile(settingsPath)
						if err != nil {
							t.Fatal(err)
						}
						if c.wantFor("claudecode") == "refuse" {
							if runErr == nil || !strings.Contains(runErr.Error(), "cannot be read") {
								t.Fatalf("%s accepted a marked bearer whose owner is unresolved: %v", path, runErr)
							}
							if verifyErr == nil {
								t.Fatal("managed Verify passed an unresolved bearer")
							}
							if string(raw) != string(before) {
								t.Fatal("refused cleanup changed settings.json")
							}
							return
						}
						if runErr != nil {
							t.Fatalf("%s: %v", path, runErr)
						}
						if verifyErr != nil {
							t.Fatalf("managed Verify: %v", verifyErr)
						}
						if !c.keepAuth && strings.Contains(string(raw), productToken) {
							t.Fatal("product bearer survived")
						}
						got := readClaudeUpgradeEnv(t, settingsPath)
						for key, value := range operator {
							if got[key] != value {
								t.Errorf("operator %s = %q, want %q", key, got[key], value)
							}
						}
						for key, value := range got {
							if strings.Contains(strings.ToLower(value), "x-defenseclaw-") {
								t.Fatalf("product marker survived in %s", key)
							}
						}
						switch c.wantFor("claudecode") {
						case "remove_route":
							if _, kept := got["OTEL_EXPORTER_OTLP_LOGS_ENDPOINT"]; kept {
								t.Fatal("product logs route survived on a retired port")
							}
						default:
							wantHeaders := "x-tenant=logs"
							if c.keepAuth {
								wantHeaders = "authorization=" + c.authorization(productToken) + ",x-tenant=logs"
							}
							if got["OTEL_EXPORTER_OTLP_LOGS_ENDPOINT"] != route || got["OTEL_EXPORTER_OTLP_LOGS_HEADERS"] != wantHeaders || got["OTEL_LOGS_EXPORTER"] != "otlp" {
								t.Fatalf("operator logs route changed: endpoint=%q headers=%q gate=%q", got["OTEL_EXPORTER_OTLP_LOGS_ENDPOINT"], got["OTEL_EXPORTER_OTLP_LOGS_HEADERS"], got["OTEL_LOGS_EXPORTER"])
							}
						}
						if residue, err := UserNativeOTLPResidue("claudecode", SetupOpts{DataDir: dir, ManagedEnterprise: true}); err != nil {
							t.Fatalf("managed Verify after %s: %v", path, err)
						} else {
							for _, field := range residue {
								if strings.HasPrefix(field, "settings.json") {
									t.Fatalf("residue after %s: %v", path, residue)
								}
							}
						}
					})
				}
			}
		}
	}
}

// scrubClaudeBackupRecordedHeaders drops the OTLP headers the released Setup
// recorded, so no product bearer can be established from the backup.
func scrubClaudeBackupRecordedHeaders(t *testing.T, dir string) {
	t.Helper()
	path := filepath.Join(dir, "claudecode_backup.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var backup map[string]interface{}
	if err := json.Unmarshal(raw, &backup); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"managed_env", "ManagedEnv"} {
		managed, _ := backup[field].(map[string]interface{})
		for key := range managed {
			if claudeCodeOTLPHeadersKey(key) {
				delete(managed, key)
			}
		}
	}
	out, err := json.Marshal(backup)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
}
