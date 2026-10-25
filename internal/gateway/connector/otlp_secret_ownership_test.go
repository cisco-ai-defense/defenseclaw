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

// One product-owned versus operator-owned table for every native OTLP writer
// (Codex and Claude Code Setup, the managed per-user cleanup and Verify that
// the Linux, macOS and Windows enterprise paths call, and VerifyClean). The
// rule is the secret: a route that carries a DefenseClaw credential is the
// product's and is removed, whatever its host, port, query, header-name or
// scheme spelling, and even when the scoped token sidecar is gone. A route
// without one is the operator's and keeps its bytes, stale marker headers
// included, on any loopback address or port.
type otlpSecretRow struct {
	name      string
	base      string // replaces the released http://127.0.0.1:19081 route base
	query     string // appended to every endpoint
	auth      string // Authorization lines; {tok} is the product token
	markers   string // keep, drop or caps
	scoped    bool   // the product token is in the endpoint path
	dropToken bool   // the scoped sidecar (and the Claude backup) is gone
	product   bool
	// recorded: Claude Code's backup recorded writing this exact logs
	// endpoint, which proves the route is the product's; the operator's
	// own header entry still keeps its bytes.
	recorded bool
}

const otlpSecretOperatorBearer = "operator-collector-token"

func otlpSecretRows() []otlpSecretRow {
	return []otlpSecretRow{
		{name: "released_retired_port", base: "http://127.0.0.1:19081", auth: "authorization = 'Bearer {tok}'", markers: "keep", product: true},
		{name: "capitalized_authorization", base: "http://127.0.0.1:19081", auth: "Authorization = 'Bearer {tok}'", markers: "drop", product: true},
		{name: "upper_key_lower_scheme_moved_host", base: "http://127.0.0.2:19081", auth: "AUTHORIZATION = 'bearer {tok}'", markers: "drop", product: true},
		{name: "missing_scoped_token", base: "http://127.0.0.1:19081", query: "?tenant=x", auth: "authorization = 'Bearer {tok}'", markers: "keep", dropToken: true, product: true},
		{name: "missing_token_moved_host", base: "http://127.1:19081", query: "?tenant=x", auth: "Authorization = 'BEARER {tok}'", markers: "caps", dropToken: true, product: true},
		{name: "localhost_retired_port", base: "http://localhost:19081", auth: "Authorization = 'Bearer {tok}'", markers: "drop", product: true},
		{name: "remote_collector", base: "https://collector.example.test", auth: "Authorization = 'Bearer {tok}'", markers: "drop", product: true},
		{name: "beside_operator_credential", base: "http://127.0.0.1:19081", auth: "Authorization = 'Bearer {tok}'\nauthorization = 'Bearer " + otlpSecretOperatorBearer + "'", markers: "drop", product: true},
		{name: "scoped_path_token", base: "http://127.0.0.1:19081", markers: "drop", scoped: true, dropToken: true, product: true},
		{name: "operator_127_0_0_1_stale_markers", base: "http://127.0.0.1:4318", markers: "keep"},
		{name: "operator_localhost_own_bearer", base: "http://localhost:4318", auth: "Authorization = 'Bearer " + otlpSecretOperatorBearer + "'", markers: "caps"},
		{name: "operator_localhost_missing_token", base: "http://localhost:4318", auth: "authorization = 'Bearer " + otlpSecretOperatorBearer + "'", markers: "keep", dropToken: true},
		{name: "operator_moved_127_1_stale_markers", base: "http://127.1:19081", markers: "keep"},
		{name: "operator_retired_port_own_bearer", base: "http://127.0.0.1:19081", auth: "AUTHORIZATION = 'bearer " + otlpSecretOperatorBearer + "'", markers: "drop", recorded: true},
	}
}

func codexSecretFixture(t *testing.T, release, goos string, row otlpSecretRow, token string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "codex_otel_"+release+"_product.toml"))
	if err != nil {
		t.Fatal(err)
	}
	body := strings.ReplaceAll(string(raw), "\r\n", "\n")
	body = strings.ReplaceAll(body, "fixture-os", goos)
	source, client := "x-defenseclaw-source = 'codex'\n", "x-defenseclaw-client = 'codex-otel/1.0'\n"
	switch row.markers {
	case "drop":
		body = strings.ReplaceAll(body, source, "")
		body = strings.ReplaceAll(body, client, "")
	case "caps":
		body = strings.ReplaceAll(body, source, "X-DefenseClaw-Source = 'codex'\n")
		body = strings.ReplaceAll(body, client, "X-DefenseClaw-Client = 'codex-otel/1.0'\n")
	}
	auth := ""
	if row.auth != "" {
		auth = strings.ReplaceAll(row.auth, "{tok}", token) + "\n"
	}
	body = strings.ReplaceAll(body, "authorization = 'Bearer f00dfeedf00dfeedf00dfeedf00dfeedf00dfeedf00dfeedf00dfeedf00dfeed'\n", auth)
	route := row.base + "/"
	if row.scoped {
		route += "otlp/codex/" + token + "/"
	}
	for _, signal := range []string{"logs", "traces", "metrics"} {
		body = strings.ReplaceAll(body, "'http://127.0.0.1:19081/v1/"+signal+"'", "'"+route+"v1/"+signal+row.query+"'")
	}
	if goos == "windows" {
		body = strings.ReplaceAll(body, "\n", "\r\n")
	}
	return body
}

func otlpSecretResidue(t *testing.T, connectorName, dir, prefix string) []string {
	t.Helper()
	residue, err := UserNativeOTLPResidue(connectorName, SetupOpts{DataDir: dir, ManagedEnterprise: true})
	if err != nil {
		t.Fatalf("managed Verify: %v", err)
	}
	var fields []string
	for _, field := range residue {
		if strings.HasPrefix(field, prefix) {
			fields = append(fields, field)
		}
	}
	return fields
}

func TestCodexSecretOwnershipAcrossWriters(t *testing.T) {
	for _, release := range []string{"1.0.2", "1.0.3"} {
		for _, goos := range []string{"linux", "darwin", "windows"} {
			for _, row := range otlpSecretRows() {
				for _, writer := range []string{"setup", "managed_cleanup"} {
					t.Run(release+"/"+goos+"/"+row.name+"/"+writer, func(t *testing.T) {
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
						token, err := EnsureOTLPPathToken(dir, OTLPScopeCodex)
						if err != nil {
							t.Fatal(err)
						}
						fixture := codexSecretFixture(t, release, goos, row, token)
						baseText := strings.ReplaceAll(string(base), "\r\n", "\n")
						if goos == "windows" {
							baseText = strings.ReplaceAll(baseText, "\n", "\r\n")
						}
						before := baseText + fixture
						if err := os.WriteFile(configPath, []byte(before), 0o600); err != nil {
							t.Fatal(err)
						}
						if row.dropToken {
							if err := RemoveOTLPPathToken(dir, OTLPScopeCodex); err != nil {
								t.Fatal(err)
							}
						}

						var parsed map[string]interface{}
						if err := toml.Unmarshal([]byte(before), &parsed); err != nil {
							t.Fatal(err)
						}
						verifyClean := codexOtelResidueFields(parsed["otel"], SetupOpts{DataDir: dir})
						residue := otlpSecretResidue(t, "codex", dir, "config.toml")
						if row.product != (len(verifyClean) > 0) || row.product != (len(residue) > 0) {
							t.Fatalf("product=%t but verify_clean=%v residue=%v", row.product, verifyClean, residue)
						}

						if writer == "setup" {
							upgrade := earlier
							upgrade.APIAddr = "127.0.0.1:19082"
							if err := conn.Setup(context.Background(), upgrade); err != nil {
								t.Fatalf("upgrade: %v", err)
							}
						} else if _, err := RemoveUserNativeOTLP("codex", SetupOpts{DataDir: dir, ManagedEnterprise: true}); err != nil {
							t.Fatalf("managed cleanup: %v", err)
						}
						got, err := os.ReadFile(configPath)
						if err != nil {
							t.Fatal(err)
						}
						if strings.Contains(string(got), token) {
							t.Fatal("product credential survived")
						}
						if left := otlpSecretResidue(t, "codex", dir, "config.toml"); len(left) != 0 {
							t.Fatalf("residue after %s: %v", writer, left)
						}
						if !row.product {
							if !strings.Contains(string(got), fixture) {
								t.Fatalf("operator [otel] bytes changed; want:\n%s\ngot:\n%s", fixture, got)
							}
							return
						}
						var after map[string]interface{}
						if err := toml.Unmarshal(got, &after); err != nil {
							t.Fatal(err)
						}
						otel, _ := after["otel"].(map[string]interface{})
						for _, key := range codexOtelExporterKeys {
							if _, kept := otel[key]; kept {
								t.Fatalf("product exporter otel.%s survived", key)
							}
						}
					})
				}
			}
		}
	}
}

// Claude Code runs the same rows on its logs route beside the real operator
// collector recorded on a published 1.0.2 upgrade subject (also the 1.0.3
// shape) and the rest of the released product env.
func TestClaudeSecretOwnershipAcrossWriters(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("testdata", "claudecode_operator_1.0.2_1.0.3.json"))
	if err != nil {
		t.Fatal(err)
	}
	var operator map[string]string
	if err := json.Unmarshal(fixture, &operator); err != nil {
		t.Fatal(err)
	}
	for _, release := range []string{"1.0.2", "1.0.3"} {
		for _, goos := range []string{"linux", "darwin", "windows"} {
			for _, row := range otlpSecretRows() {
				for _, writer := range []string{"setup", "managed_cleanup"} {
					t.Run(release+"/"+goos+"/"+row.name+"/"+writer, func(t *testing.T) {
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
						token, err := LoadOTLPPathToken(dir, OTLPScopeClaude)
						if err != nil || token == "" {
							t.Fatalf("released scoped token: present=%t err=%v", token != "", err)
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
						route := row.base + "/"
						if row.scoped {
							route += "otlp/claudecode/" + token + "/"
						}
						route += "v1/logs" + row.query
						var parts []string
						if row.auth != "" {
							for _, line := range strings.Split(strings.ReplaceAll(row.auth, "{tok}", token), "\n") {
								name, value, _ := strings.Cut(line, " = ")
								parts = append(parts, name+"="+strings.Trim(value, "'"))
							}
						}
						switch row.markers {
						case "keep":
							parts = append(parts, "x-defenseclaw-source=claudecode", "x-defenseclaw-client=claudecode-otel/1.0")
						case "caps":
							parts = append(parts, "X-DefenseClaw-Source=claudecode", "X-DefenseClaw-Client=claudecode-otel/1.0")
						}
						headers := strings.Join(append(parts, "x-tenant=logs"), ",")
						env["OTEL_EXPORTER_OTLP_LOGS_ENDPOINT"] = route
						env["OTEL_EXPORTER_OTLP_LOGS_HEADERS"] = headers
						env["OTEL_LOGS_EXPORTER"] = "otlp"
						writeClaudeUpgradeSettings(t, settingsPath, settings)
						if row.dropToken {
							if err := RemoveOTLPPathToken(dir, OTLPScopeClaude); err != nil {
								t.Fatal(err)
							}
							if err := os.Remove(filepath.Join(dir, "claudecode_backup.json")); err != nil {
								t.Fatal(err)
							}
						}

						if writer == "setup" {
							upgrade := earlier
							upgrade.sandboxNativeOTLP = false
							upgrade.APIAddr = "127.0.0.1:19082"
							if err := conn.Setup(context.Background(), upgrade); err != nil {
								t.Fatalf("upgrade: %v", err)
							}
						} else if _, err := RemoveUserNativeOTLP("claudecode", SetupOpts{DataDir: dir, ManagedEnterprise: true}); err != nil {
							t.Fatalf("managed cleanup: %v", err)
						}
						raw, err := os.ReadFile(settingsPath)
						if err != nil {
							t.Fatal(err)
						}
						if strings.Contains(string(raw), token) {
							t.Fatal("product credential survived")
						}
						got := readClaudeUpgradeEnv(t, settingsPath)
						for key, value := range operator {
							if got[key] != value {
								t.Errorf("operator %s = %q, want %q", key, got[key], value)
							}
						}
						if row.recorded {
							if _, kept := got["OTEL_EXPORTER_OTLP_LOGS_ENDPOINT"]; kept || got["OTEL_EXPORTER_OTLP_LOGS_HEADERS"] != headers {
								t.Fatalf("recorded product route kept=%t or operator headers changed", kept)
							}
						} else if row.product {
							if _, kept := got["OTEL_EXPORTER_OTLP_LOGS_ENDPOINT"]; kept {
								t.Fatal("product logs route survived")
							}
							// Headers that carry no credential (the scoped-path row)
							// are the operator's bytes.
							if _, kept := got["OTEL_EXPORTER_OTLP_LOGS_HEADERS"]; kept == (row.auth != "") {
								t.Fatalf("logs headers kept=%t, want %t", kept, row.auth == "")
							}
						} else if got["OTEL_EXPORTER_OTLP_LOGS_ENDPOINT"] != route || got["OTEL_EXPORTER_OTLP_LOGS_HEADERS"] != headers || got["OTEL_LOGS_EXPORTER"] != "otlp" {
							t.Fatalf("operator logs route changed: endpoint=%t headers=%t gate=%q",
								got["OTEL_EXPORTER_OTLP_LOGS_ENDPOINT"] == route, got["OTEL_EXPORTER_OTLP_LOGS_HEADERS"] == headers, got["OTEL_LOGS_EXPORTER"])
						}
						if left := otlpSecretResidue(t, "claudecode", dir, "settings.json"); len(left) != 0 {
							t.Fatalf("residue after %s: %v", writer, left)
						}
					})
				}
			}
		}
	}
}

func TestOTLPCarriesProductCredentialIsTheSecretShape(t *testing.T) {
	token := strings.Repeat("0123456789abcdef", 4)
	for _, value := range []string{token, "Bearer " + token, "bearer%20" + token, "http://127.1:1/otlp/codex/" + token + "/v1/logs", "a=1,Authorization=Bearer " + token} {
		if !otlpCarriesProductCredential(value, nil) {
			t.Errorf("credential not found in %q", value)
		}
	}
	for _, value := range []string{"Bearer " + strings.ToUpper(token), "Bearer x" + token, "Bearer " + token + "0", "Bearer " + token[:63], "Bearer operator-collector-token", "http://127.0.0.1:4318/v1/logs"} {
		if otlpCarriesProductCredential(value, nil) {
			t.Errorf("operator value %q claimed", value)
		}
	}
	if !otlpCarriesProductCredential(map[string]interface{}{"otlp-http": map[string]interface{}{"headers": map[string]interface{}{"X-Api-Key": "configured-token"}}}, []string{"configured-token"}) {
		t.Error("known credential under another header name not found")
	}
	if otlpCarriesProductCredential("abc", []string{"ab"}) {
		t.Error("a short known value matched ordinary text")
	}
}

// Upgrade cleanup removes a released product exporter from an [otel] table
// that also holds operator collectors. The operator's lines, comments and
// layout stay byte for byte, through Setup and the managed cleanup.
func TestCodexSecretOwnershipKeepsOperatorBytesBesideProductExporter(t *testing.T) {
	operator := "# operator traces collector\n[otel.trace_exporter.otlp-http]\nendpoint = 'http://127.0.0.1:4318/v1/traces' # keep\nprotocol = 'json'\n\n" +
		"[otel.trace_exporter.otlp-http.headers]\nx-defenseclaw-source = 'codex'\nX-Tenant = 'ops'\n"
	for _, release := range []string{"1.0.2", "1.0.3"} {
		for _, goos := range []string{"linux", "darwin", "windows"} {
			for _, writer := range []string{"setup", "managed_cleanup"} {
				t.Run(release+"/"+goos+"/"+writer, func(t *testing.T) {
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
					token, err := EnsureOTLPPathToken(dir, OTLPScopeCodex)
					if err != nil {
						t.Fatal(err)
					}
					row := otlpSecretRow{base: "http://127.0.0.1:19081", auth: "Authorization = 'Bearer {tok}'", markers: "keep"}
					product := strings.ReplaceAll(codexSecretFixture(t, release, "linux", row, token), "\n[otel.trace_exporter]\n", "\n[otel.unused_trace_exporter]\n")
					// Keep only the logs and metrics product exporters; the operator owns traces.
					if cut := strings.Index(product, "\n[otel.unused_trace_exporter]"); cut >= 0 {
						product = product[:cut+1]
					}
					text := strings.ReplaceAll(string(base), "\r\n", "\n") + product + "\n" + operator
					want := operator
					if goos == "windows" {
						text = strings.ReplaceAll(text, "\n", "\r\n")
						want = strings.ReplaceAll(operator, "\n", "\r\n")
					}
					if err := os.WriteFile(configPath, []byte(text), 0o600); err != nil {
						t.Fatal(err)
					}
					if writer == "setup" {
						upgrade := earlier
						upgrade.APIAddr = "127.0.0.1:19082"
						if err := conn.Setup(context.Background(), upgrade); err != nil {
							t.Fatalf("upgrade: %v", err)
						}
					} else if _, err := RemoveUserNativeOTLP("codex", SetupOpts{DataDir: dir, ManagedEnterprise: true}); err != nil {
						t.Fatalf("managed cleanup: %v", err)
					}
					got, err := os.ReadFile(configPath)
					if err != nil {
						t.Fatal(err)
					}
					if strings.Contains(string(got), token) || strings.Contains(string(got), "otel.exporter") || strings.Contains(string(got), "otel.metrics_exporter") {
						t.Fatalf("product exporter survived:\n%s", got)
					}
					if !strings.Contains(string(got), want) {
						t.Fatalf("operator collector bytes changed; want:\n%s\ngot:\n%s", want, got)
					}
				})
			}
		}
	}
}
