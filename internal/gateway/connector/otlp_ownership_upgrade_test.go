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

// otlpOwnershipCase is one row of the product-owned versus operator-owned
// matrix that every native OTLP writer runs on upgrade and cleanup: Codex and
// Claude Code Setup, and the managed per-user cleanup the Linux, macOS and
// Windows enterprise paths share (RemoveUserNativeOTLP). Each row starts from
// a released 1.0.2 or 1.0.3 product route whose markers the operator removed,
// then respells or moves it the way an operator or a reviewer might.
type otlpOwnershipCase struct {
	name      string
	host      string // replaces the released 127.0.0.1 in the route
	authKey   string // Authorization header-name spelling
	scheme    string // Bearer scheme spelling
	product   bool   // the credential is DefenseClaw's scoped token
	duplicate bool   // a second Authorization spelling holds an operator credential
	markers   bool   // keep the product markers under capitalised names
	local     bool   // connections to host stay on this machine
}

func otlpOwnershipCases() []otlpOwnershipCase {
	return []otlpOwnershipCase{
		{name: "capitalized_key", host: "127.0.0.1", authKey: "Authorization", scheme: "Bearer", product: true, local: true},
		{name: "upper_key_lower_scheme", host: "127.0.0.1", authKey: "AUTHORIZATION", scheme: "bearer", product: true, local: true},
		{name: "loopback_alias", host: "127.0.0.2", authKey: "authorization", scheme: "Bearer", product: true, local: true},
		{name: "loopback_alias_capitalized", host: "127.9.8.7", authKey: "Authorization", scheme: "BEARER", product: true, local: true},
		{name: "localhost_fqdn", host: "LOCALHOST.", authKey: "authorization", scheme: "Bearer", product: true, local: true},
		{name: "ipv6_loopback", host: "[::1]", authKey: "Authorization", scheme: "Bearer", product: true, local: true},
		{name: "ipv4_mapped_loopback", host: "[::ffff:127.0.0.1]", authKey: "authorization", scheme: "Bearer", product: true, local: true},
		{name: "inet_aton_shorthand", host: "127.1", authKey: "authorization", scheme: "Bearer", product: true, local: true},
		{name: "unspecified_address", host: "0.0.0.0", authKey: "Authorization", scheme: "Bearer", product: true, local: true},
		{name: "capitalized_markers", host: "127.0.0.2", authKey: "Authorization", scheme: "Bearer", product: true, markers: true, local: true},
		{name: "remote_collector", host: "collector.example.test", authKey: "Authorization", scheme: "Bearer", product: true},
		{name: "duplicate_operator_spelling", host: "127.0.0.1", authKey: "Authorization", scheme: "Bearer", product: true, duplicate: true, local: true},
		{name: "operator_capitalized", host: "127.0.0.1", authKey: "Authorization", scheme: "Bearer", local: true},
		{name: "operator_loopback_alias", host: "127.0.0.2", authKey: "AUTHORIZATION", scheme: "bearer", local: true},
	}
}

// want names the one outcome every writer must reach for the row.
func (c otlpOwnershipCase) want() string {
	switch {
	case !c.product:
		return "operator_unchanged"
	case c.duplicate:
		return "strip_product_spelling"
	case c.local:
		return "remove_route"
	default:
		return "strip_bearer"
	}
}

const otlpOwnershipOperatorToken = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"

func TestOTLPLocalHostRecognizesEveryLocalSpelling(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "127.0.0.2", "127.255.255.254", "localhost", "LOCALHOST.", "app.localhost", "::1", "0:0:0:0:0:0:0:1", "::ffff:127.0.0.1", "::1%lo0", "0.0.0.0", "::", "127.1", "0x7f.1", "0177.0.0.1", "2130706433", "0"} {
		if !otlpLocalHost(host) {
			t.Errorf("otlpLocalHost(%q) = false", host)
		}
	}
	for _, host := range []string{"", "128.0.0.1", "10.0.0.1", "collector.example.test", "localhost.example.test", "::2", "1.2.3.4", "0x80.1", "127.0.0.1.example", "1_27.0.0.1", "4294967296"} {
		if otlpLocalHost(host) {
			t.Errorf("otlpLocalHost(%q) = true", host)
		}
	}
}

func TestOTLPBearerCredentialIgnoresSchemeSpelling(t *testing.T) {
	for value, want := range map[string]string{
		"Bearer abc": "abc", "bearer abc": "abc", "BEARER  abc ": "abc", " Bearer\tabc": "abc",
		"Basic abc": "", "Bearer": "", "Bearerabc": "", "": "",
	} {
		if got, _ := otlpBearerCredential(value); got != want {
			t.Errorf("otlpBearerCredential(%q) = %q, want %q", value, got, want)
		}
	}
}

func codexOwnershipFixture(t *testing.T, release, goos string, c otlpOwnershipCase, productToken string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "codex_otel_"+release+"_product.toml"))
	if err != nil {
		t.Fatal(err)
	}
	body := strings.ReplaceAll(string(raw), "\r\n", "\n")
	body = strings.ReplaceAll(body, "fixture-os", goos)
	source, client := "x-defenseclaw-source = 'codex'\n", "x-defenseclaw-client = 'codex-otel/1.0'\n"
	if c.markers {
		body = strings.ReplaceAll(body, source, "X-DefenseClaw-Source = 'codex'\n")
		body = strings.ReplaceAll(body, client, "X-DefenseClaw-Client = 'codex-otel/1.0'\n")
	} else {
		body = strings.ReplaceAll(body, source, "")
		body = strings.ReplaceAll(body, client, "")
	}
	credential := otlpOwnershipOperatorToken
	if c.product {
		credential = productToken
	}
	auth := c.authKey + " = '" + c.scheme + " " + credential + "'\n"
	if c.duplicate {
		auth += "authorization = 'Bearer " + otlpOwnershipOperatorToken + "'\n"
	}
	body = strings.ReplaceAll(body, "authorization = 'Bearer released-static-token'\n", auth)
	body = strings.ReplaceAll(body, "http://127.0.0.1:19081/", "http://"+c.host+":19081/")
	if goos == "windows" {
		body = strings.ReplaceAll(body, "\n", "\r\n")
	}
	return body
}

func codexConfigResidue(t *testing.T, dir, token string) []string {
	t.Helper()
	residue, err := UserNativeOTLPResidue("codex", SetupOpts{DataDir: dir, ManagedEnterprise: true, OTLPPathToken: token})
	if err != nil {
		t.Fatalf("managed Verify: %v", err)
	}
	var fields []string
	for _, field := range residue {
		if strings.HasPrefix(field, "config.toml") {
			fields = append(fields, field)
		}
	}
	return fields
}

// A released Codex exporter keeps its owner through every respelling: Setup,
// managed cleanup, Verify and VerifyClean agree, the product bearer never
// stays on a port DefenseClaw no longer owns, and operator bytes survive.
func TestCodexOTLPOwnershipMatrixAcrossWriters(t *testing.T) {
	for _, release := range []string{"1.0.2", "1.0.3"} {
		for _, goos := range []string{"linux", "darwin", "windows"} {
			for _, c := range otlpOwnershipCases() {
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
						fixture := codexOwnershipFixture(t, release, goos, c, productToken)
						baseText := strings.ReplaceAll(string(base), "\r\n", "\n")
						if goos == "windows" {
							baseText = strings.ReplaceAll(baseText, "\n", "\r\n")
						}
						before := baseText + fixture
						if err := os.WriteFile(configPath, []byte(before), 0o600); err != nil {
							t.Fatal(err)
						}

						// Verify (managed residue) and VerifyClean name the product
						// credential before cleanup and nothing for operator rows.
						var parsed map[string]interface{}
						if err := toml.Unmarshal([]byte(before), &parsed); err != nil {
							t.Fatal(err)
						}
						verifyClean := codexOtelResidueFields(parsed["otel"], SetupOpts{DataDir: dir})
						residue := codexConfigResidue(t, dir, "")
						if c.want() == "operator_unchanged" {
							if len(verifyClean) != 0 || len(residue) != 0 {
								t.Fatalf("operator exporter reported as residue: verify_clean=%v residue=%v", verifyClean, residue)
							}
						} else {
							if !strings.Contains(strings.Join(verifyClean, "\n"), "retains DefenseClaw credential") || len(residue) == 0 {
								t.Fatalf("product bearer not reported: verify_clean=%v residue=%v", verifyClean, residue)
							}
						}

						if path == "setup" {
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
						if strings.Contains(string(got), productToken) {
							t.Fatal("product bearer survived")
						}
						if left := codexConfigResidue(t, dir, productToken); len(left) != 0 {
							t.Fatalf("residue after %s: %v", path, left)
						}
						var after map[string]interface{}
						if err := toml.Unmarshal(got, &after); err != nil {
							t.Fatal(err)
						}
						otel, _ := after["otel"].(map[string]interface{})
						switch c.want() {
						case "operator_unchanged":
							if !strings.Contains(string(got), fixture) {
								t.Fatalf("operator [otel] bytes changed; want:\n%s\ngot:\n%s", fixture, got)
							}
						case "remove_route":
							for _, key := range codexOtelExporterKeys {
								if _, kept := otel[key]; kept {
									t.Fatalf("product exporter otel.%s survived on a retired local port", key)
								}
							}
						case "strip_bearer", "strip_product_spelling":
							for _, key := range codexOtelExporterKeys {
								exporter, _ := otel[key].(map[string]interface{})
								http, _ := exporter["otlp-http"].(map[string]interface{})
								endpoint, _ := http["endpoint"].(string)
								if !strings.HasPrefix(endpoint, "http://"+c.host+":19081/v1/") {
									t.Fatalf("operator route otel.%s changed: %q", key, endpoint)
								}
								headers, _ := http["headers"].(map[string]interface{})
								wantAuth := 0
								if c.duplicate {
									wantAuth = 1
									if headers["authorization"] != "Bearer "+otlpOwnershipOperatorToken {
										t.Fatalf("operator Authorization spelling changed on otel.%s", key)
									}
								}
								if n := len(otlpHeaderKeys(headers, "authorization")); n != wantAuth {
									t.Fatalf("otel.%s has %d Authorization spellings, want %d", key, n, wantAuth)
								}
							}
						}
					})
				}
			}
		}
	}
}

// Claude Code runs the same matrix on its env-block exporter, beside the real
// operator collector recorded on a published 1.0.2 upgrade subject (also the
// 1.0.3 shape) or beside a traces-only operator route.
func TestClaudeOTLPOwnershipMatrixAcrossWriters(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("testdata", "claudecode_operator_1.0.2_1.0.3.json"))
	if err != nil {
		t.Fatal(err)
	}
	var t11 map[string]string
	if err := json.Unmarshal(fixture, &t11); err != nil {
		t.Fatal(err)
	}
	traces := map[string]string{
		"CLAUDE_CODE_ENABLE_TELEMETRY":       "1",
		"OTEL_TRACES_EXPORTER":               "otlp",
		"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": "https://collector.example.test/v1/traces",
		"OTEL_EXPORTER_OTLP_TRACES_HEADERS":  "x-tenant=traces",
	}
	for _, release := range []string{"1.0.2", "1.0.3"} {
		for _, goos := range []string{"linux", "darwin", "windows"} {
			for _, collector := range []string{"t11_generic", "traces_only"} {
				operator := t11
				if collector == "traces_only" {
					operator = traces
				}
				for _, c := range otlpOwnershipCases() {
					for _, path := range []string{"setup", "managed_cleanup"} {
						t.Run(release+"/"+goos+"/"+collector+"/"+c.name+"/"+path, func(t *testing.T) {
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
							credential := otlpOwnershipOperatorToken
							if c.product {
								credential = productToken
							}
							route := "http://" + c.host + ":19097/v1/logs"
							headers := c.authKey + "=" + c.scheme + " " + credential + ",x-tenant=logs"
							if c.markers {
								headers += ",X-DefenseClaw-Source=claudecode,X-DefenseClaw-Client=claudecode-otel/1.0"
							}
							if c.duplicate {
								headers += ",authorization=Bearer " + otlpOwnershipOperatorToken
							}
							env["OTEL_EXPORTER_OTLP_LOGS_ENDPOINT"] = route
							env["OTEL_EXPORTER_OTLP_LOGS_HEADERS"] = headers
							env["OTEL_LOGS_EXPORTER"] = "otlp"
							writeClaudeUpgradeSettings(t, settingsPath, settings)

							if path == "setup" {
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
							if strings.Contains(string(raw), productToken) {
								t.Fatal("product bearer survived")
							}
							got := readClaudeUpgradeEnv(t, settingsPath)
							for key, value := range operator {
								if got[key] != value {
									t.Errorf("operator %s = %q, want %q", key, got[key], value)
								}
							}
							switch c.want() {
							case "operator_unchanged":
								if got["OTEL_EXPORTER_OTLP_LOGS_ENDPOINT"] != route || got["OTEL_EXPORTER_OTLP_LOGS_HEADERS"] != headers || got["OTEL_LOGS_EXPORTER"] != "otlp" {
									t.Fatal("operator logs route changed")
								}
							case "remove_route":
								if _, kept := got["OTEL_EXPORTER_OTLP_LOGS_ENDPOINT"]; kept {
									t.Fatal("product logs route survived on a retired local address")
								}
								// The logs gate is the operator's while their generic
								// collector stays; otherwise the product gate goes.
								if collector == "traces_only" && got["OTEL_LOGS_EXPORTER"] == "otlp" {
									t.Fatal("product logs export gate survived")
								}
							case "strip_bearer":
								if got["OTEL_EXPORTER_OTLP_LOGS_ENDPOINT"] != route || got["OTEL_EXPORTER_OTLP_LOGS_HEADERS"] != "x-tenant=logs" || got["OTEL_LOGS_EXPORTER"] != "otlp" {
									t.Fatalf("operator collector route changed: endpoint=%t headers=%q gate=%q", got["OTEL_EXPORTER_OTLP_LOGS_ENDPOINT"] == route, got["OTEL_EXPORTER_OTLP_LOGS_HEADERS"], got["OTEL_LOGS_EXPORTER"])
								}
							case "strip_product_spelling":
								if got["OTEL_EXPORTER_OTLP_LOGS_ENDPOINT"] != route || got["OTEL_LOGS_EXPORTER"] != "otlp" ||
									got["OTEL_EXPORTER_OTLP_LOGS_HEADERS"] != "x-tenant=logs,authorization=Bearer "+otlpOwnershipOperatorToken {
									t.Fatalf("operator spelling or route changed: endpoint=%t headers=%q gate=%q", got["OTEL_EXPORTER_OTLP_LOGS_ENDPOINT"] == route, got["OTEL_EXPORTER_OTLP_LOGS_HEADERS"], got["OTEL_LOGS_EXPORTER"])
								}
							}
							if residue, err := UserNativeOTLPResidue("claudecode", SetupOpts{DataDir: dir, ManagedEnterprise: true}); err != nil {
								t.Fatalf("managed Verify: %v", err)
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
}
