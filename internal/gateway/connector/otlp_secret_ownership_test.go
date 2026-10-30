// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"
)

// One product-owned versus operator-owned table for every native OTLP writer
// (Codex and Claude Code Setup, the managed per-user cleanup and Verify that
// the Linux, macOS and Windows enterprise paths call, and VerifyClean). The
// rule is the secret: a route that carries a DefenseClaw credential is the
// product's and is removed, whatever its host, port, query, header-name or
// scheme spelling, while the install can name that credential. A route
// without one is the operator's and keeps its bytes, stale marker headers
// included, on any loopback address or port. Review of 70603235: a released
// exporter whose token no sidecar, Setup option or backup names any more is
// the operator's too; the token shape, markers or the scoped route are no
// proof.
type otlpSecretRow struct {
	name      string
	base      string // replaces the released http://127.0.0.1:19081 route base
	query     string // appended to every endpoint
	auth      string // Authorization lines; {tok} is the product token
	markers   string // keep, drop or caps
	scoped    bool   // the product token is in the endpoint path
	scopedHex bool   // an operator's own 64-hex segment is in the endpoint path
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
		{name: "missing_scoped_token", base: "http://127.0.0.1:19081", query: "?tenant=x", auth: "authorization = 'Bearer {tok}'", markers: "keep", dropToken: true},
		{name: "missing_token_moved_host", base: "http://127.1:19081", query: "?tenant=x", auth: "Authorization = 'BEARER {tok}'", markers: "caps", dropToken: true},
		{name: "localhost_retired_port", base: "http://localhost:19081", auth: "Authorization = 'Bearer {tok}'", markers: "drop", product: true},
		{name: "remote_collector", base: "https://collector.example.test", auth: "Authorization = 'Bearer {tok}'", markers: "drop", product: true},
		{name: "beside_operator_credential", base: "http://127.0.0.1:19081", auth: "Authorization = 'Bearer {tok}'\nauthorization = 'Bearer " + otlpSecretOperatorBearer + "'", markers: "drop", product: true},
		{name: "scoped_path_token", base: "http://127.0.0.1:19081", markers: "drop", scoped: true, product: true},
		{name: "scoped_path_missing_token", base: "http://127.0.0.1:19081", markers: "keep", scoped: true, dropToken: true},
		{name: "operator_127_0_0_1_stale_markers", base: "http://127.0.0.1:4318", markers: "keep"},
		{name: "operator_localhost_own_bearer", base: "http://localhost:4318", auth: "Authorization = 'Bearer " + otlpSecretOperatorBearer + "'", markers: "caps"},
		{name: "operator_localhost_missing_token", base: "http://localhost:4318", auth: "authorization = 'Bearer " + otlpSecretOperatorBearer + "'", markers: "keep", dropToken: true},
		{name: "operator_moved_127_1_stale_markers", base: "http://127.1:19081", markers: "keep"},
		{name: "operator_retired_port_own_bearer", base: "http://127.0.0.1:19081", auth: "AUTHORIZATION = 'bearer " + otlpSecretOperatorBearer + "'", markers: "drop", recorded: true},
		// Review of feb972ad (P1): HTTP Basic with the scoped token as the
		// password, standard or URL-safe base64, padded or not, with or
		// without markers, with the sidecar present or gone.
		{name: "basic_scoped_password", base: "http://127.0.0.1:19081", auth: "Authorization = 'Basic {basic}'", markers: "keep", product: true},
		{name: "basic_no_markers", base: "http://127.1:19081", auth: "authorization = 'Basic {basic}'", markers: "drop", product: true},
		{name: "basic_urlsafe_lower_scheme", base: "http://localhost:19081", auth: "Authorization = 'basic {basicurl}'", markers: "drop", product: true},
		{name: "basic_missing_sidecar_marked", base: "http://127.0.0.1:19081", auth: "Authorization = 'Basic {basic}'", markers: "keep", dropToken: true},
		{name: "basic_in_encoded_header_list", base: "http://127.0.0.1:19081", auth: "x-list = 'a=1,Authorization=Basic%20{basic}'", markers: "drop", product: true},
		// Review of feb972ad (P2): an operator collector with its own 64-hex
		// bearer and no DefenseClaw provenance keeps its bytes, the sidecar
		// present or gone, Bearer or Basic.
		{name: "operator_remote_own_hex_bearer", base: "https://collector.example.test", auth: "Authorization = 'Bearer {ophex}'", markers: "drop"},
		{name: "operator_remote_own_hex_missing_sidecar", base: "https://collector.example.test", auth: "Authorization = 'Bearer {ophex}'", markers: "drop", dropToken: true},
		{name: "operator_loopback_own_hex_basic", base: "http://127.0.0.1:4318", auth: "Authorization = 'Basic {opbasic}'", markers: "drop", dropToken: true},
		// Review of 70603235 (P2): the token shape with stale DefenseClaw
		// markers or in the scoped route position is no proof either.
		{name: "operator_marked_own_hex_bearer", base: "http://127.0.0.1:19081", auth: "Authorization = 'Bearer {ophex}'", markers: "keep", recorded: true},
		{name: "operator_marked_own_hex_basic", base: "http://127.0.0.1:19081", auth: "Authorization = 'Basic {opbasic}'", markers: "caps", recorded: true},
		{name: "operator_marked_hex_route", base: "http://127.0.0.1:19081", markers: "keep", scopedHex: true},
	}
}

// otlpSecretOperatorHex is an operator collector's own bearer in the product
// token shape.
var otlpSecretOperatorHex = strings.Repeat("c0ffee00", 8)

// otlpSecretAuth fills an Authorization template with the product token, its
// Basic encodings, or the operator's own token-shaped bearer.
func otlpSecretAuth(auth, token string) string {
	return strings.NewReplacer(
		"{tok}", token,
		"{basic}", base64.StdEncoding.EncodeToString([]byte("defenseclaw:"+token)),
		"{basicurl}", base64.RawURLEncoding.EncodeToString([]byte(token+":x")),
		"{ophex}", otlpSecretOperatorHex,
		"{opbasic}", base64.StdEncoding.EncodeToString([]byte("ops:"+otlpSecretOperatorHex)),
	).Replace(auth)
}

// otlpSecretLeaked reports the product token raw, percent-encoded or inside a
// Basic credential.
func otlpSecretLeaked(text, token string) bool {
	for _, form := range []string{token, otlpTestPercentEncode(token), otlpSecretAuth("{basic}", token), otlpSecretAuth("{basicurl}", token)} {
		if strings.Contains(text, form) {
			return true
		}
	}
	return false
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
		auth = otlpSecretAuth(row.auth, token) + "\n"
	}
	body = strings.ReplaceAll(body, "authorization = 'Bearer f00dfeedf00dfeedf00dfeedf00dfeedf00dfeedf00dfeedf00dfeedf00dfeed'\n", auth)
	route := row.base + "/"
	if row.scoped {
		route += "otlp/codex/" + token + "/"
	}
	if row.scopedHex {
		route += "otlp/codex/" + otlpSecretOperatorHex + "/"
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

// The Linux, Darwin and Windows tests run the table for one fixture GOOS
// each: the whole table is too long for one CI shard (about 18 minutes on
// a Windows runner), and the shard scripts split only top-level tests.
func TestCodexSecretOwnershipAcrossWritersLinux(t *testing.T) {
	codexSecretOwnershipAcrossWriters(t, "linux")
}
func TestCodexSecretOwnershipAcrossWritersDarwin(t *testing.T) {
	codexSecretOwnershipAcrossWriters(t, "darwin")
}
func TestCodexSecretOwnershipAcrossWritersWindows(t *testing.T) {
	codexSecretOwnershipAcrossWriters(t, "windows")
}

func codexSecretOwnershipAcrossWriters(t *testing.T, goos string) {
	for _, release := range []string{"1.0.2", "1.0.3"} {
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
					if row.product && otlpSecretLeaked(string(got), token) {
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

// Claude Code runs the same rows on its logs route beside the real operator
// collector recorded on a published 1.0.2 upgrade subject (also the 1.0.3
// shape) and the rest of the released product env.
//
// The Linux, Darwin and Windows tests run the table for one fixture GOOS
// each: the whole table is too long for one CI shard (about 18 minutes on
// a Windows runner), and the shard scripts split only top-level tests.
func TestClaudeSecretOwnershipAcrossWritersLinux(t *testing.T) {
	claudeSecretOwnershipAcrossWriters(t, "linux")
}
func TestClaudeSecretOwnershipAcrossWritersDarwin(t *testing.T) {
	claudeSecretOwnershipAcrossWriters(t, "darwin")
}
func TestClaudeSecretOwnershipAcrossWritersWindows(t *testing.T) {
	claudeSecretOwnershipAcrossWriters(t, "windows")
}

func claudeSecretOwnershipAcrossWriters(t *testing.T, goos string) {
	fixture, err := os.ReadFile(filepath.Join("testdata", "claudecode_operator_1.0.2_1.0.3.json"))
	if err != nil {
		t.Fatal(err)
	}
	var operator map[string]string
	if err := json.Unmarshal(fixture, &operator); err != nil {
		t.Fatal(err)
	}
	for _, release := range []string{"1.0.2", "1.0.3"} {
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
					if row.scopedHex {
						route += "otlp/claudecode/" + otlpSecretOperatorHex + "/"
					}
					route += "v1/logs" + row.query
					var parts []string
					if row.auth != "" {
						for _, line := range strings.Split(otlpSecretAuth(row.auth, token), "\n") {
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
					if row.product && otlpSecretLeaked(string(raw), token) {
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

func TestOTLPCarriesProductCredentialIsAKnownSecret(t *testing.T) {
	token := strings.Repeat("0123456789abcdef", 4)
	basic := base64.StdEncoding.EncodeToString([]byte("dc:" + token))
	for _, value := range []string{token, "Bearer " + token, "bearer%20" + token, "a=1,Authorization=Bearer " + token,
		"Basic " + basic, "BASIC " + strings.TrimRight(basic, "="), "Authorization=Basic%20" + basic,
		"basic " + base64.RawURLEncoding.EncodeToString([]byte(token+":"))} {
		if !otlpCarriesProductCredential(value, []string{token}) {
			t.Errorf("known credential not found in %q", value)
		}
		// Review of 70603235 (P2): only a known credential is proof; the
		// token shape is not, with a DefenseClaw marker beside it or not.
		if otlpCarriesProductCredential(value, nil) || otlpCarriesProductCredential("x-defenseclaw-source=codex,"+value, nil) {
			t.Errorf("token shape claimed %q", value)
		}
	}
	route := "http://127.1:1/otlp/codex/" + token + "/v1/logs"
	if otlpCarriesProductCredential(route, nil) || !otlpCarriesProductCredential(route, []string{token}) {
		t.Error("the scoped route is the product's only when its token is known")
	}
	if otlpCarriesProductCredential(map[string]interface{}{"otlp-http": map[string]interface{}{"headers": map[string]interface{}{
		"X-DefenseClaw-Client": "codex-otel/1.0", "authorization": "Basic " + basic}}}, nil) {
		t.Error("marked exporter with an unknown token-shaped Basic password claimed")
	}
	for _, value := range []string{"Bearer " + strings.ToUpper(token), "Bearer " + token[:63], "Bearer " + otlpSecretOperatorHex, "Bearer operator-collector-token", "http://127.0.0.1:4318/v1/logs",
		"Basic " + base64.StdEncoding.EncodeToString([]byte("ops:operator-collector-token")), "Basic !!!!"} {
		if otlpCarriesProductCredential("x-defenseclaw-source=codex,"+value, []string{token, "configured-token"}) {
			t.Errorf("operator value %q claimed", value)
		}
	}
	if !otlpCarriesProductCredential(map[string]interface{}{"otlp-http": map[string]interface{}{"headers": map[string]interface{}{"X-Api-Key": "configured-token"}}}, []string{"configured-token"}) {
		t.Error("known credential under another header name not found")
	}
	// Review of 95ed75a6: one stray "%" must not stop the decode (Doctor's
	// unquote is lenient too), and a table key is searched like a value.
	enc := otlpTestPercentEncode(token)
	for _, value := range []interface{}{
		"load=90%,session.id=" + enc,
		"Bearer%20" + enc + "%zz",
		"http://dc:" + enc + "@127.0.0.1:19081/v1/logs?p=5%",
		"x=%" + enc,
		"configured%2Dtoken%",
		map[string]interface{}{"resource_attributes": map[string]interface{}{token: "session"}},
		[]interface{}{"a", map[string]interface{}{"k": "v=100%,t=" + enc}},
	} {
		if !otlpCarriesProductCredential(value, []string{token, "configured-token"}) {
			t.Errorf("credential not found in %#v", value)
		}
	}
	for _, value := range []string{"load=90%,tenant=ops", "%zz%", "100%", "Bearer%20" + enc[:len(enc)-3]} {
		if otlpCarriesProductCredential(value, []string{token}) {
			t.Errorf("operator value %q claimed", value)
		}
	}
	if otlpCarriesProductCredential("abc", []string{"ab"}) {
		t.Error("a short known value matched ordinary text")
	}
}

// Review of 70603235 (P2): the decode budget is fixed and complete. Two
// percent layers (an env-string list value, encoded once more) and one Basic
// decode in each are checked; a value past that, or over the size cap, is
// reported as limited and its deeper forms are not, so it stays the
// operator's. The work is linear in the value whatever its nesting.
func TestOTLPValueFormsAreBounded(t *testing.T) {
	maxForms := (1 + otlpMaxPercentLayers) * (1 + otlpMaxBasicCredentials)
	nested := "%" + strings.Repeat("25", 1200) + "41"
	if len(nested) != 2403 {
		t.Fatalf("fixture is %d bytes", len(nested))
	}
	forms, limited := otlpValueForms(nested)
	if len(forms) != 1+otlpMaxPercentLayers || !limited {
		t.Fatalf("nested escapes: %d forms, limited=%t", len(forms), limited)
	}
	var repeated strings.Builder
	for i := range 500 {
		fmt.Fprintf(&repeated, "Basic %s ", base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("a:x%d", 1000+i))))
	}
	forms, limited = otlpValueForms(repeated.String())
	if len(forms) > maxForms || !limited {
		t.Fatalf("repeated Basic: %d forms, limited=%t", len(forms), limited)
	}
	token := strings.Repeat("0123456789abcdef", 4)
	once := otlpTestPercentEncode(token)
	twice := otlpTestPercentEncode(once)
	thrice := otlpTestPercentEncode(twice)
	basicOf := func(s string) string { return "Basic " + base64.StdEncoding.EncodeToString([]byte("dc:"+s)) }
	for _, row := range []struct {
		name, value    string
		found, limited bool
	}{
		{"raw", "k=" + token, true, false},
		{"one_layer", "k=" + once, true, false},
		{"two_layers", "k=" + twice, true, false},
		{"three_layers", "k=" + thrice, false, true},
		{"basic", basicOf(token), true, false},
		{"basic_in_two_layers", otlpTestPercentEncode(otlpTestPercentEncode(basicOf(token))), true, false},
		{"basic_payload_encoded_again", basicOf(once), false, true},
		{"basic_in_basic", "Basic " + base64.StdEncoding.EncodeToString([]byte("x:"+basicOf(token))), false, true},
		{"over_size_cap_raw", strings.Repeat("x", otlpMaxDecodeBytes) + token, true, false},
		{"over_size_cap_encoded", strings.Repeat("x", otlpMaxDecodeBytes) + once, false, true},
		{"plain", "load=90%,tenant=ops", false, false},
	} {
		forms, limited := otlpValueForms(row.value)
		if found := otlpCarriesProductCredential(row.value, []string{token}); found != row.found || limited != row.limited || len(forms) > maxForms {
			t.Errorf("%s: found=%t limited=%t forms=%d, want found=%t limited=%t", row.name, found, limited, len(forms), row.found, row.limited)
		}
	}
}

// Review of feb972ad (P2): the managed Verify check of a 2,403-byte value of
// 1,200 nested %25 escapes does bounded work, not one copy per layer.
func TestOTLPCredentialCheckWorkIsBounded(t *testing.T) {
	nested := map[string]interface{}{"environment": "%" + strings.Repeat("25", 1200) + "41"}
	allocs := testing.AllocsPerRun(5, func() { otlpCarriesProductCredential(nested, []string{"configured-token"}) })
	if allocs > 200 {
		t.Fatalf("credential check made %.0f allocations for one nested value", allocs)
	}
}

// Review of feb972ad and 70603235 (P2): a token-shaped value that carries no
// known credential (an operator's sha256 resource attribute or environment,
// with stale DefenseClaw markers or not, a nested-escape value) is the
// operator's. Setup, the managed cleanup, VerifyClean and managed Verify keep
// it byte for byte, with the sidecar present or gone.
func TestOTLPShapeOnlyValueKeepsOperatorBytes(t *testing.T) {
	nested := "%" + strings.Repeat("25", 1200) + "41"
	values := map[string]string{
		"sha_environment": "deploy-" + otlpSecretOperatorHex,
		"nested_escapes":  nested,
		// Review of 70603235: stale markers beside the shape are no proof.
		"marked_sha": "x-defenseclaw-source=codex,deploy-" + otlpSecretOperatorHex,
	}
	for _, goos := range []string{"linux", "darwin", "windows"} {
		for name, value := range values {
			for _, drop := range []bool{false, true} {
				for _, writer := range []string{"setup", "managed_cleanup"} {
					t.Run(fmt.Sprintf("codex/%s/%s/drop=%t/%s", goos, name, drop, writer), func(t *testing.T) {
						dir := t.TempDir()
						configPath := filepath.Join(dir, "config.toml")
						prior := CodexConfigPathOverride
						CodexConfigPathOverride = configPath
						t.Cleanup(func() { CodexConfigPathOverride = prior })
						operator := "[otel]\nenvironment = '" + value + "'\nlog_user_prompt = false\n\n[otel.resource_attributes]\n'deploy.sha' = '" + otlpSecretOperatorHex + "'\n"
						if err := os.WriteFile(configPath, []byte("model = 'gpt-5'\n\n"+operator), 0o600); err != nil {
							t.Fatal(err)
						}
						if _, err := EnsureOTLPPathToken(dir, OTLPScopeCodex); err != nil {
							t.Fatal(err)
						}
						if drop {
							if err := RemoveOTLPPathToken(dir, OTLPScopeCodex); err != nil {
								t.Fatal(err)
							}
						}
						var parsed map[string]interface{}
						if err := toml.Unmarshal([]byte(operator), &parsed); err != nil {
							t.Fatal(err)
						}
						if fields := codexOtelResidueFields(parsed["otel"], SetupOpts{DataDir: dir}); len(fields) != 0 {
							t.Fatalf("VerifyClean = %v", fields)
						}
						if residue := otlpSecretResidue(t, "codex", dir, "config.toml"); len(residue) != 0 {
							t.Fatalf("managed Verify = %v", residue)
						}
						if writer == "setup" {
							if err := NewCodexConnector().Setup(context.Background(), SetupOpts{DataDir: dir, APIAddr: "127.0.0.1:19082", APIToken: "test-hook-token", GOOS: goos}); err != nil {
								t.Fatalf("setup: %v", err)
							}
						} else if _, err := RemoveUserNativeOTLP("codex", SetupOpts{DataDir: dir, ManagedEnterprise: true}); err != nil {
							t.Fatalf("managed cleanup: %v", err)
						}
						got, err := os.ReadFile(configPath)
						if err != nil {
							t.Fatal(err)
						}
						var after map[string]interface{}
						if err := toml.Unmarshal(got, &after); err != nil {
							t.Fatal(err)
						}
						otel, _ := after["otel"].(map[string]interface{})
						resource, _ := otel["resource_attributes"].(map[string]interface{})
						if otel["environment"] != value || resource["deploy.sha"] != otlpSecretOperatorHex {
							t.Fatalf("operator [otel] changed:\n%s", got)
						}
					})
					t.Run(fmt.Sprintf("claudecode/%s/%s/drop=%t/%s", goos, name, drop, writer), func(t *testing.T) {
						dir := t.TempDir()
						pinClaudeUpgradeTestOwner(t, dir)
						settingsPath := filepath.Join(dir, "settings.json")
						prior := ClaudeCodeSettingsPathOverride
						ClaudeCodeSettingsPathOverride = settingsPath
						t.Cleanup(func() { ClaudeCodeSettingsPathOverride = prior })
						conn := NewClaudeCodeConnector()
						earlier := SetupOpts{DataDir: dir, APIAddr: "127.0.0.1:19081", GOOS: goos, sandboxNativeOTLP: true}
						if err := conn.Setup(context.Background(), earlier); err != nil {
							t.Fatalf("released setup: %v", err)
						}
						env := map[string]interface{}{
							"CLAUDE_CODE_ENABLE_TELEMETRY":       "1",
							"OTEL_TRACES_EXPORTER":               "otlp",
							"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": "https://collector.example.test/v1/traces",
							"OTEL_EXPORTER_OTLP_TRACES_HEADERS":  "Authorization=Bearer " + otlpSecretOperatorHex,
							"OTEL_RESOURCE_ATTRIBUTES":           "deploy.sha=" + otlpSecretOperatorHex,
							"OTEL_SERVICE_NAME":                  value,
						}
						writeClaudeUpgradeSettings(t, settingsPath, map[string]interface{}{"env": env})
						if drop {
							if err := RemoveOTLPPathToken(dir, OTLPScopeClaude); err != nil {
								t.Fatal(err)
							}
							if err := os.Remove(filepath.Join(dir, "claudecode_backup.json")); err != nil {
								t.Fatal(err)
							}
						}
						if left := otlpSecretResidue(t, "claudecode", dir, "settings.json"); len(left) != 0 {
							t.Fatalf("managed Verify = %v", left)
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
						got := readClaudeUpgradeEnv(t, settingsPath)
						for key, want := range env {
							if key != "CLAUDE_CODE_ENABLE_TELEMETRY" && got[key] != want {
								t.Errorf("operator %s = %q, want %q", key, got[key], want)
							}
						}
					})
				}
			}
		}
	}
}

// otlpTestPercentEncode percent-encodes every byte of s.
func otlpTestPercentEncode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		fmt.Fprintf(&b, "%%%02X", s[i])
	}
	return b.String()
}

// TestCodexSecretOwnershipCoversEveryOtelValue is the Codex side of the
// review of 95ed75a6: a DefenseClaw credential in any [otel] value (the
// environment that becomes a resource attribute, a resource or other table,
// a table key, an exporter's header list, endpoint userinfo or query),
// percent-encoded beside a stray "%" or not, with the sidecar present or gone,
// is reported by VerifyClean and managed Verify and removed by Setup and the
// managed cleanup. The operator collector, environment and prompt preference
// keep their bytes.
//
// The Linux, Darwin and Windows tests run the table for one fixture GOOS
// each: the whole table is too long for one CI shard (about 18 minutes on
// a Windows runner), and the shard scripts split only top-level tests.
func TestCodexSecretOwnershipCoversEveryOtelValueLinux(t *testing.T) {
	codexSecretOwnershipCoversEveryOtelValue(t, "linux")
}
func TestCodexSecretOwnershipCoversEveryOtelValueDarwin(t *testing.T) {
	codexSecretOwnershipCoversEveryOtelValue(t, "darwin")
}
func TestCodexSecretOwnershipCoversEveryOtelValueWindows(t *testing.T) {
	codexSecretOwnershipCoversEveryOtelValue(t, "windows")
}

func codexSecretOwnershipCoversEveryOtelValue(t *testing.T, goos string) {
	const operator = "[otel.trace_exporter.otlp-http]\nendpoint = 'http://127.0.0.1:4318/v1/traces'\nprotocol = 'json'\n\n" +
		"[otel.trace_exporter.otlp-http.headers]\nX-Tenant = 'ops'\n"
	rows := []struct {
		name, environment, block, gone string
		dropToken                      bool
	}{
		{name: "environment_token", environment: "{tok}", gone: "environment"},
		{name: "environment_encoded_stray_percent", environment: "ops-%{enc}", gone: "environment"},
		{name: "resource_table_value", block: "[otel.resource_attributes]\n'session.id' = '{tok}'\n", gone: "resource_attributes"},
		{name: "resource_table_key", block: "[otel.resource_attributes]\n'{tok}' = 'session'\n", gone: "resource_attributes"},
		{name: "resource_list_encoded_stray_percent", block: "[otel.resource_attributes]\nlist = 'load=90%,session.id={enc}'\n", gone: "resource_attributes"},
		{name: "exporter_header_list_stray_percent", block: "[otel.exporter.otlp-http]\nendpoint = 'http://127.0.0.1:19081/v1/logs'\nprotocol = 'binary'\n\n" +
			"[otel.exporter.otlp-http.headers]\nx-list = 'a=50%,Authorization=Bearer%20{enc}'\n", gone: "exporter"},
		{name: "exporter_userinfo_encoded", block: "[otel.exporter.otlp-http]\nendpoint = 'http://dc:{enc}@127.0.0.1:19081/v1/logs?note=100%'\nprotocol = 'binary'\n", gone: "exporter"},
		{name: "metrics_query_encoded", block: "[otel.metrics_exporter.otlp-http]\nendpoint = 'http://127.0.0.1:19081/v1/metrics?load=9%&key={enc}'\nprotocol = 'binary'\n", gone: "metrics_exporter"},
	}
	for _, release := range []string{"1.0.2", "1.0.3"} {
		for _, row := range rows {
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
						t.Fatalf("seed %s setup: %v", release, err)
					}
					base, err := os.ReadFile(configPath)
					if err != nil {
						t.Fatal(err)
					}
					token, err := EnsureOTLPPathToken(dir, OTLPScopeCodex)
					if err != nil {
						t.Fatal(err)
					}
					fill := strings.NewReplacer("{tok}", token, "{enc}", otlpTestPercentEncode(token))
					environment := "ops-env"
					if row.environment != "" {
						environment = fill.Replace(row.environment)
					}
					text := strings.ReplaceAll(string(base), "\r\n", "\n") + "\n[otel]\nenvironment = '" + environment + "'\nlog_user_prompt = false\n\n" +
						operator + "\n" + fill.Replace(row.block)
					want := operator
					if goos == "windows" {
						text = strings.ReplaceAll(text, "\n", "\r\n")
						want = strings.ReplaceAll(operator, "\n", "\r\n")
					}
					if err := os.WriteFile(configPath, []byte(text), 0o600); err != nil {
						t.Fatal(err)
					}
					if row.dropToken {
						if err := RemoveOTLPPathToken(dir, OTLPScopeCodex); err != nil {
							t.Fatal(err)
						}
					}
					var parsed map[string]interface{}
					if err := toml.Unmarshal([]byte(text), &parsed); err != nil {
						t.Fatal(err)
					}
					field := "config.toml otel." + row.gone
					if fields := codexOtelResidueFields(parsed["otel"], SetupOpts{DataDir: dir}); !slices.ContainsFunc(fields, func(f string) bool { return strings.HasPrefix(f, field+" ") }) {
						t.Fatalf("VerifyClean = %v, want %s", fields, field)
					}
					if residue := otlpSecretResidue(t, "codex", dir, "config.toml"); !slices.Contains(residue, field) {
						t.Fatalf("managed Verify = %v, want %s", residue, field)
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
					if strings.Contains(string(got), token) || strings.Contains(string(got), otlpTestPercentEncode(token)) {
						t.Fatalf("product credential survived:\n%s", got)
					}
					if !strings.Contains(string(got), want) {
						t.Fatalf("operator collector bytes changed; want:\n%s\ngot:\n%s", want, got)
					}
					var after map[string]interface{}
					if err := toml.Unmarshal(got, &after); err != nil {
						t.Fatal(err)
					}
					otel, _ := after["otel"].(map[string]interface{})
					if _, kept := otel[row.gone]; kept {
						t.Fatalf("otel.%s kept", row.gone)
					}
					if otel["log_user_prompt"] != false || row.gone != "environment" && otel["environment"] != "ops-env" {
						t.Fatalf("operator [otel] values changed: %v", otel)
					}
					if left := otlpSecretResidue(t, "codex", dir, "config.toml"); len(left) != 0 {
						t.Fatalf("residue after %s: %v", writer, left)
					}
				})
			}
		}
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

// TestClaudeSecretOwnershipCoversEveryOTLPEnvValue is the class of the
// round e loop 2 P1: a DefenseClaw credential in any OTLP env value (resource
// attributes, service name, a log gate, an OTLP key the profile never wrote,
// percent-encoded or not, with the sidecar present or gone) is removed beside
// an operator route that carries none, by Setup and the managed cleanup, and
// managed Verify reports it first. The operator route and its other values
// keep their bytes.
//
// The Linux, Darwin and Windows tests run the table for one fixture GOOS
// each: the whole table is too long for one CI shard (about 18 minutes on
// a Windows runner), and the shard scripts split only top-level tests.
func TestClaudeSecretOwnershipCoversEveryOTLPEnvValueLinux(t *testing.T) {
	claudeSecretOwnershipCoversEveryOTLPEnvValue(t, "linux")
}
func TestClaudeSecretOwnershipCoversEveryOTLPEnvValueDarwin(t *testing.T) {
	claudeSecretOwnershipCoversEveryOTLPEnvValue(t, "darwin")
}
func TestClaudeSecretOwnershipCoversEveryOTLPEnvValueWindows(t *testing.T) {
	claudeSecretOwnershipCoversEveryOTLPEnvValue(t, "windows")
}

func claudeSecretOwnershipCoversEveryOTLPEnvValue(t *testing.T, goos string) {
	encode := func(s string) string {
		var b strings.Builder
		for i := 0; i < len(s); i++ {
			fmt.Fprintf(&b, "%%%02X", s[i])
		}
		return b.String()
	}
	rows := []struct {
		name, key, value string
		dropToken        bool
	}{
		{name: "resource_session_id", key: "OTEL_RESOURCE_ATTRIBUTES", value: "team=a,session.id={tok}"},
		{name: "resource_missing_sidecar", key: "OTEL_RESOURCE_ATTRIBUTES", value: "session.id={tok}"},
		{name: "resource_percent_encoded", key: "OTEL_RESOURCE_ATTRIBUTES", value: "session.id={enc}"},
		{name: "service_name", key: "OTEL_SERVICE_NAME", value: "claude-{tok}"},
		{name: "log_gate", key: "OTEL_LOG_TOOL_DETAILS", value: "{tok}"},
		{name: "unlisted_otlp_key", key: "OTEL_EXPORTER_OTLP_TRACES_TIMEOUT", value: "{tok}"},
		// Review of 95ed75a6: the decode is lenient, so one stray "%" in a
		// comma/equals list, a URL or a query never hides an encoded token.
		{name: "resource_list_stray_percent", key: "OTEL_RESOURCE_ATTRIBUTES", value: "load=90%,session.id={enc}"},
		{name: "resource_encoded_separator", key: "OTEL_RESOURCE_ATTRIBUTES", value: "team=a%2Csession.id%3D{tok}"},
		{name: "logs_headers_list_stray_percent", key: "OTEL_EXPORTER_OTLP_LOGS_HEADERS", value: "x-a=50%,Authorization=Bearer%20{enc}"},
		{name: "metrics_endpoint_userinfo_encoded", key: "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", value: "http://dc:{enc}@127.0.0.1:19081/v1/metrics?load=9%"},
		{name: "generic_endpoint_query_encoded", key: "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT", value: "http://127.0.0.1:19081/v1/logs?n=100%&k={enc}"},
	}
	const operatorRoute = "http://127.1:19081/v1/traces"
	for _, release := range []string{"1.0.2", "1.0.3"} {
		for _, row := range rows {
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
					// The operator replaced the product routes with one traces
					// collector that carries no credential.
					env := map[string]interface{}{
						"CLAUDE_CODE_ENABLE_TELEMETRY":       "1",
						"OTEL_TRACES_EXPORTER":               "otlp",
						"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": operatorRoute,
						"OTEL_EXPORTER_OTLP_TRACES_PROTOCOL": "http/protobuf",
					}
					value := strings.NewReplacer("{tok}", token, "{enc}", encode(token)).Replace(row.value)
					env[row.key] = value
					settings["env"] = env
					writeClaudeUpgradeSettings(t, settingsPath, settings)
					if row.dropToken {
						if err := RemoveOTLPPathToken(dir, OTLPScopeClaude); err != nil {
							t.Fatal(err)
						}
						if err := os.Remove(filepath.Join(dir, "claudecode_backup.json")); err != nil {
							t.Fatal(err)
						}
					}
					want := "settings.json env." + row.key
					if left := otlpSecretResidue(t, "claudecode", dir, "settings.json"); !slices.Contains(left, want) {
						t.Fatalf("managed Verify before %s = %v, want %s", writer, left, want)
					}

					if writer == "setup" {
						upgrade := earlier
						upgrade.sandboxNativeOTLP = false
						upgrade.APIAddr = "127.0.0.1:19082"
						if err := conn.Setup(context.Background(), upgrade); err != nil {
							t.Fatalf("upgrade: %v", err)
						}
					} else {
						removed, err := RemoveUserNativeOTLP("claudecode", SetupOpts{DataDir: dir, ManagedEnterprise: true})
						if err != nil {
							t.Fatalf("managed cleanup: %v", err)
						}
						if !slices.Contains(removed, want) {
							t.Fatalf("managed cleanup removed %v, want %s", removed, want)
						}
					}
					raw, err := os.ReadFile(settingsPath)
					if err != nil {
						t.Fatal(err)
					}
					if strings.Contains(string(raw), token) || strings.Contains(string(raw), encode(token)) {
						t.Fatalf("product credential survived in env.%s", row.key)
					}
					got := readClaudeUpgradeEnv(t, settingsPath)
					// Setup may render its own pin ("0") under a gate key.
					if got[row.key] == value {
						t.Fatalf("env.%s kept", row.key)
					}
					if got["OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"] != operatorRoute || got["OTEL_TRACES_EXPORTER"] != "otlp" ||
						got["OTEL_EXPORTER_OTLP_TRACES_PROTOCOL"] != "http/protobuf" {
						t.Fatalf("operator traces route changed: %v", got)
					}
					if left := otlpSecretResidue(t, "claudecode", dir, "settings.json"); len(left) != 0 {
						t.Fatalf("residue after %s: %v", writer, left)
					}
				})
			}
		}
	}
}

// Review of 70603235: the Claude cleanup restores a backed-up value only when
// it carries no known product credential. With no token-shape rule, the
// restore check must use the known credentials, or a backup holding the
// scoped token would put it back.
func TestClaudeOTLPCleanupDoesNotRestoreBackedUpProductCredential(t *testing.T) {
	for _, goos := range []string{"linux", "darwin", "windows"} {
		t.Run(goos, func(t *testing.T) {
			dir := t.TempDir()
			pinClaudeUpgradeTestOwner(t, dir)
			token, err := EnsureOTLPPathToken(dir, OTLPScopeClaude)
			if err != nil {
				t.Fatal(err)
			}
			original, err := json.Marshal(map[string]string{"OTEL_SERVICE_NAME": "svc-" + token, "OTEL_RESOURCE_ATTRIBUTES": "team=ops"})
			if err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(map[string]interface{}{"env": map[string]interface{}{
				"OTEL_SERVICE_NAME":        "claude-" + token,
				"OTEL_RESOURCE_ATTRIBUTES": "team=ops",
			}})
			if err != nil {
				t.Fatal(err)
			}
			backup := claudeCodeBackup{HadEnvKey: true, OriginalEnv: original}
			out, removed, err := claudeCodeWithoutUserNativeOTLP(raw, backup, SetupOpts{DataDir: dir, GOOS: goos})
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Contains(removed, "settings.json env.OTEL_SERVICE_NAME") {
				t.Fatalf("removed = %v", removed)
			}
			if strings.Contains(string(out), token) {
				t.Fatalf("backed-up product credential restored:\n%s", out)
			}
			if !strings.Contains(string(out), "team=ops") {
				t.Fatalf("operator value lost:\n%s", out)
			}
		})
	}
}

// TestClaudeMarkedOperatorCollectorKeepsBytes{Linux,Darwin,Windows} are
// GAP-1511: an operator Claude Code collector whose header list holds its own
// credential (the product token shape or not) and only stale
// x-defenseclaw-* markers is the operator's. With no credential this install
// can name in it, fresh Setup, an upgrade from a released profile, the
// managed cleanup and Verify, and Teardown leave its settings byte-identical,
// on the signal-specific or the generic header key. A header list that
// carries the scoped token is still the product's and is removed.
//
// Each test runs the table for one fixture GOOS: the whole table is 126 full
// Setup/Teardown runs, which outlasted the connector package's 660 s Go
// timeout on a hosted Windows runner even alone in its shard (GAP-2199,
// GAP-2645: no write was blocked; the subtest in the rename was 3 s old),
// and the shard scripts split only top-level tests.
func TestClaudeMarkedOperatorCollectorKeepsBytesLinux(t *testing.T) {
	claudeMarkedOperatorCollectorKeepsBytes(t, "linux")
}
func TestClaudeMarkedOperatorCollectorKeepsBytesDarwin(t *testing.T) {
	claudeMarkedOperatorCollectorKeepsBytes(t, "darwin")
}
func TestClaudeMarkedOperatorCollectorKeepsBytesWindows(t *testing.T) {
	claudeMarkedOperatorCollectorKeepsBytes(t, "windows")
}

func claudeMarkedOperatorCollectorKeepsBytes(t *testing.T, goos string) {
	headerSets := map[string]string{
		"hex_bearer_markers":     "authorization=Bearer " + otlpSecretOperatorHex + ",x-defenseclaw-client=claudecode-otel/1.0,x-defenseclaw-source=claudecode",
		"encoded_bearer_markers": "authorization=Bearer%20" + otlpSecretOperatorHex + ",x-defenseclaw-client=claudecode-otel%2F1.0,x-defenseclaw-source=claudecode",
		"caps_bearer_markers":    "Authorization=Bearer " + otlpSecretOperatorHex + ",X-DefenseClaw-Source=claudecode",
		"token_header_markers":   "x-defenseclaw-token=" + otlpSecretOperatorHex + ",x-defenseclaw-source=claudecode",
		"opaque_bearer_markers":  "authorization=Bearer " + otlpSecretOperatorBearer + ",x-defenseclaw-source=claudecode",
		"source_marker_only":     "x-defenseclaw-source=claudecode",
		"product_token_markers":  "authorization=Bearer {tok},x-defenseclaw-client=claudecode-otel/1.0,x-defenseclaw-source=claudecode",
		"product_token_mixed":    "x-tenant=traces,authorization=Bearer {tok}",
		"product_token_encoded":  "x-defenseclaw-source=claudecode,authorization=Bearer%20{tok}",
	}
	for name, template := range headerSets {
		product := strings.Contains(template, "{tok}")
		for _, headersKey := range []string{"OTEL_EXPORTER_OTLP_TRACES_HEADERS", "OTEL_EXPORTER_OTLP_HEADERS"} {
			for _, path := range []string{"fresh", "upgrade", "managed_cleanup"} {
				if !product && path != "fresh" && headersKey == "OTEL_EXPORTER_OTLP_HEADERS" {
					// The released per-signal traces header overrides a
					// generic one, so that traces route carries the
					// product credential and is the product's.
					continue
				}
				t.Run(name+"/"+headersKey+"/"+path, func(t *testing.T) {
					dir := t.TempDir()
					pinClaudeUpgradeTestOwner(t, dir)
					settingsPath := filepath.Join(dir, "settings.json")
					prior := ClaudeCodeSettingsPathOverride
					ClaudeCodeSettingsPathOverride = settingsPath
					t.Cleanup(func() { ClaudeCodeSettingsPathOverride = prior })
					conn := NewClaudeCodeConnector()
					host := SetupOpts{DataDir: dir, APIAddr: "127.0.0.1:19082", APIToken: "test-hook-token", GOOS: goos}
					settings := map[string]interface{}{"model": "opus"}
					var token string
					if path == "fresh" {
						// No DefenseClaw backup; a scoped sidecar names the
						// product token.
						var err error
						if token, err = EnsureOTLPPathToken(dir, OTLPScopeClaude); err != nil {
							t.Fatal(err)
						}
					} else {
						released := SetupOpts{DataDir: dir, APIAddr: "127.0.0.1:19081", GOOS: goos, sandboxNativeOTLP: true}
						if err := conn.Setup(context.Background(), released); err != nil {
							t.Fatalf("released setup: %v", err)
						}
						var err error
						if token, err = LoadOTLPPathToken(dir, OTLPScopeClaude); err != nil || token == "" {
							t.Fatalf("released scoped token: present=%t err=%v", token != "", err)
						}
						data, err := os.ReadFile(settingsPath)
						if err != nil {
							t.Fatal(err)
						}
						if err := json.Unmarshal(data, &settings); err != nil {
							t.Fatal(err)
						}
					}
					env, _ := settings["env"].(map[string]interface{})
					if env == nil {
						env = map[string]interface{}{}
					}
					operator := map[string]string{
						"CLAUDE_CODE_ENABLE_TELEMETRY":       "1",
						"OTEL_TRACES_EXPORTER":               "otlp",
						"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": "http://localhost:4318/v1/traces",
						headersKey:                           strings.ReplaceAll(template, "{tok}", token),
					}
					for key, value := range operator {
						env[key] = value
					}
					settings["env"] = env
					writeClaudeUpgradeSettings(t, settingsPath, settings)

					check := func(stage string) {
						t.Helper()
						raw, err := os.ReadFile(settingsPath)
						if err != nil {
							t.Fatal(err)
						}
						got := readClaudeUpgradeEnv(t, settingsPath)
						if product {
							if otlpSecretLeaked(string(raw), token) {
								t.Fatalf("%s: product credential survived", stage)
							}
							return
						}
						for key, want := range operator {
							if key == "CLAUDE_CODE_ENABLE_TELEMETRY" && path == "upgrade" && stage == "teardown" {
								// The released profile wrote this same value
								// (claudeCodeEarlierReleaseEnv).
								continue
							}
							if got[key] != want {
								t.Errorf("%s: operator %s = %q, want %q", stage, key, got[key], want)
							}
						}
					}
					if path == "managed_cleanup" {
						if !product {
							if left := otlpSecretResidue(t, "claudecode", dir, "settings.json env."+headersKey); len(left) != 0 {
								t.Fatalf("managed Verify claims the operator headers: %v", left)
							}
						}
						if _, err := RemoveUserNativeOTLP("claudecode", SetupOpts{DataDir: dir, ManagedEnterprise: true}); err != nil {
							t.Fatalf("managed cleanup: %v", err)
						}
						check("managed cleanup")
						return
					}
					if err := conn.Setup(context.Background(), host); err != nil {
						t.Fatalf("%s setup: %v", path, err)
					}
					check(path + " setup")
					if err := conn.Teardown(context.Background(), host); err != nil {
						t.Fatalf("teardown: %v", err)
					}
					check("teardown")
				})
			}
		}
	}
}
