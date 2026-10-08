// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

func TestManagedConfigRefusalsHideDiagnosticCodes(t *testing.T) {
	h := newTestHost(t, "linux")
	for _, err := range []error{
		&config.V8YAMLError{Code: config.V8YAMLErrorDuplicateKey, Path: "$.guardrail.mode", Line: 3, Summary: "duplicate mapping key"},
		&config.V8YAMLError{Code: config.V8YAMLErrorInvalidUTF8, Path: "$", Summary: "invalid UTF-8"},
		&config.V8SemanticError{Path: "$.guardrail", Summary: "unknown rule pack"},
	} {
		got, ok := h.env.plainConfigProblem(err, "/tmp/admin.yaml", nil)
		if !ok || !strings.Contains(got, "/tmp/admin.yaml") || strings.Contains(got, "[$") ||
			strings.Contains(got, "[yaml_") || strings.Contains(got, "[config_") || strings.Contains(got, " $.") {
			t.Fatalf("managed refusal = %q (handled %t)", got, ok)
		}
	}
}

func TestManagedConfigPatternNamesAllowedFormat(t *testing.T) {
	h := newTestHost(t, "linux")
	for _, tc := range []struct{ path, expected string }{
		{"$.guardrail.rule_pack", "lowercase letters, digits, - or _"},
		{"$.guardrail.custom_packs.example.digest", "sha256: followed by 64 lowercase hexadecimal"},
	} {
		got, ok := h.env.plainConfigProblem(&config.V8SchemaError{Path: tc.path, Keyword: "pattern", Expected: "a value matching the schema-declared pattern"}, "/tmp/admin.yaml", nil)
		if !ok || !strings.Contains(got, tc.expected) || strings.Contains(got, "schema-declared pattern") {
			t.Fatalf("%s: %q", tc.path, got)
		}
	}
}

func TestManagedConfigModeAndProfileNameOnlyInstalledChoices(t *testing.T) {
	h := newTestHost(t, "linux")
	mode := &config.V8SchemaError{Path: "$.deployment_mode", Keyword: "enum", Expected: `one of ["","managed_enterprise","saas"]`, Value: "standalone"}
	got, ok := h.env.plainConfigProblem(mode, "/tmp/admin.yaml", nil)
	if !ok || !strings.Contains(got, "allowed values: managed_enterprise") || strings.Contains(got, "saas") {
		t.Fatalf("deployment mode = %q", got)
	}
	got, ok = h.env.plainConfigProblem(errors.New(`config: enterprise.profile="secure_client" conflicts with immutable DEFENSECLAW_ENTERPRISE_PROFILE="standalone"`), "/tmp/admin.yaml", nil)
	if !ok || !strings.Contains(got, "fixed to standalone") || strings.Contains(got, "DEFENSECLAW_ENTERPRISE_PROFILE") {
		t.Fatalf("enterprise profile = %q", got)
	}
}

// GAP-1948, GAP-1944: a bad enum value and an unstored credential are
// reported in plain words, with the value, the line and the fix, and
// without the validator's rule id, JSONPath or YAML node type.
func TestConfigProblemsArePlain(t *testing.T) {
	h := newTestHost(t, "linux")
	dir := t.TempDir()
	enum := filepath.Join(dir, "enum.yaml")
	bad := strings.Replace(string(DefaultConfig(h.env.Layout)), "mode: observe", "mode: bogus", 1)
	if err := os.WriteFile(enum, []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	r := h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: enum})
	requireError(t, r, codeConfig)
	enumMsg := r.Errors[0].Message
	got := enumMsg
	if !strings.HasPrefix(got, enum+" line ") || !strings.Contains(got, `guardrail.mode is "bogus"; allowed values: observe, action`) ||
		!strings.Contains(got, settingsReferenceURL) {
		t.Fatalf("enum error = %q", got)
	}

	cred := filepath.Join(dir, "cred.yaml")
	raw := string(DefaultConfig(h.env.Layout)) + `observability:
  destinations:
    - name: galileo
      kind: otlp
      preset: galileo
      endpoint: https://api.galileo.ai/otel/traces
      headers:
        Galileo-API-Key: {credential: dctest-missing}
`
	if err := os.WriteFile(cred, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	r = h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: cred})
	requireError(t, r, codeConfig)
	got = r.Errors[0].Message
	if !strings.HasPrefix(got, cred+" line ") ||
		!strings.Contains(got, `the galileo destination's header Galileo-API-Key uses protected credential "dctest-missing", which is not stored; store it with`) ||
		!strings.Contains(got, "store it with `printf '%s' \"$VALUE\" | /") ||
		!strings.Contains(got, "/defenseclaw-gateway enterprise secret set --name dctest-missing --from-stdin` (or --from-file <root-only file>), or remove the reference") {
		t.Fatalf("credential error = %q", got)
	}
	for _, message := range []string{enumMsg, got} {
		for _, jargon := range []string{"(received", "config_semantic_invalid", "config_schema_invalid", "$.", "canonical v8", "not stored or not trusted"} {
			if strings.Contains(message, jargon) {
				t.Fatalf("message keeps %q: %s", jargon, message)
			}
		}
	}
}

// GAP-1949: the default uninstall names the accounts that keep per-user
// files, and binaries only for an account that has them.
func TestUninstallKeptLineNamesAccounts(t *testing.T) {
	h := newTestHost(t, "darwin")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	// The enumerator's root-only record of the enrolled accounts.
	record := h.env.P(enterprisehooks.UnixEligibleAccountsPath(h.env.Layout.ManifestPath))
	if err := os.MkdirAll(filepath.Dir(record), 0o700); err != nil {
		t.Fatal(err)
	}
	accounts := `{"version":1,"accounts":[{"user":"alice","uid":501,"gid":20,"home":"/Users/alice"},` +
		`{"user":"bob","uid":502,"gid":20,"home":"/Users/bob"},{"user":"carol","uid":503,"gid":20,"home":"/Users/carol"}]}`
	if err := os.WriteFile(record, []byte(accounts), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"/Users/alice/.defenseclaw", "/Users/bob/.defenseclaw", "/Users/bob/.local/bin"} {
		if err := os.MkdirAll(h.env.P(dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(h.env.P("/Users/bob/.local/bin/defenseclaw-gateway"), []byte("x"), 0o700); err != nil {
		t.Fatal(err)
	}
	r := h.run(Options{Action: ActionUninstall})
	requireOK(t, r)
	summary := strings.Join(r.Changes, "\n")
	want := "kept: the DefenseClaw per-user data (~/.defenseclaw) of alice, bob; the per-user binaries in ~/.local/bin of bob. " +
		"To delete them too, install the DefenseClaw enterprise package again and run `"
	if !strings.Contains(summary, want) || strings.Contains(summary, "carol") {
		t.Fatalf("kept line:\n%s", summary)
	}
}

// installMessage runs a first install with raw as the config and returns
// the config_invalid message.
func installMessage(t *testing.T, h *testHost, raw string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "admin.yaml")
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	r := h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: path})
	requireError(t, r, codeConfig)
	if exists(h.env.P(h.env.Layout.ConfigPath)) {
		t.Fatal("a refused config was installed")
	}
	return r.Errors[0].Message
}

// GAP-0939, GAP-0940: a destination secret read from an environment
// variable is refused up front whether or not the variable is set (set, the
// config was applied and the gateway failed to start into a rollback), and
// a destination with both fields gets the documented sentence.
func TestManagedConfigRefusesEnvironmentSecretReferences(t *testing.T) {
	hec := "observability:\n  destinations:\n    - name: eoi-hec\n      kind: splunk_hec\n" +
		"      endpoint: https://hec.example.test:8088/services/collector\n      token_env: EO3_REF\n"
	for _, value := range []string{"", "set"} {
		t.Setenv("EO3_REF", value)
		h := newTestHost(t, "linux")
		got := installMessage(t, h, string(DefaultConfig(h.env.Layout))+hec)
		if !strings.Contains(got, "(eoi-hec) token_env reads a secret from an environment variable") ||
			!strings.Contains(got, "never passes one to its services") || !strings.Contains(got, "token_credential") ||
			!strings.Contains(got, "enterprise secret set") || strings.Contains(got, "keys set") {
			t.Fatalf("EO3_REF=%q: %s", value, got)
		}
	}
	h := newTestHost(t, "linux")
	both := string(DefaultConfig(h.env.Layout)) + "observability:\n  destinations:\n    - name: eo3-http\n      kind: http_jsonl\n" +
		"      endpoint: https://collector.example.test/ingest\n      bearer_credential: eo3-http-token\n      bearer_env: EO3_REF\n"
	if got := installMessage(t, h, both); !strings.Contains(got, "(eo3-http) sets both bearer_credential and bearer_env; set either bearer_credential or bearer_env, not both") {
		t.Fatalf("both fields: %s", got)
	}
}

// GAP-0829: a malformed agent identity names the assignment, the value and
// the form.
func TestManagedConfigNamesTheMalformedAgentIdentity(t *testing.T) {
	h := newTestHost(t, "linux")
	raw := string(DefaultConfig(h.env.Layout)) + "  profiles:\n    strict:\n      mode: action\n" +
		"  profile_assignments:\n    - profile: strict\n      match:\n        agents: [agt-49fb88f74f28975]\n"
	got := installMessage(t, h, raw)
	if !strings.Contains(got, `guardrail.profile_assignments[0].match.agents[0] is "agt-49fb88f74f28975"`) ||
		!strings.Contains(got, "agt- followed by 16 lowercase hexadecimal digits") {
		t.Fatalf("agent identity: %s", got)
	}
}
