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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

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
		!strings.Contains(got, "enterprise secret set --name dctest-missing`, or remove the reference") {
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
