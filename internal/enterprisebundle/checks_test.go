// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package enterprisebundle

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func bundleOf(files map[string]string) *Bundle {
	b := &Bundle{Files: map[string][]byte{}}
	for name, body := range files {
		b.Files[name] = []byte(body)
	}
	return b
}

func TestCheckFiles(t *testing.T) {
	b := bundleOf(map[string]string{ConfigName: "config_version: 9\n", "policies/guardrail/p/rules.yaml": "rules: []\n"})
	m := &Manifest{Files: FileEntries(b)}
	if err := CheckFiles(m, b); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]struct {
		edit func(*Bundle, *Manifest)
		code Code
	}{
		"missing":  {func(b *Bundle, _ *Manifest) { delete(b.Files, ConfigName) }, CodeFileMissing},
		"extra":    {func(b *Bundle, _ *Manifest) { b.Files["policies/guardrail/p/more.yaml"] = nil }, CodeFileExtra},
		"edited":   {func(b *Bundle, _ *Manifest) { b.Files[ConfigName] = []byte("config_version: 8\n") }, CodeFileHashMismatch},
		"size":     {func(_ *Bundle, m *Manifest) { m.Files[0].Size++ }, CodeFileHashMismatch},
		"bad hash": {func(_ *Bundle, m *Manifest) { m.Files[0].SHA256 = "zz" }, CodeFileHashMismatch},
	} {
		t.Run(name, func(t *testing.T) {
			b := bundleOf(map[string]string{ConfigName: "config_version: 9\n", "policies/guardrail/p/rules.yaml": "rules: []\n"})
			m := &Manifest{Files: FileEntries(b)}
			change.edit(b, m)
			wantCode(t, CheckFiles(m, b), change.code)
		})
	}
}

func testPrivateKeyPEM(t *testing.T) string {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func TestCheckInlineSecrets(t *testing.T) {
	// Credential shapes are assembled at run time so no literal in this file
	// looks like one.
	accessKey := "AK" + "IA" + "Q7XK2M9P" + "LW4RT8VN"
	refused := map[string]map[string]string{
		"private key in a pack":   {ConfigName: "config_version: 9\n", "policies/guardrail/p/k.yaml": "key: |\n" + testPrivateKeyPEM(t)},
		"access key in a pack":    {ConfigName: "config_version: 9\n", "policies/guardrail/p/rules.yaml": "x: " + accessKey + "\n"},
		"token in config":         {ConfigName: "config_version: 9\ngateway:\n  token: abc123\n"},
		"api key in config":       {ConfigName: "config_version: 9\nscanners:\n  skill_scanner:\n    api_key: \"k-123\"\n"},
		"password in a list":      {ConfigName: "config_version: 9\nx:\n  - password: hunter2\n"},
		"access key in config":    {ConfigName: "config_version: 9\nblock_message: " + accessKey + "\n"},
		"secret through an alias": {ConfigName: "config_version: 9\na: &v plain\ngateway:\n  token: *v\n"},
		// The config loader matches keys case-insensitively and reads a
		// dotted key as a path; a literal ${...} is not expanded.
		"upper-case key":        {ConfigName: "config_version: 9\nllm:\n  API_KEY: hunter2\n"},
		"dotted key":            {ConfigName: "config_version: 9\nllm.api_key: hunter2\n"},
		"literal in braces":     {ConfigName: "config_version: 9\nllm:\n  api_key: ${hunter2 abc123}\n"},
		"secret ref not a name": {ConfigName: "config_version: 9\nllm:\n  api_key: secret://hunter2/abc123\n"},
		"static auth header":    {ConfigName: "config_version: 9\nobservability:\n  destinations:\n    - headers:\n        Authorization: Bearer abc123\n"},
	}
	for name, files := range refused {
		t.Run(name, func(t *testing.T) {
			err := CheckInlineSecrets(bundleOf(files))
			wantCode(t, err, CodeInlineSecret)
			if strings.Contains(err.Error(), "abc123") || strings.Contains(err.Error(), accessKey) || strings.Contains(err.Error(), "hunter2") {
				t.Fatalf("error quotes the secret: %v", err)
			}
		})
	}
	accepted := map[string]map[string]string{
		"references":     {ConfigName: "config_version: 9\ngateway:\n  token: \"\"\nscanners:\n  skill_scanner:\n    api_key: secret://vt\n  x:\n    api_key: ${VT_KEY}\nheaders:\n  secret:\n    credential: galileo\n"},
		"shape in regex": {ConfigName: "config_version: 9\n", "policies/guardrail/p/rules.yaml": "pattern: 'AKIA[0-9A-Z]{16}'\n"},
		"placeholder":    {ConfigName: "config_version: 9\n", "policies/guardrail/p/rules.yaml": "example: AKIA" + strings.Repeat("X", 16) + "\n"},
		"null value":     {ConfigName: "config_version: 9\ngateway:\n  token: null\n"},
		"static header":  {ConfigName: "config_version: 9\nobservability:\n  destinations:\n    - headers:\n        X-Scope-OrgID: team-a\n"},
	}
	for name, files := range accepted {
		t.Run(name, func(t *testing.T) {
			if err := CheckInlineSecrets(bundleOf(files)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCheckSecretRefs(t *testing.T) {
	raw := "config_version: 9\nenterprise:\n  inspection:\n    ai_defense:\n      credential: ai-defense-api-key\nobservability:\n  destinations:\n    - headers:\n        Galileo-API-Key: {credential: galileo-api-key}\n"
	b := bundleOf(map[string]string{ConfigName: raw})
	names, err := ConfigCredentials(b.Files[ConfigName])
	if err != nil || strings.Join(names, ",") != "ai-defense-api-key,galileo-api-key" {
		t.Fatalf("credentials %v (%v)", names, err)
	}
	bound := func(name string) SecretRef {
		return SecretRef{Ref: SecretRefScheme + name, Required: true, ValueSHA256: CredentialValueSHA256("acme", name, []byte("value"))}
	}
	m := &Manifest{TenantID: "acme", SecretRefs: []SecretRef{bound("ai-defense-api-key")}}
	wantCode(t, CheckSecretRefs(m, b), CodeManifestInvalid)
	m.SecretRefs = append(m.SecretRefs, bound("galileo-api-key"))
	if err := CheckSecretRefs(m, b); err != nil {
		t.Fatal(err)
	}
	// A reference that signs the name only (every bundle signed before
	// 1.0.4) binds no value: secret_ref_unbound.
	m.SecretRefs[1].ValueSHA256 = ""
	wantCode(t, CheckSecretRefs(m, b), CodeSecretRefUnbound)
}

func TestReachability(t *testing.T) {
	cfg := &config.Config{}
	cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{
		{Profile: "ml", Match: config.ProfileMatch{Groups: []string{
			"S-1-12-1-111-222-333-444",             // Entra SID
			"6f1c2a3b-0d4e-4f5a-8b6c-7d8e9f0a1b2c", // Entra object id
			"S-1-5-21-1-2-3-1105",                  // AD SID
			"S-1-5-21-x",                           // not a SID
			"dc-ml-*",                              // pattern
			"1001",                                 // gid
			`DCLAB\ml-team`,                        // name: never warned
			"ml-team",
		}}},
	}
	got := map[string][]string{}
	for _, warning := range Reachability(cfg, Platforms) {
		got[warning.Subject] = append(got[warning.Subject], warning.Platform+"="+warning.Code)
		if err := checkDisplayText(warning.Message, 512); err != nil || warning.Message == "" {
			t.Fatalf("message %q: %v", warning.Message, err)
		}
	}
	want := map[string][]string{
		"S-1-12-1-111-222-333-444":             {"linux=" + WarnEntraGroupLinux, "darwin=" + WarnEntraGroupMacOS, "windows=" + WarnEntraGroupWindows},
		"6f1c2a3b-0d4e-4f5a-8b6c-7d8e9f0a1b2c": {"linux=" + WarnEntraGroupLinux, "darwin=" + WarnEntraGroupMacOS, "windows=" + WarnEntraObjectIDWindows},
		"S-1-5-21-1-2-3-1105":                  {"linux=" + WarnGroupSIDNotOnPlatform, "darwin=" + WarnGroupSIDNotOnPlatform},
		"S-1-5-21-x":                           {"linux=" + WarnGroupSIDMalformed, "darwin=" + WarnGroupSIDMalformed, "windows=" + WarnGroupSIDMalformed},
		"dc-ml-*":                              {"linux=" + WarnGroupPattern, "darwin=" + WarnGroupPattern, "windows=" + WarnGroupPattern},
		"1001":                                 {"linux=" + WarnGroupNumericID, "darwin=" + WarnGroupNumericID},
	}
	if len(got) != len(want) {
		t.Fatalf("warned for %v, want %v", got, want)
	}
	for subject, codes := range want {
		if strings.Join(got[subject], " ") != strings.Join(codes, " ") {
			t.Fatalf("%s: %v, want %v", subject, got[subject], codes)
		}
	}
	if warnings := Reachability(cfg, []string{PlatformWindows}); len(warnings) != 4 {
		t.Fatalf("windows only: %d warnings, want 4", len(warnings))
	}
	// A large fleet's warnings never make the manifest invalid: the list is
	// cut at MaxWarnings with a closing count, and every subject stays
	// display text.
	groups := []string{"x\x01" + strings.Repeat("\x02", 200)}
	for i := 0; i < MaxWarnings; i++ {
		groups = append(groups, fmt.Sprintf("S-1-12-1-%d-1-1-1", i))
	}
	cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{{Profile: "ml", Match: config.ProfileMatch{Groups: groups}}}
	warnings := Reachability(cfg, Platforms)
	if len(warnings) != MaxWarnings || warnings[MaxWarnings-1].Code != WarnTruncated {
		t.Fatalf("%d warnings, last %+v; want %d ending in %s", len(warnings), warnings[len(warnings)-1], MaxWarnings, WarnTruncated)
	}
	m := validManifest()
	m.Warnings = warnings
	if err := m.Validate(); err != nil {
		t.Fatalf("manifest with the reachability warnings: %v", err)
	}
}
