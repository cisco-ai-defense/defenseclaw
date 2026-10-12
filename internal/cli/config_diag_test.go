// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func writeSandboxProfileConfig(t *testing.T, openshell, sandbox string) (path, dir string) {
	t.Helper()
	dir = t.TempDir()
	path = filepath.Join(dir, "config.yaml")
	source := "config_version: 9\ndata_dir: " + dir + "\n" + openshell +
		"guardrail:\n  profiles:\n    contractors:\n      sandbox:\n" + sandbox
	if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, dir
}

// GAP-0337, GAP-0323: a sandbox-profile refusal of the runtime loader named
// neither the setting nor the profile ("configuration could not be compiled
// safely" at "$") and reported config_version 8 for a source-9 file.
func TestConfigValidateNamesTheSandboxProfileRefusal(t *testing.T) {
	for _, c := range []struct{ name, openshell, sandbox, want string }{
		{"required agent in a disallowed sandbox", "",
			"        allowed: false\n        required_for: [claudecode]\n",
			"sandbox: allowed: false contradicts required_for [claudecode]"},
		{"empty egress intersection",
			"openshell:\n  admin:\n    egress_allow_only: [a.example.com]\n",
			"        egress_allow_only: [b.example.com]\n", "egress_allow_only"},
		{"none with another credential", "",
			"        allowed_credentials: [none, openai]\n", "none cannot be combined with other credentials"},
		{"unknown connector", "",
			"        required_for: [nosuchagent]\n", `"nosuchagent" is not a known connector`},
		{"below the minimum", "",
			"        max_silence_after: 1s\n", "must be at least 1m"},
	} {
		t.Run(c.name, func(t *testing.T) {
			path, dir := writeSandboxProfileConfig(t, c.openshell, c.sandbox)
			failure := configV8ValidationFailure(mustFailLoad(t, path, dir))
			if failure.Path != `$.guardrail.profiles["contractors"]` ||
				!strings.Contains(failure.Reason, "config_semantic_invalid") || !strings.Contains(failure.Reason, c.want) {
				t.Fatalf("failure = %+v\nwant %s at the profile", failure, c.want)
			}
			if failure.ConfigVersion != config.ConfigVersionV9 {
				t.Fatalf("config_version = %d for a source-9 file", failure.ConfigVersion)
			}
		})
	}
}

// GAP-0323: the check Windows Setup /ensure runs before it changes anything
// names the profile and the rule, not only the generic text.
func TestStandaloneGatewayConfigCheckNamesTheSandboxProfile(t *testing.T) {
	path, dir := writeSandboxProfileConfig(t, "", "        allowed: false\n        required_for: [claudecode]\n")
	err := validateStandaloneGatewayConfig(path, dir, "")
	if err == nil || !strings.Contains(err.Error(), `at $.guardrail.profiles["contractors"]`) ||
		!strings.Contains(err.Error(), "allowed: false contradicts required_for [claudecode]") ||
		strings.Contains(err.Error(), "could not be compiled safely") {
		t.Fatalf("validateStandaloneGatewayConfig error = %v", err)
	}
}

func mustFailLoad(t *testing.T, path, dir string) error {
	t.Helper()
	if _, err := checkConfigV8Candidate(path, dir); err != nil {
		return err
	}
	t.Fatal("the candidate was accepted")
	return nil
}
