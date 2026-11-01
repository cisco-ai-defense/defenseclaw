// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

// GAP-0691 (#1226): the OpenShell settings whose values are lowercase words
// take any letter case: config validate and ensure (the schema check) and
// the loader accept `install: Prerequisite`, `driver: VM` or
// `foreign_sandboxes: Alert` and use the lowercase word. A value that is no
// such word is still refused.
func TestOpenShellEnumValuesTakeAnyCase(t *testing.T) {
	doc := "config_version: 9\ndeployment_mode: managed_enterprise\nenterprise:\n  profile: standalone\n" +
		"  openshell:\n    install: Prerequisite\n    driver: VM\n    driver_fallback: Docker\n" +
		"openshell:\n" +
		"  admin:\n    on_silence: Alert\n    foreign_sandboxes: Alert\n    min_profile: Strict\n" +
		"guardrail:\n  profiles:\n    eng:\n      mode: action\n      sandbox:\n        foreign_sandboxes: Alert\n        when_unavailable: Refuse\n"
	if err := ValidateV8SchemaBytes("admin.yaml", []byte(doc)); err != nil {
		t.Fatalf("mixed-case OpenShell values refused: %v", err)
	}
	bad := strings.Replace(doc, "when_unavailable: Refuse", "when_unavailable: Maybe", 1)
	if err := ValidateV8SchemaBytes("admin.yaml", []byte(bad)); err == nil {
		t.Fatal("a value that is no allowed word in any case was accepted")
	}

	floor := &OpenShellAdminConfig{ForeignSandboxes: "Alert", OnSilence: "STOP", WhenUnavailable: "Refuse", UserApprovals: "Session", DriverFallback: "None", MinProfile: "Strict"}
	if err := floor.validateAs("sandbox"); err != nil {
		t.Fatalf("loader refused a mixed-case floor: %v", err)
	}
	if floor.ForeignSandboxes != "alert" || floor.OnSilence != "stop" || floor.WhenUnavailable != "refuse" ||
		floor.UserApprovals != "session" || floor.DriverFallback != "none" || floor.MinProfile != "strict" {
		t.Fatalf("loader kept the letter case: %+v", floor)
	}
	o := &OpenShellConfig{}
	o.Admin.ForeignSandboxes = "Alert"
	if err := o.Validate(); err != nil || o.Admin.ForeignSandboxes != "alert" {
		t.Fatalf("loader: openshell.admin mixed case = %v, %q", err, o.Admin.ForeignSandboxes)
	}
	// The user's own settings keep their exact words (the shared
	// config_validation_cases corpus refuses `llm: Bedrock`).
	if err := (&OpenShellConfig{LLM: "Bedrock"}).Validate(); err == nil {
		t.Fatal("llm: Bedrock was accepted")
	}
}
