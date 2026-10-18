// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisestatus

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/contracttest"
)

const lifecycleSchema = "lifecycle-result.schema.json"

// The status v2 types and their closed schema definitions name the same
// members, required exactly where Go always renders them.
func TestStatusV2SchemaDescribesEveryMember(t *testing.T) {
	for pointer, typ := range map[string]reflect.Type{
		"#/$defs/connectorState":      reflect.TypeOf(ConnectorState{}),
		"#/$defs/connectorTargets":    reflect.TypeOf(ConnectorTargets{}),
		"#/$defs/openshellCapability": reflect.TypeOf(OpenShellCapability{}),
		"#/$defs/identityHealth":      reflect.TypeOf(IdentityHealth{}),
		"#/$defs/identitySource":      reflect.TypeOf(IdentitySource{}),
	} {
		contracttest.RequireMembers(t, lifecycleSchema+pointer, typ)
	}
}

// statusV2Result is a Linux status with every builder outcome of the blocks.
func statusV2Result(t *testing.T, platform string) *Result {
	t.Helper()
	r := New("status", "standalone", platform, "1.0.3")
	r.Installed, r.InstalledVersion = true, "1.0.3"
	r.Inspection = Inspection{Local: "active", AIDefense: "disabled"}
	block, _ := BuildConnectors(ConnectorInputs{
		ConfigLoaded: true, Enabled: []string{"codex", "amp", "hermes"}, Mode: func(string) string { return "observe" },
		ManifestRead: true, Manifest: []ConnectorInstall{{Connector: "codex", Version: "0.160.0", Enabled: true}, {Connector: "cursor", Enabled: true}},
		GuardianKnown: true, Guardian: []ConnectorTarget{{Connector: "codex", OK: true}, {Connector: "cursor"}, {Connector: "amp", Pending: true}},
		MachinePolicy: []string{"codex"},
	}, func(name string) string {
		if name == "codex" {
			return "closed"
		}
		return "open"
	})
	unknown, _ := BuildConnectors(ConnectorInputs{ManifestRead: true, Manifest: []ConnectorInstall{{Connector: "devin", Enabled: true}}}, nil)
	block["devin"] = unknown["devin"]
	r.Connectors = block
	r.Identity = ParseIdentityHealth([]byte(`{"identity":{"sources":[{"source":"sssd","directory":"active_directory","last_ok_age_seconds":3}],"failing":1,"stale":1}}`))
	if platform == "windows" {
		r.OpenShell = OpenShellUnsupportedCapability()
	} else {
		installed := true
		r.OpenShell = &OpenShellCapability{Enabled: true, Install: "prerequisite", Installed: &installed, Version: "0.0.36", Driver: "auto",
			DriverAvailable: OpenShellDriverDocker, ReasonCode: "openshell_driver_fallback"}
	}
	r.Finish(platform, 0)
	return r
}

func TestStatusV2ResultsValidateAndRoundTrip(t *testing.T) {
	schemas := contracttest.Compile(t)
	results := map[string]*Result{"linux": statusV2Result(t, "linux"), "windows": statusV2Result(t, "windows")}
	disabled := statusV2Result(t, "darwin")
	disabled.OpenShell = OpenShellDisabledCapability()
	disabled.Identity = IdentityGatewayNotReady()
	results["darwin disabled"] = disabled
	idle := statusV2Result(t, "linux")
	idle.Identity = ParseIdentityHealth([]byte(`{"identity":{"sources":[],"failing":0,"stale":0}}`))
	idle.Connectors = nil
	results["idle"] = idle
	older := statusV2Result(t, "linux")
	older.Identity = ParseIdentityHealth([]byte(`{"ok":true}`))
	results["older gateway"] = older
	for name, r := range results {
		document, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		decoded := schemas.Validate(t, lifecycleSchema, document)
		var again Result
		if err := json.Unmarshal(document, &again); err != nil || !reflect.DeepEqual(again.Connectors, r.Connectors) ||
			!reflect.DeepEqual(again.OpenShell, r.OpenShell) || !reflect.DeepEqual(again.Identity, r.Identity) {
			t.Fatalf("%s: blocks did not round-trip (%v):\n%s", name, err, document)
		}
		if _, ok := decoded["openshell"]; !ok {
			t.Fatalf("%s: no openshell block:\n%s", name, document)
		}
	}
}

// A not_root result checked nothing, so it leaves the blocks out like every
// other field that reports the deployment.
func TestStatusV2BlocksLeftOutOfNotRoot(t *testing.T) {
	r := statusV2Result(t, "linux")
	r.AddError("not_root", "run this command as root")
	r.Finish("linux", 0)
	document, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	decoded := contracttest.Compile(t).Validate(t, lifecycleSchema, document)
	for _, name := range []string{"connectors", "openshell", "identity"} {
		if _, ok := decoded[name]; ok {
			t.Fatalf("not_root result carries %s:\n%s", name, document)
		}
	}
}
