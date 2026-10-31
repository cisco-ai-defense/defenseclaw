// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"reflect"
	"strings"
	"testing"
)

// The managed sandbox floor keys decode from openshell.admin and from a
// profile's sandbox section, and the schema accepts them.
func TestSandboxFloorKeysDecode(t *testing.T) {
	const floor = `
      allowed: true
      required_for: [claudecode, codex]
      when_unavailable: alert
      user_approvals: session
      allowed_credentials: [bedrock]
      on_silence: stop
      max_silence_after: 5m
      process_tree: true
      foreign_sandboxes: alert
      allow_upstream_telemetry: false
      delete_stopped_after: 14d
      request_access: it-help@example.com
`
	raw := "config_version: 9\nopenshell:\n  admin:" + strings.ReplaceAll(floor, "\n      ", "\n    ") +
		"guardrail:\n  profiles:\n    contractors:\n      sandbox:" + strings.ReplaceAll(floor, "\n      ", "\n        ") +
		"observability: {}\n"
	if err := ValidateV8SchemaBytes("config.yaml", []byte(raw)); err != nil {
		t.Fatalf("schema: %v", err)
	}
	cfg, err := loadConfigSource("config.yaml", []byte(raw), false, false)
	if err != nil {
		t.Fatal(err)
	}
	f, tr := false, true
	want := OpenShellAdminConfig{
		Allowed: &tr, RequiredFor: []string{"claudecode", "codex"}, WhenUnavailable: OpenShellWhenUnavailableAlert,
		UserApprovals: OpenShellUserApprovalsSession, AllowedCredentials: []string{"bedrock"},
		OnSilence: OpenShellOnSilenceStop, MaxSilenceAfter: "5m", ProcessTree: &tr,
		ForeignSandboxes: OpenShellForeignSandboxesAlert, AllowUpstreamTelemetry: &f,
		DeleteStoppedAfter: "14d", RequestAccess: "it-help@example.com",
	}
	if !reflect.DeepEqual(cfg.OpenShell.Admin, want) {
		t.Errorf("openshell.admin = %+v", cfg.OpenShell.Admin)
	}
	got := cfg.Guardrail.Profiles["contractors"].Sandbox
	if got == nil || !reflect.DeepEqual(*got, want) {
		t.Errorf("profile sandbox = %+v", got)
	}
}

// An explicit empty intersect list is refused by the schema (unset means
// no constraint).
func TestSandboxFloorSchemaRefusesEmptyLists(t *testing.T) {
	for _, key := range []string{"required_for", "allowed_credentials", "allowed_harnesses", "egress_allow_only"} {
		raw := "config_version: 9\nopenshell:\n  admin:\n    " + key + ": []\nobservability: {}\n"
		if err := ValidateV8SchemaBytes("config.yaml", []byte(raw)); err == nil {
			t.Errorf("%s: [] accepted", key)
		}
	}
	for _, bad := range []string{
		"when_unavailable: sometimes", "user_approvals: always", "on_silence: pause",
		"foreign_sandboxes: keep", "max_silence_after: 5 minutes", "delete_stopped_after: 2w",
		"allowed_credentials: [Bedrock]", "request_access: " + strings.Repeat("x", 513),
	} {
		raw := "config_version: 9\nopenshell:\n  admin:\n    " + bad + "\nobservability: {}\n"
		if err := ValidateV8SchemaBytes("config.yaml", []byte(raw)); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

// Every openshell.admin key, set alone, counts as a configured constraint.
func TestOpenShellAdminIsZeroCoversEveryField(t *testing.T) {
	typ := reflect.TypeOf(OpenShellAdminConfig{})
	for i := 0; i < typ.NumField(); i++ {
		var a OpenShellAdminConfig
		f := reflect.ValueOf(&a).Elem().Field(i)
		switch f.Kind() {
		case reflect.String:
			f.SetString("x")
		case reflect.Bool:
			f.SetBool(true)
		case reflect.Pointer:
			f.Set(reflect.New(f.Type().Elem()))
		case reflect.Slice:
			f.Set(reflect.MakeSlice(f.Type(), 1, 1))
		case reflect.Struct:
			f.Field(0).SetString("x")
		default:
			t.Fatalf("%s: unhandled kind %s", typ.Field(i).Name, f.Kind())
		}
		if a.IsZero() {
			t.Errorf("IsZero ignores openshell.admin %s", typ.Field(i).Name)
		}
	}
}

func TestEnterpriseOpenShellSchemaAndEmptiness(t *testing.T) {
	ok := "config_version: 9\nenterprise:\n  openshell: {install: setup, driver: vm, version: 0.1.3, gateway_port: 17671, e2fsprogs_dir: /opt/e2fsprogs}\nobservability: {}\n"
	if err := ValidateV8SchemaBytes("config.yaml", []byte(ok)); err != nil {
		t.Fatalf("schema: %v", err)
	}
	for _, bad := range []string{"{install: bundled}", "{driver: kvm}", "{gateway_port: 80}", "{version: latest}", "{unknown: 1}"} {
		raw := "config_version: 9\nenterprise:\n  openshell: " + bad + "\nobservability: {}\n"
		if err := ValidateV8SchemaBytes("config.yaml", []byte(raw)); err == nil {
			t.Errorf("enterprise.openshell %s accepted", bad)
		}
	}
	if enterpriseBlockEmpty(EnterpriseConfig{OpenShell: EnterpriseOpenShellConfig{Install: EnterpriseOpenShellInstallSetup}}) {
		t.Fatal("an enterprise block with only openshell counts as empty")
	}
	// Outside managed_enterprise an enterprise block is refused, openshell
	// included.
	if _, err := loadConfigSource("config.yaml", []byte(ok), false, false); err == nil {
		t.Fatal("enterprise.openshell accepted in a non-managed config")
	}
}

// gateway_port is the administrator's enterprise.openshell key. A per-user
// openshell.gateway_port is not a setting: the per-user OpenShell gateway
// listens on 17670, so the schema refuses it (rel-1-0-6:GAP-0094).
func TestPerUserOpenShellHasNoGatewayPortKey(t *testing.T) {
	raw := "config_version: 9\nopenshell:\n  gateway_port: 17691\nobservability: {}\n"
	if err := ValidateV8SchemaBytes("config.yaml", []byte(raw)); err == nil {
		t.Fatal("openshell.gateway_port accepted")
	}
	ok := "config_version: 9\nenterprise:\n  openshell: {gateway_port: 17691}\nobservability: {}\n"
	if err := ValidateV8SchemaBytes("config.yaml", []byte(ok)); err != nil {
		t.Fatalf("enterprise.openshell.gateway_port: %v", err)
	}
}
