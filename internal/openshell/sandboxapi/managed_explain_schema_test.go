// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package sandboxapi

import (
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v5"
)

func jsonTags(t *testing.T, v any) []string {
	t.Helper()
	typ := reflect.TypeOf(v)
	var tags []string
	for i := 0; i < typ.NumField(); i++ {
		tag := strings.Split(typ.Field(i).Tag.Get("json"), ",")[0]
		if tag != "" && tag != "-" {
			tags = append(tags, tag)
		}
	}
	sort.Strings(tags)
	return tags
}

func compileManagedExplainSchema(t *testing.T) (*jsonschema.Schema, map[string]any) {
	t.Helper()
	raw, err := os.ReadFile("testdata/managed_explain.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource("managed_explain.schema.json", strings.NewReader(string(raw))); err != nil {
		t.Fatal(err)
	}
	schema, err := c.Compile("managed_explain.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return schema, doc
}

// The managed explain JSON is a published contract (`policy explain --json`):
// the golden schema lists exactly the fields of ManagedExplain, so a field
// added to the struct without a schema change fails here, and a sample that
// uses every field validates.
func TestManagedExplainMatchesGoldenSchema(t *testing.T) {
	schema, doc := compileManagedExplainSchema(t)
	props := doc["properties"].(map[string]any)
	var schemaTags []string
	for name := range props {
		schemaTags = append(schemaTags, name)
	}
	sort.Strings(schemaTags)
	if got := jsonTags(t, ManagedExplain{}); !reflect.DeepEqual(got, schemaTags) {
		t.Fatalf("ManagedExplain fields %v\nschema properties %v\nupdate testdata/managed_explain.schema.json with the struct", got, schemaTags)
	}

	full := ManagedExplain{
		Profile: "contractors", Description: "Contractors", Match: "group", MatchedGroup: "CORP\\Contractors", Provisional: true,
		Allowed: true, RequiredFor: []string{"claudecode"}, WhenUnavailable: "refuse",
		HostRunGate: "exempt", EnrollmentExempt: true,
		AllowedHarnesses: []string{"claudecode"}, AllowedCredentials: []string{"none"},
		EgressAllowOnly: []string{"api.example.net"}, EgressBlock: []string{"bad.example"},
		UserApprovals: "session", AllowUnblock: true, ForeignSandboxes: "stop",
		MCPIncluded: []string{"docs"}, MCPBlocked: []ManagedMCP{{Name: "x", Reason: "organization_block"}},
		MCPProjectCount: 1, MCPProjectBlocked: true,
		WorkdirMode: "copy", AllowMount: false, AllowHostPorts: false, AllowYolo: true,
		OnSilence: "alert", MaxSilenceAfter: "10m", ProcessTree: true, DeleteStoppedAfter: "30d",
		Driver: "docker", DriverReason: "kvm_missing", DriverFallback: "docker",
		PolicyDigest: "sha256:abc", UpdatedAt: time.Unix(1_700_000_000, 0).UTC(), RequestAccess: "it@example.com",
		Sources: map[string]string{"egress_allow_only": ExplainSourceProfile},
		Posture: &ManagedPosture{
			Pack: "contractors", PackSource: "organization", PackDigest: "sha256:def",
			PackChain: []PackLink{{Name: "balanced", Builtin: true, Source: "builtin:balanced", Digest: "sha256:123"}},
			Profile:   "balanced", NetworkMode: "allowlist", Approvals: "manual",
			Settings:      []Setting{{Key: "pack", Value: "contractors", Source: "admin", Origin: "openshell.admin.required_pack"}},
			Violations:    []Violation{{Key: "pack", Source: "flag", Attempted: "open", Constraint: "openshell.admin.required_pack", Fatal: true, Admin: true, Message: "m"}},
			RepoTightened: []string{"network.mode"},
		},
	}
	for name, ex := range map[string]ManagedExplain{"full": full, "minimal": {Match: "none", PolicyDigest: "sha256:abc"}} {
		raw, err := json.Marshal(ex)
		if err != nil {
			t.Fatal(err)
		}
		var v any
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatal(err)
		}
		if err := schema.Validate(v); err != nil {
			t.Errorf("%s sample does not validate: %v\n%s", name, err, raw)
		}
	}

	var stray any
	_ = json.Unmarshal([]byte(`{"profile":"p","match":"none","allowed":true,"allow_unblock":true,"allow_mount":false,"allow_host_ports":false,"allow_yolo":false,"policy_digest":"d","user":"alice"}`), &stray)
	if schema.Validate(stray) == nil {
		t.Error("the schema accepts an unknown field; additionalProperties must be false")
	}
}

// Privacy rule: nothing in the managed explain or status can name another
// account; they carry no field for a user, uid, pid, principal, group list
// or any profile other than the caller's own.
func TestManagedViewsHaveNoFieldForOtherAccounts(t *testing.T) {
	banned := []string{"user", "user_name", "user_id", "uid", "pid", "principal", "upn", "sid", "groups", "profiles",
		"account", "accounts", "owner", "holder", "other_profile", "other_accounts"}
	for name, v := range map[string]any{"ManagedExplain": ManagedExplain{}, "ManagedStatus": ManagedStatus{}} {
		for _, tag := range jsonTags(t, v) {
			if slices.Contains(banned, tag) {
				t.Errorf("%s has field %q, which could describe another account", name, tag)
			}
		}
	}
}
