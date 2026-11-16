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

package connector

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// hookContractLockRegeneratedFields is the stable-field rule for
// hook_contract_lock.json (rel-1-0-3:GAP-0284). Every connector's entry goes
// through saveHookContractLockEntry, so the rule holds for each connector on
// every OS. Gateway boot (SaveFreshHookContractLockEntry) rewrites the lock
// on purpose: setup's restart readiness waits for a fresh updated_at. An
// upgrade, rollback or roll-forward also sets the writer's version. No other
// field may change on those writes, and the connector compatibility page must
// name exactly these fields so a restore audit knows what to leave out.
var hookContractLockRegeneratedFields = []string{"updated_at", "defenseclaw_version"}

func stableFieldRuleEntry(name, version string) HookContractLockEntry {
	return HookContractLockEntry{
		Connector:              name,
		RawAgentVersion:        "1.2.3",
		NormalizedAgentVersion: "1.2.3",
		ContractID:             name + "-hooks-v1",
		CompatibilityStatus:    "compatible",
		CompatibilityReason:    "reviewed range",
		HookScriptVersion:      "7",
		HookScriptDigests:      map[string]string{name + "-hook.sh": "sha256:" + strings.Repeat("a", 64)},
		Locations: ConnectorLocations{
			HookConfigPaths: []string{filepath.Join("home", name, "hooks.json")},
		},
		DefenseClawVersion: version,
		HookFailMode:       "open",
		RegistrationPosture: &HookRegistrationPosture{
			GuardrailMode:         "observe",
			HookCredentialBinding: "user:abc123",
		},
	}
}

func flattenLockJSON(t *testing.T, body []byte) map[string]string {
	t.Helper()
	var doc any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("lock is not JSON: %v", err)
	}
	out := map[string]string{}
	var walk func(prefix string, value any)
	walk = func(prefix string, value any) {
		switch typed := value.(type) {
		case map[string]any:
			for key, child := range typed {
				walk(prefix+"/"+key, child)
			}
		case []any:
			for index, child := range typed {
				walk(fmt.Sprintf("%s/%d", prefix, index), child)
			}
		default:
			raw, _ := json.Marshal(typed)
			out[prefix] = string(raw)
		}
	}
	walk("", doc)
	return out
}

// changedLockFields returns the leaf names (last path element) that differ.
func changedLockFields(t *testing.T, before, after []byte) []string {
	t.Helper()
	left, right := flattenLockJSON(t, before), flattenLockJSON(t, after)
	names := map[string]bool{}
	for path, value := range left {
		if other, ok := right[path]; !ok || other != value {
			names[path[strings.LastIndex(path, "/")+1:]] = true
		}
	}
	for path := range right {
		if _, ok := left[path]; !ok {
			names[path[strings.LastIndex(path, "/")+1:]] = true
		}
	}
	changed := make([]string, 0, len(names))
	for name := range names {
		changed = append(changed, name)
	}
	sort.Strings(changed)
	return changed
}

func readLockBytes(t *testing.T, dir string) []byte {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(dir, hookContractLockFile))
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestHookContractLockLifecycleRewritesOnlyRegeneratedFields(t *testing.T) {
	allowed := map[string]bool{}
	for _, name := range hookContractLockRegeneratedFields {
		allowed[name] = true
	}
	dir := testenv.PrivateTempDir(t)
	for _, name := range []string{"copilot", "devin"} {
		if err := SaveHookContractLockEntry(dir, stableFieldRuleEntry(name, "1.0.5")); err != nil {
			t.Fatal(err)
		}
	}
	setup := readLockBytes(t, dir)
	var setupLock hookContractLock
	if err := json.Unmarshal(setup, &setupLock); err != nil {
		t.Fatal(err)
	}

	// An ordinary save of unchanged evidence stays byte for byte.
	if err := SaveHookContractLockEntry(dir, stableFieldRuleEntry("copilot", "1.0.5")); err != nil {
		t.Fatal(err)
	}
	if got := readLockBytes(t, dir); !bytes.Equal(got, setup) {
		t.Fatalf("idempotent save rewrote the lock: %v", changedLockFields(t, setup, got))
	}

	steps := []struct {
		label   string
		version string
	}{
		{"gateway start", "1.0.5"},
		{"upgrade", "1.0.6"},
		{"rollback", "1.0.5"},
	}
	previous := setup
	for _, step := range steps {
		if err := SaveFreshHookContractLockEntry(dir, stableFieldRuleEntry("copilot", step.version)); err != nil {
			t.Fatalf("%s: %v", step.label, err)
		}
		current := readLockBytes(t, dir)
		changed := changedLockFields(t, previous, current)
		if !stringInSlice(changed, "updated_at") {
			t.Fatalf("%s did not refresh updated_at (setup readiness needs it): %v", step.label, changed)
		}
		for _, field := range changed {
			if !allowed[field] {
				t.Fatalf("%s changed %q, outside the documented stable-field rule %v", step.label, field, hookContractLockRegeneratedFields)
			}
		}
		var lock hookContractLock
		if err := json.Unmarshal(current, &lock); err != nil {
			t.Fatal(err)
		}
		if lock.Connectors["devin"].UpdatedAt != setupLock.Connectors["devin"].UpdatedAt {
			t.Fatalf("%s rewrote the peer connector's entry", step.label)
		}
		previous = current
	}
}

func TestHookContractLockStableFieldRuleIsDocumented(t *testing.T) {
	const heading = "### Fields the gateway rewrites"
	page := filepath.Join("..", "..", "..", "docs-site", "content", "docs", "connectors", "compatibility.mdx")
	body, err := os.ReadFile(page)
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	start := strings.Index(text, heading)
	if start < 0 {
		t.Fatalf("%s has no stable-field rule for hook_contract_lock.json (%q)", page, heading)
	}
	section := text[start+len(heading):]
	if end := strings.Index(section, "\n#"); end >= 0 {
		section = section[:end]
	}
	named := map[string]bool{}
	for index, part := range strings.Split(section, "`") {
		if index%2 == 1 {
			named[part] = true
		}
	}
	for _, field := range hookContractLockRegeneratedFields {
		if !named[field] {
			t.Errorf("stable-field rule does not name `%s`", field)
		}
	}
	for _, field := range []string{
		"raw_agent_version", "contract_id", "hook_script_digests", "hook_fail_mode", "registration_posture",
	} {
		if named[field] {
			t.Errorf("stable-field rule names `%s` as regenerated, but the gateway keeps it", field)
		}
	}
}
