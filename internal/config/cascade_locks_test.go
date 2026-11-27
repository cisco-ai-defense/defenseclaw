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
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// GAP-0580: admin.locked is enforced at runtime in every overlay. A narrower
// scope (connector, legacy hook mode, application_protection, profile,
// profile connector; identity profiles and meets are these profiles) that
// sets a locked key does not decide: the administrator's value applies, the
// violation is named (Ignored), the top-level cascade stays (no fallback),
// and every writer still refuses the document (CascadeCandidateError).
const lockedAdminTop = "guardrail:\n  enabled: true\n  mode: action\n  block_at: HIGH\n  alert_at: MEDIUM\n" +
	"  cascade:\n    unknown: block\n    admin:\n      critical_floor: block\n" +
	"      locked: [mode, block_at, alert_at, hilt, unknown, judge, lanes]\n"

func TestCascadeLockedOverlaysDoNotDecide(t *testing.T) {
	body := lockedAdminTop +
		"  connectors:\n    codex:\n      mode: observe\n      block_at: CRITICAL\n      cascade:\n        unknown: alert\n        judge:\n          max_action: log\n" +
		"  profiles:\n    contractors:\n      mode: observe\n      block_at: CRITICAL\n      alert_at: HIGH\n" +
		"      cascade:\n        unknown: alert\n        lanes:\n          test_live: \"off\"\n" +
		"      connectors:\n        claudecode:\n          mode: observe\n          block_at: CRITICAL\n          cascade:\n            judge:\n              no_verdict: rules\n" +
		"  profile_assignments:\n    - {profile: contractors, match: {groups: [contractors-group]}}\n" +
		"claude_code:\n  mode: observe\n"
	cfg := loadCascadeDoc(t, body)
	if inv := cfg.Guardrail.Cascade.Invalid(); inv != nil {
		t.Fatalf("a narrower-scope lock violation made the whole cascade fall back: %s", inv.Message())
	}
	if CascadeCandidateError(cfg) == nil {
		t.Fatal("writers would accept a document that sets locked keys below the top level")
	}
	ignored := map[string]bool{}
	for _, ig := range cfg.Guardrail.Cascade.Ignored() {
		ignored[ig.Path] = true
		if !strings.Contains(ig.Reason, "locked by guardrail.cascade.admin.locked") {
			t.Fatalf("%s: reason %q", ig.Path, ig.Reason)
		}
	}
	for _, path := range []string{
		"guardrail.connectors.codex.mode", "guardrail.connectors.codex.block_at",
		"guardrail.connectors.codex.cascade.unknown", "guardrail.connectors.codex.cascade.judge.max_action",
		"guardrail.profiles.contractors.mode", "guardrail.profiles.contractors.block_at", "guardrail.profiles.contractors.alert_at",
		"guardrail.profiles.contractors.cascade.unknown", "guardrail.profiles.contractors.cascade.lanes.test_live",
		"guardrail.profiles.contractors.connectors.claudecode.mode", "guardrail.profiles.contractors.connectors.claudecode.block_at",
		"guardrail.profiles.contractors.connectors.claudecode.cascade.judge.no_verdict",
		"claude_code.mode",
	} {
		if !ignored[path] {
			t.Errorf("%s not reported as ignored (got %v)", path, cfg.Guardrail.Cascade.Ignored())
		}
	}
	check := func(scope string, c *Config, connector string) {
		t.Helper()
		e := c.ResolveCascade(connector)
		if e.Unknown != CascadeBlock || e.CriticalFloor != CascadeBlock || e.JudgeMaxAction != CascadeBlock || e.JudgeNoVerdict != CascadeFromRules {
			t.Errorf("%s/%s: the admin cascade does not decide: %+v", scope, connector, e)
		}
		if e.LaneMode("test_live") != CascadeLaneShadow {
			t.Errorf("%s/%s: locked lane = %s", scope, connector, e.LaneMode("test_live"))
		}
		if mode := c.HookModeForConnector(connector); mode != "action" {
			t.Errorf("%s/%s: locked mode = %s", scope, connector, mode)
		}
		if block, alert := c.Guardrail.EffectiveBlockAt(connector), c.Guardrail.EffectiveAlertAt(connector); block != "HIGH" || alert != "MEDIUM" {
			t.Errorf("%s/%s: locked levels block_at=%s alert_at=%s", scope, connector, block, alert)
		}
	}
	for _, connector := range []string{"", "codex", "claudecode"} {
		check("base", cfg, connector)
	}
	derived, err := cfg.DerivedForProfile("contractors")
	if err != nil {
		t.Fatal(err)
	}
	for _, connector := range []string{"", "codex", "claudecode"} {
		check("profile", derived, connector)
	}
	// The identity path: every profile the gateway derives at load and reload.
	all, err := cfg.DeriveGuardrailProfiles()
	if err != nil {
		t.Fatal(err)
	}
	for name, p := range all {
		for _, connector := range []string{"codex", "claudecode"} {
			check("identity "+name, p.Config, connector)
		}
	}
}

// A lock violation with a last-known-good copy saved neither falls back nor
// replaces the administrator's cascade (the reviewer's check 4).
func TestCascadeLockViolationKeepsTheAdminCascadeWithALastGood(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("DEFENSECLAW_HOME", filepath.Join(home, ".defenseclaw"))
	state := filepath.Join(home, "state")
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	good := loadCascadeDocIn(t, state, lockedAdminTop)
	if good.Guardrail.Cascade.Invalid() != nil {
		t.Fatal(good.Guardrail.Cascade.Invalid().Message())
	}
	if err := WriteCascadeLastGood(good); err != nil {
		t.Fatal(err)
	}
	bad := loadCascadeDocIn(t, state, lockedAdminTop+"  profiles:\n    p:\n      block_at: CRITICAL\n      cascade:\n        unknown: alert\n")
	if inv := bad.Guardrail.Cascade.Invalid(); inv != nil {
		t.Fatalf("fallback %s for a profile's lock violation", inv.Fallback)
	}
	d, err := bad.DerivedForProfile("p")
	if err != nil {
		t.Fatal(err)
	}
	if e := d.ResolveCascade("codex"); e.Unknown != CascadeBlock || e.CriticalFloor != CascadeBlock || len(e.Locked) == 0 {
		t.Fatalf("admin cascade lost: %+v", e)
	}
	if got := d.Guardrail.EffectiveBlockAt("codex"); got != "HIGH" {
		t.Fatalf("locked block_at in the profile still decides: %s", got)
	}
}

// An invalid connector or profile cascade (a writable scope) is ignored on
// its own: the top-level cascade and the other scopes stay, no fallback.
func TestCascadeInvalidScopeIsIgnoredNotFallenBack(t *testing.T) {
	body := "guardrail:\n  enabled: true\n  cascade:\n    unknown: block\n    admin:\n      critical_floor: block\n" +
		"  connectors:\n    codex:\n      cascade:\n        unknown: allow\n    cursor:\n      cascade:\n        unknown: confirm\n" +
		"  profiles:\n    p:\n      cascade:\n        lanes:\n          nope: on\n"
	cfg := loadCascadeDoc(t, body)
	if inv := cfg.Guardrail.Cascade.Invalid(); inv != nil {
		t.Fatalf("an invalid scope cascade made the top level fall back: %s", inv.Message())
	}
	if CascadeCandidateError(cfg) == nil {
		t.Fatal("writers would accept an invalid scope cascade")
	}
	var paths []string
	for _, ig := range cfg.Guardrail.Cascade.Ignored() {
		paths = append(paths, ig.Path)
	}
	if !slices.Equal(paths, []string{"guardrail.connectors.codex.cascade", "guardrail.profiles.p.cascade"}) {
		t.Fatalf("ignored = %v", cfg.Guardrail.Cascade.Ignored())
	}
	if e := cfg.ResolveCascade("codex"); e.Unknown != CascadeBlock || e.CriticalFloor != CascadeBlock {
		t.Fatalf("codex: %+v", e)
	}
	if e := cfg.ResolveCascade("cursor"); e.Unknown != CascadeConfirm {
		t.Fatalf("a valid sibling scope was dropped: %+v", e)
	}
	d, err := cfg.DerivedForProfile("p")
	if err != nil {
		t.Fatal(err)
	}
	if e := d.ResolveCascade("codex"); e.Unknown != CascadeBlock {
		t.Fatalf("profile: %+v", e)
	}
	if msg := cfg.Guardrail.Cascade.IgnoredMessage(); !strings.Contains(msg, "guardrail.connectors.codex.cascade") {
		t.Fatalf("message = %q", msg)
	}
}

// The reviewer's four invalid cascades (GAP-0581) are refused by the one
// writer check, whatever the loader does with them.
func TestCascadeReviewerCandidatesRefused(t *testing.T) {
	for name, body := range map[string]string{
		"lock violation (profile block_at)":  "guardrail:\n  cascade:\n    admin:\n      locked: [block_at]\n  profiles:\n    p:\n      block_at: CRITICAL\n",
		"lock violation (connector unknown)": "guardrail:\n  cascade:\n    admin:\n      locked: [unknown]\n  connectors:\n    codex:\n      cascade:\n        unknown: block\n",
		"unknown allow":                      "guardrail:\n  cascade:\n    unknown: allow\n",
		"shadow-only lane on":                "guardrail:\n  cascade:\n    lanes:\n      secret_flow: on\n",
	} {
		t.Run(name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("DEFENSECLAW_HOME", filepath.Join(home, ".defenseclaw"))
			raw := []byte("config_version: 9\ndata_dir: " + filepath.Join(home, "state") + "\n" + body)
			if err := ValidateCandidate(filepath.Join(home, "config.yaml"), raw); err == nil || !strings.Contains(err.Error(), "guardrail") {
				t.Fatalf("ValidateCandidate = %v", err)
			}
		})
	}
}

// GAP-0584: the WEAKER list names every scope and key the fallback drops.
func TestCascadeWeakerNamesEveryScope(t *testing.T) {
	path, digest := writeModule(t, t.TempDir(), "package defenseclaw.cascade\nimport rego.v1\n\ndecisions contains {\"action\": \"alert\"} if { false }\n")
	body := "guardrail:\n  enabled: true\n  cascade:\n    unknown: block\n    judge:\n      no_verdict: unknown\n    system_one:\n      on_unsure: confirm\n" +
		"    lanes:\n      test_live: \"on\"\n    admin:\n      critical_floor: block\n      locked: [nope]\n" +
		"    policy:\n      module: {path: " + path + ", digest: \"" + digest + "\"}\n" +
		"  connectors:\n    codex:\n      cascade:\n        unknown: confirm\n        lanes:\n          test_live: \"on\"\n" +
		"  profiles:\n    p:\n      cascade:\n        judge:\n          no_verdict: unknown\n" +
		"      connectors:\n        cursor:\n          cascade:\n            unknown: block\n"
	cfg := loadCascadeDoc(t, body)
	inv := cfg.Guardrail.Cascade.Invalid()
	if inv == nil || inv.Fallback != CascadeFallbackPack {
		t.Fatalf("invalid = %+v", inv)
	}
	weaker := strings.Join(inv.Weaker, "\n")
	for _, want := range []string{
		"guardrail.cascade.unknown block", "guardrail.cascade.judge.no_verdict unknown", "guardrail.cascade.lanes.test_live on",
		"admin.critical_floor block", "the Rego policy you configured is not running",
		"guardrail.connectors.codex.cascade.unknown confirm", "guardrail.connectors.codex.cascade.lanes.test_live on",
		"guardrail.profiles.p.cascade.judge.no_verdict unknown",
		"guardrail.profiles.p.connectors.cursor.cascade.unknown block",
	} {
		if !strings.Contains(weaker, want) {
			t.Errorf("WEAKER misses %q:\n%s", want, weaker)
		}
	}
}

// GAP-0580: admin.locked [mode] decides for a connector under
// application_protection (automatic protection of a connector nobody set
// up by hand) too. The overlay sets observe, sets action, or sets no mode:
// the locked top-level mode applies in each, never the observe default of
// an overlay without a mode. The same for a profile and for the identity
// profiles derived from it.
func TestCascadeLockedModeUnderApplicationProtection(t *testing.T) {
	for _, top := range []string{"action", "observe"} {
		head := strings.Replace(lockedAdminTop, "mode: action", "mode: "+top, 1)
		for name, ap := range map[string]string{
			"ap-global-observe":    "application_protection:\n  enabled: true\n  guardrail:\n    mode: observe\n",
			"ap-global-action":     "application_protection:\n  enabled: true\n  guardrail:\n    mode: action\n",
			"ap-connector-observe": "application_protection:\n  enabled: true\n  connectors:\n    cursor:\n      guardrail:\n        mode: observe\n",
			"ap-connector-action":  "application_protection:\n  enabled: true\n  connectors:\n    cursor:\n      guardrail:\n        mode: action\n",
			"ap-no-mode":           "application_protection:\n  enabled: true\n",
		} {
			cfg := loadCascadeDoc(t, head+ap)
			for _, c := range []string{"cursor", "codex", "claudecode"} {
				if got := cfg.HookModeForConnector(c); got != top {
					t.Errorf("top %s, %s/%s: hook mode %s, want the locked top-level %s", top, name, c, got, top)
				}
				if got := cfg.EffectiveGuardrailModeForConnector(c); got != top {
					t.Errorf("top %s, %s/%s: effective mode %s, want %s", top, name, c, got, top)
				}
			}
			profile := head + "  profiles:\n    contractors:\n      mode: observe\n      connectors:\n        codex:\n          mode: observe\n" + ap
			pcfg := loadCascadeDoc(t, profile)
			d, err := pcfg.DerivedForProfile("contractors")
			if err != nil {
				t.Fatal(err)
			}
			for _, c := range []string{"cursor", "codex", "claudecode"} {
				if got := d.HookModeForConnector(c); got != top {
					t.Errorf("top %s, %s, profile contractors/%s: hook mode %s, want %s", top, name, c, got, top)
				}
			}
		}
	}
	// Without the lock the overlay decides as before (observe when it sets
	// no mode).
	unlocked := strings.Replace(lockedAdminTop, "locked: [mode, ", "locked: [", 1)
	cfg := loadCascadeDoc(t, unlocked+"application_protection:\n  enabled: true\n")
	if got := cfg.HookModeForConnector("cursor"); got != "observe" {
		t.Errorf("unlocked, overlay with no mode: hook mode %s, want observe", got)
	}
	cfg = loadCascadeDoc(t, unlocked+"application_protection:\n  enabled: true\n  guardrail:\n    mode: action\n")
	if got := cfg.HookModeForConnector("cursor"); got != "action" {
		t.Errorf("unlocked, overlay action: hook mode %s, want action", got)
	}
}

// GAP-0686: the v8 schema refuses on for a lane that ships shadow-only, as
// rel's lane enum did, and every shipped shadow-only lane has that enum; the
// effects lane takes on since DET111.
func TestCascadeSchemaRefusesOnForShadowOnlyLanes(t *testing.T) {
	raw, err := os.ReadFile("../../schemas/config/v8/defenseclaw-config.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Defs map[string]json.RawMessage `json:"$defs"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	var lanes struct {
		Properties map[string]struct {
			Ref string `json:"$ref"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(doc.Defs["cascadeLanes"], &lanes); err != nil {
		t.Fatal(err)
	}
	props := lanes.Properties
	for _, lane := range CascadeLanes() {
		if lane.ShadowOnly == "" || strings.HasPrefix(lane.Name, "test_") {
			continue
		}
		if props[lane.Name].Ref != "#/$defs/cascadeLane" {
			t.Errorf("shadow-only lane %s has no off|shadow enum in the schema", lane.Name)
		}
	}
	dataDir := t.TempDir()
	for _, tc := range []struct {
		lanes string
		ok    bool
	}{
		{"effects: \"on\"", true}, {"secret_flow: \"on\"", false}, {"effects: live", false},
		{"effects: \"off\"", true}, {"secret_flow: shadow", true},
	} {
		body := []byte("config_version: 9\ndata_dir: " + dataDir + "\nguardrail:\n  cascade:\n    lanes:\n      " + tc.lanes + "\n")
		_, err := ParseCompileObservabilityV8("config.yaml", body, ObservabilityV8CompileOptions{DefaultDataDir: dataDir})
		if (err == nil) != tc.ok {
			t.Errorf("lanes %s: schema err=%v, want ok=%v", tc.lanes, err, tc.ok)
		}
	}
}
