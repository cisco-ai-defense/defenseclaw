// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package packs

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestResolvedRunKeepsIndependentInputsAndPrivateAuthority(t *testing.T) {
	allowed := false
	cfg := &config.Config{OpenShell: config.OpenShellConfig{
		Enabled: true, LLM: config.OpenShellLLMNone, Pack: "balanced",
		Egress: config.OpenShellEgressConfig{Allow: []string{"operator.example"}},
		Admin:  config.OpenShellAdminConfig{AllowYolo: &allowed, EgressBlock: []string{"blocked.example"}},
	}}
	flags := Flags{Harness: "claudecode", Unmask: []string{"template.txt"},
		RepoPolicy: &RepoPolicy{Digest: "sha256:" + strings.Repeat("b", 64),
			Masks: []string{"repo-secret"}, Content: []byte("fixed-public-policy\n")}}
	run, _, err := ResolveRun(cfg, flags)
	if err != nil {
		t.Fatal(err)
	}
	firstConfig, firstFlags, first, _, err := run.ExecutionInputs()
	if err != nil {
		t.Fatal(err)
	}
	before, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	// Change caller inputs and a complete copy-out, including fields absent
	// from JSON. Neither is allowed to rewrite the capsule's authority.
	cfg.OpenShell.Egress.Allow[0] = "changed.example"
	allowed = true
	flags.Unmask[0] = "changed"
	flags.RepoPolicy.Masks[0] = "changed"
	flags.RepoPolicy.Content[0] = '!'
	firstConfig.OpenShell.Admin.EgressBlock[0] = "changed.example"
	firstFlags.Unmask[0] = "changed"
	firstFlags.RepoPolicy.Content[0] = '!'
	mutateRunExported(reflect.ValueOf(first))
	first.admin.EgressBlock[0] = "changed.example"
	*first.admin.AllowYolo = true
	first.curatedAllow[0] = "changed.example"
	first.hostNames = append(first.hostNames[:0], "changed-host.example")
	first.reservedPorts[1] = "changed"
	first.settings["profile"] = Setting{Value: "changed"}

	ownedConfig, ownedFlags, second, _, err := run.ExecutionInputs()
	if err != nil {
		t.Fatal(err)
	}
	after, err := json.Marshal(second)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("a caller input or copy-out changed the captured run", err)
	}
	if ownedConfig.OpenShell.Admin.EgressBlock[0] != "blocked.example" ||
		ownedFlags.Unmask[0] != "template.txt" || ownedFlags.RepoPolicy.Content[0] != 'f' {
		t.Fatal("config or flags aliased an earlier input")
	}
	if second.Allow(Action{Kind: ActionYolo}) == nil || second.DecideEgress("blocked.example", 443).Allowed {
		t.Fatal("private administrative authority was lost")
	}
	broker, err := second.EgressOptions(nil)
	if err != nil || slices.Contains(broker.Allow, "registry.npmjs.org") ||
		!slices.Contains(broker.Allow, "operator.example") || !second.DecideEgress("registry.npmjs.org", 443).Allowed {
		t.Fatal("curated feed entries became operator grants", err)
	}
	if second.decider != run.effective.decider {
		t.Fatal("copy rebuilt the existing immutable evaluator")
	}
}

// Mutate all exported leaves, including nested pack/repository collections, so
// newly added mutable public fields also exercise the copy-out boundary.
func mutateRunExported(value reflect.Value) {
	switch value.Kind() {
	case reflect.Pointer:
		if !value.IsNil() {
			mutateRunExported(value.Elem())
		}
	case reflect.Struct:
		for i := range value.NumField() {
			if value.Type().Field(i).PkgPath == "" {
				mutateRunExported(value.Field(i))
			}
		}
	case reflect.Slice:
		for i := range value.Len() {
			mutateRunExported(value.Index(i))
		}
	case reflect.String:
		if value.CanSet() {
			value.SetString("changed")
		}
	case reflect.Bool:
		if value.CanSet() {
			value.SetBool(!value.Bool())
		}
	case reflect.Int, reflect.Int64:
		if value.CanSet() {
			value.SetInt(123)
		}
	case reflect.Uint8:
		if value.CanSet() {
			value.SetUint('!')
		}
	}
}

func TestResolvedAuthorityCopiesRequiredPackAndPrivateCollections(t *testing.T) {
	cfg := &config.Config{DeploymentMode: "managed_enterprise", OpenShell: config.OpenShellConfig{
		Enabled: true, Pack: "strict", LLM: config.OpenShellLLMNone,
		Admin: config.OpenShellAdminConfig{RequiredPack: "balanced"},
	}}
	run, _, err := ResolveRun(cfg, Flags{Harness: "claudecode"})
	if err != nil {
		t.Fatal(err)
	}
	e := run.effective
	if e.requiredLoaded == nil || e.requiredLoaded == e.Pack {
		t.Fatal("test must cover a distinct required pack")
	}
	// These synthetic private facts are deliberately absent from the wire
	// form, so a JSON-based clone would silently discard this authority.
	e.requiredLoaded.builtinAllow = []string{"fixed-required.example"}
	e.Pack.builtinAllow = []string{"fixed-selected.example"}
	e.firewallBlock = []string{"fixed-firewall.example"}
	e.policySources = []string{"fixed-protected-source"}
	e.hostNames = []string{"fixed-host.example"}
	e.curatedAllow = []string{"fixed-curated.example"}
	clone, err := e.cloneAuthority()
	if err != nil {
		t.Fatal(err)
	}
	e.requiredLoaded.builtinAllow[0], e.Pack.builtinAllow[0] = "changed", "changed"
	e.firewallBlock[0], e.policySources[0], e.hostNames[0], e.curatedAllow[0] = "changed", "changed", "changed", "changed"
	if clone.RequiredPackContent().builtinAllow[0] != "fixed-required.example" ||
		clone.Pack.builtinAllow[0] != "fixed-selected.example" ||
		clone.firewallBlock[0] != "fixed-firewall.example" || clone.PolicySources()[0] != "fixed-protected-source" ||
		clone.hostNames[0] != "fixed-host.example" || clone.curatedAllow[0] != "fixed-curated.example" {
		t.Fatal("private resolver state was dropped or aliased")
	}
	e.requiredLoaded = e.Pack
	clone, err = e.cloneAuthority()
	if err != nil || clone.requiredLoaded != clone.Pack || clone.Pack == e.Pack {
		t.Fatal("required/selected pack identity was not preserved", err)
	}
}

func TestResolvedRunRejectsWireViewsZeroValuesAndChangedPolicy(t *testing.T) {
	run, _, err := ResolveRun(&config.Config{OpenShell: config.OpenShellConfig{Enabled: true}}, Flags{Harness: "claudecode"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := json.Marshal(run); err == nil {
		t.Fatal("host resolution was serialized")
	}
	var wire ResolvedRun
	if json.Unmarshal([]byte(`{}`), &wire) == nil {
		t.Fatal("wire input constructed a host resolution")
	}
	for _, missing := range []*ResolvedRun{nil, {}} {
		if _, _, _, _, err := missing.ExecutionInputs(); err == nil {
			t.Fatal("empty host resolution acquired execution inputs")
		}
	}
	data, err := json.Marshal(run.effective)
	if err != nil {
		t.Fatal(err)
	}
	var view Effective
	if json.Unmarshal(data, &view) != nil {
		t.Fatal("test inspection view did not decode")
	}
	for _, invalid := range []*Effective{nil, {}, &view} {
		if _, err := invalid.cloneAuthority(); err == nil {
			t.Fatal("incomplete/view state acquired runtime authority")
		}
	}
	run.effective.Yolo = !run.effective.Yolo
	if _, _, _, _, err := run.ExecutionInputs(); err == nil {
		t.Fatal("mutated policy retained the earlier digest's authority")
	}
}

func TestResolvedRunOwnsManagedUserPackBytesAndSubject(t *testing.T) {
	root := t.TempDir()
	subject := Subject{UID: 1001, Home: filepath.Join(root, "fixed-account")}
	pack := []byte("version: 1\nname: fixed-user\nextends: balanced\n")
	cfg := &config.Config{DeploymentMode: "managed_enterprise", OpenShell: config.OpenShellConfig{
		Enabled: true, LLM: config.OpenShellLLMNone, PackDir: filepath.Join(root, "fixed-admin-packs"),
	}}
	flags := Flags{Harness: "claudecode", Subject: &subject,
		Pack: filepath.Join(root, "unread-user-pack.yaml"), UserPack: pack}
	run, _, err := ResolveRun(cfg, flags)
	if err != nil {
		t.Fatal(err)
	}
	_, first, _, _, err := run.ExecutionInputs()
	if err != nil {
		t.Fatal(err)
	}
	wantPack := slices.Clone(pack)
	pack[0], first.UserPack[0] = '!', '?'
	subject.Home, first.Subject.Home = "changed-caller", "changed-copy"
	_, second, effective, _, err := run.ExecutionInputs()
	if err != nil || !bytes.Equal(second.UserPack, wantPack) || second.Subject.Home != filepath.Join(root, "fixed-account") ||
		effective.Pack.Name != "fixed-user" {
		t.Fatal("managed user pack bytes or subject aliased another owner", err)
	}
}
