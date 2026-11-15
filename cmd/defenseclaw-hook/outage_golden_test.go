// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookcli"
)

// The gateway-outage mode of a per-user hook comes from config.yaml, read
// with the checks the binary links: a pinned custom rule pack sets the tier
// only where the rule loader is linked, and a sandbox profile floor is
// refused only where the pack check is. The slim main decides every config
// shape as the full-CLI main did (testdata/outage-golden.json, recorded from
// rel/1.0.10 9efb4f1799; rel-1-0-10:GAP-0603). This test binary links what
// the main links (TestOutageGoldenSeesTheLinkSetOfTheMain), so a check the
// main stops linking fails here.
func TestOutageModeGoldenMatchesTheFullCLIHook(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("testdata", "outage-golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	var want []outageResult
	if err := json.Unmarshal(body, &want); err != nil {
		t.Fatal(err)
	}
	// The machine signals are not what this golden compares: a test host
	// that is itself managed answers closed for every shape.
	// Nor is the account the test runs as: its own ~/.defenseclaw (an
	// install lock, a config) and the deployment pin of its environment.
	secure, standalone, uncertain, descriptor := hookcli.SecureClientHost, hookcli.ManagedHostWindowsStandalone,
		hookcli.ManagedHostWindowsMarkerUncertain, hookcli.ManagedHostDescriptorPath
	account, installed := hookcli.OutageAccountHome, hookcli.OutageInstalledDataRoot
	t.Cleanup(func() {
		hookcli.SecureClientHost, hookcli.ManagedHostWindowsStandalone = secure, standalone
		hookcli.ManagedHostWindowsMarkerUncertain, hookcli.ManagedHostDescriptorPath = uncertain, descriptor
		hookcli.OutageAccountHome, hookcli.OutageInstalledDataRoot = account, installed
	})
	accountHome := t.TempDir()
	hookcli.OutageAccountHome = func() string { return accountHome }
	hookcli.OutageInstalledDataRoot = func() (string, bool) { return "", false }
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	hookcli.SecureClientHost = func() bool { return false }
	hookcli.ManagedHostWindowsStandalone = func() (string, bool) { return "", false }
	hookcli.ManagedHostWindowsMarkerUncertain = func() bool { return false }
	missing := filepath.Join(t.TempDir(), "no-runtime-descriptor")
	hookcli.ManagedHostDescriptorPath = func() string { return missing }
	got := runOutageShapes(t, filepath.Join("testdata", "outage-packs"), hookcli.HookOutageFailModeNow)
	if len(got) != len(want) {
		t.Fatalf("decided %d shapes, the golden has %d", len(got), len(want))
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("%s: outage mode %q, the full-CLI hook decided %q", got[i].Name, got[i].Mode, want[i].Mode)
		}
	}
}

// The test binary of this package must link the packages the main links and
// no others from the module or outside the standard library, so the outage
// golden decides with the checks of the shipped binary.
func TestOutageGoldenSeesTheLinkSetOfTheMain(t *testing.T) {
	gotool := goToolOrSkip(t)
	list := func(args ...string) map[string]bool {
		cmd := exec.Command(gotool, append([]string{"list", "-deps"}, args...)...)
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("go list %v: %v", args, err)
		}
		set := map[string]bool{}
		for _, line := range strings.Split(string(out), "\n") {
			// -test names a test variant "pkg [pkg.test]".
			if pkg, _, _ := strings.Cut(strings.TrimSpace(line), " "); pkg != "" {
				set[pkg] = true
			}
		}
		return set
	}
	main, withTests := list("."), list("-test", ".")
	for pkg := range withTests {
		if main[pkg] || !strings.Contains(strings.SplitN(pkg, "/", 2)[0], ".") ||
			pkg == "github.com/defenseclaw/defenseclaw/cmd/defenseclaw-hook.test" {
			continue
		}
		t.Errorf("only the tests of cmd/defenseclaw-hook link %s: it could register a check the main does not have", pkg)
	}
}

// The config-load checks the hook needs register in the init of packages
// the slim main must link (rel-1-0-10:GAP-0603): checked directly, so an
// unlinking fails here even for a config shape the golden lacks.
func TestSlimHookRegistersTheConfigLoadChecks(t *testing.T) {
	if config.SandboxProfilePackCheck == nil {
		t.Error("config.SandboxProfilePackCheck is not registered: internal/openshell/packs is not linked")
	}
	if config.SandboxMachinePolicyRoute == nil {
		t.Error("config.SandboxMachinePolicyRoute is not registered: internal/enterprisepolicy is not linked")
	}
	if !config.CustomRulePackValidatorRegistered() {
		t.Error("the custom rule pack validator is not registered: internal/guardrail is not linked")
	}
}
