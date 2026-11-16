//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// OpenCode V1 cannot run the V2 plugin (rel-1-0-6 GAP-0037), so the
// separate-copy scan finds the opencode-ai package wherever the account can
// run it: its home, a machine prefix, and an administrator prefix below
// /opt that enterprise.enrollment.agent_prefixes does not name (found the
// way the gateway finds OpenCode, GAP-0040). A V2 copy alone reports
// nothing, and V1 beside V2 is still reported.
func TestDiscoverUnixPrivateInstallsFindOpenCodeV1(t *testing.T) {
	withExtendedUnixDiscovery(t)
	machine := machineTestDir(t)
	machinePrefix := filepath.Join(machine, "machine")
	adminRoot := filepath.Join(machine, "opt")
	for _, dir := range []string{machinePrefix, adminRoot} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	withPrivateInstallMachinePrefixes(t, machinePrefix)
	previousRoots := unixAdminPrefixRoots
	unixAdminPrefixRoots = []string{adminRoot}
	t.Cleanup(func() { unixAdminPrefixRoots = previousRoots })
	home := makeHome(t, trustedTestDir(t), "alice")

	v1 := func(prefix string) string {
		return npmCopy(t, filepath.Join(prefix, "lib", "node_modules", "opencode-ai"), "opencode-ai", "1.18.34", "bin/opencode")
	}
	v2 := func(prefix string) string {
		return npmCopy(t, filepath.Join(prefix, "lib", "node_modules", "@opencode", "cli"), "@opencode/cli", "2.2.3", "bin/opencode")
	}
	scan := func() []string {
		var got []string
		for _, install := range DiscoverUnixPrivateAgentInstalls(context.Background(), home, []string{"opencode"}) {
			line := install.Connector + " " + install.Version + " " + install.Path
			line = strings.ReplaceAll(line, home, "HOME")
			line = strings.ReplaceAll(line, machinePrefix, "MACHINE")
			got = append(got, strings.ReplaceAll(line, adminRoot, "OPT"))
		}
		return got
	}

	v2(filepath.Join(home, ".npm-global"))
	v2(filepath.Join(adminRoot, "dc-agents"))
	if got := scan(); len(got) != 0 {
		t.Fatalf("OpenCode V2 alone was reported: %v", got)
	}

	adminCopy := v1(filepath.Join(adminRoot, "dc-agents"))
	v1(filepath.Join(home, ".npm-global"))
	v1(machinePrefix)
	got := strings.Join(scan(), "\n")
	want := strings.Join([]string{
		"opencode 1.18.34 HOME/.npm-global/lib/node_modules/opencode-ai",
		"opencode 1.18.34 MACHINE/lib/node_modules/opencode-ai",
		"opencode 1.18.34 OPT/dc-agents/lib/node_modules/opencode-ai",
	}, "\n")
	if got != want {
		t.Fatalf("OpenCode V1 copies:\n%s\nwant:\n%s", got, want)
	}

	// The root parent records the administrator-prefix copy the worker
	// names, and still refuses any other path below /opt.
	if !UnixPrivateInstallPathAllowed(home, adminCopy) {
		t.Fatalf("the parent refuses the administrator-prefix V1 copy %s", adminCopy)
	}
	for _, other := range []string{filepath.Join(adminRoot, "dc-agents", "lib", "node_modules", "@openai", "codex"), filepath.Join(adminRoot, "dc-agents", "bin"),
		filepath.Join(adminRoot, "a", "b", "lib", "node_modules", "opencode-ai")} {
		if UnixPrivateInstallPathAllowed(home, other) {
			t.Fatalf("the parent accepts %s", other)
		}
	}

	// Through the record, each copy is OpenCode V1 with the remedy.
	var agents []UnprotectedAgent
	for _, install := range DiscoverUnixPrivateAgentInstalls(context.Background(), home, []string{"opencode"}) {
		agent, ok := privateInstallUnprotected(install)
		if !ok {
			t.Fatalf("copy %+v is not unprotected", install)
		}
		agent.User = "alice"
		agents = append(agents, agent)
	}
	data, err := MarshalUnprotectedAgents(agents)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseUnprotectedAgents(data)
	if err != nil || len(parsed) != 3 {
		t.Fatalf("record = %+v, %v", parsed, err)
	}
	for _, agent := range parsed {
		if agent.Code != UnprotectedCodeOpenCodeV1 || agent.Reason != openCodeV1Reason {
			t.Fatalf("copy %+v is not reported as OpenCode V1", agent)
		}
	}
}
