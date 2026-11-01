//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// OpenCode V1 loads the V2 plugin in the Windows machine policy and runs
// every call unchecked (rel-1-0-6 GAP-0037): the profile scan finds the
// opencode-ai package in the npm prefix, a version manager and the machine
// npm prefix, even beside OpenCode V2, and the record names it OpenCode V1.
// OpenCode V2 alone reports nothing.
func TestDiscoverWindowsPrivateInstallsFindOpenCodeV1(t *testing.T) {
	home := t.TempDir()
	machine := filepath.Join(t.TempDir(), "nodejs")
	if err := os.MkdirAll(machine, 0o755); err != nil {
		t.Fatal(err)
	}
	previous := windowsPrivateInstallMachineRoots
	windowsPrivateInstallMachineRoots = func() []string { return []string{machine} }
	t.Cleanup(func() { windowsPrivateInstallMachineRoots = previous })
	copyAt := func(dir, version string) {
		writeWindowsAgentPackageJSON(t, dir, version)
		if err := os.MkdirAll(filepath.Join(dir, "bin"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "bin", "opencode"), []byte("fixture"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	npm := filepath.Join(home, "AppData", "Roaming", "npm", "node_modules")
	scan := func() []string {
		var got []string
		for _, install := range DiscoverWindowsPrivateAgentInstalls(context.Background(), home, []string{"opencode"}) {
			path := strings.Replace(install.Path, machine, "MACHINE", 1)
			got = append(got, install.Connector+" "+install.Version+" "+strings.TrimPrefix(path, home))
		}
		sort.Strings(got)
		return got
	}
	copyAt(filepath.Join(npm, "@opencode", "cli"), "2.2.3")
	if got := scan(); len(got) != 0 {
		t.Fatalf("OpenCode V2 alone was reported: %v", got)
	}
	copyAt(filepath.Join(npm, "opencode-ai"), "1.18.34")
	copyAt(filepath.Join(home, "AppData", "Roaming", "nvm", "v20.1.0", "node_modules", "opencode-ai"), "1.18.32")
	copyAt(filepath.Join(machine, "node_modules", "opencode-ai"), "1.18.30")
	want := []string{
		`opencode 1.18.30 MACHINE\node_modules\opencode-ai`,
		`opencode 1.18.32 \AppData\Roaming\nvm\v20.1.0\node_modules\opencode-ai`,
		`opencode 1.18.34 \AppData\Roaming\npm\node_modules\opencode-ai`,
	}
	if got := scan(); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("OpenCode V1 copies:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	var agents []UnprotectedAgent
	for _, install := range DiscoverWindowsPrivateAgentInstalls(context.Background(), home, []string{"opencode"}) {
		agent, ok := privateInstallUnprotected(install)
		if !ok {
			t.Fatalf("copy %+v is not unprotected", install)
		}
		agent.User, agent.SID = "alice", "S-1-5-21-1-2-3-1001"
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
		if agent.Code != UnprotectedCodeOpenCodeV1 || !strings.Contains(agent.Message(), "OpenCode is NOT protected until OpenCode V2") {
			t.Fatalf("copy %+v is not reported as OpenCode V1", agent)
		}
	}
}
