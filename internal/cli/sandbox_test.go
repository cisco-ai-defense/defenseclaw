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

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// sandboxManifestCommand describes one sandbox subcommand for the Python
// stub parity check (track G2) and for this golden test.
type sandboxManifestCommand struct {
	Path  string                 `json:"path"`
	Use   string                 `json:"use"`
	Short string                 `json:"short"`
	Flags []sandboxManifestFlagJ `json:"flags,omitempty"`
}

type sandboxManifestFlagJ struct {
	Name      string `json:"name"`
	Shorthand string `json:"shorthand,omitempty"`
	Type      string `json:"type"`
	Default   string `json:"default,omitempty"`
}

func sandboxManifest(root *cobra.Command) []sandboxManifestCommand {
	var out []sandboxManifestCommand
	var walk func(c *cobra.Command, path string)
	walk = func(c *cobra.Command, path string) {
		for _, sub := range c.Commands() {
			if sub.Hidden || sub.Name() == "help" {
				continue
			}
			p := strings.TrimSpace(path + " " + sub.Name())
			m := sandboxManifestCommand{Path: p, Use: sub.Use, Short: sub.Short}
			sub.Flags().VisitAll(func(f *pflag.Flag) {
				if f.Name == "help" {
					return
				}
				m.Flags = append(m.Flags, sandboxManifestFlagJ{Name: f.Name, Shorthand: f.Shorthand, Type: f.Value.Type(), Default: f.DefValue})
			})
			sort.Slice(m.Flags, func(i, j int) bool { return m.Flags[i].Name < m.Flags[j].Name })
			out = append(out, m)
			walk(sub, p)
		}
	}
	walk(root, "sandbox")
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// TestSandboxCommandManifest pins the `sandbox` command tree (commands,
// flags, defaults). The Python Click stubs mirror it; regenerate with
// DEFENSECLAW_UPDATE_GOLDEN=1 after an intended change.
func TestSandboxCommandManifest(t *testing.T) {
	got, err := json.MarshalIndent(sandboxManifest(sandboxCmd), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	golden := filepath.Join("testdata", "sandbox_commands.json")
	if os.Getenv("DEFENSECLAW_UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(golden, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read %s (DEFENSECLAW_UPDATE_GOLDEN=1 writes it): %v", golden, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("the sandbox command tree changed; update %s with DEFENSECLAW_UPDATE_GOLDEN=1 and the Python stubs", golden)
	}
}

// sandboxCommandPaths lists every sandbox subcommand path.
func sandboxCommandPaths(cmd *cobra.Command, prefix string) []string {
	var out []string
	for _, c := range cmd.Commands() {
		if c.Hidden || c.Name() == "help" {
			continue
		}
		p := strings.TrimSpace(prefix + " " + c.Name())
		out = append(out, p)
		out = append(out, sandboxCommandPaths(c, p)...)
	}
	return out
}

func TestSandboxCommandTreeCoversThePlan(t *testing.T) {
	paths := sandboxCommandPaths(sandboxCmd, "")
	for _, want := range []string{
		"setup", "doctor", "run", "list", "status", "connect", "exec", "stop", "start", "delete", "logs", "activity",
		"undo", "review", "approvals", "approve", "reject", "unblock", "pull", "policy show", "policy explain",
		"policy suggest", "policy allow", "policy block", "pack list", "pack show", "pack validate", "image build",
		"image list", "image prune", "enable", "disable", "teardown",
	} {
		if !slices.Contains(paths, want) {
			t.Errorf("sandbox %s is missing", want)
		}
	}
	for _, path := range []string{"list", "status", "approvals", "doctor"} {
		cmd, _, err := sandboxCmd.Find(strings.Fields(path))
		if err != nil || cmd.Flags().Lookup("output") == nil {
			t.Errorf("sandbox %s has no --output", path)
		}
	}
}

func TestSandboxRunArgs(t *testing.T) {
	run, _, err := sandboxCmd.Find([]string{"run"})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		argv    []string
		wantErr string
		dashed  []string
	}{
		{[]string{"claude"}, "", nil},
		{[]string{"claude", "--copy", "--", "-p", "fix it"}, "", []string{"-p", "fix it"}},
		{[]string{}, "name the harness", nil},
		{[]string{"claude", "extra"}, "pass harness arguments after --", nil},
	}
	for _, c := range cases {
		cmd := newSandboxRunCmd()
		if err := cmd.ParseFlags(c.argv); err != nil {
			t.Fatalf("%v: %v", c.argv, err)
		}
		args := cmd.Flags().Args()
		err := cmd.Args(cmd, args)
		switch {
		case c.wantErr == "" && err != nil:
			t.Errorf("%v: %v", c.argv, err)
		case c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)):
			t.Errorf("%v: err = %v, want %q", c.argv, err, c.wantErr)
		case c.dashed != nil && !slices.Equal(args[cmd.ArgsLenAtDash():], c.dashed):
			t.Errorf("%v: harness args = %v", c.argv, args[cmd.ArgsLenAtDash():])
		}
	}
	if run.Flags().Lookup("prompt").Shorthand != "p" || run.Flags().Lookup("detach").Shorthand != "d" {
		t.Error("run lost its -p/-d shorthands")
	}
	cmd := newSandboxExecCmd()
	_ = cmd.ParseFlags([]string{"box", "--", "ls", "-la"})
	if err := cmd.Args(cmd, cmd.Flags().Args()); err != nil {
		t.Errorf("exec box -- ls -la: %v", err)
	}
	cmd = newSandboxExecCmd()
	_ = cmd.ParseFlags([]string{"box", "ls"})
	if err := cmd.Args(cmd, cmd.Flags().Args()); err == nil {
		t.Error("exec without -- accepted")
	}
}
