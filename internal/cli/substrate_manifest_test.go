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

// substrateManifestCommand describes one substrate subcommand for the
// Python stub generator (scripts/gen_substrate_stubs.py) and this golden
// test. Unlike the sandbox manifest it carries each flag's help and the
// arguments, so the stubs are generated, not copied by hand.
type substrateManifestCommand struct {
	Path        string                     `json:"path"`
	Use         string                     `json:"use"`
	Short       string                     `json:"short"`
	Long        string                     `json:"long,omitempty"`
	Example     string                     `json:"example,omitempty"`
	Passthrough bool                       `json:"passthrough,omitempty"`
	Args        []substrateManifestArgJSON `json:"args,omitempty"`
	Flags       []substrateManifestFlagJ   `json:"flags,omitempty"`
}

type substrateManifestArgJSON struct {
	Name     string `json:"name"`
	Required bool   `json:"required"`
	Many     bool   `json:"many,omitempty"`
}

type substrateManifestFlagJ struct {
	Name      string `json:"name"`
	Shorthand string `json:"shorthand,omitempty"`
	Type      string `json:"type"`
	Default   string `json:"default,omitempty"`
	Usage     string `json:"usage"`
	Metavar   string `json:"metavar,omitempty"`
}

// substrateUseArgs reads the positional arguments from a Use line:
// <name> is required, [name] optional, a trailing ... means several.
func substrateUseArgs(use string) []substrateManifestArgJSON {
	fields := strings.Fields(use)
	if len(fields) <= 1 {
		return nil
	}
	var out []substrateManifestArgJSON
	for _, f := range fields[1:] {
		if f == "[flags]" {
			continue
		}
		a := substrateManifestArgJSON{Required: strings.HasPrefix(f, "<")}
		f = strings.Trim(f, "<>[]")
		if strings.HasSuffix(f, "...") {
			a.Many = true
			f = strings.TrimSuffix(f, "...")
		}
		a.Name = f
		out = append(out, a)
	}
	return out
}

func substrateManifest(root *cobra.Command) []substrateManifestCommand {
	// The root comes first: the stub generator takes the group's help from it.
	out := []substrateManifestCommand{{Path: "substrate", Use: root.Use, Short: root.Short, Long: root.Long}}
	var walk func(c *cobra.Command, path string)
	walk = func(c *cobra.Command, path string) {
		for _, sub := range c.Commands() {
			if sub.Hidden || sub.Name() == "help" || sub.Name() == "completion" {
				continue
			}
			p := strings.TrimSpace(path + " " + sub.Name())
			m := substrateManifestCommand{
				Path: p, Use: sub.Use, Short: sub.Short, Long: sub.Long, Example: sub.Example,
				Passthrough: sub.Annotations["defenseclaw.passthrough"] == "true",
				Args:        substrateUseArgs(sub.Use),
			}
			sub.Flags().VisitAll(func(f *pflag.Flag) {
				if f.Name == "help" || f.Hidden {
					return
				}
				m.Flags = append(m.Flags, substrateManifestFlagJ{
					Name: f.Name, Shorthand: f.Shorthand, Type: f.Value.Type(), Default: f.DefValue, Usage: f.Usage,
					Metavar: flagMetavar(f.Name),
				})
			})
			sort.Slice(m.Flags, func(i, j int) bool { return m.Flags[i].Name < m.Flags[j].Name })
			out = append(out, m)
			walk(sub, p)
		}
	}
	walk(root, "substrate")
	sort.Slice(out[1:], func(i, j int) bool { return out[1+i].Path < out[1+j].Path })
	return out
}

// flagMetavar is the value placeholder the help shows for a flag; the
// generator turns it into the Click metavar.
func flagMetavar(name string) string {
	switch name {
	case "output":
		return "FORMAT"
	case "admin-url", "router-url":
		return "URL"
	case "issuer", "clone":
		return "URL"
	case "client-id":
		return "ID"
	case "context", "name", "profile", "template", "default-profile", "default-template", "branch", "to":
		return "NAME"
	case "admin-ca-file", "issuer-ca-file", "router-ca-file", "router-cert-file", "router-key-file", "workload-token-file",
		"patch-out", "install-file", "plan":
		return "FILE"
	case "batch":
		return "ID"
	case "task", "reason":
		return "TEXT"
	case "ref":
		return "REF"
	case "scope":
		return "SCOPE"
	case "unmask", "exclude":
		return "GLOB"
	case "secret":
		return "NAME"
	case "transport":
		return "MODE"
	case "every", "timeout":
		return "DURATION"
	}
	return ""
}

// TestSubstrateCommandManifest pins the `substrate` command tree (commands,
// help texts, flags, defaults). The Python stubs are generated from it
// (scripts/gen_substrate_stubs.py); regenerate this file with
// DEFENSECLAW_UPDATE_GOLDEN=1 after an intended change, then the stubs.
func TestSubstrateCommandManifest(t *testing.T) {
	got, err := json.MarshalIndent(substrateManifest(substrateCmd), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	golden := filepath.Join("testdata", "substrate_commands.json")
	if os.Getenv("DEFENSECLAW_UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(golden, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read %s (DEFENSECLAW_UPDATE_GOLDEN=1 writes it): %v", golden, err)
	}
	// A Windows checkout gives the golden CRLF line endings.
	want = bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n"))
	if !bytes.Equal(got, want) {
		t.Fatalf("the substrate command tree changed; update %s with DEFENSECLAW_UPDATE_GOLDEN=1, then run scripts/gen_substrate_stubs.py", golden)
	}
}

// TestSubstrateCommandTreeCoversThePlan guards the commands of PLAN 6.5
// independently of the regenerable golden manifest.
func TestSubstrateCommandTreeCoversThePlan(t *testing.T) {
	var paths []string
	for _, m := range substrateManifest(substrateCmd)[1:] {
		paths = append(paths, strings.TrimPrefix(m.Path, "substrate "))
	}
	for _, want := range []string{
		"login", "logout", "whoami", "run", "connect", "list", "status", "logs", "pull", "checkpoint", "undo", "delete", "migrate",
		"approvals", "approve", "reject", "usage", "secrets list", "secrets set", "secrets rm", "secrets test",
		"policy explain", "policy show", "policy test", "policy reset", "doctor", "setup", "bundle apply", "bundle status",
		"verify", "template build", "template verify", "template scan", "template publish",
	} {
		if !slices.Contains(paths, want) {
			t.Errorf("substrate %s is missing", want)
		}
	}
	// Every read command has --output and --json.
	for _, path := range []string{"list", "status", "approvals", "usage", "whoami", "doctor", "secrets list", "policy explain", "policy show"} {
		cmd, _, err := substrateCmd.Find(strings.Fields(path))
		if err != nil || cmd.Flags().Lookup("output") == nil {
			t.Errorf("substrate %s has no --output", path)
			continue
		}
		if cmd.Flags().Lookup("json") == nil {
			t.Errorf("substrate %s has no --json", path)
		}
	}
	// Every command that talks to a cluster can name which one.
	for _, path := range []string{"list", "status", "run", "connect", "pull", "delete", "approvals", "usage", "secrets list"} {
		cmd, _, err := substrateCmd.Find(strings.Fields(path))
		if err != nil || cmd.Flags().Lookup("context") == nil {
			t.Errorf("substrate %s has no --context", path)
		}
	}
}

// TestSubstrateRunArgs pins how run takes the agent and its arguments.
func TestSubstrateRunArgs(t *testing.T) {
	for _, c := range []struct {
		argv    []string
		wantErr string
		dashed  []string
	}{
		{[]string{"claude"}, "", nil},
		{[]string{"claude", "--task", "fix it"}, "", nil},
		{[]string{"claude", "--", "--model", "sonnet"}, "", []string{"--model", "sonnet"}},
		{[]string{}, "name the agent", nil},
		{[]string{"claude", "extra"}, "pass agent arguments after --", nil},
	} {
		cmd := newSubstrateRunCmd()
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
			t.Errorf("%v: agent args = %v", c.argv, args[cmd.ArgsLenAtDash():])
		}
	}
}

// TestSubstrateHelpIsPlain keeps the user-facing help free of the words the
// docs style bans and of leaked internals.
func TestSubstrateHelpIsPlain(t *testing.T) {
	banned := []string{"seamless", "leverage", "robust", "ate-target-actor", "dcrelay", "SPIFFE"}
	for _, m := range substrateManifest(substrateCmd) {
		text := strings.ToLower(m.Short + " " + m.Long + " " + m.Example)
		for _, f := range m.Flags {
			text += " " + strings.ToLower(f.Usage)
		}
		for _, b := range banned {
			if strings.Contains(text, strings.ToLower(b)) {
				t.Errorf("%s: help mentions %q", m.Path, b)
			}
		}
	}
}
