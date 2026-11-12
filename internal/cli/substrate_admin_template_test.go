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
	"context"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// subAdminTemplateStub replaces the template runner and records its calls.
func subAdminTemplateStub(t *testing.T, code int, say string) *[][]string {
	t.Helper()
	old := substrateTemplateRun
	t.Cleanup(func() { substrateTemplateRun = old })
	var calls [][]string
	substrateTemplateRun = func(_ context.Context, args []string, stdout, stderr io.Writer) int {
		calls = append(calls, slices.Clone(args))
		if say != "" {
			io.WriteString(stdout, say)
		}
		return code
	}
	return &calls
}

// The flags templatecli declares for each command (internal/substrate/attest/templatecli).
var subAdminTemplateFlags = map[string][]string{
	"build": {"json", "insecure-registry", "registry-user", "registry-password-file", "config", "platform",
		"connector", "from", "to", "kit-version", "hook-binary", "relay-binary", "key", "anchors", "allow-unverified-base",
		"block-at", "policy-generation", "builder-id", "provider", "model", "gateway-url", "fail-mode", "no-mcp-static",
		"mcp-analyzers", "keep-entrypoint", "dry-run", "trusted-base", "mcp-host", "session-key"},
	"verify": {"json", "insecure-registry", "registry-user", "registry-password-file", "config", "platform",
		"anchors", "min-policy-generation", "max-age", "allow-unverified-base", "allow-tag", "revoke"},
	"scan": {"json", "insecure-registry", "registry-user", "registry-password-file", "config", "platform",
		"no-mcp-static", "mcp-analyzers", "block-at", "connector", "mcp-host"},
	"publish": {"json", "insecure-registry", "registry-user", "registry-password-file", "config", "platform",
		"anchors", "min-policy-generation"},
	"keygen": {"out", "json"},
}

func TestSubstrate_Admin_TemplateGroup(t *testing.T) {
	g := newSubstrateTemplateCmd()
	var names []string
	for _, c := range g.Commands() {
		names = append(names, c.Name())
		if c.Annotations["defenseclaw.passthrough"] != "true" {
			t.Errorf("%s is not marked as a passthrough", c.Name())
		}
		if !c.DisableFlagParsing {
			t.Errorf("%s parses flags itself", c.Name())
		}
		if c.Flags().HasFlags() {
			t.Errorf("%s declares flags; templatecli owns them", c.Name())
		}
		if strings.TrimSpace(c.Short) == "" || strings.TrimSpace(c.Example) == "" {
			t.Errorf("%s has no short text or example", c.Name())
		}
	}
	slices.Sort(names)
	if want := []string{"build", "keygen", "publish", "scan", "verify"}; !slices.Equal(names, want) {
		t.Errorf("commands %v, want %v", names, want)
	}
}

func TestSubstrate_Admin_TemplatePassesTheLineThrough(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"build", []string{"--from", "registry.example.test/base:1", "--to", "registry.example.test/actor:1", "--hook-binary", "h", "--relay-binary", "r", "--key", "k", "--dry-run", "--trusted-base", "sha256:aa", "--trusted-base", "sha256:bb"}},
		{"verify", []string{"registry.example.test/actor@sha256:aa", "--anchors", "a.pub", "--max-age", "720h", "--json"}},
		{"scan", []string{"registry.example.test/actor@sha256:aa", "--connector", "codex", "--block-at", "none"}},
		{"publish", []string{"src@sha256:aa", "dst:1", "--anchors", "a.pub"}},
		{"keygen", []string{"--out", "keys"}},
		{"verify", nil},
		{"build", []string{"-x", "--", "-h"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls := subAdminTemplateStub(t, 0, "done\n")
			root := newSubstrateTemplateCmd()
			out, _, err := runSubAdmin(root, append([]string{tc.name}, tc.args...)...)
			if err != nil {
				t.Fatal(err)
			}
			if len(*calls) != 1 || !slices.Equal((*calls)[0], append([]string{tc.name}, tc.args...)) {
				t.Errorf("templatecli got %v", *calls)
			}
			if out != "done\n" {
				t.Errorf("output %q", out)
			}
		})
	}
}

func TestSubstrate_Admin_TemplateExitCodes(t *testing.T) {
	for _, code := range []int{1, 2, 7} {
		calls := subAdminTemplateStub(t, code, "NOT ADMITTED: x\n")
		root := newSubstrateTemplateCmd()
		out, errText, err := runSubAdmin(root, "verify", "img", "--anchors", "a.pub")
		if err == nil || commandExitCode(err) != code {
			t.Fatalf("code %d: err %v (exit %d)", code, err, commandExitCode(err))
		}
		if len(*calls) != 1 || out != "NOT ADMITTED: x\n" {
			t.Errorf("calls %v output %q", *calls, out)
		}
		if strings.Contains(errText, "Error:") {
			t.Errorf("the failure is printed again: %q", errText)
		}
	}
}

func TestSubstrate_Admin_TemplateHelpIsAnsweredHere(t *testing.T) {
	for name, flags := range subAdminTemplateFlags {
		for _, arg := range []string{"-h", "--help"} {
			t.Run(name+" "+arg, func(t *testing.T) {
				calls := subAdminTemplateStub(t, 0, "")
				root := newSubstrateTemplateCmd()
				out, _, err := runSubAdmin(root, name, arg)
				if err != nil {
					t.Fatal(err)
				}
				if len(*calls) != 0 {
					t.Errorf("help ran templatecli: %v", *calls)
				}
				sub, _, _ := root.Find([]string{name})
				if !strings.Contains(out, strings.TrimSpace(sub.Long)) {
					t.Errorf("help is not the Long text:\n%s", out)
				}
				for _, f := range flags {
					if !strings.Contains(out, "--"+f) {
						t.Errorf("help lacks --%s", f)
					}
				}
			})
		}
	}
	t.Run("help after other arguments", func(t *testing.T) {
		calls := subAdminTemplateStub(t, 0, "")
		out, _, err := runSubAdmin(newSubstrateTemplateCmd(), "build", "--from", "x", "--help")
		if err != nil || len(*calls) != 0 || !strings.Contains(out, "--hook-binary FILE") {
			t.Errorf("%v %v\n%s", err, *calls, out)
		}
	})
	t.Run("help after the double dash goes through", func(t *testing.T) {
		calls := subAdminTemplateStub(t, 0, "")
		if _, _, err := runSubAdmin(newSubstrateTemplateCmd(), "scan", "--", "--help"); err != nil || len(*calls) != 1 {
			t.Errorf("%v %v", err, *calls)
		}
	})
}

func TestSubstrate_Admin_TemplateHelpTextsStayWithTheirDefaults(t *testing.T) {
	// The defaults templatecli declares, as the help states them.
	want := map[string][]string{
		"build":   {"(default claudecode)", "(default dev)", "(default high)", "(default 1)", "(default yara)", "(default linux/amd64)"},
		"verify":  {"(default 0)", "(default linux/amd64)"},
		"scan":    {"(default yara)", "(default high)"},
		"publish": {"(default 0)"},
	}
	g := newSubstrateTemplateCmd()
	for name, parts := range want {
		sub, _, _ := g.Find([]string{name})
		for _, p := range parts {
			if !strings.Contains(sub.Long, p) {
				t.Errorf("template %s help lacks %q", name, p)
			}
		}
	}
}

// With the real runner: keygen writes a key pair, and a missing argument is a
// usage error that names what is missing.
func TestSubstrate_Admin_TemplateWithTheRealRunner(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	out, _, err := runSubAdmin(newSubstrateTemplateCmd(), "keygen", "--out", dir)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "attestation.key") {
		t.Errorf("output %q", out)
	}
	for _, f := range []string{"attestation.key", "attestation.pub"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Error(err)
		}
	}
	_, errText, err := runSubAdmin(newSubstrateTemplateCmd(), "verify")
	if commandExitCode(err) != 2 || !strings.Contains(errText, "verify needs an image and --anchors") {
		t.Errorf("exit %d, stderr %q", commandExitCode(err), errText)
	}
}

func TestSubstrate_Admin_TemplateIsInTheTree(t *testing.T) {
	var found *cobra.Command
	for _, c := range substrateCmd.Commands() {
		if c.Name() == "template" {
			found = c
		}
	}
	if found == nil || len(found.Commands()) != 5 {
		t.Fatalf("template is not in the substrate tree with its five commands")
	}
}
