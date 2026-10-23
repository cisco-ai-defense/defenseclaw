// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// The Codex page's managed section quotes the Windows header and Codex row
// with its requirements file as enterprise policy verify prints them.
func TestCodexPageQuotesTheVerifyLines(t *testing.T) {
	resetEnterprisePolicyFlags(t)
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs-site", "content", "docs", "connectors", "codex.mdx"))
	if err != nil {
		t.Fatal(err)
	}
	_, section, ok := strings.Cut(string(raw), "## On a managed computer")
	if !ok {
		t.Fatal("codex.mdx has no managed section")
	}
	section, _, _ = strings.Cut(section, "\n## ")
	blocks := []string{}
	for _, m := range regexp.MustCompile("(?s)```text\n(.*?)```").FindAllStringSubmatch(section, -1) {
		blocks = append(blocks, m[1])
	}

	layout, err := managed.StandaloneWindowsLayoutForRoots(`C:\Program Files`, `C:\ProgramData`)
	if err != nil {
		t.Fatal(err)
	}
	opts := enterprisepolicy.LayoutOptions(layout, `C:\Program Files`, `C:\ProgramData`)
	requirements, err := enterprisepolicy.CodexRequirementsPath(opts)
	if err != nil {
		t.Fatal(err)
	}
	// The report marks a file this host cannot see; render with one it can
	// and put the Windows path back.
	present := filepath.Join(t.TempDir(), "requirements.toml")
	if err := os.WriteFile(present, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	groups, err := connector.ManagedHookGroupsForOS("codex", "", "windows")
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) == 0 {
		t.Fatal("Windows Codex machine policy has no managed hook groups")
	}
	report := enterprisePolicyReport{goos: "windows", HookBinary: opts.HookBinary, Result: enterprisepolicy.Result{States: []enterprisepolicy.State{
		{
			Connector: "codex", Route: enterprisepolicy.RouteMachinePolicy,
			Covered: true, EffectiveLock: config.ManagedHooksOnlyEnforce,
			ForeignHooks: config.ForeignHooksRemove, OwnedEntries: len(groups),
			Paths: []string{present},
		},
	}}}
	var out bytes.Buffer
	if err := writeEnterprisePolicyReport(&out, report); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.ReplaceAll(out.String(), present, requirements), "\n")
	if len(lines) < 5 || !strings.HasPrefix(lines[0], "Standalone machine agent policy (hook binary ") ||
		!strings.HasPrefix(lines[2], "codex ") || !strings.HasPrefix(lines[3], "    file:      ") {
		t.Fatalf("unexpected verify output:\n%s", out.String())
	}
	for _, quote := range []string{lines[0] + "\n", lines[2] + "\n" + lines[3] + "\n"} {
		found := false
		for _, block := range blocks {
			if block == quote {
				found = true
			}
		}
		if !found {
			t.Errorf("the managed section does not quote the verify output:\n%s", quote)
		}
	}
}
