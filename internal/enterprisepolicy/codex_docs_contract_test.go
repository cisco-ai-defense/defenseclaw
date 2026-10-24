// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-0577: the Codex page's managed section names, for each OS, the
// requirements file that carries the hooks and the hook program it runs.
func TestCodexPageNamesTheManagedHookFiles(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs-site", "content", "docs", "connectors", "codex.mdx"))
	if err != nil {
		t.Fatal(err)
	}
	_, managedSection, ok := strings.Cut(string(raw), "## On a managed computer")
	if !ok {
		t.Fatal("codex.mdx has no managed section")
	}
	managedSection, _, _ = strings.Cut(managedSection, "\n## ")
	for _, tc := range []struct{ goos, row string }{{"linux", "Linux"}, {"darwin", "macOS"}, {"windows", "Windows"}} {
		var layout managed.StandaloneLayout
		if tc.goos == "windows" {
			layout, err = managed.StandaloneWindowsLayoutForRoots(`C:\Program Files`, `C:\ProgramData`)
		} else {
			layout, err = managed.StandaloneLayoutFor(tc.goos)
		}
		if err != nil {
			t.Fatal(err)
		}
		opts := LayoutOptions(layout, `C:\Program Files`, `C:\ProgramData`)
		requirements, err := CodexRequirementsPath(opts)
		if err != nil {
			t.Fatal(err)
		}
		want := "| " + tc.row + " | `" + requirements + "` | `" + opts.HookBinary + "` |"
		if !strings.Contains(managedSection, want) {
			t.Errorf("the managed section has no row %s", want)
		}
	}
}
