// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package processutil

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// writeScannerScript writes an executable that prints label.
func writeScannerScript(t *testing.T, path, label string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho "+label+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}

// A relative scanner command (scanners.mcp_scanner.binary: ./bin/...) is
// relative to cmd.Dir, as when exec starts it directly. The contained
// runner must start the same file exec would, or refuse it as exec would:
// it must neither reject a project-relative scanner nor resolve it against
// another folder.
func TestRunTreeIsolatedRunsTheFileExecWouldStart(t *testing.T) {
	root := t.TempDir()
	project := filepath.Join(root, "project")
	writeScannerScript(t, filepath.Join(project, "bin", "scanner"), "project")
	if err := os.MkdirAll(filepath.Join(project, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	// project/link points at real/inner: "link/../bin/scanner" is
	// real/bin/scanner for the kernel, project/bin/scanner lexically.
	writeScannerScript(t, filepath.Join(root, "real", "bin", "scanner"), "physical")
	if err := os.MkdirAll(filepath.Join(root, "real", "inner"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "real", "inner"), filepath.Join(project, "link")); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, cwd, dir, path, want string
	}{
		{name: "project-relative scanner", dir: project, path: "./bin/scanner", want: "project"},
		{name: "parent of the folder", dir: filepath.Join(project, "sub"), path: "../bin/scanner", want: "project"},
		{name: "file name in the folder", dir: filepath.Join(project, "bin"), path: "scanner", want: "project"},
		{name: "symlinked folder then parent", dir: filepath.Join(project, "link"), path: "../bin/scanner", want: "physical"},
		{name: "relative folder", cwd: root, dir: "project", path: "./bin/scanner", want: "project"},
		{name: "no folder", cwd: project, path: "./bin/scanner", want: "project"},
		{name: "missing scanner", dir: filepath.Join(project, "sub"), path: "./bin/scanner"},
		{name: "missing scanner in the gateway folder", cwd: root, path: "./bin/scanner"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.cwd != "" {
				t.Chdir(tc.cwd)
			}
			newCmd := func() (*exec.Cmd, *bytes.Buffer) {
				cmd := CommandContext(context.Background(), "./placeholder")
				cmd.Path, cmd.Args, cmd.Dir = tc.path, []string{tc.path}, tc.dir
				var out bytes.Buffer
				cmd.Stdout = &out
				return cmd, &out
			}
			direct, directOut := newCmd()
			directErr := direct.Run()
			contained, containedOut := newCmd()
			containedErr := RunTreeIsolated(context.Background(), contained)
			if tc.want == "" {
				if directErr == nil || containedErr == nil {
					t.Fatalf("missing scanner ran: direct %v, contained %v (%q)", directErr, containedErr, containedOut.String())
				}
				return
			}
			if directErr != nil || strings.TrimSpace(directOut.String()) != tc.want {
				t.Fatalf("fixture: direct exec = %q, %v; want %q", directOut.String(), directErr, tc.want)
			}
			if containedErr != nil {
				t.Fatalf("contained scanner %q in %q: %v", tc.path, tc.dir, containedErr)
			}
			if got := strings.TrimSpace(containedOut.String()); got != tc.want {
				t.Fatalf("contained scanner ran %q, want %q (the file exec starts)", got, tc.want)
			}
		})
	}
}
