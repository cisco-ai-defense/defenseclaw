// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

func TestGAP0996MakeCopySourceDispatch(t *testing.T) {
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cwd := filepath.Join(home, "project")
	for _, dir := range []string{cwd, filepath.Join(home, ".ssh")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "authorized_keys"), []byte("fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	for _, connector := range []string{"claudecode", "codex"} {
		installToolCallCorpusProfileConnector(t, connector, "default")
		for _, tc := range []struct {
			name, recipe string
			block        bool
		}{
			{"ordinary copy", `cp ~/.ssh/authorized_keys report.txt`, false},
			{"ordinary copy through env", `env cp ~/.ssh/authorized_keys report.txt`, false},
			{"protected destination", `cp report.txt ~/.ssh/authorized_keys`, true},
		} {
			t.Run(connector+"/"+tc.name, func(t *testing.T) {
				if err := os.WriteFile(filepath.Join(cwd, "Makefile"), []byte("safe:\n\t"+tc.recipe+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				if got := gap0994And0996Dispatch(t, connector, "make safe", cwd, home, actionfacts.DialectPOSIX); got != tc.block {
					t.Fatalf("blocked=%t, want %t", got, tc.block)
				}
			})
		}
	}
}
