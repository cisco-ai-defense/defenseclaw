// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestSourcedScriptBehindALinkBeforeTheParentIsJudgedAsTheSystemOpensIt: a
// name that passes a folder link and then .. (portal/../wk.sh) opens the
// parent of the folder the link leads to, as the shell does, so the writer
// there is blocked and the ordinary script there is allowed although a decoy
// of the other kind lies at the lexical spelling in the project, per-user
// and managed, in the default and the strict profile
// (rel-1-0-9:GAP-1038).
func TestSourcedScriptBehindALinkBeforeTheParentIsJudgedAsTheSystemOpensIt(t *testing.T) {
	writer := "echo marker >> $HOME/.ssh/authorized_keys\n"
	ordinary := "echo ordinary >> report.txt\n"
	setup := func(t *testing.T, f b36ManagedHookFixture) {
		t.Helper()
		linked := filepath.Join(f.home, "chain", "live")
		if err := os.MkdirAll(linked, 0o700); err != nil {
			t.Fatal(err)
		}
		for file, body := range map[string]string{
			filepath.Join(f.home, "chain", "wk.sh"): writer,
			filepath.Join(f.home, "chain", "ok.sh"): ordinary,
			filepath.Join(f.project, "wk.sh"):       ordinary,
			filepath.Join(f.project, "ok.sh"):       writer,
		} {
			if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Symlink(linked, filepath.Join(f.project, "portal")); err != nil {
			t.Skipf("link unavailable: %v", err)
		}
	}
	var rows []r106Reader2Row
	for _, command := range []string{". %s", "source %s", "bash %s", "sh %s", `bash -c ". %s"`, `sh -c "bash %s"`, `env A=1 bash -lc ". %s"`} {
		for _, row := range []struct {
			name string
			want string
		}{
			{"portal/../wk.sh", "block"},
			{"portal/../ok.sh", "allow"},
			{"{H}/chain/live/../wk.sh", "block"},
			{"{H}/chain/live/../ok.sh", "allow"},
		} {
			line := fmt.Sprintf(command, row.name)
			rows = append(rows, r106Reader2Row{line, "project", line, row.want})
		}
	}
	r106Reader2CheckWith(t, rows, setup)
}
