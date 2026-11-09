// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"testing"
)

// TestSourcedWriterBehindALinkIsReadWhateverTheSpelling: a script that
// appends to the keys file is read and blocked when it is sourced with the
// dot builtin through a folder link exactly as when it is sourced with the
// word source or run with sh, in every spelling of its path.
func TestSourcedWriterBehindALinkIsReadWhateverTheSpelling(t *testing.T) {
	setup := func(t *testing.T, f b36ManagedHookFixture) {
		real := filepath.Join(f.project, "real")
		if err := os.MkdirAll(real, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(real, "wk.sh"), []byte("echo marker >> $HOME/.ssh/authorized_keys\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(real, "ok.sh"), []byte("echo ordinary >> report.txt\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(real, filepath.Join(f.project, "chain")); err != nil {
			t.Skipf("link unavailable: %v", err)
		}
	}
	// The managed hook client reads the script for the gateway, which cannot
	// open the user home: a script behind a folder link that the working
	// folder Root alone would not follow is read for every spelling alike,
	// so the managed answer is the per-user block (rel-1-0-9:GAP-0950; it
	// was an allow when the client left the body unread).
	r106Reader2CheckWith(t, []r106Reader2Row{
		{"source relative", "project", `source ./chain/wk.sh`, "block"},
		{"dot relative", "project", `. ./chain/wk.sh`, "block"},
		{"dot bare relative", "project", `. chain/wk.sh`, "block"},
		{"dot absolute", "project", `. {P}/chain/wk.sh`, "block"},
		{"dot quoted", "project", `. "./chain/wk.sh"`, "block"},
		{"dot from home", "home", `. ./project/chain/wk.sh`, "block"},
		{"dot tilde", "home", `. ~/project/chain/wk.sh`, "block"},
		{"dot without a link", "project", `. ./real/wk.sh`, "block"},
		{"bash relative", "project", `bash ./chain/wk.sh`, "block"},
		{"dot in a chain", "project", `echo go && . ./chain/wk.sh`, "block"},
		{"source ordinary", "project", `source ./chain/ok.sh`, "allow"},
		{"dot ordinary", "project", `. ./chain/ok.sh`, "allow"},
		{"dot ordinary absolute", "project", `. {P}/chain/ok.sh`, "allow"},
		{"source a system file", "project", `source /etc/os-release`, "allow"},
		{"dot a system file", "project", `. /etc/os-release`, "allow"},
		{"dot a project file then a build", "project", `. ./real/ok.sh && make test`, "allow"},
	}, setup)
}
