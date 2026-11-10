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
	// The managed gateway keeps a read it cannot make behind ProtectHome, for
	// every spelling alike (the allow after the slash).
	r106Reader2CheckWith(t, []r106Reader2Row{
		{"source relative", "project", `source ./chain/wk.sh`, "block/allow"},
		{"dot relative", "project", `. ./chain/wk.sh`, "block/allow"},
		{"dot bare relative", "project", `. chain/wk.sh`, "block/allow"},
		{"dot absolute", "project", `. {P}/chain/wk.sh`, "block/allow"},
		{"dot quoted", "project", `. "./chain/wk.sh"`, "block/allow"},
		{"dot from home", "home", `. ./project/chain/wk.sh`, "block/allow"},
		{"dot tilde", "home", `. ~/project/chain/wk.sh`, "block/allow"},
		{"dot without a link", "project", `. ./real/wk.sh`, "block"},
		{"bash relative", "project", `bash ./chain/wk.sh`, "block/allow"},
		{"dot in a chain", "project", `echo go && . ./chain/wk.sh`, "block/allow"},
		{"source ordinary", "project", `source ./chain/ok.sh`, "allow"},
		{"dot ordinary", "project", `. ./chain/ok.sh`, "allow"},
		{"dot ordinary absolute", "project", `. {P}/chain/ok.sh`, "allow"},
		{"source a system file", "project", `source /etc/os-release`, "allow"},
		{"dot a system file", "project", `. /etc/os-release`, "allow"},
		{"dot a project file then a build", "project", `. ./real/ok.sh && make test`, "allow"},
	}, setup)
}
