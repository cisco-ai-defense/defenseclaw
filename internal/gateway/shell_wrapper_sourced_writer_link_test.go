// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"testing"
)

// TestSourcedWriterBehindALinkInAShellWrapperIsReadAsWithoutIt: the inner
// command of a bash -c or sh -c wrapper reaches the same link walk of a
// sourced script body as the same command typed at the top level, so a
// writer of the keys file behind folder links is blocked in the wrapper
// exactly as outside it and an ordinary script behind the links is allowed.
func TestSourcedWriterBehindALinkInAShellWrapperIsReadAsWithoutIt(t *testing.T) {
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
	r106Reader2CheckWith(t, []r106Reader2Row{
		{"top level dot", "project", `. ./chain/wk.sh`, "block/allow"},
		{"bash -c dot", "project", `bash -c ". ./chain/wk.sh"`, "block/allow"},
		{"bash -c source", "project", `bash -c "source ./chain/wk.sh"`, "block/allow"},
		{"sh -c dot", "project", `sh -c ". ./chain/wk.sh"`, "block/allow"},
		{"sh -c single quoted", "project", `sh -c '. ./chain/wk.sh'`, "block/allow"},
		{"dash -c dot", "project", `dash -c ". ./chain/wk.sh"`, "block/allow"},
		{"bash -c absolute", "project", `bash -c ". {P}/chain/wk.sh"`, "block/allow"},
		{"bash -c from home", "home", `bash -c ". ./project/chain/wk.sh"`, "block/allow"},
		{"bash -c chained", "project", `bash -c "echo go && . ./chain/wk.sh"`, "block/allow"},
		{"bash -c nested", "project", `bash -c "sh -c '. ./chain/wk.sh'"`, "block/allow"},
		{"bash -c run", "project", `bash -c "bash ./chain/wk.sh"`, "block/allow"},
		{"bash -c without a link", "project", `bash -c ". ./real/wk.sh"`, "block"},
		{"bash -c ordinary dot", "project", `bash -c ". ./chain/ok.sh"`, "allow"},
		{"bash -c ordinary source", "project", `bash -c "source ./chain/ok.sh"`, "allow"},
		{"sh -c ordinary dot", "project", `sh -c ". ./chain/ok.sh"`, "allow"},
		{"bash -c ordinary then build", "project", `bash -c ". ./chain/ok.sh && make test"`, "allow"},
		{"bash -c nested ordinary", "project", `bash -c "sh -c '. ./chain/ok.sh'"`, "allow"},
		{"bash -c plain command", "project", `bash -c "echo hello"`, "allow"},
		{"bash -c system file", "project", `bash -c ". /etc/os-release"`, "allow"},
	}, setup)
}
