//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"errors"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-2432: a folder of the policy tree the service account cannot list
// (a root shell under umask 077 made it 0700) is named with its mode, its
// owner and the fix, not only "open <folder>: permission denied".
func TestGAP2432UnreadablePolicyFolderNamesModeOwnerAndFix(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("this test needs an unprivileged account, which cannot list a folder without read permission")
	}
	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	// Trust the test account as the service account, so the walk reaches
	// the listing of the folder instead of stopping at its owner.
	t.Setenv(UnixServiceAccountEnv, me.Username)
	root := t.TempDir()
	guardrail := filepath.Join(root, "guardrail")
	if err := os.Mkdir(guardrail, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(guardrail, "my-pack"), 0o700); err != nil {
		t.Fatal(err)
	}
	// Write and search but no read: the owner cannot list it either.
	if err := os.Chmod(guardrail, 0o300); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(guardrail, 0o700) })

	err = validateServiceRuntimeTreeEntries(root, "policy_dir")
	if err == nil {
		t.Fatal("an unlistable policy folder passed the tree check")
	}
	msg := err.Error()
	for _, want := range []string{
		guardrail + " is 0300 owned by " + me.Username + ":",
		"so the " + me.Username + " service account cannot read the policy_dir below it",
		"chown root:" + me.Username + " " + guardrail + " && chmod 0750 " + guardrail,
		"permission denied",
	} {
		if !strings.Contains(msg, want) {
			t.Fatalf("error = %q, want it to contain %q", msg, want)
		}
	}
	if !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("error %v no longer wraps the permission error", err)
	}
}

func TestGAP2432ServiceGroupNameFollowsTheServiceAccount(t *testing.T) {
	for _, tc := range []struct{ goos, custom, want string }{
		{"linux", "", StandaloneLinuxServiceUser},
		{"darwin", "", StandaloneDarwinServiceUser},
		{"linux", " dcsvc ", "dcsvc"},
	} {
		if got := serviceGroupName(tc.goos, tc.custom); got != tc.want {
			t.Fatalf("serviceGroupName(%q, %q) = %q, want %q", tc.goos, tc.custom, got, tc.want)
		}
	}
}
