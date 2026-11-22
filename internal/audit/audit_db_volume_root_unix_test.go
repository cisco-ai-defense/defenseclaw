// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package audit

import (
	"os"
	"path/filepath"
	"testing"
)

// A8 item: a Kubernetes volume root is 0777; the leader declares it with
// TrustVolumeRoot and keeps its store in a 0700 directory under it.
func TestTrustVolumeRootAcceptsOnlyThatAncestor(t *testing.T) {
	vol := filepath.Join(t.TempDir(), "vol")
	if err := os.Mkdir(vol, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(vol, 0o777); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(vol)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateAuditDBDirectory(vol, info, true); err == nil {
		t.Fatal("a 0777 ancestor was accepted before TrustVolumeRoot")
	}
	TrustVolumeRoot(vol)
	t.Cleanup(func() { trustedVolumeRoots.Delete(vol) })
	if err := validateAuditDBDirectory(vol, info, true); err != nil {
		t.Fatalf("declared volume root as an ancestor: %v", err)
	}
	// Never as the database's own directory.
	if err := validateAuditDBDirectory(vol, info, false); err == nil {
		t.Fatal("the volume root was accepted as the database directory")
	}
	// Another 0777 directory stays refused.
	other := filepath.Join(t.TempDir(), "other")
	_ = os.Mkdir(other, 0o700)
	_ = os.Chmod(other, 0o777)
	oinfo, _ := os.Lstat(other)
	if err := validateAuditDBDirectory(other, oinfo, true); err == nil {
		t.Fatal("an undeclared 0777 ancestor was accepted")
	}
}
