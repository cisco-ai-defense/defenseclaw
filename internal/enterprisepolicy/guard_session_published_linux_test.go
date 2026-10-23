//go:build linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"errors"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/posixacl"
	systemdunits "github.com/defenseclaw/defenseclaw/packaging/systemd"
)

// Kill switch: the gateway and guardian units run under
// ProtectSystem=strict, so the folder of the record key (the folder above
// the record folder) must be writable to them, or the gateway could not
// remove the key before a block, nor the guardian before a removal.
func TestTheUnitsCanChangeTheSessionRecordKey(t *testing.T) {
	layout, err := managed.StandaloneLayoutFor("linux")
	if err != nil {
		t.Fatal(err)
	}
	holds, ok := PublishedSessionKeyDir(layout.HookSessionDir)
	if !ok {
		t.Fatal("no key folder")
	}
	for _, unit := range []string{"defenseclaw-gateway.service", "defenseclaw-hook-guardian.service", "defenseclaw-hook-guardian-reconcile.service"} {
		data, err := systemdunits.ReadFile(unit)
		if err != nil {
			t.Fatal(err)
		}
		writable := false
		for _, line := range strings.Split(string(data), "\n") {
			value, found := strings.CutPrefix(strings.TrimSpace(line), "ReadWritePaths=")
			if !found {
				continue
			}
			for _, path := range strings.Fields(value) {
				path = strings.TrimPrefix(path, "-")
				writable = writable || path == holds || strings.HasPrefix(holds, path+"/")
			}
		}
		if !writable {
			t.Errorf("%s cannot write the key folder %s", unit, holds)
		}
	}
}

// The Linux per-account folder gets one named-user entry (r-x) and a mask
// without write, so its mode reads 0750 and no group-class entry can write.
func TestGrantPublishedSessionReaderSetsOneReadEntry(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := grantPublishedSessionReader(dir, 4242); err != nil {
		if errors.Is(err, unix.EOPNOTSUPP) {
			t.Skip("the test filesystem has no POSIX ACLs")
		}
		t.Fatal(err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o750 {
		t.Fatalf("mode %04o, want 0750 (mask r-x)", info.Mode().Perm())
	}
	acl, err := posixacl.System.Read(dir, info.Mode())
	if err != nil {
		t.Fatal(err)
	}
	found, allowed := acl.NamedUserAllows(4242, 5)
	if !found || !allowed || len(acl.Users) != 1 || len(acl.Groups) != 0 || acl.Mask&2 != 0 || acl.Other != 0 || acl.Group != 0 {
		t.Fatalf("unexpected ACL: %+v", acl)
	}
}
