// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package enterpriseunix

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestSandboxGroupsRowAcceptsNamedKVMACL(t *testing.T) {
	h := newOSHost(t, "linux")
	bob := SandboxAccount{Name: "bob", UID: h.alice.UID + 1, Home: "/home/bob"}
	h.ops.accounts = append(h.ops.accounts, bob)
	h.ops.groups["alice"] = []string{"alice", "kvm", "docker"}
	h.ops.groups["bob"] = []string{"bob", "docker"}
	dev := h.env.P(kvmDevice)
	if err := os.MkdirAll(filepath.Dir(dev), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dev, nil, 0o660); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dev, 0o660); err != nil {
		t.Fatal(err)
	}
	acl := make([]byte, 4+5*8)
	binary.LittleEndian.PutUint32(acl, 2)
	for i, entry := range [][3]uint32{
		{0x01, 6, ^uint32(0)}, {0x02, 6, uint32(bob.UID)},
		{0x04, 6, ^uint32(0)}, {0x10, 6, ^uint32(0)}, {0x20, 0, ^uint32(0)},
	} {
		off := 4 + i*8
		binary.LittleEndian.PutUint16(acl[off:], uint16(entry[0]))
		binary.LittleEndian.PutUint16(acl[off+2:], uint16(entry[1]))
		binary.LittleEndian.PutUint32(acl[off+4:], entry[2])
	}
	if err := unix.Setxattr(dev, "system.posix_acl_access", acl, 0); err != nil {
		if errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EOPNOTSUPP) {
			t.Skip("test filesystem has no POSIX ACLs")
		}
		t.Fatal(err)
	}
	vm := map[string]any{"install": "prerequisite", "driver": "vm", "driver_fallback": "docker"}
	requireOK(t, h.ensure(sandboxConfig(t, "linux", true, vm)))
	h.registerSandboxUser(t, bob)
	r := h.run(Options{Action: ActionStatus})
	if state, ok := rowState(r, "sandbox groups kvm"); !ok || !strings.HasPrefix(state, "ok:") {
		t.Fatalf("named user KVM ACL was ignored: %q", state)
	}
}
