// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// upgradePackage replaces the binaries the way a deb/rpm upgrade does.
func upgradePackage(t *testing.T, h *testHost, version string) {
	t.Helper()
	staged := h.payload(version)
	for _, name := range []string{binGateway, binHook, binSensorHelper} {
		if err := h.env.copyFileAtomic(filepath.Join(staged, name), h.env.P(filepath.Join(h.env.Layout.BinDir, name)), 0o755, rootOwner()); err != nil {
			t.Fatal(err)
		}
	}
}

func socketCalls(h *testHost, from int) []string {
	var out []string
	for _, call := range h.services.calls[from:] {
		if strings.HasSuffix(call, ".socket") && !strings.HasPrefix(call, "enable ") {
			out = append(out, call)
		}
	}
	return out
}

// PID 1 holds the gateway's listeners across restarts. Releasing them on
// every package upgrade opened a window in which any local user could bind
// 127.0.0.1:18970 and keep the gateway (and with it the hook socket) from
// starting. A socket is only replaced when its definition changed, and then
// in one restart job.
func TestPackageUpgradeKeepsUnchangedSocketsListening(t *testing.T) {
	h := packageHost(t, "1.2.0")
	requireOK(t, h.run(Options{Action: ActionEnsure, FromPackage: true, Reason: "package"}))

	upgradePackage(t, h, "1.3.0")
	before := len(h.services.calls)
	r := h.run(Options{Action: ActionEnsure, FromPackage: true, Reason: "package"})
	requireOK(t, r)
	if r.InstalledVersion != "1.3.0" {
		t.Fatalf("installed version %q", r.InstalledVersion)
	}
	if calls := socketCalls(h, before); len(calls) > 0 {
		t.Fatalf("an upgrade with unchanged socket units touched the listeners: %v", calls)
	}

	// The previous package shipped a different API socket definition.
	record, err := h.env.loadDeployment()
	if err != nil || record == nil {
		t.Fatal(err)
	}
	api := filepath.Join(packageUnitDir, unitAPISocket)
	if record.Files[api] == "" {
		t.Fatalf("the package channel does not record the applied unit %s", api)
	}
	record.Files[api] = strings.Repeat("0", 64)
	if err := h.env.saveDeployment(record); err != nil {
		t.Fatal(err)
	}
	upgradePackage(t, h, "1.4.0")
	before = len(h.services.calls)
	requireOK(t, h.run(Options{Action: ActionEnsure, FromPackage: true, Reason: "package"}))
	calls := socketCalls(h, before)
	if strings.Join(calls, ",") != "restart "+unitAPISocket {
		t.Fatalf("a changed socket definition must be replaced in one restart, and only that socket: %v", calls)
	}
}

// GAP-0746: after chown -R root:wheel over the deployment the stale
// run/hook.sock belonged to root, the macOS gateway refused to replace it,
// and every repair failed activation and rolled back. repair removes a hook
// socket another account owns that nothing answers on.
func TestRepairRemovesAStaleHookSocketAnotherAccountOwns(t *testing.T) {
	h := newTestHost(t, "darwin")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	// A socket path under the test root is too long to bind; bind a short one
	// and move it into place.
	short, err := os.MkdirTemp("", "s")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(short) })
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(short, "h.sock"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	listener.SetUnlinkOnClose(false)
	_ = listener.Close()
	socket := h.env.P(h.env.Layout.HookSocketPath)
	if err := os.Rename(filepath.Join(short, "h.sock"), socket); err != nil {
		t.Fatal(err)
	}
	h.owners[socket] = [2]int{0, 0}
	r := h.run(Options{Action: ActionRepair})
	requireOK(t, r)
	if _, err := os.Lstat(socket); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("repair left the stale root-owned hook socket in place: %v", err)
	}
	if !strings.Contains(strings.Join(r.Changes, "\n"), h.env.Layout.HookSocketPath) {
		t.Fatalf("repair does not say it removed the socket: %v", r.Changes)
	}
}
