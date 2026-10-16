// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package sandboxcli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

func TestManagedMacDoctorUsesTheGatewaysE2fsprogsSetting(t *testing.T) {
	withManagedHost(t)
	ta := newTestApp(t, "")
	ta.GOOS = "darwin"
	ta.daemon.status.Managed = managedStatusFixture()
	ta.daemon.status.Managed.Driver = "vm"
	// The access rule refuses an administrator's folder under an ancestor
	// some account cannot traverse, before the setting this test checks.
	root := testenv.TraversableTempDir(t)
	prefix, sbin := filepath.Join(root, "e2fsprogs"), filepath.Join(root, "e2fsprogs", "sbin")
	if err := os.MkdirAll(sbin, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, tool := range []string{"mke2fs", "debugfs"} {
		if err := os.WriteFile(filepath.Join(sbin, tool), []byte("tool"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	admin, answered, trusted := prefix, true, true
	ta.ManagedE2fsprogsDir = func(context.Context) (string, bool) { return admin, answered }
	ta.ManagedAccountHome = func() (string, error) { return ta.home, nil }
	ta.HostDoctor = func(_ context.Context, d *openshell.Doctor) *openshell.DoctorReport {
		if got, _ := d.HomeDir(); got != ta.home {
			t.Fatalf("doctor home = %q, gateway home %q", got, ta.home)
		}
		d.TrustedE2fsprogsDir = func(string, string) error {
			if !trusted {
				return errors.New("another account can change it")
			}
			return nil
		}
		d.TrustedE2fsprogsFile = func(string, string) error { return nil }
		return hostReport(nil)(bg, d)
	}
	row := func() *openshell.Check { return ta.runDoctor(bg).Get(openshell.CheckIDManagedE2fsprogs) }
	for _, form := range []string{prefix, sbin} {
		admin = form
		if got := row(); got == nil || got.Status != openshell.StatusPass || !strings.Contains(got.Detail, sbin) {
			t.Fatalf("managed setting %q: %+v", form, got)
		}
	}
	admin = filepath.Join(root, "bad")
	if got := row(); got == nil || got.Status != openshell.StatusFail || got.Fix == nil || !strings.Contains(got.Fix.Summary, "install prefix or the folder") {
		t.Fatalf("bad administrator directory: %+v", got)
	}
	admin, trusted = prefix, false
	if got := row(); got == nil || got.Status != openshell.StatusFail || !strings.Contains(got.Detail, "not trusted") {
		t.Fatalf("untrusted administrator directory: %+v", got)
	}
	trusted, answered = true, false
	if got := row(); got == nil || got.Status != openshell.StatusFail || !strings.Contains(got.Detail, "did not answer") {
		t.Fatalf("unknown administrator directory: %+v", got)
	}
	ta.daemon.status.Managed = nil
	if got := row(); got == nil || got.Status != openshell.StatusFail || !strings.Contains(got.Detail, "did not answer") {
		t.Fatalf("unknown daemon and administrator directory: %+v", got)
	}
}
