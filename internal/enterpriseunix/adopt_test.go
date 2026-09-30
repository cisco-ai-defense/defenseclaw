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
	"os"
	"path/filepath"
	"strings"
	"testing"

	systemdunits "github.com/defenseclaw/defenseclaw/packaging/systemd"
)

func writeHostFile(t *testing.T, h *testHost, canonical, content string) {
	t.Helper()
	path := h.env.P(canonical)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// legacyUnits are what the earlier manual Linux deployment ran: a gateway
// under the managed unit name, and the guardian watch and timer.
var legacyUnits = map[string]string{
	"/etc/systemd/system/" + unitGateway:                          "[Service]\nExecStart=/opt/defenseclaw/bin/defenseclaw-gateway legacy\n",
	"/etc/systemd/system/defenseclaw-hook-guardian-watch.service": "[Service]\nExecStart=/opt/defenseclaw/bin/defenseclaw-gateway enterprise hooks watch\n",
	"/etc/systemd/system/defenseclaw-hook-guardian.timer":         "[Timer]\nOnCalendar=hourly\n",
}

func legacyHost(t *testing.T) *testHost {
	t.Helper()
	h := newTestHost(t, "linux")
	for path, content := range legacyUnits {
		writeHostFile(t, h, path, content)
		name := filepath.Base(path)
		h.services.active[name] = true
		h.services.enabled[name] = true
	}
	return h
}

func requireLegacyIntact(t *testing.T, h *testHost) {
	t.Helper()
	for path, content := range legacyUnits {
		data, err := os.ReadFile(h.env.P(path))
		if err != nil || string(data) != content {
			t.Fatalf("legacy unit %s not intact: %q %v", path, data, err)
		}
		name := filepath.Base(path)
		if !h.services.isActive(name) || !h.services.enabled[name] {
			t.Fatalf("legacy unit %s is not running and enabled as before (active=%v enabled=%v)", name, h.services.isActive(name), h.services.enabled[name])
		}
	}
}

// --adopt-existing takes over a legacy deployment only once the install is
// known to be possible: a missing payload or an invalid config is refused
// before any legacy unit is stopped, disabled or removed.
func TestAdoptionChangesNothingUntilThePlanIsValid(t *testing.T) {
	t.Run("no payload", func(t *testing.T) {
		h := legacyHost(t)
		requireError(t, h.run(Options{Action: ActionInstall, AdoptExisting: true}), codeInvalidArguments)
		requireLegacyIntact(t, h)
	})
	t.Run("invalid config", func(t *testing.T) {
		h := legacyHost(t)
		cfg := filepath.Join(t.TempDir(), "config.yaml")
		bad := strings.Replace(string(DefaultConfig(h.env.Layout)), "api_port: 18970", "api_port: 18971", 1)
		if err := os.WriteFile(cfg, []byte(bad), 0o600); err != nil {
			t.Fatal(err)
		}
		requireError(t, h.run(Options{Action: ActionInstall, AdoptExisting: true, PayloadDir: h.payload("1.0.0"), ConfigFile: cfg}), codeConfig)
		requireLegacyIntact(t, h)
	})
}

// Adoption is part of the install transaction: when activation fails, the
// rollback puts the legacy unit files back and restarts and re-enables what
// was running, so the host keeps its previous enforcement.
func TestFailedAdoptionRestoresTheLegacyDeployment(t *testing.T) {
	h := legacyHost(t)
	h.healthy = false
	r := h.run(Options{Action: ActionInstall, AdoptExisting: true, PayloadDir: h.payload("1.0.0")})
	requireError(t, r, codeActivate)
	if !hasWarning(r, codeRolledBack) {
		t.Fatalf("expected a rollback: %+v %+v", r.Errors, r.Warnings)
	}
	requireLegacyIntact(t, h)
	archives, _ := filepath.Glob(filepath.Join(h.env.P(h.env.Layout.LifecycleDir), adoptedPrefix+"*.tar.gz"))
	if len(archives) != 1 {
		t.Fatalf("expected the adoption backup to be kept, got %v", archives)
	}
	if exists(h.env.P("/etc/systemd/system/" + unitAPISocket)) {
		t.Fatal("the rolled-back install left its socket unit behind")
	}

	h.healthy = true
	requireOK(t, h.run(Options{Action: ActionInstall, AdoptExisting: true, PayloadDir: h.payload("1.0.0")}))
	for _, name := range []string{"defenseclaw-hook-guardian-watch.service", "defenseclaw-hook-guardian.timer"} {
		if exists(h.env.P("/etc/systemd/system/"+name)) || h.services.isActive(name) || h.services.enabled[name] {
			t.Fatalf("a successful adoption kept legacy unit %s", name)
		}
	}
	if h.read("/etc/systemd/system/"+unitGateway) == legacyUnits["/etc/systemd/system/"+unitGateway] {
		t.Fatal("the adopted gateway unit was not replaced")
	}
}

// packageHost stages what the deb/rpm places before its postinstall runs.
func packageHost(t *testing.T, version string) *testHost {
	t.Helper()
	h := newTestHost(t, "linux")
	bin := h.env.P(h.env.Layout.BinDir)
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	staged := h.payload(version)
	for _, name := range []string{binGateway, binHook, binSensorHelper} {
		if err := h.env.copyFileAtomic(filepath.Join(staged, name), filepath.Join(bin, name), 0o755, rootOwner()); err != nil {
			t.Fatal(err)
		}
	}
	for _, unit := range h.services.Units() {
		data, err := systemdunits.ReadFile(unit.Name)
		if err != nil {
			t.Fatal(err)
		}
		writeHostFile(t, h, h.services.DefinitionPath(unit, ChannelPackage), string(data))
	}
	return h
}

// systemd prefers /etc/systemd/system over the packaged /usr/lib units. A
// unit an earlier manual deployment left there under a packaged name (the
// oneshot guardian of the base layout, say) would silently replace the
// package's definition, so the package channel treats it as a leftover,
// adoption removes it, and verify names any override that appears later.
func TestPackageChannelTreatsEtcUnitsAsOverrides(t *testing.T) {
	h := packageHost(t, "1.2.0")
	override := "/etc/systemd/system/" + unitGuardian
	writeHostFile(t, h, override, "[Service]\nType=oneshot\nExecStart=/opt/defenseclaw/bin/defenseclaw-gateway enterprise hooks reconcile\n")

	refused := h.run(Options{Action: ActionEnsure, FromPackage: true, Reason: "package"})
	requireError(t, refused, codeUnmanagedLayout)
	if !strings.Contains(refused.Errors[0].Message, override) {
		t.Fatalf("the refusal does not name the override: %+v", refused.Errors)
	}

	requireOK(t, h.run(Options{Action: ActionEnsure, FromPackage: true, Reason: "package", AdoptExisting: true}))
	if exists(h.env.P(override)) {
		t.Fatal("adoption kept the /etc unit that overrides the packaged guardian")
	}

	writeHostFile(t, h, override, "[Service]\nType=oneshot\n")
	verify := h.run(Options{Action: ActionVerify})
	found := false
	for _, e := range verify.Errors {
		found = found || strings.Contains(e.Message, unitGuardian+" is loaded from "+override)
	}
	if !found {
		t.Fatalf("verify does not report the override: %+v", verify.Errors)
	}
}

// On a merged-/usr host a split-/usr systemd reports a packaged unit under
// /lib/systemd/system; that is the same file, not an override.
func TestFragmentCheckAcceptsTheMergedUsrAlias(t *testing.T) {
	h := newTestHost(t, "linux")
	writeHostFile(t, h, "/usr/lib/systemd/system/"+unitGateway, "[Service]\n")
	if err := os.Symlink("usr/lib", h.env.P("/lib")); err != nil {
		t.Fatal(err)
	}
	if !sameUnitFile(h.env, "/lib/systemd/system/"+unitGateway, "/usr/lib/systemd/system/"+unitGateway) {
		t.Fatal("the merged-/usr alias of the packaged unit was reported as an override")
	}
	writeHostFile(t, h, "/etc/systemd/system/"+unitGateway, "[Service]\n")
	if sameUnitFile(h.env, "/etc/systemd/system/"+unitGateway, "/usr/lib/systemd/system/"+unitGateway) {
		t.Fatal("an /etc override was accepted as the packaged unit")
	}
}
