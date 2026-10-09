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

// unitSyscallFilter returns the allow-listed and deny-listed entries of a
// unit's SystemCallFilter lines.
func unitSyscallFilter(t *testing.T, unit string) (allow, deny map[string]bool) {
	t.Helper()
	data, err := systemdunits.ReadFile(unit)
	if err != nil {
		t.Fatal(err)
	}
	allow, deny = map[string]bool{}, map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		value, ok := strings.CutPrefix(strings.TrimSpace(line), "SystemCallFilter=")
		if !ok {
			continue
		}
		target := allow
		if rest, negated := strings.CutPrefix(value, "~"); negated {
			target, value = deny, rest
		}
		for _, entry := range strings.Fields(value) {
			target[entry] = true
		}
	}
	return allow, deny
}

// The sensor helper's Plane C file-access watch opens fanotify.
// fanotify_init and fanotify_mark belong to @privileged, not to
// @system-service or @network-io, so the unit must allow them by name or
// the seccomp filter answers EPERM despite CAP_SYS_ADMIN and credential
// file access goes unobserved.
func TestSensorHelperSyscallFilterAllowsFanotify(t *testing.T) {
	allow, deny := unitSyscallFilter(t, unitSensorHelper)
	if !allow["@system-service"] {
		t.Fatalf("sensor helper filter no longer starts from @system-service: %v", allow)
	}
	for _, call := range []string{"fanotify_init", "fanotify_mark"} {
		if !allow[call] || deny[call] {
			t.Fatalf("sensor helper SystemCallFilter does not allow %s (allow=%v deny=%v)", call, allow, deny)
		}
	}
	if allow["@privileged"] {
		t.Fatal("sensor helper allows all of @privileged; allow only the fanotify calls")
	}
}

// GAP-0474: a drop-in that widened the gateway sandbox (User=root,
// ProtectHome=false) or pointed it at another config was never named; only
// its symptoms showed. A drop-in that keeps the unit as installed (a site
// proxy) is listed as a warning.
func TestStatusNamesDropInsThatChangeTheGatewayUnit(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	dir := h.env.P("/etc/systemd/system/" + unitGateway + ".d")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"90-site-proxy.conf": "[Service]\nEnvironment=HTTPS_PROXY=http://proxy.example:3128\n",
		"95-env.conf":        "[Service]\nEnvironment=DEFENSECLAW_CONFIG=/etc/other/config.yaml\n",
		"96-widen.conf":      "[Service]\nProtectHome=false\nUser=root\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	status := h.run(Options{Action: ActionStatus})
	got := messagesOf(status.Errors, codeVerify)
	if !strings.Contains(got, "96-widen.conf changes "+unitGateway+" (ProtectHome, User)") || !strings.Contains(got, "95-env.conf changes "+unitGateway+" (Environment=DEFENSECLAW_CONFIG)") {
		t.Fatalf("status does not name the drop-ins: %s", got)
	}
	if strings.Contains(got, "90-site-proxy.conf") || !strings.Contains(messagesOf(status.Warnings, codeUnitDropIn), "90-site-proxy.conf") {
		t.Fatalf("the proxy drop-in is not a %s warning: errors %s warnings %v", codeUnitDropIn, got, status.Warnings)
	}
}

// GAP-1195: ensure must reject a foreign command override even when the
// installed files and the currently running service still look healthy.
func TestEnsureRefusesGatewayExecStartDropIn(t *testing.T) {
	h := newTestHost(t, "linux")
	payload := h.payload("1.0.0")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: payload}))
	dir := h.env.P("/etc/systemd/system/" + unitGateway + ".d")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "99-command.conf"), []byte("[Service]\nExecStart=\nExecStart=/usr/bin/true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	result := h.run(Options{Action: ActionEnsure, PayloadDir: payload})
	if result.OK || result.Noop || !strings.Contains(messagesOf(result.Errors, codeVerify), "99-command.conf") {
		t.Fatalf("ensure accepted the command override: %+v", result)
	}
}
