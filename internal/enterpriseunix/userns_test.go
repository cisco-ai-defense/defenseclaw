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
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func TestUnprivilegedUserNamespaceWarning(t *testing.T) {
	for _, test := range []struct {
		name     string
		settings map[string]string
		warn     bool
		// names is a setting the warning must name besides the limit.
		names string
	}{
		{name: "disabled by limit", settings: map[string]string{sysctlMaxUserNamespaces: "0"}},
		{name: "rhel default", settings: map[string]string{sysctlMaxUserNamespaces: "63229"}, warn: true},
		{name: "apparmor userns and unconfined restrictions", settings: map[string]string{sysctlMaxUserNamespaces: "63229", sysctlAppArmorRestrictUserns: "1", sysctlAppArmorRestrictUnconfined: "1"}},
		{
			name:     "ubuntu 24.04 default: apparmor userns restriction, unconfined profile changes allowed",
			settings: map[string]string{sysctlMaxUserNamespaces: "63229", sysctlAppArmorRestrictUserns: "1", sysctlAppArmorRestrictUnconfined: "0"},
			warn:     true,
			names:    "kernel.apparmor_restrict_unprivileged_unconfined=0",
		},
	} {
		message := unprivilegedUserNamespaceWarning(func(path string) (string, bool) {
			value, ok := test.settings[path]
			return value, ok
		})
		if (message != "") != test.warn {
			t.Fatalf("%s: warning %q, want warning=%v", test.name, message, test.warn)
		}
		if test.warn && !strings.Contains(message, "user.max_user_namespaces="+test.settings[sysctlMaxUserNamespaces]) {
			t.Fatalf("%s: warning does not name the setting: %q", test.name, message)
		}
		if test.names != "" && !strings.Contains(message, test.names) {
			t.Fatalf("%s: warning does not name %s: %q", test.name, test.names, message)
		}
	}
}

// TestVerifyWarnsAboutUnprivilegedUserNamespaces: `enterprise linux verify`
// reports a host where standard users can create user namespaces as a
// warning (never an error), and status stays unchanged.
func TestVerifyWarnsAboutUnprivilegedUserNamespaces(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	ledger := filepath.Join(h.env.P(h.env.Layout.GuardianAuthDir), managed.HookGuardianAuthorizationFile)
	data, _ := json.Marshal(map[string]any{"version": 1, "updated_at": h.env.Now().UTC().Format("2006-01-02T15:04:05Z"), "ok": true, "target_count": 1, "success_count": 1})
	if err := os.WriteFile(ledger, data, 0o640); err != nil {
		t.Fatal(err)
	}
	hasWarning := func(r *enterprisestatus.Result) bool {
		for _, warning := range r.Warnings {
			if warning.Code == codeUserNamespaces {
				return true
			}
		}
		return false
	}
	sysctl := h.env.P(sysctlMaxUserNamespaces)
	if err := os.MkdirAll(filepath.Dir(sysctl), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sysctl, []byte("63229\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	verify := h.run(Options{Action: ActionVerify})
	requireOK(t, verify)
	if !hasWarning(verify) {
		t.Fatalf("verify did not warn about unprivileged user namespaces: %+v", verify.Warnings)
	}
	if status := h.run(Options{Action: ActionStatus}); hasWarning(status) {
		t.Fatalf("status changed: %+v", status.Warnings)
	}
	if err := os.WriteFile(sysctl, []byte("0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if verify := h.run(Options{Action: ActionVerify}); hasWarning(verify) {
		t.Fatalf("verify warned with user.max_user_namespaces=0: %+v", verify.Warnings)
	}
}
