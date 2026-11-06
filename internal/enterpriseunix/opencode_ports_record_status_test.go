// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package enterpriseunix

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

func openCodeRecordWarnings(t *testing.T, env *Env) map[string]string {
	t.Helper()
	r := &enterprisestatus.Result{}
	env.warnOpenCodePortsRecord(r)
	codes := map[string]string{}
	for _, warning := range r.Warnings {
		codes[warning.Code] = warning.Message
	}
	return codes
}

// gas-ux-r1 GAP-0053, REVIEW-gx053-4/5 MF2: status and verify warn when the
// guardian's OpenCode ports record cannot be read; a non-root status that
// cannot open the guardian folder says it could not check, where OpenCode is
// on the machine policy.
func TestStatusWarnsOnAnUnreadableOpenCodePortsRecord(t *testing.T) {
	root := t.TempDir()
	env := &Env{GOOS: "linux", Root: root, Layout: mustLayout(t, "linux")}
	record := env.P(filepath.Join(env.Layout.GuardianAuthDir, enterprisehooks.UnixOpenCodeServicePortsFileName))
	if err := os.MkdirAll(filepath.Dir(record), 0o750); err != nil {
		t.Fatal(err)
	}
	previous := openCodePortsRecordGeteuid
	t.Cleanup(func() { openCodePortsRecordGeteuid = previous })
	openCodePortsRecordGeteuid = func() int { return 0 }

	if codes := openCodeRecordWarnings(t, env); len(codes) != 0 {
		t.Fatalf("no record: %v", codes)
	}
	if err := os.WriteFile(record, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if codes := openCodeRecordWarnings(t, env); codes["opencode_port_record_unreadable"] == "" {
		t.Fatalf("a corrupt record is not reported: %v", codes)
	}

	if os.Geteuid() == 0 {
		t.Skip("the non-root case needs a non-root test runner")
	}
	openCodePortsRecordGeteuid = func() int { return 1000 }
	folder := filepath.Dir(record)
	if err := os.Chmod(folder, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(folder, 0o750) })
	if codes := openCodeRecordWarnings(t, env); len(codes) != 0 {
		t.Fatalf("without OpenCode on the machine policy nothing is said: %v", codes)
	}
	plugin := env.P(filepath.Join(openCodePluginDir(env.Layout), "index.js"))
	if err := os.MkdirAll(filepath.Dir(plugin), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(plugin, []byte("//"), 0o644); err != nil {
		t.Fatal(err)
	}
	codes := openCodeRecordWarnings(t, env)
	if msg := codes["opencode_port_record_unchecked"]; msg == "" || !filepath.IsAbs(env.Layout.GuardianAuthDir) {
		t.Fatalf("a non-root status says nothing: %v", codes)
	}
}

// Status, verify (and doctor, from status) name each contested port, its
// claimants and the exact clear command.
func TestStatusNamesContestedOpenCodePorts(t *testing.T) {
	root := t.TempDir()
	env := &Env{GOOS: "linux", Root: root, Layout: mustLayout(t, "linux")}
	record := env.P(filepath.Join(env.Layout.GuardianAuthDir, enterprisehooks.UnixOpenCodeServicePortsFileName))
	if err := os.MkdirAll(filepath.Dir(record), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(record, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := loadOpenCodePortsRecord
	t.Cleanup(func() { loadOpenCodePortsRecord = previous })
	loadOpenCodePortsRecord = func(string) (enterprisehooks.UnixOpenCodeServicePortsState, error) {
		return enterprisehooks.UnixOpenCodeServicePortsState{Exists: true,
			Contested: []enterprisehooks.UnixOpenCodeContestedPort{{Port: 25003, UIDs: []int{1001, 1002}}}}, nil
	}
	msg := openCodeRecordWarnings(t, env)["opencode_port_contested"]
	for _, want := range []string{"port 25003", "uids 1001, 1002", "sudo /opt/defenseclaw/bin/defenseclaw-gateway enterprise linux opencode-port-clear 25003 --yes"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("the contested line %q lacks %q", msg, want)
		}
	}
}
