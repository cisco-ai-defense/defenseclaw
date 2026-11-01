// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"syscall"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/enterpriseunix"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

type anchorsInstallDoc struct {
	SchemaVersion  int                        `json:"schema_version"`
	Command        string                     `json:"command"`
	OK             bool                       `json:"ok"`
	Result         string                     `json:"result"`
	Anchors        string                     `json:"anchors"`
	SHA256         string                     `json:"sha256"`
	PreviousSHA256 string                     `json:"previous_sha256"`
	TenantID       string                     `json:"tenant_id"`
	DeviceGroups   []string                   `json:"device_groups"`
	KeyIDs         []string                   `json:"key_ids"`
	Warnings       []enterprisebundle.Warning `json:"warnings"`
	Errors         []bundleError              `json:"errors"`
}

func runAnchorsInstall(t *testing.T, args ...string) (anchorsInstallDoc, int) {
	t.Helper()
	out, code := runBundle(t, append([]string{"anchors", "install"}, args...)...)
	var doc anchorsInstallDoc
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("not one JSON document (exit %d): %v\n%s", code, err, out)
	}
	if doc.SchemaVersion != 1 || doc.Command != "anchors install" || doc.Warnings == nil || doc.Errors == nil {
		t.Fatalf("document frame: %+v", doc)
	}
	return doc, code
}

// anchorsInstallDevice makes the test a standalone managed Linux or macOS
// device whose lifecycle runs under a temp root as root, with the trust
// checks reduced to the parts a test account can satisfy.
func anchorsInstallDevice(t *testing.T) (root string, layout managed.StandaloneLayout, euid *int) {
	t.Helper()
	e := newBundleCLIEnv(t)
	bundleDevice(t, e)
	layout, err := managed.StandaloneLayoutFor(enterpriseunix.CurrentGOOS())
	if err != nil {
		t.Skip(err)
	}
	root = t.TempDir()
	uid := 0
	euid = &uid
	bundleDefaultAnchors = func() (string, error) {
		return filepath.Join(layout.ConfigDir, "trust", enterprisebundle.AnchorsName), nil
	}
	previous := newUnixLifecycleEnv
	newUnixLifecycleEnv = func(goos string) (*enterpriseunix.Env, error) {
		return &enterpriseunix.Env{GOOS: goos, Root: root, Layout: layout, Geteuid: func() int { return *euid },
			Trust:  func(string, enterpriseunix.TrustKind) error { return nil },
			Lchown: func(string, int, int) error { return nil }, Now: time.Now,
			LockTimeout: 50 * time.Millisecond, PollInterval: 10 * time.Millisecond}, nil
	}
	t.Cleanup(func() { newUnixLifecycleEnv = previous })
	return root, layout, euid
}

func testAnchorsFile(t *testing.T, statuses ...string) string {
	t.Helper()
	keys := ""
	for i, status := range statuses {
		public, _, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		spki, err := x509.MarshalPKIXPublicKey(public)
		if err != nil {
			t.Fatal(err)
		}
		if i > 0 {
			keys += ","
		}
		keys += fmt.Sprintf(`{"key_id":"k%d","alg":"ed25519","public_key":%q,"not_before":"2020-01-01T00:00:00Z","not_after":"2099-01-01T00:00:00Z","status":%q}`,
			i+1, base64.StdEncoding.EncodeToString(spki), status)
	}
	path := filepath.Join(t.TempDir(), enterprisebundle.AnchorsName)
	doc := `{"schema_version":1,"tenant_id":"acme","device_groups":[],"min_version":0,"keys":[` + keys + `]}`
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// Every refusal prints one anchors-install document with its code: Secure
// Client and computers that are not standalone managed devices (per-user
// installs) before anything is read, a caller bug with exit 2, a standard
// account with not_root.
func TestEnterpriseBundleAnchorsInstallRefusals(t *testing.T) {
	_, _, euid := anchorsInstallDevice(t)
	file := testAnchorsFile(t, "active")

	bundleSecureClient = func() bool { return true }
	if doc, code := runAnchorsInstall(t, "--file", file, "--json"); code != 1 || doc.OK || doc.Result != "refused" ||
		len(doc.Errors) != 1 || doc.Errors[0].Code != "not_supported_secure_client" {
		t.Fatalf("Secure Client: exit %d %+v", code, doc)
	}
	bundleSecureClient = func() bool { return false }

	bundleManagedDevice = func() bool { return false }
	if doc, code := runAnchorsInstall(t, "--file", file, "--json"); code != 1 || len(doc.Errors) != 1 || doc.Errors[0].Code != "not_managed" {
		t.Fatalf("not managed: exit %d %+v", code, doc)
	}
	bundleManagedDevice = func() bool { return true }

	if doc, code := runAnchorsInstall(t, "--json"); code != 2 || len(doc.Errors) != 1 || doc.Errors[0].Code != "invalid_arguments" {
		t.Fatalf("no --file: exit %d %+v", code, doc)
	}

	*euid = 1000
	if doc, code := runAnchorsInstall(t, "--file", file, "--json"); code != 1 || len(doc.Errors) != 1 || doc.Errors[0].Code != "not_root" {
		t.Fatalf("not root: exit %d %+v", code, doc)
	}
}

// A first install reports what was installed for the agent's own report;
// the same file again is unchanged; a lifecycle run holding the lock is
// lifecycle_busy with the retry exit code 75.
func TestEnterpriseBundleAnchorsInstallReportsTheInstalledFile(t *testing.T) {
	root, layout, _ := anchorsInstallDevice(t)
	file := testAnchorsFile(t, "active", "retired")
	doc, code := runAnchorsInstall(t, "--file", file, "--json")
	want := filepath.Join(layout.ConfigDir, "trust", enterprisebundle.AnchorsName)
	if code != 0 || !doc.OK || doc.Result != "installed" || doc.Anchors != want || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(doc.SHA256) ||
		doc.PreviousSHA256 != "" || doc.TenantID != "acme" || len(doc.KeyIDs) != 2 || doc.KeyIDs[0] != "k1" || len(doc.Errors) != 0 {
		t.Fatalf("install: exit %d %+v", code, doc)
	}
	raw, err := os.ReadFile(filepath.Join(root, want))
	source, _ := os.ReadFile(file)
	if err != nil || string(raw) != string(source) {
		t.Fatalf("installed file: %v", err)
	}
	if again, code := runAnchorsInstall(t, "--file", file, "--json"); code != 0 || again.Result != "unchanged" || again.SHA256 != doc.SHA256 {
		t.Fatalf("again: exit %d %+v", code, again)
	}

	lockPath := filepath.Join(root, layout.LifecycleDir, "lifecycle.lock")
	lock, err := os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	busy, code := runAnchorsInstall(t, "--file", testAnchorsFile(t, "active"), "--lock-wait", "1s", "--json")
	if code != 75 || busy.OK || len(busy.Errors) != 1 || busy.Errors[0].Code != "lifecycle_busy" || busy.SHA256 != doc.SHA256 {
		t.Fatalf("busy: exit %d %+v", code, busy)
	}
}

// #1316: --device-group pins the device to one group. The result names the
// group the installed file lists; a file that does not allow it, a malformed
// name, and --device-group without --trust-anchors on apply are refused.
func TestEnterpriseBundleAnchorsInstallPinsTheDeviceGroup(t *testing.T) {
	root, layout, _ := anchorsInstallDevice(t)
	file := testAnchorsFile(t, "active")
	doc, code := runAnchorsInstall(t, "--file", file, "--device-group", "eng", "--json")
	if code != 0 || !doc.OK || doc.Result != "installed" || len(doc.DeviceGroups) != 1 || doc.DeviceGroups[0] != "eng" {
		t.Fatalf("pinned install: exit %d %+v", code, doc)
	}
	raw, err := os.ReadFile(filepath.Join(root, layout.ConfigDir, "trust", enterprisebundle.AnchorsName))
	if err != nil || !regexp.MustCompile(`"device_groups": \[\s*"eng"\s*\]`).Match(raw) {
		t.Fatalf("installed file: %v\n%s", err, raw)
	}

	if doc, code := runAnchorsInstall(t, "--file", file, "--device-group", "-eng", "--json"); code != 2 || len(doc.Errors) != 1 || doc.Errors[0].Code != "invalid_arguments" {
		t.Fatalf("bad group name: exit %d %+v", code, doc)
	}
	listed := filepath.Join(t.TempDir(), enterprisebundle.AnchorsName)
	source, _ := os.ReadFile(file)
	if err := os.WriteFile(listed, []byte(regexp.MustCompile(`"device_groups":\[\]`).ReplaceAllString(string(source), `"device_groups":["sales"]`)), 0o600); err != nil {
		t.Fatal(err)
	}
	if doc, code := runAnchorsInstall(t, "--file", listed, "--device-group", "eng", "--json"); code != 1 || len(doc.Errors) != 1 || doc.Errors[0].Code != "anchor_invalid" {
		t.Fatalf("group not in the file: exit %d %+v", code, doc)
	}

	for _, args := range [][]string{
		{"apply", "--bundle", "/nonexistent.dcbundle", "--device-group", "eng", "--json"},
		{"apply", "--inbox", "--trust-anchors", file, "--json"},
	} {
		out, code := runBundle(t, args...)
		var refusal struct {
			Errors []bundleError `json:"errors"`
		}
		if err := json.Unmarshal([]byte(out), &refusal); err != nil || code != 2 || len(refusal.Errors) != 1 || refusal.Errors[0].Code != "invalid_arguments" {
			t.Fatalf("%v: exit %d %s", args, code, out)
		}
	}
}

// The signer warnings are the codes bundle status already reports.
func TestBundleSignerWarningCodes(t *testing.T) {
	anchors, _, err := enterprisebundle.ReadAnchorsFile(testAnchorsFile(t, "active", "revoked"), nil)
	if err != nil {
		t.Fatal(err)
	}
	for signer, want := range map[string]string{"": "", "k1": "", "k2": "key_revoked", "k9": "key_unknown"} {
		got := ""
		if w := bundleSignerWarning(anchors, signer); w != nil {
			got = w.Code
		}
		if got != want {
			t.Errorf("signer %q: warning %q, want %q", signer, got, want)
		}
	}
}

func TestEnterpriseBundleAnchorsVerbIsRegistered(t *testing.T) {
	cmd, _, err := newEnterpriseBundleCommand().Find([]string{"anchors", "install"})
	if err != nil || cmd.Name() != "install" || cmd.Flags().Lookup("file") == nil || cmd.Flags().Lookup("lock-wait") == nil {
		t.Fatalf("anchors install: %v", err)
	}
}
