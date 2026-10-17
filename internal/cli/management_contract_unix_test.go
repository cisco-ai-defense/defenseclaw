// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/contracttest"
	"github.com/defenseclaw/defenseclaw/internal/enterpriseunix"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// contractHostCommands answers `systemctl --version` as a supported systemd
// host does, and the service account lookups as a device the package has not
// installed yet does (getent exit 2, dscl eDSRecordNotFound). It runs no
// other host command.
type contractHostCommands struct{ noHostCommands }

func (c contractHostCommands) Run(ctx context.Context, name string, args ...string) (enterpriseunix.CommandResult, error) {
	switch {
	case name == "systemctl" && len(args) == 1 && args[0] == "--version":
		return enterpriseunix.CommandResult{Stdout: []byte("systemd 252 (252-46.el9)\n")}, nil
	case name == "getent" && len(args) == 2 && args[0] == "passwd":
		return enterpriseunix.CommandResult{ExitCode: 2}, errors.New("exit status 2")
	case name == "dscl" && len(args) == 4 && args[1] == "-read":
		return enterpriseunix.CommandResult{ExitCode: 56}, errors.New("eDSRecordNotFound")
	}
	return c.noHostCommands.Run(ctx, name, args...)
}

// contractUnixEnv points the Linux and macOS lifecycle at an empty device
// tree that a root caller runs against. On Linux the tree and the host
// commands show systemd as the running init system, as on a supported host,
// so both platforms report the same device that is not installed yet.
func contractUnixEnv(t *testing.T) (root string, layout managed.StandaloneLayout) {
	t.Helper()
	goos := enterpriseunix.CurrentGOOS()
	layout, err := managed.StandaloneLayoutFor(goos)
	if err != nil {
		t.Skip(err)
	}
	root = t.TempDir()
	if goos == "linux" {
		if err := os.MkdirAll(filepath.Join(root, "run", "systemd", "system"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	previous := newUnixLifecycleEnv
	newUnixLifecycleEnv = func(goos string) (*enterpriseunix.Env, error) {
		// The test runs unprivileged: ownership changes are no-ops, as root
		// on a real device makes them succeed.
		return &enterpriseunix.Env{GOOS: goos, Root: root, Layout: layout, Geteuid: func() int { return 0 }, Runner: contractHostCommands{},
			Lchown: func(string, int, int) error { return nil }, Fchown: func(*os.File, int, int) error { return nil }}, nil
	}
	t.Cleanup(func() { newUnixLifecycleEnv = previous })
	return root, layout
}

func contractUnixPlatform() string {
	if enterpriseunix.CurrentGOOS() == "darwin" {
		return "macos"
	}
	return "linux"
}

// TestManagementContractUnixStatusAndSecrets validates `enterprise <os>
// status`, `enterprise secret status` and `enterprise secret set` as a root
// caller prints them on a device that is not installed yet (contract 5.0).
func TestManagementContractUnixStatusAndSecrets(t *testing.T) {
	schemas := contracttest.Compile(t)
	root, layout := contractUnixEnv(t)

	cmd := &cobra.Command{}
	cmd.SetContext(t.Context())
	var out bytes.Buffer
	cmd.SetOut(&out)
	err := runUnixLifecycle(cmd, contractUnixPlatform(), "status", &unixLifecycleOptions{json: true})
	doc := schemas.Validate(t, "lifecycle-result.schema.json", out.Bytes())
	requireExit(t, doc, runExit(err), 0)
	if doc["ok"] != true || doc["installed"] != false {
		t.Fatalf("status of an empty device = %s", out.String())
	}

	const value = "contract-test-credential-value"
	set := newEnterpriseSecretCommand("set", "")
	set.SetContext(t.Context())
	out.Reset()
	set.SetOut(&out)
	set.SetIn(strings.NewReader(value + "\n"))
	err = runEnterpriseSecret(set, "set", &enterpriseSecretOptions{name: "ai-defense-api-key", fromStdin: true, json: true})
	if strings.Contains(out.String(), value) {
		t.Fatalf("the credential value was printed: %s", out.String())
	}
	doc = schemas.Validate(t, "secret-result.schema.json", out.Bytes())
	requireExit(t, doc, runExit(err), 0)

	secrets := root + layout.SecretsDir
	if err := os.MkdirAll(secrets, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(secrets, "splunk-hec-token"), []byte("contract-status-value"), 0o600); err != nil {
		t.Fatal(err)
	}
	status := newEnterpriseSecretCommand("status", "")
	out.Reset()
	status.SetOut(&out)
	if err := runEnterpriseSecret(status, "status", &enterpriseSecretOptions{json: true}); err != nil {
		t.Fatalf("secret status: %v", err)
	}
	if strings.Contains(out.String(), "contract-status-value") {
		t.Fatalf("secret status printed a value: %s", out.String())
	}
	schemas.Validate(t, "secret-result.schema.json", out.Bytes())
}

// TestManagementContractBundleApplyArgumentErrorsPrintNoJSON pins guide
// section 2.3: on a managed device, `bundle apply` argument errors print
// nothing on stdout and exit 2, so the agent classifies them by the exit
// code alone (bundle verify and anchors install print invalid_arguments).
func TestManagementContractBundleApplyArgumentErrorsPrintNoJSON(t *testing.T) {
	e := newBundleCLIEnv(t)
	bundleDevice(t, e)
	bundle := filepath.Join(e.dir, "policy.dcbundle")
	for name, args := range map[string][]string{
		"no --bundle":           {"apply", "--json"},
		"--bundle and --inbox":  {"apply", "--bundle", bundle, "--inbox", "--json"},
		"--lock-wait over 15m":  {"apply", "--bundle", bundle, "--lock-wait", "16m", "--json"},
		"negative --lock-wait":  {"apply", "--bundle", bundle, "--lock-wait", "-1s", "--json"},
		"unknown flag":          {"apply", "--bundle", bundle, "--bogus", "--json"},
		"stray argument":        {"apply", "--bundle", bundle, "extra", "--json"},
		"malformed --lock-wait": {"apply", "--bundle", bundle, "--lock-wait", "soon", "--json"},
		// F10: --delivery-id is 1 to 128 of A-Z a-z 0-9 . _ : -.
		"empty --delivery-id":            {"apply", "--bundle", bundle, "--delivery-id", "", "--json"},
		"--delivery-id over 128 bytes":   {"apply", "--bundle", bundle, "--delivery-id", strings.Repeat("a", 129), "--json"},
		"--delivery-id with a space":     {"apply", "--bundle", bundle, "--delivery-id", "agent 7", "--json"},
		"--delivery-id with a control":   {"apply", "--bundle", bundle, "--delivery-id", "agent\x1b7", "--json"},
		"--delivery-id with a slash":     {"apply", "--bundle", bundle, "--delivery-id", "agent/7", "--json"},
		"--delivery-id with a non-ASCII": {"apply", "--bundle", bundle, "--delivery-id", "agent\u00e97", "--json"},
	} {
		t.Run(name, func(t *testing.T) {
			out, code := runBundle(t, args...)
			if out != "" || code != 2 {
				t.Fatalf("apply %v: exit %d, stdout %q; want exit 2 and no stdout", args, code, out)
			}
		})
	}
	out, code := runBundle(t, "verify", "--json")
	if code != 2 || !strings.Contains(out, `"invalid_arguments"`) {
		t.Fatalf("verify without --bundle: exit %d, stdout %q; want a JSON invalid_arguments document", code, out)
	}
}

// TestManagementContractAnchorsInstallRefusals validates the refusals of
// `enterprise bundle anchors install` before it reads the source.
func TestManagementContractAnchorsInstallRefusals(t *testing.T) {
	schemas := contracttest.Compile(t)
	e := newBundleCLIEnv(t)
	e.writeAnchors(t, map[string]any{"k1": e.edKey.Public()})
	for name, setup := range map[string]func(){
		"not managed":   func() { bundleManagedDevice = func() bool { return false } },
		"secure client": func() { bundleSecureClient = func() bool { return true } },
	} {
		t.Run(name, func(t *testing.T) {
			savedDevice, savedSC := bundleManagedDevice, bundleSecureClient
			t.Cleanup(func() { bundleManagedDevice, bundleSecureClient = savedDevice, savedSC })
			setup()
			out, code := runBundle(t, "anchors", "install", "--file", e.anchors, "--json")
			doc := schemas.Validate(t, "anchors-install.schema.json", []byte(out))
			requireExit(t, doc, code, bundleFailureExitCode())
		})
	}
}

// TestManagementContractAnchorsInstallResults validates every result of
// `enterprise bundle anchors install` on a managed device: installed,
// unchanged, replaced, and the refusals an agent acts on (insecure or
// invalid source, usage, busy, not root).
func TestManagementContractAnchorsInstallResults(t *testing.T) {
	schemas := contracttest.Compile(t)
	root, layout, euid := anchorsInstallDevice(t)
	install := func(want int, args ...string) map[string]any {
		t.Helper()
		out, code := runBundle(t, append([]string{"anchors", "install"}, args...)...)
		doc := schemas.Validate(t, "anchors-install.schema.json", []byte(out))
		requireExit(t, doc, code, want)
		return doc
	}
	errorCode := func(doc map[string]any) any {
		errs, _ := doc["errors"].([]any)
		if len(errs) == 0 {
			return nil
		}
		return errs[0].(map[string]any)["code"]
	}
	first := testAnchorsFile(t, "active", "retired")
	if doc := install(0, "--file", first, "--json"); doc["result"] != "installed" {
		t.Fatalf("first install: %v", doc)
	}
	if doc := install(0, "--file", first, "--json"); doc["result"] != "unchanged" {
		t.Fatalf("same file again: %v", doc)
	}
	if doc := install(0, "--file", testAnchorsFile(t, "active", "revoked"), "--json"); doc["result"] != "replaced" || doc["previous_sha256"] == nil {
		t.Fatalf("other file: %v", doc)
	}

	invalid := filepath.Join(t.TempDir(), "bundle-anchors.json")
	if err := os.WriteFile(invalid, []byte(`{"schema_version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if doc := install(1, "--file", invalid, "--json"); errorCode(doc) != "anchor_invalid" {
		t.Fatalf("invalid source: %v", doc)
	}

	insecure := testAnchorsFile(t, "active")
	trusting := newUnixLifecycleEnv
	t.Cleanup(func() { newUnixLifecycleEnv = trusting })
	newUnixLifecycleEnv = func(goos string) (*enterpriseunix.Env, error) {
		env, err := trusting(goos)
		if err == nil {
			env.Trust = func(path string, _ enterpriseunix.TrustKind) error {
				if path == insecure {
					return errors.New("the file is writable by group staff")
				}
				return nil
			}
		}
		return env, err
	}
	if doc := install(1, "--file", insecure, "--json"); errorCode(doc) != "anchor_insecure" {
		t.Fatalf("insecure source: %v", doc)
	}
	newUnixLifecycleEnv = trusting

	install(2, "--json")
	install(2, "--file", first, "--lock-wait", "1h", "--json")

	lock, err := os.OpenFile(filepath.Join(root, layout.LifecycleDir, "lifecycle.lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	if doc := install(75, "--file", first, "--lock-wait", "1s", "--json"); errorCode(doc) != "lifecycle_busy" {
		t.Fatalf("busy: %v", doc)
	}
	_ = lock.Close()

	*euid = 1000
	if doc := install(1, "--file", first, "--json"); errorCode(doc) != "not_root" {
		t.Fatalf("not root: %v", doc)
	}
}

// TestBundleApplyForwardsDeliveryID pins F10 on Linux and macOS: apply takes
// --delivery-id (empty by default) and hands it to the ensure run that
// writes the receipt.
func TestBundleApplyForwardsDeliveryID(t *testing.T) {
	cmd := newEnterpriseBundleApplyCommand()
	if got, err := cmd.Flags().GetString("delivery-id"); err != nil || got != "" {
		t.Fatalf("--delivery-id default %q, %v", got, err)
	}
	if err := cmd.Flags().Parse([]string{"--bundle", "/x.dcbundle", "--delivery-id", "agent-7:d.1"}); err != nil {
		t.Fatal(err)
	}
	if got, _ := cmd.Flags().GetString("delivery-id"); got != "agent-7:d.1" {
		t.Fatalf("--delivery-id parsed as %q", got)
	}
	for _, want := range []string{"", "agent-7:d.1"} {
		opts := unixBundleApplyOptions(&bundleApplyOptions{inbox: true, reason: "management", deliveryID: want}, "")
		if opts.DeliveryID != want || !opts.BundleInbox || opts.Reason != "management" || opts.Action != enterpriseunix.ActionEnsure {
			t.Fatalf("options %+v, want delivery id %q", opts, want)
		}
	}
}
