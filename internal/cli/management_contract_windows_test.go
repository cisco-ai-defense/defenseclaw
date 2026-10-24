// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/contracttest"
	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// TestManagementContractWindowsBundleStatusDeliveryID drives the Windows
// apply with --delivery-id to a confirmed bundle and validates the
// `bundle status --json` and the public receipt files that follow
// (GAP-0001: current carries the delivery id).
func TestManagementContractWindowsBundleStatusDeliveryID(t *testing.T) {
	schemas := contracttest.Compile(t)
	e := newBundleCLIEnv(t)
	e.writeAnchors(t, map[string]any{"k1": e.edKey.Public()})
	signed := filepath.Join(e.dir, "v5.dcbundle")
	if out, code := runBundle(t, e.signArgs("--out", signed, "--key", filepath.Join(e.dir, "key.pem"), "--key-id", "k1")...); code != 0 {
		t.Fatalf("sign exit %d:\n%s", code, out)
	}
	layout := stubWindowsBundleHost(t)
	ctx := context.Background()
	cmd, out := windowsBundleCommand()
	opts := &windowsEnterpriseLifecycleOptions{bundlePath: signed, trustAnchors: e.anchors,
		profile: managed.ProfileStandalone, jsonOutput: true, installedBeforeRun: true, bundleDeliveryID: "agent-7:d.1"}
	if done, err := prepareWindowsEnterpriseBundle(ctx, cmd, "ensure", opts); done {
		t.Fatalf("prepare ended the run: %v\n%s", err, out.String())
	}
	cleanupPreparedWindowsBundle(t, opts)
	// The ensure transaction installs the rendered config.
	rendered, err := os.ReadFile(opts.configPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(layout.ConfigPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(layout.ConfigPath, rendered, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := migrateManagedStandaloneConfig(ctx, layout.ConfigPath); err != nil {
		t.Fatalf("record installed bundle config: %v", err)
	}
	result := newWindowsEnterpriseStandaloneResult("ensure", opts)
	// finishWindowsEnterpriseBundle consumes opts.bundle, so keep what the
	// checks below need from the prepared receipt.
	expected := opts.bundle.prepared.Receipt.ExpectedDigest
	receiptID := opts.bundle.prepared.Receipt.ReceiptID
	result.Policy = &enterprisestatus.PolicyState{EffectiveDigest: expected, GatewayReportedDigest: expected, ConfigGeneration: 3, Applied: true}
	finishWindowsEnterpriseBundle(cmd, opts, result)
	if len(result.Errors) != 0 || result.Bundle == nil || result.Bundle.State != enterprisebundle.StateConfirmed || result.Bundle.DeliveryID != "agent-7:d.1" {
		t.Fatalf("bundle not confirmed with its delivery id: errors %+v bundle %+v", result.Errors, result.Bundle)
	}

	// An elevated status reads the store the apply wrote.
	store := newWindowsBundleDriver(layout).Store
	bundleDevice(t, e)
	bundleStore = func() (*enterprisebundle.Store, error) { return store, nil }
	bundlePrivilege = func() error { return nil }
	bundleGatewayPolicy = func(context.Context) *enterprisestatus.PolicyState {
		return &enterprisestatus.PolicyState{EffectiveDigest: expected, GatewayReportedDigest: expected, Applied: true}
	}
	status, code := runBundle(t, "status", "--json")
	doc := schemas.Validate(t, "bundle-status.schema.json", []byte(status))
	requireExit(t, doc, code, 0)
	for _, block := range []string{"current", "last_receipt", "bundle"} {
		if member, _ := doc[block].(map[string]any); member["delivery_id"] != "agent-7:d.1" {
			t.Fatalf("%s.delivery_id = %v, want agent-7:d.1: %s", block, member["delivery_id"], status)
		}
	}
	for _, file := range []string{filepath.Join(store.PublicReceiptEventsDir(), receiptID+".json"), store.PublicReceiptPath()} {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if receipt := schemas.Validate(t, "bundle-receipt.schema.json", raw); receipt["delivery_id"] != "agent-7:d.1" {
			t.Fatalf("%s: %s", file, raw)
		}
	}
}

// TestManagementContractWindowsSecret validates what Windows
// `enterprise secret set`, `status` and `remove` print with --json.
func TestManagementContractWindowsSecret(t *testing.T) {
	schemas := contracttest.Compile(t)
	windowsSecretTestHarness(t)
	const value = "contract-test-credential-value"

	out, err := runWindowsSecretCommand(t, "set", enterpriseSecretOptions{name: "ai-defense-api-key", fromStdin: true, json: true}, value+"\r\n")
	if err != nil {
		t.Fatalf("set: %v", err)
	}
	if strings.Contains(out, value) {
		t.Fatal("the credential value was printed")
	}
	if doc := schemas.Validate(t, "secret-result.schema.json", []byte(out)); doc["ok"] != true || doc["action"] != "set" {
		t.Fatalf("set result %s", out)
	}
	// An identical set keeps the contract v1 success shape, whose schema
	// allows no other member, with the gateway stopped and running alike.
	previousRestart := windowsSecretRestartGateway
	t.Cleanup(func() { windowsSecretRestartGateway = previousRestart })
	for _, running := range []bool{false, true} {
		windowsSecretRestartGateway = func(beforeStop func() error) (bool, error) {
			if running {
				if err := beforeStop(); err != nil {
					return false, err
				}
			}
			return running, nil
		}
		out, err = runWindowsSecretCommand(t, "set", enterpriseSecretOptions{name: "ai-defense-api-key", fromStdin: true, json: true}, value+"\r\n")
		if err != nil {
			t.Fatalf("identical set (gateway running %v): %v", running, err)
		}
		if doc := schemas.Validate(t, "secret-result.schema.json", []byte(out)); doc["gateway_restarted"] != running || len(doc) != 5 {
			t.Fatalf("identical set result (gateway running %v): %s", running, out)
		}
	}

	out, err = runWindowsSecretCommand(t, "status", enterpriseSecretOptions{json: true}, "")
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if strings.Contains(out, value) {
		t.Fatal("the credential value was printed")
	}
	schemas.Validate(t, "secret-result.schema.json", []byte(out))

	out, err = runWindowsSecretCommand(t, "remove", enterpriseSecretOptions{name: "ai-defense-api-key", json: true}, "")
	if err != nil {
		t.Fatalf("remove: %v", err)
	}
	schemas.Validate(t, "secret-result.schema.json", []byte(out))

	t.Run("failures print one document", func(t *testing.T) {
		opts := enterpriseSecretOptions{name: "ai-defense-api-key", fromStdin: true, json: true}
		notElevated := func(managedHost bool) func() {
			return func() {
				windowsSecretIsElevated = func() bool { return false }
				managedHostWindowsStandalone = func() (string, bool) {
					if managedHost {
						return `HKLM\` + WindowsEnterpriseMarkerKey, true
					}
					return "", false
				}
			}
		}
		cases := map[string]struct {
			setup func()
			opts  enterpriseSecretOptions
			exit  int
		}{
			"not elevated, managed":   {notElevated(true), opts, enterprisestatus.WindowsExitAccessDenied},
			"not elevated, unmanaged": {notElevated(false), opts, windowsSecretExitFailure},
			"bad name":                {func() {}, enterpriseSecretOptions{name: "BAD", fromStdin: true, json: true}, windowsSecretExitInvalid},
			"not installed":           {func() { windowsSecretDeploymentInstalled = func() (bool, error) { return false, nil } }, opts, windowsSecretExitFailure},
		}
		for name, tc := range cases {
			t.Run(name, func(t *testing.T) {
				savedElevated, savedInstalled, savedManaged := windowsSecretIsElevated, windowsSecretDeploymentInstalled, managedHostWindowsStandalone
				t.Cleanup(func() {
					windowsSecretIsElevated, windowsSecretDeploymentInstalled, managedHostWindowsStandalone = savedElevated, savedInstalled, savedManaged
				})
				tc.setup()
				out, err := runWindowsSecretCommand(t, "set", tc.opts, value+"\r\n")
				doc := schemas.Validate(t, "secret-result.schema.json", []byte(out))
				requireExit(t, doc, runExit(err), tc.exit)
				if strings.Contains(out, value) {
					t.Fatal("the credential value was printed")
				}
			})
		}
	})
}

// TestManagementContractWindowsSecretEveryVerbAndFailure runs set, remove
// and status through their command with --json for every failure class:
// stdout holds exactly one secret-result document, stderr nothing, and the
// exit code is the document's. A standard account's `secret status --json`
// printed only its sentence on stderr (mgmt-agent-api GAP-0029). status
// takes no lock and needs no deployment, so it answers "not installed" and
// "lock busy" with its listing.
func TestManagementContractWindowsSecretEveryVerbAndFailure(t *testing.T) {
	schemas := contracttest.Compile(t)
	const value = "matrix-credential-value"
	verbs := []string{"set", "remove", "status"}
	valid := map[string][]string{
		"set":    {"--name", "ai-defense-api-key", "--from-stdin", "--json"},
		"remove": {"--name", "ai-defense-api-key", "--json"},
		"status": {"--json"},
	}
	type outcome struct {
		code string // errors[0].code; "" is the status listing (exit 0)
		exit int
	}
	every := func(o outcome) map[string]outcome {
		return map[string]outcome{"set": o, "remove": o, "status": o}
	}
	listing := outcome{}
	for _, class := range []struct {
		name  string
		args  func(verb string) []string
		setup func(t *testing.T, host *windowsSecretLockEvents, layout managed.StandaloneLayout)
		want  map[string]outcome
	}{
		{name: "not elevated, managed",
			setup: func(*testing.T, *windowsSecretLockEvents, managed.StandaloneLayout) {
				windowsSecretIsElevated = func() bool { return false }
				managedHostWindowsStandalone = func() (string, bool) { return `HKLM\` + WindowsEnterpriseMarkerKey, true }
			},
			want: every(outcome{"elevation_required", enterprisestatus.WindowsExitAccessDenied})},
		{name: "not elevated, unmanaged",
			setup: func(*testing.T, *windowsSecretLockEvents, managed.StandaloneLayout) {
				windowsSecretIsElevated = func() bool { return false }
			},
			want: every(outcome{"elevation_required", windowsSecretExitFailure})},
		{name: "bad name",
			// status has no --name: passing one is a flag error.
			args: func(verb string) []string {
				if verb == "status" {
					return []string{"--name", "BAD", "--json"}
				}
				return append([]string{"--name", "BAD"}, valid[verb][2:]...)
			},
			want: every(outcome{"invalid_arguments", windowsSecretExitInvalid})},
		{name: "bad flag",
			args: func(verb string) []string { return append(append([]string{}, valid[verb]...), "--bogus") },
			want: every(outcome{"invalid_arguments", windowsSecretExitInvalid})},
		{name: "not installed",
			setup: func(*testing.T, *windowsSecretLockEvents, managed.StandaloneLayout) {
				windowsSecretDeploymentInstalled = func() (bool, error) { return false, nil }
			},
			want: map[string]outcome{"set": {"not_installed", windowsSecretExitFailure}, "remove": {"not_installed", windowsSecretExitFailure}, "status": listing}},
		{name: "lock busy",
			setup: func(_ *testing.T, host *windowsSecretLockEvents, _ managed.StandaloneLayout) {
				host.bundleErr = errWindowsBundleStoreBusy
			},
			want: map[string]outcome{"set": {"lifecycle_busy", enterprisestatus.WindowsExitBusy}, "remove": {"lifecycle_busy", enterprisestatus.WindowsExitBusy}, "status": listing}},
		{name: "corrupt deployment",
			setup: func(*testing.T, *windowsSecretLockEvents, managed.StandaloneLayout) {
				// Each path lookup makes a new error in production. A stable
				// sentinel would hide duplicate stderr after the JSON refusal.
				windowsSecretLayout = func() (managed.StandaloneLayout, error) {
					return managed.StandaloneLayout{}, errors.New("the standalone deployment record cannot be read")
				}
				windowsSecretDeploymentInstalled = func() (bool, error) {
					return false, errors.New("the standalone deployment record cannot be read")
				}
			},
			want: every(outcome{"state_invalid", windowsSecretExitFailure})},
		{name: "corrupt store",
			// A file where the secrets folder belongs: status cannot list it.
			setup: func(t *testing.T, _ *windowsSecretLockEvents, layout managed.StandaloneLayout) {
				if err := os.WriteFile(layout.SecretsDir, []byte("not a folder"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			want: map[string]outcome{"status": {"state_invalid", windowsSecretExitFailure}}},
	} {
		for _, verb := range verbs {
			want, ok := class.want[verb]
			if !ok {
				continue
			}
			t.Run(class.name+"/"+verb, func(t *testing.T) {
				layout := managed.StandaloneLayout{GOOS: "windows", SecretsDir: filepath.Join(t.TempDir(), "secrets"), LifecycleDir: t.TempDir()}
				host := stubWindowsSecretHost(t, layout)
				if class.setup != nil {
					class.setup(t, host, layout)
				}
				args := valid[verb]
				if class.args != nil {
					args = class.args(verb)
				}
				secretRawArgs = func() []string { return args }
				cmd := newEnterpriseSecretCommand(verb, "matrix")
				var stdout, stderr bytes.Buffer
				cmd.SetOut(&stdout)
				cmd.SetErr(&stderr)
				cmd.SetIn(strings.NewReader(value))
				cmd.SetArgs(args)
				err := cmd.Execute()
				if stderr.Len() != 0 {
					t.Fatalf("%v: stderr %q, want nothing (the document carries the error); stdout %q", args, stderr.String(), stdout.String())
				}
				if strings.Contains(stdout.String(), value) {
					t.Fatal("the credential value was printed")
				}
				doc := schemas.Validate(t, "secret-result.schema.json", stdout.Bytes())
				requireExit(t, doc, runExit(err), want.exit)
				if want.code == "" {
					if err != nil || doc["secrets"] == nil {
						t.Fatalf("%v: want the status listing, got %v %s", args, err, stdout.String())
					}
					return
				}
				var code any
				if errs, _ := doc["errors"].([]any); len(errs) > 0 {
					if first, ok := errs[0].(map[string]any); ok {
						code = first["code"]
					}
				}
				if doc["ok"] != false || doc["action"] != verb || code != want.code {
					t.Fatalf("%v: document %s, want action %s code %s", args, stdout.String(), verb, want.code)
				}
				for _, event := range host.events {
					if event == "restart" {
						t.Fatal("the gateway restarted after a refusal")
					}
				}
			})
		}
	}
}
