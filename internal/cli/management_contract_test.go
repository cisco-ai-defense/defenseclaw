// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/contracttest"
	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// The management agent contract (packaging/mdm/contract/management-agent.md)
// publishes a JSON Schema for every document the enterprise commands print
// to a management agent. These tests run the commands through their test
// seams and validate what they print, so an output change the schema does
// not describe fails here. The lifecycle results of a managed device are
// checked the same way in internal/enterpriseunix.

// runExit is the exit status a command run ends with: 0 for success, else
// the code its failure asked for (commandExitCode only labels failures).
func runExit(err error) int {
	if err == nil {
		return 0
	}
	return commandExitCode(err)
}

// requireExit checks the process exit code and, when the document carries
// one, that exit_code agrees with it.
func requireExit(t *testing.T, doc map[string]any, got, want int) {
	t.Helper()
	if got != want {
		t.Fatalf("exit %d, want %d: %v", got, want, doc)
	}
	if code, ok := doc["exit_code"].(json.Number); ok && code.String() != strconv.Itoa(want) {
		t.Fatalf("exit_code %s does not match the exit %d", code, want)
	}
}

func TestManagementContractVersionJSON(t *testing.T) {
	schemas := contracttest.Compile(t)
	savedVersion, savedCommit, savedBuilt := appVersion, appCommit, appBuildDate
	t.Cleanup(func() { appVersion, appCommit, appBuildDate = savedVersion, savedCommit, savedBuilt })
	appVersion, appCommit, appBuildDate = "1.0.3", "0123456789", "2026-10-30T18:00:00Z"
	var out bytes.Buffer
	if err := writeMachineVersion(&out); err != nil {
		t.Fatal(err)
	}
	if strings.Count(out.String(), "\n") != 1 {
		t.Fatalf("--version-json must print one line: %q", out.String())
	}
	doc := schemas.Validate(t, "version.schema.json", out.Bytes())
	if doc["management_contract"] != json.Number("1") {
		t.Fatalf("management_contract = %v, want 1", doc["management_contract"])
	}
}

func TestManagementContractBundleVerify(t *testing.T) {
	schemas := contracttest.Compile(t)
	e := newBundleCLIEnv(t)
	e.writeAnchors(t, map[string]any{"k1": e.edKey.Public()})
	signed := filepath.Join(e.dir, "v5.dcbundle")
	if out, code := runBundle(t, e.signArgs("--out", signed, "--key", filepath.Join(e.dir, "key.pem"), "--key-id", "k1")...); code != 0 {
		t.Fatalf("sign exit %d:\n%s", code, out)
	}
	out, code := runBundle(t, "verify", "--bundle", signed, "--anchors", e.anchors, "--platform", "linux", "--json")
	doc := schemas.Validate(t, "bundle-verify.schema.json", []byte(out))
	requireExit(t, doc, code, 0)
	if doc["result"] != "verified" {
		t.Fatalf("verify result %v", doc["result"])
	}

	// The anchor file verify accepted is a valid contract input.
	raw, err := os.ReadFile(e.anchors)
	if err != nil {
		t.Fatal(err)
	}
	schemas.Validate(t, "bundle-anchors.schema.json", raw)

	b, err := readBundleInput(signed)
	if err != nil {
		t.Fatal(err)
	}
	b.Files["discovery/confidence.yaml"] = []byte("version: 2\n")
	tampered := filepath.Join(e.dir, "tampered.dcbundle")
	if err := writeBundleArchive(tampered, b); err != nil {
		t.Fatal(err)
	}
	out, code = runBundle(t, "verify", "--bundle", tampered, "--anchors", e.anchors, "--platform", "linux", "--json")
	doc = schemas.Validate(t, "bundle-verify.schema.json", []byte(out))
	requireExit(t, doc, code, bundleFailureExitCode())

	out, code = runBundle(t, "verify", "--bundle", signed, "--anchors", filepath.Join(e.dir, "missing.json"), "--json")
	doc = schemas.Validate(t, "bundle-verify.schema.json", []byte(out))
	requireExit(t, doc, code, bundleFailureExitCode())

	out, code = runBundle(t, "verify", "--json")
	doc = schemas.Validate(t, "bundle-verify.schema.json", []byte(out))
	requireExit(t, doc, code, enterprisestatus.InvalidArgsExitCode(runtime.GOOS))
}

// TestManagementContractBundleApplyRefusals validates the short document an
// apply prints when it refuses before the lifecycle runs.
func TestManagementContractBundleApplyRefusals(t *testing.T) {
	schemas := contracttest.Compile(t)
	e := newBundleCLIEnv(t)
	for name, setup := range map[string]func(){
		"not managed":   func() { bundleManagedDevice = func() bool { return false } },
		"secure client": func() { bundleSecureClient = func() bool { return true } },
	} {
		t.Run(name, func(t *testing.T) {
			savedDevice, savedSC := bundleManagedDevice, bundleSecureClient
			t.Cleanup(func() { bundleManagedDevice, bundleSecureClient = savedDevice, savedSC })
			setup()
			out, code := runBundle(t, "apply", "--bundle", filepath.Join(e.dir, "v1.dcbundle"), "--json")
			doc := schemas.Validate(t, "bundle-refused.schema.json", []byte(out))
			requireExit(t, doc, code, bundleFailureExitCode())
		})
	}
}

// TestManagementContractBundleStatus validates bundle status on a device with
// a confirmed bundle and a later failed delivery, the public receipt files
// those deliveries wrote, and the refusals.
func TestManagementContractBundleStatus(t *testing.T) {
	schemas := contracttest.Compile(t)
	e := newBundleCLIEnv(t)
	e.writeAnchors(t, map[string]any{"k1": e.edKey.Public()})
	store := bundleDevice(t, e)
	digest := "sha256:" + strings.Repeat("1", 64)
	confirmBundle(t, store, "b-01JA0000000000000000000007", 7, digest)
	bad, err := store.Receive("b-01JA0000000000000000000008", 8, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Fail(bad, enterprisebundle.CodeSecretRefMissing, "credential ai-defense-api-key is not stored"); err != nil {
		t.Fatal(err)
	}
	bundleGatewayPolicy = func(context.Context) *enterprisestatus.PolicyState {
		return &enterprisestatus.PolicyState{EffectiveDigest: digest, GatewayReportedDigest: digest, Applied: true}
	}

	out, code := runBundle(t, "status", "--json")
	doc := schemas.Validate(t, "bundle-status.schema.json", []byte(out))
	requireExit(t, doc, code, 0)
	if doc["applied"] != true || doc["last_receipt"].(map[string]any)["state"] != "confirmed" ||
		doc["last_refusal"].(map[string]any)["error_code"] != "secret_ref_missing" {
		t.Fatalf("status = %s", out)
	}

	events, err := filepath.Glob(filepath.Join(store.PublicReceiptEventsDir(), "*.json"))
	if err != nil || len(events) != 2 {
		t.Fatalf("receipt events %v (%v)", events, err)
	}
	states := map[any]int{}
	for _, file := range events {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		receipt := schemas.Validate(t, "bundle-receipt.schema.json", raw)
		states[receipt["state"]]++
		if base := filepath.Base(file); base != receipt["receipt_id"].(string)+".json" {
			t.Fatalf("receipt event %s holds receipt_id %v", base, receipt["receipt_id"])
		}
	}
	if states["confirmed"] != 1 || states["failed"] != 1 {
		t.Fatalf("receipt event states %v, want one confirmed and one failed", states)
	}
	raw, err := os.ReadFile(store.PublicReceiptPath())
	if err != nil {
		t.Fatal(err)
	}
	schemas.Validate(t, "bundle-receipt.schema.json", raw)

	t.Run("not_admin", func(t *testing.T) {
		saved := bundlePrivilege
		t.Cleanup(func() { bundlePrivilege = saved })
		bundlePrivilege = func() error {
			return &enterprisebundle.Error{Code: enterprisebundle.CodeNotAdmin, Detail: "administrator required"}
		}
		out, code := runBundle(t, "status", "--json")
		doc := schemas.Validate(t, "bundle-status.schema.json", []byte(out))
		requireExit(t, doc, code, bundleFailureExitCode())
		schemas.Validate(t, "bundle-refused.schema.json", []byte(out))
	})
	t.Run("refused before the session scan", func(t *testing.T) {
		for name, setup := range map[string]func(){
			"not managed":   func() { bundleManagedDevice = func() bool { return false } },
			"secure client": func() { bundleSecureClient = func() bool { return true } },
			"state invalid": func() {
				if err := os.WriteFile(store.StatePath(), []byte("{"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		} {
			t.Run(name, func(t *testing.T) {
				savedDevice, savedSC := bundleManagedDevice, bundleSecureClient
				savedState, readErr := os.ReadFile(store.StatePath())
				t.Cleanup(func() {
					bundleManagedDevice, bundleSecureClient = savedDevice, savedSC
					if readErr == nil {
						_ = os.WriteFile(store.StatePath(), savedState, 0o600)
					} else {
						_ = os.Remove(store.StatePath())
					}
				})
				setup()
				out, code := runBundle(t, "status", "--json")
				doc := schemas.Validate(t, "bundle-status.schema.json", []byte(out))
				requireExit(t, doc, code, bundleFailureExitCode())
				if doc["ok"] != false {
					t.Fatalf("status = %s", out)
				}
				if name == "state invalid" && !strings.Contains(out, "state_invalid") {
					t.Fatalf("an invalid state is not reported state_invalid: %s", out)
				}
			})
		}
	})
}

// TestManagementContractWindowsElevationResult validates the lifecycle
// result a Windows status or verify prints for a standard account: exit 5.
func TestManagementContractWindowsElevationResult(t *testing.T) {
	schemas := contracttest.Compile(t)
	result := enterprisestatus.New("status", "standalone", "windows", "1.0.3")
	result.AddError("elevation_required", "run this command from an elevated administrator or SYSTEM session")
	result.Finish("windows", enterprisestatus.WindowsExitAccessDenied)
	document, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	doc := schemas.Validate(t, "lifecycle-result.schema.json", document)
	requireExit(t, doc, enterprisestatus.WindowsExitAccessDenied, enterprisestatus.WindowsExitAccessDenied)
}
