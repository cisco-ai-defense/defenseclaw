// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
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

// GAP-2448: `--version --json` (in either order) prints the version document
// of --version-json instead of a usage error with no JSON; any other unknown
// root flag stays a usage error.
func TestManagementContractVersionAndJSONSpelledApart(t *testing.T) {
	schemas := contracttest.Compile(t)
	saved := secretRawArgs
	savedVersion := appVersion
	t.Cleanup(func() { secretRawArgs, appVersion = saved, savedVersion; rootCmd.SetOut(nil) })
	appVersion = "1.0.5"
	for _, args := range [][]string{{"--version", "--json"}, {"--json", "--version"}} {
		secretRawArgs = func() []string { return args }
		var out bytes.Buffer
		rootCmd.SetOut(&out)
		if err := usageFlagError(rootCmd, errors.New("unknown flag: --json")); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		schemas.Validate(t, "version.schema.json", out.Bytes())
	}
	for _, args := range [][]string{{"--version", "--json", "--bogus"}, {"--json"}, {"--bogus", "--version"}} {
		secretRawArgs = func() []string { return args }
		var out bytes.Buffer
		rootCmd.SetOut(&out)
		if err := usageFlagError(rootCmd, errors.New("unknown flag: --json")); runExit(err) != 2 || out.Len() != 0 {
			t.Fatalf("%v: exit %d, stdout %q; want a usage error", args, runExit(err), out.String())
		}
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

// TestManagementContractBundleStatusDescribesEveryMember pins the closed
// bundle-status.schema.json to the Go result: every member status can print
// is a schema property (its current, last_good and last_receipt members are
// checked in internal/enterprisebundle).
func TestManagementContractBundleStatusDescribesEveryMember(t *testing.T) {
	contracttest.RequireMembers(t, "bundle-status.schema.json#/$defs/full", reflect.TypeOf(bundleStatusResult{}))
	contracttest.RequireMembers(t, "bundle-status.schema.json#/$defs/anchorsSummary", reflect.TypeOf(enterprisebundle.AnchorsSummary{}))
	contracttest.RequireMembers(t, "bundle-status.schema.json#/$defs/anchorsSummary/properties/keys/items", reflect.TypeOf(enterprisebundle.AnchorKeySummary{}))
	contracttest.RequireMembers(t, "bundle-verify.schema.json#/$defs/warning", reflect.TypeOf(enterprisebundle.Warning{}))
	contracttest.RequireMembers(t, "bundle-refused.schema.json#/$defs/bundleError", reflect.TypeOf(bundleError{}))
}

// TestManagementContractBundleStatus validates bundle status on a device with
// two bundles confirmed with --delivery-id (current and last_good) and a later
// failed delivery, the public receipt files those deliveries wrote, the status
// once their receipts were pruned, and the refusals. Every block that names a
// delivery carries its delivery_id (GAP-0001: current and last_good did, and
// the schema rejected them).
func TestManagementContractBundleStatus(t *testing.T) {
	schemas := contracttest.Compile(t)
	e := newBundleCLIEnv(t)
	e.writeAnchors(t, map[string]any{"k1": e.edKey.Public()})
	store := bundleDevice(t, e)
	digest := "sha256:" + strings.Repeat("1", 64)
	confirmBundleDelivery(t, store, "b-01JA0000000000000000000006", 6, "sha256:"+strings.Repeat("6", 64), "agent-7:d.6")
	confirmBundleDelivery(t, store, "b-01JA0000000000000000000007", 7, digest, "agent-7:d.7")
	bad, err := store.Receive("b-01JA0000000000000000000008", 8, "agent-7:d.8")
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
	requireDeliveryIDs := func(t *testing.T, doc map[string]any, want map[string]string) {
		t.Helper()
		for block, id := range want {
			if member, _ := doc[block].(map[string]any); member["delivery_id"] != id {
				t.Errorf("%s.delivery_id = %v, want %s", block, member["delivery_id"], id)
			}
		}
	}
	requireDeliveryIDs(t, doc, map[string]string{"current": "agent-7:d.7", "last_good": "agent-7:d.6",
		"last_receipt": "agent-7:d.7", "bundle": "agent-7:d.7", "last_refusal": "agent-7:d.8"})
	// anchors_summary is what the installed anchor file says, with the hash
	// of its bytes and without the public keys (GitHub #1320).
	anchorBytes, err := os.ReadFile(e.anchors)
	if err != nil {
		t.Fatal(err)
	}
	anchorSum := sha256.Sum256(anchorBytes)
	summary, _ := doc["anchors_summary"].(map[string]any)
	keys, _ := summary["keys"].([]any)
	if summary["sha256"] != hex.EncodeToString(anchorSum[:]) || summary["tenant_id"] != "acme" || len(keys) != 1 ||
		keys[0].(map[string]any)["key_id"] != "k1" || keys[0].(map[string]any)["public_key"] != nil {
		t.Fatalf("anchors_summary = %v", doc["anchors_summary"])
	}

	events, err := filepath.Glob(filepath.Join(store.PublicReceiptEventsDir(), "*.json"))
	if err != nil || len(events) != 3 {
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
		if version, _ := receipt["version"].(json.Number); receipt["delivery_id"] != "agent-7:d."+version.String() {
			t.Fatalf("receipt event %s: delivery_id %v", file, receipt["delivery_id"])
		}
	}
	if states["confirmed"] != 2 || states["failed"] != 1 {
		t.Fatalf("receipt event states %v, want two confirmed and one failed", states)
	}
	raw, err := os.ReadFile(store.PublicReceiptPath())
	if err != nil {
		t.Fatal(err)
	}
	if receipt := schemas.Validate(t, "bundle-receipt.schema.json", raw); receipt["delivery_id"] != "agent-7:d.7" {
		t.Fatalf("receipt.json: %s", raw)
	}

	// Pruned receipts: current and last_good keep their delivery ids from
	// the state alone.
	t.Run("receipts pruned", func(t *testing.T) {
		for _, id := range []string{"b-01JA0000000000000000000006", "b-01JA0000000000000000000007"} {
			if err := os.Remove(filepath.Join(store.LifecycleDir, enterprisebundle.ReceiptsDirName, id+".json")); err != nil {
				t.Fatal(err)
			}
		}
		out, code := runBundle(t, "status", "--json")
		doc := schemas.Validate(t, "bundle-status.schema.json", []byte(out))
		requireExit(t, doc, code, 0)
		requireDeliveryIDs(t, doc, map[string]string{"current": "agent-7:d.7", "last_good": "agent-7:d.6"})
	})

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
