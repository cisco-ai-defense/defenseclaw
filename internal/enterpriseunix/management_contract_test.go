// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package enterpriseunix

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/contracttest"
	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// The management agent contract (packaging/mdm/contract/management-agent.md)
// publishes a JSON Schema for every document a management agent reads. These
// tests drive real lifecycle runs on the fake host and validate the results
// and the public receipt files against those schemas. The CLI prints these
// results unchanged with --json.

// TestManagementContractBundleApplyResults validates the apply results a
// management agent acts on (confirmed, already_applied, refused), the device
// status after them and the public receipt files.
func TestManagementContractBundleApplyResults(t *testing.T) {
	schemas := contracttest.Compile(t)
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			b := newBundleHost(t, goos)
			v1, v2, _ := bundleConfigs(b.testHost)
			b.mapPromotedBundleOwners(1)
			first := b.apply(b.dir(1, v1))
			requireOK(t, first)
			schemas.ValidateValue(t, "lifecycle-result.schema.json", first)
			b.mapPromotedBundleOwners(2)
			path := b.dir(2, v2)

			applied := b.apply(path)
			requireOK(t, applied)
			doc := schemas.ValidateValue(t, "lifecycle-result.schema.json", applied)
			if applied.Bundle == nil || applied.Bundle.State != enterprisebundle.StateConfirmed || applied.Bundle.BundleID != bundleID(2) {
				t.Fatalf("apply did not confirm: %+v", applied.Bundle)
			}

			store := b.env.bundleStore()
			events, err := filepath.Glob(filepath.Join(store.PublicReceiptEventsDir(), "*.json"))
			if err != nil || len(events) != 2 {
				t.Fatalf("receipt events %v (%v)", events, err)
			}
			receiptID := ""
			for _, file := range append(events, store.PublicReceiptPath()) {
				raw, err := os.ReadFile(file)
				if err != nil {
					t.Fatal(err)
				}
				receipt := schemas.Validate(t, "bundle-receipt.schema.json", raw)
				if receipt["state"] != "confirmed" {
					t.Fatalf("%s: %s", file, raw)
				}
				if receipt["bundle_id"] == bundleID(2) {
					receiptID, _ = receipt["receipt_id"].(string)
				}
			}
			t.Run("receipt_id of a fresh apply", func(t *testing.T) {
				if got := doc["bundle"].(map[string]any)["receipt_id"]; got != receiptID {
					t.Fatalf("bundle.receipt_id = %v, want the receipt written, %s", got, receiptID)
				}
			})

			// The same bytes again: a success no-op that writes no receipt
			// and reports the confirmed receipt.
			again := b.apply(path)
			requireOK(t, again)
			doc = schemas.ValidateValue(t, "lifecycle-result.schema.json", again)
			if !again.Noop || again.NoopReason != "already_applied" {
				t.Fatalf("repeated delivery: noop=%v reason=%q", again.Noop, again.NoopReason)
			}
			t.Run("receipt_id of already_applied", func(t *testing.T) {
				if got := doc["bundle"].(map[string]any)["receipt_id"]; got != receiptID {
					t.Fatalf("bundle.receipt_id = %v, want the current confirmed receipt, %s", got, receiptID)
				}
			})

			// Other bytes at the same version: refused, final.
			refused := b.apply(b.dir(2, v1))
			requireError(t, refused, string(enterprisebundle.CodeVersionNotNewer))
			schemas.ValidateValue(t, "lifecycle-result.schema.json", refused)
			if refused.ExitCode != enterprisestatus.UnixExitFailure {
				t.Fatalf("refusal exit %d", refused.ExitCode)
			}

			// A refusal before the bundle was received writes no receipt,
			// so the result has no bundle block and no receipt_id.
			unmanaged := newTestHost(t, goos)
			early := unmanaged.run(Options{Action: ActionEnsure, Bundle: path})
			requireError(t, early, codeNotInstalled)
			doc = schemas.ValidateValue(t, "lifecycle-result.schema.json", early)
			if _, present := doc["bundle"]; present {
				t.Fatalf("refusal before the receipt has a bundle block: %v", doc["bundle"])
			}

			status := b.run(Options{Action: ActionStatus})
			requireOK(t, status)
			schemas.ValidateValue(t, "lifecycle-result.schema.json", status)
			if status.Bundle == nil || status.Bundle.BundleID != bundleID(2) || status.Bundle.State != enterprisebundle.StateConfirmed {
				t.Fatalf("status bundle block = %+v", status.Bundle)
			}
		})
	}
}

// TestManagementContractSecretAndBusyResults validates what Linux and macOS
// `enterprise secret set` print (lifecycle result v2 through
// secret-result.schema.json) and the busy result an agent retries.
func TestManagementContractSecretAndBusyResults(t *testing.T) {
	schemas := contracttest.Compile(t)
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			const value = "contract-test-credential-value"

			stored := h.run(Options{Action: ActionEnsure, Reason: "secret", Mutate: func(ctx context.Context) error {
				return h.env.WriteSecret(ctx, "ai-defense-api-key", []byte(value))
			}})
			requireOK(t, stored)
			document, err := json.Marshal(stored)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(document, []byte(value)) {
				t.Fatalf("the credential value is in the result: %s", document)
			}
			schemas.Validate(t, "secret-result.schema.json", document)

			failed := h.run(Options{Action: ActionEnsure, Reason: "secret", Mutate: func(context.Context) error {
				return errors.New("the credential could not be written")
			}})
			requireError(t, failed, codeChange)
			schemas.ValidateValue(t, "secret-result.schema.json", failed)

			states, err := h.env.SecretStatus()
			if err != nil {
				t.Fatal(err)
			}
			listing, err := json.Marshal(map[string]any{"schema_version": 1, "secrets": states})
			if err != nil {
				t.Fatal(err)
			}
			schemas.Validate(t, "secret-result.schema.json", listing)

			held, err := h.env.acquireLock(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer held.release()
			h.env.LockTimeout = 50 * time.Millisecond
			for _, action := range []string{ActionEnsure, ActionStatus} {
				busy := h.run(Options{Action: action})
				if action == ActionStatus {
					// A pending apply: ok, the busy code as a warning (GAP-0129).
					if !busy.OK || !busy.PendingApply || !hasMessageCode(busy.Warnings, codeBusy) {
						t.Fatalf("status busy: ok=%v pending_apply=%v warnings=%+v", busy.OK, busy.PendingApply, busy.Warnings)
					}
				} else {
					requireError(t, busy, codeBusy)
				}
				if busy.ExitCode != enterprisestatus.UnixExitBusy {
					t.Fatalf("%s busy exit %d, want %d", action, busy.ExitCode, enterprisestatus.UnixExitBusy)
				}
				schemas.ValidateValue(t, "lifecycle-result.schema.json", busy)
			}
		})
	}
}

// TestManagementContractBundleApplyDeliveryID pins F10 (guide section 4.3):
// --delivery-id reaches the result bundle block, the public receipt files,
// the refusal summary and the state records `bundle status` prints as
// current and last_good (GAP-0001); a repeat of the current bundle reports
// the confirmed receipt (and its delivery id), not its own; an invalid id or
// one without a bundle is invalid_arguments, exit 2, before any receipt.
func TestManagementContractBundleApplyDeliveryID(t *testing.T) {
	schemas := contracttest.Compile(t)
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			b := newBundleHost(t, goos)
			v1, v2, _ := bundleConfigs(b.testHost)
			b.mapPromotedBundleOwners(1)
			path := b.dir(1, v1)
			deliveryOf := func(doc map[string]any, block string) any {
				t.Helper()
				member, _ := doc[block].(map[string]any)
				return member["delivery_id"]
			}

			first := b.run(Options{Action: ActionEnsure, Bundle: path, DeliveryID: "agent-7:d.1"})
			requireOK(t, first)
			doc := schemas.ValidateValue(t, "lifecycle-result.schema.json", first)
			if got := deliveryOf(doc, "bundle"); got != "agent-7:d.1" {
				t.Fatalf("bundle.delivery_id = %v, want agent-7:d.1", got)
			}
			store := b.env.bundleStore()
			for _, file := range []string{filepath.Join(store.PublicReceiptEventsDir(), bundleID(1)+".json"), store.PublicReceiptPath()} {
				raw, err := os.ReadFile(file)
				if err != nil {
					t.Fatal(err)
				}
				if receipt := schemas.Validate(t, "bundle-receipt.schema.json", raw); receipt["delivery_id"] != "agent-7:d.1" {
					t.Fatalf("%s: %s", file, raw)
				}
			}
			// bundle status prints the state record and the receipt as they are.
			if current := b.state().Current; current == nil || current.DeliveryID != "agent-7:d.1" {
				t.Fatalf("state current = %+v, want delivery id agent-7:d.1", current)
			}
			schemas.ValidateValue(t, "bundle-status.schema.json#/$defs/ref", b.state().Current)
			schemas.ValidateValue(t, "bundle-status.schema.json#/$defs/receipt", b.receipt(bundleID(1)))

			again := b.run(Options{Action: ActionEnsure, Bundle: path, DeliveryID: "agent-7:d.2"})
			requireOK(t, again)
			doc = schemas.ValidateValue(t, "lifecycle-result.schema.json", again)
			// noop_reason is already_applied only when ensure repaired
			// nothing else (guide 4.3), so the test reads the block alone.
			if deliveryOf(doc, "bundle") != "agent-7:d.1" || doc["bundle"].(map[string]any)["receipt_id"] != bundleID(1) {
				t.Fatalf("repeat: bundle=%v; want the confirmed receipt and its delivery id", doc["bundle"])
			}
			if events, _ := filepath.Glob(filepath.Join(store.PublicReceiptEventsDir(), "*.json")); len(events) != 1 {
				t.Fatalf("a repeat wrote a receipt: %v", events)
			}

			refused := b.run(Options{Action: ActionEnsure, Bundle: b.dir(1, v2), DeliveryID: "agent-7:d.3"})
			requireError(t, refused, string(enterprisebundle.CodeVersionNotNewer))
			doc = schemas.ValidateValue(t, "lifecycle-result.schema.json", refused)
			if got := deliveryOf(doc, "last_refusal"); got != "agent-7:d.3" {
				t.Fatalf("last_refusal.delivery_id = %v, want agent-7:d.3 (%v)", got, doc["last_refusal"])
			}

			events, _ := filepath.Glob(filepath.Join(store.PublicReceiptEventsDir(), "*.json"))
			for name, opts := range map[string]Options{
				"invalid id":    {Action: ActionEnsure, Bundle: path, DeliveryID: "bad id"},
				"id over 128":   {Action: ActionEnsure, Bundle: path, DeliveryID: string(bytes.Repeat([]byte("a"), 129))},
				"id, no bundle": {Action: ActionEnsure, DeliveryID: "agent-7:d.4"},
			} {
				bad := b.run(opts)
				requireError(t, bad, codeInvalidArguments)
				if bad.ExitCode != enterprisestatus.UnixExitInvalidArgs {
					t.Fatalf("%s: exit %d", name, bad.ExitCode)
				}
				schemas.ValidateValue(t, "lifecycle-result.schema.json", bad)
			}
			if after, _ := filepath.Glob(filepath.Join(store.PublicReceiptEventsDir(), "*.json")); len(after) != len(events) {
				t.Fatalf("an invalid delivery id wrote a receipt: %v -> %v", events, after)
			}

			// A newer bundle with its own id: current and last_good each keep
			// the delivery id that confirmed them.
			b.mapPromotedBundleOwners(2)
			next := b.run(Options{Action: ActionEnsure, Bundle: b.dir(2, v2), DeliveryID: "agent-7:d.5"})
			requireOK(t, next)
			if got := deliveryOf(schemas.ValidateValue(t, "lifecycle-result.schema.json", next), "bundle"); got != "agent-7:d.5" {
				t.Fatalf("v2 bundle.delivery_id = %v, want agent-7:d.5", got)
			}
			st := b.state()
			if st.Current == nil || st.Current.DeliveryID != "agent-7:d.5" || st.LastGood == nil || st.LastGood.DeliveryID != "agent-7:d.1" {
				t.Fatalf("state current %+v, last_good %+v; want delivery ids agent-7:d.5 and agent-7:d.1", st.Current, st.LastGood)
			}
			for _, ref := range []*enterprisebundle.Ref{st.Current, st.LastGood} {
				schemas.ValidateValue(t, "bundle-status.schema.json#/$defs/ref", ref)
			}
			schemas.ValidateValue(t, "bundle-status.schema.json#/$defs/receipt", b.receipt(bundleID(2)))
			status := b.run(Options{Action: ActionStatus})
			requireOK(t, status)
			if got := deliveryOf(schemas.ValidateValue(t, "lifecycle-result.schema.json", status), "bundle"); got != "agent-7:d.5" {
				t.Fatalf("status bundle.delivery_id = %v, want agent-7:d.5", got)
			}
		})
	}
}
