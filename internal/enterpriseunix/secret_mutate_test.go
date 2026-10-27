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
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
)

// A credential change runs inside the lifecycle lock: an apply watcher that
// the write wakes cannot start its own ensure until the change is applied.
func TestSecretChangeIsWrittenAndAppliedUnderOneLock(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			var raced error
			r := h.run(Options{Action: ActionEnsure, Reason: "secret", Mutate: func(ctx context.Context) error {
				if err := h.env.WriteSecret(ctx, "ai-defense-api-key", []byte("s3cr3t")); err != nil {
					return err
				}
				lock, err := h.env.acquireLock(ctx)
				if err == nil {
					lock.release()
				}
				raced = err
				return nil
			}})
			requireOK(t, r)
			if !errors.Is(raced, errLockBusy) {
				t.Fatalf("a concurrent lifecycle run could take the lock during the change: %v", raced)
			}
			if r.Noop {
				t.Fatal("the new credential must be applied by the same run")
			}
			if !exists(filepath.Join(h.env.P(h.env.Layout.SecretsDir), "ai-defense-api-key")) {
				t.Fatal("credential not written")
			}
			if !h.run(Options{Action: ActionEnsure}).Noop {
				t.Fatal("the watcher's follow-up ensure should find nothing left to apply")
			}
		})
	}
}

func TestFailedSecretChangeAppliesNothing(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	before := len(h.services.calls)
	r := h.run(Options{Action: ActionEnsure, Reason: "secret", Mutate: func(context.Context) error {
		return errors.New("credential name is not valid")
	}})
	if r.OK || len(r.Errors) == 0 || r.Errors[0].Code != codeChange {
		t.Fatalf("result %+v", r)
	}
	// Only the apply watcher's pause around the change (GAP-2261).
	if got, want := h.services.calls[before:], []string{"stop " + unitApplyPath, "start " + unitApplyPath}; !slices.Equal(got, want) {
		t.Fatalf("a failed change touched services: %v", got)
	}
	if r := h.run(Options{Action: ActionRepair, Mutate: func(context.Context) error { return nil }}); r.OK {
		t.Fatal("a change outside ensure must be refused")
	}
}

// A secret set the signed bundle refuses (a value it does not bind) fails
// with the bundle's code, so the agent can tell a rotation that needs a new
// bundle from a failed write (GAP-0335).
func TestSecretChangeRefusalKeepsTheBundleCode(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	confirmed := &enterprisebundle.Manifest{TenantID: "acme", SecretRefs: []enterprisebundle.SecretRef{{Ref: "secret://splunk-token", Required: true,
		ValueSHA256: enterprisebundle.CredentialValueSHA256("acme", "splunk-token", []byte("v1"))}}}
	r := h.run(Options{Action: ActionEnsure, Reason: "secret", Mutate: func(context.Context) error {
		return enterprisebundle.CheckCredentialChange(confirmed, nil, "splunk-token", []byte("v2"))
	}})
	if r.OK || len(r.Errors) == 0 || r.Errors[0].Code != string(enterprisebundle.CodeSecretRefMismatch) {
		t.Fatalf("result %+v, want secret_ref_mismatch", r)
	}
}

// The apply watcher does not see the change's own write: it would start a
// redundant ensure that holds the lock after this run returns, so a command
// typed right after secret set failed lifecycle_busy (GAP-2261).
func TestSecretChangePausesTheApplyWatcher(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	if !h.services.isActive(unitApplyPath) {
		t.Fatal("the apply watcher should run after install")
	}
	watching := true
	r := h.run(Options{Action: ActionEnsure, Reason: "secret", Mutate: func(ctx context.Context) error {
		watching = h.services.isActive(unitApplyPath)
		return h.env.WriteSecret(ctx, "ai-defense-api-key", []byte("s3cr3t"))
	}})
	requireOK(t, r)
	if watching {
		t.Fatal("the apply watcher was watching while the credential was written")
	}
	if !h.services.isActive(unitApplyPath) {
		t.Fatal("the apply watcher was not started again")
	}
}

// GAP-1734: a credential change whose ensure then refuses the config before
// it changes anything (an untrusted pack in use) is put back: the credential
// store holds what it held, as the result's "the refused config changed
// nothing" says.
func TestRefusedSecretChangeIsPutBack(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	const pack = "/etc/defenseclaw/policies/guardrail/custom"
	if err := os.MkdirAll(h.env.P(pack), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := writeChangedConfig(t, h, "rule_pack: default",
		"rule_pack: acme\n  custom_packs:\n    acme: {path: "+pack+", digest: \"sha256:"+strings.Repeat("a", 64)+"\"}")
	requireOK(t, h.run(Options{Action: ActionEnsure, ConfigFile: cfg}))
	h.env.Trust = func(path string, kind TrustKind) error {
		if kind == TrustRulePack && path == h.env.P(pack) {
			return errors.New(path + ": group/other writable permissions 0775 are not trusted")
		}
		return nil
	}
	secret := filepath.Join(h.env.P(h.env.Layout.SecretsDir), "galileo-api-key")
	undone := false
	r := h.run(Options{Action: ActionEnsure, Reason: "secret",
		Mutate: func(ctx context.Context) error {
			return h.env.WriteSecret(ctx, "galileo-api-key", []byte("s3cr3t"))
		},
		MutateUndo: func(context.Context) error {
			undone = true
			return h.env.RemoveRotatedSecret("galileo-api-key")
		}})
	requireError(t, r, codeConfig)
	if !r.ConfigRefused || !undone {
		t.Fatalf("refused=%v undone=%v errors=%+v", r.ConfigRefused, undone, r.Errors)
	}
	if exists(secret) {
		t.Fatal("the refused credential change left the new credential on disk")
	}
	// A change the run applies is kept.
	h.env.Trust = func(string, TrustKind) error { return nil }
	undone = false
	r = h.run(Options{Action: ActionEnsure, Reason: "secret",
		Mutate: func(ctx context.Context) error {
			return h.env.WriteSecret(ctx, "galileo-api-key", []byte("s3cr3t"))
		},
		MutateUndo: func(context.Context) error { undone = true; return nil }})
	requireOK(t, r)
	if undone || !exists(secret) {
		t.Fatalf("an applied credential change was put back: undone=%v", undone)
	}
}
