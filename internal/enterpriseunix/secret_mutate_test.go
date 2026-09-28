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
	"path/filepath"
	"testing"
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
	if len(h.services.calls) != before {
		t.Fatalf("a failed change touched services: %v", h.services.calls[before:])
	}
	if r := h.run(Options{Action: ActionRepair, Mutate: func(context.Context) error { return nil }}); r.OK {
		t.Fatal("a change outside ensure must be refused")
	}
}
