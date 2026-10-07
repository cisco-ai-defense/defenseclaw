// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package kernelpolicy

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestReconcilerRefusesToWriteWithoutItsCleanupLock(t *testing.T) {
	h := newHarness(t, observeIntent(), baseTargets)
	h.procs = twoUserProcs()
	badState := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(badState, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	h.ctl.cfg.Dirs.State = badState
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := h.ctl.Run(ctx); err == nil {
		t.Fatal("a helper without the lock must not reconcile")
	}
	for _, call := range h.tg.take() {
		if len(call) >= 4 && (call[:4] == "add:" || call[:4] == "dele") {
			t.Fatalf("policy mutation without the lock: %s", call)
		}
	}
}
