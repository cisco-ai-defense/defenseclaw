// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"context"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// TestStartRefusesARunningSandbox pins that Start leaves a running
// session alone: its ingress token, its pre-session snapshot, its tool-call
// ledger and its guard record stay as they are.
func TestStartRefusesARunningSandbox(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "livebox"})
	ingress, _ := e.client.GetProvider(ctx, "livebox-ingress")
	token := ingress.Spec.Credentials[openshell.EnvSandboxToken]
	snap := e.ws.snapshots["livebox"]
	binding, _ := e.store.Lookup("livebox")
	e.m.toolCalls.ObservePre(binding.ID, "toolu_1", false)
	e.m.mu.Lock()
	guard := e.m.boxes["livebox"].rec.Guard
	e.m.mu.Unlock()

	_, err := e.m.Start(ctx, "livebox", sandboxapi.StartRequest{})
	wantCode(t, err, sandboxapi.CodeConflict)

	ingress, _ = e.client.GetProvider(ctx, "livebox-ingress")
	if got := ingress.Spec.Credentials[openshell.EnvSandboxToken]; got != token {
		t.Fatal("start rotated the token of a running sandbox")
	}
	if e.ws.snapshots["livebox"] != snap {
		t.Fatal("start replaced the snapshot of a running session")
	}
	if n, _ := e.m.toolCalls.tracked(binding.ID); n != 1 {
		t.Fatalf("start reset the tool-call ledger (%d entries)", n)
	}
	e.m.mu.Lock()
	same := e.m.boxes["livebox"].rec.Guard == guard
	e.m.mu.Unlock()
	if !same {
		t.Fatal("start replaced the guard record of a running session")
	}
}

// TestLifecycleCallsDuringCreateFailFast pins that a lifecycle call on a
// sandbox being created is refused at once instead of waiting out the
// create, which may build an image for up to defaultCreateTimeout.
func TestLifecycleCallsDuringCreateFailFast(t *testing.T) {
	e := newEnv(t, nil)
	b, err := e.m.reserve("slowbox")
	if err != nil {
		t.Fatal(err)
	}
	b.op.Lock()
	defer b.op.Unlock()
	for name, call := range map[string]func() error{
		"stop": func() error { _, err := e.m.Stop(context.Background(), "slowbox"); return err },
		"start": func() error {
			_, err := e.m.Start(context.Background(), "slowbox", sandboxapi.StartRequest{})
			return err
		},
		"delete": func() error {
			_, err := e.m.Delete(context.Background(), "slowbox", sandboxapi.DeleteRequest{})
			return err
		},
		"undo": func() error {
			_, err := e.m.Undo(context.Background(), "slowbox", sandboxapi.UndoRequest{})
			return err
		},
	} {
		done := make(chan error, 1)
		go func() { done <- call() }()
		select {
		case err := <-done:
			wantCode(t, err, sandboxapi.CodeConflict)
		case <-time.After(5 * time.Second):
			t.Fatalf("%s waited for the create", name)
		}
	}
}
