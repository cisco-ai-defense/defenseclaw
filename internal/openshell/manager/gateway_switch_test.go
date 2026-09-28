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
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/openshelltest"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// switchGateway makes the manager's next connection gw.
func switchGateway(t *testing.T, e *harnessEnv, gw *Gateway) {
	t.Helper()
	cur, err := e.m.gateway(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	e.gw = gw
	e.m.dropGateway(cur, &types.StatusError{Code: types.ErrorUnavailable, Message: "reconnecting"})
}

// TestReconcileKeepsSandboxesOfAnotherGateway pins that a daemon that
// connects to another gateway (it followed the CLI's active gateway, say)
// does not release the sandboxes it created on the first one, which that
// gateway's list naturally lacks: they are reported missing, and adopted
// again once the daemon is back on their gateway.
func TestReconcileKeepsSandboxesOfAnotherGateway(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	e.create(sandboxapi.CreateRequest{Name: "homebox"})
	home := e.gw
	other := openshelltest.New()
	switchGateway(t, e, &Gateway{Client: other.Client(openshell.ClientOptions{PollInterval: time.Millisecond}),
		Name: "other", Endpoint: "https://127.0.0.1:27670", Port: 27670, Version: "0.1.1"})
	if err := e.m.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := e.store.Lookup("homebox"); err != nil {
		t.Fatalf("the binding of a sandbox on another gateway was revoked: %v", err)
	}
	if slices.Contains(e.ws.released, "homebox") || slices.Contains(e.ws.deleted, "homebox") {
		t.Fatalf("its mount or snapshot was released: released %v deleted %v", e.ws.released, e.ws.deleted)
	}
	got, err := e.m.Get(ctx, "homebox")
	if err != nil || got.Phase != "missing" || !slices.ContainsFunc(got.Warnings, func(w string) bool {
		return strings.Contains(w, "created on gateway openshell")
	}) {
		t.Fatalf("get = %+v, %v; want it missing with the gateway it lives on", got, err)
	}

	switchGateway(t, e, home)
	if err := e.m.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	got, err = e.m.Get(ctx, "homebox")
	if err != nil || got.Phase != "ready" || len(got.Warnings) != 0 {
		t.Fatalf("back on its gateway: %+v, %v", got, err)
	}
}

// TestReconcileKeepsSandboxesOfAnotherWorkspace is the same for an
// OpenShell workspace change on one gateway.
func TestReconcileKeepsSandboxesOfAnotherWorkspace(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	e.create(sandboxapi.CreateRequest{Name: "wsbox"})
	moved := *e.gw
	moved.Client = e.fake.Client(openshell.ClientOptions{PollInterval: time.Millisecond, Workspace: "team"})
	switchGateway(t, e, &moved)
	if err := e.m.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := e.store.Lookup("wsbox"); err != nil {
		t.Fatalf("the binding of a sandbox in another workspace was revoked: %v", err)
	}
}
