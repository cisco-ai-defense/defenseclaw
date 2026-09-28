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
	"strings"
	"testing"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/openshelltest"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// createdButLost makes the next CreateSandbox create the sandbox (with the
// given labels) and then fail as unavailable, as when the gateway restarts
// after it accepted the request.
func createdButLost(e *harnessEnv, labels map[string]string) {
	done := false
	e.fake.Intercept(func(method string) error {
		if method != openshelltest.MethodCreateSandbox || done {
			return nil
		}
		done = true
		if _, err := e.fake.SDK().Sandboxes().Create(context.Background(), openshell.DefaultWorkspace, "lostbox",
			&types.SandboxSpec{}, labels); err != nil {
			e.t.Errorf("create the sandbox under the call: %v", err)
		}
		return &types.StatusError{Code: types.ErrorUnavailable, Message: "the gateway restarted"}
	})
}

// TestCreateRollsBackASandboxWhoseCreateReplyWasLost pins that a create
// whose CreateSandbox call failed after OpenShell created the sandbox
// deletes it with everything else, instead of leaving it running with the
// project mounted and no record.
func TestCreateRollsBackASandboxWhoseCreateReplyWasLost(t *testing.T) {
	e := newEnv(t, nil)
	createdButLost(e, e.m.managedSelector())
	_, err := e.m.Create(context.Background(), sandboxapi.CreateRequest{Name: "lostbox", Harness: "claudecode", Project: e.project})
	wantCode(t, err, sandboxapi.CodeUnavailable)
	assertNothingLeft(t, e)
}

// TestCreateRollbackLeavesAnotherOwnersSandbox pins that the rollback only
// deletes a sandbox of the name that carries this data dir's labels.
func TestCreateRollbackLeavesAnotherOwnersSandbox(t *testing.T) {
	e := newEnv(t, nil)
	createdButLost(e, map[string]string{LabelManaged: "true", LabelOwner: "fedcba9876543210"})
	_, err := e.m.Create(context.Background(), sandboxapi.CreateRequest{Name: "lostbox", Harness: "claudecode", Project: e.project})
	wantCode(t, err, sandboxapi.CodeUnavailable)
	if _, err := e.client.GetSandbox(context.Background(), "lostbox"); err != nil {
		t.Fatalf("the rollback deleted another daemon's sandbox: %v", err)
	}
}

// TestCreateRollbackReleasesCredentialProfiles pins that a failed create
// collects the --credential provider profile it imported once no provider
// uses it, as a delete does.
func TestCreateRollbackReleasesCredentialProfiles(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	e.fake.FailNext(openshelltest.MethodCreateSandbox, &types.StatusError{Code: types.ErrorInvalidArgument, Message: "bad spec"})
	_, err := e.m.Create(ctx, sandboxapi.CreateRequest{Name: "credrb", Harness: "claudecode", Project: e.project,
		Credentials: []sandboxapi.CredentialBinding{{Name: "STRIPE_API_KEY", Value: "stripe-secret", Host: "api.stripe.com"}}})
	wantCode(t, err, sandboxapi.CodeInvalid)
	assertNothingLeft(t, e)
	list, err := e.client.ListProfiles(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range list {
		if strings.HasPrefix(p.ID, credentialProfilePrefix) {
			t.Fatalf("the failed create left its credential profile %s", p.ID)
		}
	}
}
