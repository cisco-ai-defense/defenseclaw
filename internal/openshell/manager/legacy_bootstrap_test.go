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

//go:build !windows

package manager

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/openshelltest"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// legacyDockerGateway makes e's fake gateway start a Docker sandbox the way
// OpenShell 0.1.5 does (GAP-0300): it reads the bootstrap the docker driver
// keeps for the sandbox in stateHome, and refuses one an OpenShell before
// 0.1.5 wrote, as the live 0.1.5 gateway did. It stages the bootstrap
// OpenShell 0.1.3 wrote for a live sandbox (../testdata/docker-bootstrap)
// as the sandbox name's (which takes that sandbox's OpenShell id), and
// returns its folder.
func legacyDockerGateway(t *testing.T, e *harnessEnv, stateHome, name string) string {
	t.Helper()
	// The id of the live sandbox the fixture is from.
	const id = "173db0f1-f401-4104-b94b-aaec75789fc3"
	sb, err := e.fake.Sandboxes().Get(t.Context(), openshell.DefaultWorkspace, name)
	must(t, err)
	sb.ID = id
	sb.ResourceVersion++
	e.fake.SDK().AddSandbox(openshell.DefaultWorkspace, sb)
	dir := filepath.Join(stateHome, "openshell", "docker-sandbox-tokens", openshell.DefaultDockerNamespace, id)
	must(t, os.MkdirAll(dir, 0o700))
	for _, f := range []string{"boundary-bootstrap.json", "runtime-descriptor.json"} {
		data, err := os.ReadFile(filepath.Join("..", "testdata", "docker-bootstrap", "0.1.3", f))
		must(t, err)
		must(t, os.WriteFile(filepath.Join(dir, f), data, 0o600))
	}
	e.fake.Intercept(func(method string) error {
		if method != openshelltest.MethodStartSandbox {
			return nil
		}
		data, err := os.ReadFile(filepath.Join(dir, "boundary-bootstrap.json"))
		if err == nil && strings.Contains(string(data), `"outer_fence"`) {
			return &types.StatusError{Code: types.ErrorConflict, Message: "start sandbox failed: decode Docker sandbox bootstrap for authentication rotation: " +
				"unknown field `outer_fence`, expected one of `boundary_id`, `generation`, `session_id`, `session_rotation`, `auth_epoch`, `gateway_id`, " +
				"`verification_keys`, `listener`, `resource_claims`, `resource_claim_files`, `workload_identity`, `provisioning_evidence`, `child_env` at line 1 column 1066"}
		}
		return nil
	})
	return dir
}

// TestADockerSandboxMadeBefore015StartsOn015 (GAP-0300): a Docker sandbox
// OpenShell 0.1.3 created stopped on the 0.1.5 upgrade and then failed
// every start ("unknown field `outer_fence`"), and so every pull that
// starts it: nothing moved the bootstrap 0.1.3 had kept for it. The start
// now moves it to 0.1.5's format first, once, and the sandbox starts with
// its work. One DefenseClaw cannot move refuses before OpenShell is asked;
// one it did not find (the gateway keeps its state elsewhere) says what
// failed and where DefenseClaw looks; a MicroVM's start moves nothing.
func TestADockerSandboxMadeBefore015StartsOn015(t *testing.T) {
	e := liveEnv(t, "oldbox", nil)
	stateHome := t.TempDir()
	dir := legacyDockerGateway(t, e, stateHome, "oldbox")
	var mu sync.Mutex
	var moved []string
	e.m.opts.MigrateBootstrap = func(id string) ([]string, error) {
		mu.Lock()
		moved = append(moved, id)
		mu.Unlock()
		moved, _, err := openshell.MigrateDockerBootstrap(stateHome, id)
		return moved, err
	}
	e.stopBox("oldbox")
	starts := e.fake.Calls(openshelltest.MethodStartSandbox)
	if _, err := e.m.Start(t.Context(), "oldbox", sandboxapi.StartRequest{}); err != nil {
		t.Fatalf("the start of a sandbox 0.1.3 made, on 0.1.5: %v", err)
	}
	if e.fake.Calls(openshelltest.MethodStartSandbox) != starts+1 || len(moved) != 1 {
		t.Fatalf("starts %d, moves %v", e.fake.Calls(openshelltest.MethodStartSandbox)-starts, moved)
	}
	data, err := os.ReadFile(filepath.Join(dir, "boundary-bootstrap.json"))
	must(t, err)
	if strings.Contains(string(data), `"outer_fence"`) || !strings.Contains(string(data), `"provisioning_evidence"`) {
		t.Fatalf("the bootstrap was not moved: %s", data)
	}
	// It stops and starts again as any 0.1.5 sandbox: nothing left to move.
	e.stopBox("oldbox")
	e.startBox("oldbox", sandboxapi.StartRequest{})

	// A bootstrap DefenseClaw cannot move: refused before OpenShell's start.
	e.stopBox("oldbox")
	must(t, os.Remove(filepath.Join(dir, "boundary-bootstrap.json")))
	legacy, err := os.ReadFile(filepath.Join("..", "testdata", "docker-bootstrap", "0.1.3", "boundary-bootstrap.json"))
	must(t, err)
	elsewhere := filepath.Join(t.TempDir(), "boundary-bootstrap.json")
	must(t, os.WriteFile(elsewhere, legacy, 0o600))
	must(t, os.Symlink(elsewhere, filepath.Join(dir, "boundary-bootstrap.json")))
	starts = e.fake.Calls(openshelltest.MethodStartSandbox)
	_, err = e.m.Start(t.Context(), "oldbox", sandboxapi.StartRequest{})
	var apiErr *sandboxapi.Error
	if !errors.As(err, &apiErr) || apiErr.Code != sandboxapi.CodeConflict || !strings.Contains(apiErr.Message, "an OpenShell older than 0.1.5 created it") ||
		!strings.Contains(apiErr.Detail, "the sandbox and its work are kept") || e.fake.Calls(openshelltest.MethodStartSandbox) != starts {
		t.Fatalf("a bootstrap that cannot be moved: %v (%d starts)", err, e.fake.Calls(openshelltest.MethodStartSandbox)-starts)
	}

	// One DefenseClaw does not find: OpenShell's refusal, said plainly.
	must(t, os.Remove(filepath.Join(dir, "boundary-bootstrap.json")))
	must(t, os.WriteFile(filepath.Join(dir, "boundary-bootstrap.json"), legacy, 0o600))
	e.m.opts.MigrateBootstrap = func(string) ([]string, error) { return nil, nil }
	_, err = e.m.Start(t.Context(), "oldbox", sandboxapi.StartRequest{})
	if !errors.As(err, &apiErr) || apiErr.Code != sandboxapi.CodeConflict || !strings.Contains(apiErr.Message, "unknown field `outer_fence`") ||
		!strings.Contains(apiErr.Detail, "docker-sandbox-tokens") {
		t.Fatalf("a bootstrap DefenseClaw did not find: %v", err)
	}
}

// TestAMicroVMStartMovesNoDockerBootstrap: only a docker gateway keeps the
// bootstrap files MigrateBootstrap moves.
func TestAMicroVMStartMovesNoDockerBootstrap(t *testing.T) {
	e, _ := newEndedVM(t, "vmbox")
	called := false
	e.m.opts.MigrateBootstrap = func(string) ([]string, error) { called = true; return nil, errors.New("not a docker sandbox") }
	e.stopBox("vmbox")
	e.startBox("vmbox", sandboxapi.StartRequest{})
	if called {
		t.Fatal("the start of a MicroVM moved a Docker bootstrap")
	}
}
