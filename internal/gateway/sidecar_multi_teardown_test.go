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

package gateway

import (
	"context"
	"errors"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// recordingConnector embeds stubConnector (which satisfies the full
// connector.Connector interface) and records teardown invocations, optionally
// returning injected errors to exercise the continue-on-error path.
type recordingConnector struct {
	stubConnector
	teardownCalls int
	verifyCalls   int
	teardownErr   error
	verifyErr     error
}

func (r *recordingConnector) Teardown(context.Context, connector.SetupOpts) error {
	r.teardownCalls++
	return r.teardownErr
}

func (r *recordingConnector) VerifyClean(connector.SetupOpts) error {
	r.verifyCalls++
	return r.verifyErr
}

func newRecordingRegistry(conns ...*recordingConnector) *connector.Registry {
	reg := connector.NewRegistry()
	for _, c := range conns {
		reg.RegisterBuiltin(c)
	}
	return reg
}

// TestTeardownRemovedConnectors_TearsDownOnlyRemoved verifies the set
// difference: connectors in previous but not current are torn down; those
// still active are left alone.
func TestTeardownRemovedConnectors_TearsDownOnlyRemoved(t *testing.T) {
	a := &recordingConnector{stubConnector: stubConnector{name: "codex"}}
	b := &recordingConnector{stubConnector: stubConnector{name: "cursor"}}
	c := &recordingConnector{stubConnector: stubConnector{name: "copilot"}}
	reg := newRecordingRegistry(a, b, c)

	teardownRemovedConnectors(reg, []string{"codex", "cursor", "copilot"}, []string{"cursor"}, connector.SetupOpts{}, context.Background())

	if a.teardownCalls != 1 {
		t.Errorf("codex (removed) teardownCalls=%d, want 1", a.teardownCalls)
	}
	if c.teardownCalls != 1 {
		t.Errorf("copilot (removed) teardownCalls=%d, want 1", c.teardownCalls)
	}
	if b.teardownCalls != 0 {
		t.Errorf("cursor (still active) teardownCalls=%d, want 0", b.teardownCalls)
	}
}

// TestTeardownRemovedConnectors_CaseInsensitiveKeep ensures a case mismatch
// between persisted and current names never tears down an active connector.
func TestTeardownRemovedConnectors_CaseInsensitiveKeep(t *testing.T) {
	a := &recordingConnector{stubConnector: stubConnector{name: "codex"}}
	reg := newRecordingRegistry(a)

	teardownRemovedConnectors(reg, []string{"codex"}, []string{"Codex"}, connector.SetupOpts{}, context.Background())

	if a.teardownCalls != 0 {
		t.Errorf("codex must be kept despite case mismatch; teardownCalls=%d, want 0", a.teardownCalls)
	}
}

// TestTeardownRemovedConnectors_ContinuesOnError verifies that a teardown
// failure on one removed connector does not stop the others from being torn
// down (DN1 / continue-on-error).
func TestTeardownRemovedConnectors_ContinuesOnError(t *testing.T) {
	a := &recordingConnector{stubConnector: stubConnector{name: "codex"}, teardownErr: errors.New("boom")}
	b := &recordingConnector{stubConnector: stubConnector{name: "cursor"}, verifyErr: errors.New("stale")}
	reg := newRecordingRegistry(a, b)

	teardownRemovedConnectors(reg, []string{"codex", "cursor"}, nil, connector.SetupOpts{}, context.Background())

	if a.teardownCalls != 1 {
		t.Errorf("codex teardownCalls=%d, want 1", a.teardownCalls)
	}
	if b.teardownCalls != 1 {
		t.Errorf("cursor teardownCalls=%d, want 1 (must run despite codex error)", b.teardownCalls)
	}
	// Even when teardown errored, VerifyClean is still attempted.
	if a.verifyCalls != 1 {
		t.Errorf("codex verifyCalls=%d, want 1", a.verifyCalls)
	}
}

// TestTeardownRemovedConnectors_SkipsUnknownRegistryName confirms a removed
// name that is not in the registry is skipped without panic.
func TestTeardownRemovedConnectors_SkipsUnknownRegistryName(t *testing.T) {
	reg := connector.NewRegistry()
	teardownRemovedConnectors(reg, []string{"ghost"}, nil, connector.SetupOpts{}, context.Background())
	// No panic, nothing to assert beyond reaching here.
}

// TestTeardownRemovedConnectors_NoPreviousIsNoop covers the empty/nil guards.
func TestTeardownRemovedConnectors_NoPreviousIsNoop(t *testing.T) {
	a := &recordingConnector{stubConnector: stubConnector{name: "codex"}}
	reg := newRecordingRegistry(a)

	teardownRemovedConnectors(reg, nil, []string{"codex"}, connector.SetupOpts{}, context.Background())
	teardownRemovedConnectors(nil, []string{"codex"}, nil, connector.SetupOpts{}, context.Background())

	if a.teardownCalls != 0 {
		t.Errorf("no-op cases must not tear down; teardownCalls=%d, want 0", a.teardownCalls)
	}
}
