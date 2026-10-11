// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
)

type sandboxStampCapture struct {
	record observability.Record
}

func (capture *sandboxStampCapture) EmitRuntimeV8(
	_ context.Context, _ router.Metadata, build audit.RuntimeV8Builder,
) (audit.RuntimeV8EmitOutcome, error) {
	record, err := build(audit.RuntimeV8BuildContext{
		ConfigGeneration: 1,
		ConfigDigest:     strings.Repeat("a", 64),
	}, router.AdmissionOrdinary)
	capture.record = record
	return audit.RuntimeV8EmitOutcome{Admission: router.AdmissionOrdinary, LocalPersisted: true}, err
}

func TestPublishedGenerationStampsSandboxWithoutWatcher(t *testing.T) {
	previous := currentGeneration()
	audit.SetPolicyStamp(nil)
	t.Cleanup(func() {
		liveGeneration.Store(previous)
		audit.SetPolicyStamp(nil)
	})

	cfg := config.DefaultConfig()
	cfg.Gateway.Watcher.Enabled = false
	sidecar := &Sidecar{}
	sidecar.publishGeneration(&Generation{
		Config: cfg,
		Digest: "sha256:" + strings.Repeat("b", 64),
	})
	capture := &sandboxStampCapture{}
	logger := audit.NewLogger(nil)
	logger.SetRuntimeV8Emitter(capture)
	recorder := audit.NewSandboxRecorder(logger)
	err := recorder.RecordSandboxEgress(context.Background(), audit.SandboxEgressEvent{
		Sandbox: audit.SandboxIdentity{Name: "sandbox-test", Runtime: audit.SandboxRuntimeOpenShell},
		Source:  audit.SandboxEgressSourceProxy,
		Host:    "example.com",
		Blocked: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := capture.record.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	var record struct {
		Body map[string]any `json:"body"`
	}
	if err := json.Unmarshal(encoded, &record); err != nil {
		t.Fatal(err)
	}
	if got := record.Body["defenseclaw.policy.effective_digest"]; got != sidecar.Generation().Digest {
		t.Fatalf("sandbox policy digest = %v, want %s", got, sidecar.Generation().Digest)
	}
	if got := record.Body["defenseclaw.policy.generation"]; got != float64(sidecar.Generation().N) {
		t.Fatalf("sandbox policy generation = %v, want %d", got, sidecar.Generation().N)
	}
}
