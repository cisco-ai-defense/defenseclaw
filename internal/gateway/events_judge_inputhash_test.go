// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
)

func TestEmitJudgePersistsHashOfInputContent(t *testing.T) {
	rows := emitJudgeAndReadBodyRows(t, "the inspected judge input text")
	want := sha256.Sum256([]byte("the inspected judge input text"))
	wantHash := "sha256:" + hex.EncodeToString(want[:])
	if len(rows) != 1 || rows[0].InputHash != wantHash {
		t.Fatalf("persisted input hash = %#v, want %q", rows, wantHash)
	}
}

func TestEmitJudgePersistsEmptyInputHashWhenContentAbsent(t *testing.T) {
	rows := emitJudgeAndReadBodyRows(t, "")
	if len(rows) != 1 || rows[0].InputHash != "" {
		t.Fatalf("persisted input hash = %#v, want empty", rows)
	}
}

func emitJudgeAndReadBodyRows(t *testing.T, input string) []audit.JudgeResponse {
	t.Helper()
	bodyStore, err := audit.NewJudgeBodyStore(filepath.Join(t.TempDir(), "judge_bodies.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bodyStore.Close() })
	store := NewJudgeStoreFromBodyStore(bodyStore, nil, 8)
	SetJudgeResponseStore(store)
	t.Cleanup(func() { SetJudgeResponseStore(nil) })
	emitJudge(
		t.Context(), "injection", "test-model", gatewaylog.DirectionPrompt,
		len(input), 42, "allow", gatewaylog.SeverityInfo, "", "response-body",
		JudgeEmitOpts{InputContent: input},
	)
	if err := store.Shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
	SetJudgeResponseStore(nil)
	rows, err := bodyStore.ListJudgeResponses(10)
	if err != nil {
		t.Fatal(err)
	}
	return rows
}
