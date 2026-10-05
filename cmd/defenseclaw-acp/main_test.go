// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// An editor entry left over after `acp remove` starts a guard whose contract
// lock is gone. The editor must get a JSON-RPC error with a next step, not a
// closed pipe and an internal term on stderr (GAP-2197).
func TestRemovedBindingAnswersInitializeWithPlainError(t *testing.T) {
	dir := t.TempDir()
	err := run([]string{
		"--client", "zed", "--agent", "kiro", "--profile", "vb9kiro", "--mode", "action",
		"--contract-lock", filepath.Join(dir, "missing.lock.json"),
		"--token-file", filepath.Join(dir, "token"),
		"--", filepath.Join(dir, "kiro-cli"),
	})
	var startup *startupError
	if !errors.As(err, &startup) {
		t.Fatalf("run() error = %v, want a startup error", err)
	}
	for _, want := range []string{
		"not set up for zed/kiro",
		"defenseclaw acp setup --client zed --agent kiro --profile vb9kiro --activate",
		"delete this editor entry",
	} {
		if !strings.Contains(startup.message, want) {
			t.Fatalf("message %q does not contain %q", startup.message, want)
		}
	}
	if strings.Contains(startup.message, "unsafe") {
		t.Fatalf("message %q still uses internal wording", startup.message)
	}

	in := strings.NewReader(`{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":1}}` + "\n")
	var out bytes.Buffer
	if !answerFirstRequest(in, &out, startup.message, time.Second) {
		t.Fatal("answerFirstRequest wrote no response")
	}
	var resp struct {
		ID    json.RawMessage `json:"id"`
		Error struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &resp); err != nil {
		t.Fatalf("response %q is not JSON: %v", out.String(), err)
	}
	if string(resp.ID) != "0" || resp.Error.Code != startupErrorCode || resp.Error.Message != startup.message {
		t.Fatalf("unexpected response %s", out.String())
	}
}

func TestAnswerFirstRequestGivesUpWithoutARequest(t *testing.T) {
	reader, writer := io.Pipe()
	defer writer.Close()
	var out bytes.Buffer
	if answerFirstRequest(reader, &out, "x", 20*time.Millisecond) || out.Len() != 0 {
		t.Fatalf("expected no response, got %q", out.String())
	}
}
