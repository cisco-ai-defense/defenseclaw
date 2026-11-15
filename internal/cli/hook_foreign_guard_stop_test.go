// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/defenseclaw/defenseclaw/internal/hookcli"
)

// foreignGuardStopCase is one connector's session: where its foreign hook
// lives, the payload's session key, and its events.
type foreignGuardStopCase struct {
	connector, file, body, key string
	// bound: the command binds the event (--event), as Codex and Copilot
	// registrations do; the others read it from the payload.
	bound       bool
	start, tool string
	stops       []string
	// deny reports whether a result is the connector's tool-call block.
	deny func(code int, stdout string) bool
	// allow is the connector's neutral stdout on a stop event.
	allow string
}

// hookResult is one full hook invocation: the guard, then hookexec.
type hookResult struct {
	code           int
	stdout, stderr string
}

func (f *foreignGuardFixture) runHook(t *testing.T, tc foreignGuardStopCase, event, session string) hookResult {
	t.Helper()
	payload, err := json.Marshal(map[string]any{"hook_event_name": event, "cwd": filepath.Join(f.project, "src"), tc.key: session})
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	opts := hookexec.Options{
		Connector:         tc.connector,
		ManagedEnterprise: true,
		FailMode:          "closed",
		Home:              filepath.Join(f.home, "managed-data"),
		Stdin:             bytes.NewReader(payload),
		Stdout:            &stdout,
		Stderr:            &stderr,
	}
	if tc.bound {
		opts.Event = event
	}
	if tc.connector == "codex" {
		opts.HookContractID = "codex-hooks-v4"
	}
	hookcli.ApplyEnterpriseForeignHookGuard(&opts)
	if !strings.HasPrefix(opts.ManagedRuntimeFailure, hookexec.ForeignHookBlockedReasonPrefix) {
		t.Fatalf("%s %s: the session must be blocked by the guard: %+v", tc.connector, event, opts)
	}
	code := hookexec.Run(context.Background(), opts)
	return hookResult{code: code, stdout: strings.TrimSpace(stdout.String()), stderr: stderr.String()}
}
