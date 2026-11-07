// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
)

func TestGAP0494ManagedAntigravityOutageReasonAndBenignTwin(t *testing.T) {
	shortRestartBudget(t)
	home := t.TempDir()
	token := "managed-test-token"
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), Options{
		Connector:                 "antigravity",
		Event:                     "PreToolUse",
		APIAddr:                   "127.0.0.1:1",
		Home:                      home,
		FailureLogHome:            userLogHome(home),
		HookDir:                   filepath.Join(home, "hooks"),
		FailMode:                  "closed",
		ManagedEnterprise:         true,
		ExplainUnenrolledAccount:  true,
		AuthenticatedManagedToken: &token,
		Stdin:                     strings.NewReader(`{"conversationId":"c1","toolCall":{"name":"run_command","args":{"CommandLine":"echo hello"}}}`),
		Stdout:                    &stdout,
		Stderr:                    &stderr,
		HTTPClient:                &http.Client{Transport: notRunningRT{}},
	})
	var answer struct {
		Decision string `json:"decision"`
		Reason   string `json:"reason"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &answer); err != nil {
		t.Fatalf("native answer %q: %v", stdout.String(), err)
	}
	if code != 0 || answer.Decision != "deny" {
		t.Fatalf("native answer: code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	for _, part := range []string{"gateway service is not running", "ask your administrator", managedGatewayNotRunningReason} {
		if !strings.Contains(answer.Reason, part) {
			t.Errorf("native reason %q lacks %q (stderr %q)", answer.Reason, part, stderr.String())
		}
	}

	benign := run(t, "antigravity", ok(`{"action":"allow"}`), func(opts *Options) {
		opts.Event = "PreToolUse"
		opts.Stdin = strings.NewReader(`{"conversationId":"c2","toolCall":{"name":"run_command","args":{"CommandLine":"echo hello"}}}`)
	})
	if benign.code != 0 || !strings.Contains(benign.stdout, `"decision":"allow"`) {
		t.Fatalf("ordinary call: code=%d stdout=%q stderr=%q", benign.code, benign.stdout, benign.stderr)
	}
}
