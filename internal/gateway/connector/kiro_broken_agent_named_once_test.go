// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// rel-1-0-10 GAP-1745: the user's default agent is a file Kiro cannot parse;
// the removal fails, and the error names the file once, not once for each
// pass that read it.
func TestKiroRemoveNamesABrokenDefaultAgentOnce(t *testing.T) {
	home := t.TempDir()
	KiroHomeOverride = home
	t.Cleanup(func() { KiroHomeOverride = "" })
	data := filepath.Join(t.TempDir(), ".defenseclaw")
	if err := os.MkdirAll(data, 0o700); err != nil {
		t.Fatal(err)
	}
	mine := filepath.Join(home, "agents", "mine.json")
	if err := os.MkdirAll(filepath.Dir(mine), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeJSONObject(mine, map[string]interface{}{"name": "mine"}); err != nil {
		t.Fatal(err)
	}
	kiroChooseDefaultAgent(t, home, "mine")
	conn := NewKiroConnector()
	opts := SetupOpts{DataDir: data, APIAddr: "127.0.0.1:18970", APIToken: "tok-test", HookFailMode: "closed"}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	// The user (or a bad edit) breaks the file after Setup hooked it.
	if err := os.WriteFile(mine, []byte(`{"name":"mine","hooks":{"preToolUse":[ {oops not json`), 0o600); err != nil {
		t.Fatal(err)
	}
	err := conn.Teardown(context.Background(), opts)
	if err == nil {
		t.Fatal("Teardown succeeded with an unparsable default agent")
	}
	if n := strings.Count(err.Error(), mine); n != 1 {
		t.Fatalf("the error names %s %d times, want once: %v", mine, n, err)
	}
}
