// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGAP0518OrdinaryLateProofBeyondMentionIndex(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	cache := filepath.Join(home, ".defenseclaw", "cache")
	for _, dir := range []string{cwd, cache} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 4100; i++ {
		if err := os.WriteFile(filepath.Join(cache, fmt.Sprintf("entry-%04d", i)), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	ordinary := filepath.Join(cwd, "notes")
	alias := filepath.Join(cwd, "notes-alias")
	if err := os.WriteFile(ordinary, []byte("ordinary"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(ordinary, alias); err != nil {
		t.Skipf("hard link unavailable: %v", err)
	}
	body := []byte(`{"hook_event_name":"PreToolUse","tool_name":"Read","cwd":` + mustJSONString(cwd) +
		`,"tool_input":{"file_path":` + mustJSONString(alias) + `}}`)
	if got := ordinaryNoAnswerPayloadInHome(body, home); !got {
		t.Error("ordinary Read cannot take balanced late outcome when state index is full")
	}
	words := make([]string, 2000)
	for i := 0; i < len(words)-1; i++ {
		words[i] = fmt.Sprintf("new-%04d", i)
	}
	words[len(words)-1] = "notes-alias"
	command := "touch " + strings.Join(words, " ")
	long := []byte(`{"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":` + mustJSONString(cwd) +
		`,"tool_input":{"command":` + mustJSONString(command) + `}}`)
	if got := ordinaryNoAnswerPayloadInHome(long, home); !got {
		t.Error("ordinary 2,000-operand touch cannot take balanced late outcome when state index is full")
	}
}
