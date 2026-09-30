// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// Devin plugin hooks run in the CLI and in Devin Local and can rewrite tool
// input: installed and locally linked plugins are scanned and reported.
func TestGuardScansDevinPluginHooks(t *testing.T) {
	req := guardRequest(t, "devin", config.ForeignHooksRemove)
	store := filepath.Join(req.Home, ".local", "share", "devin", "cli", "plugins")
	cached := filepath.Join(store, "cache", "mkt", "rewriter", "1.0.0")
	writeFile(t, filepath.Join(cached, ".devin-plugin", "plugin.json"), `{"name": "rewriter"}`)
	hooks := filepath.Join(cached, "hooks.json")
	writeFile(t, hooks, `{"PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "./rewrite.sh"}]}]}`)
	linked := filepath.Join(req.Home, "src", "linked")
	writeFile(t, filepath.Join(linked, "plugin.json"), `{"name": "linked", "hooks": {"PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "./x.sh"}]}]}}`)
	writeFile(t, filepath.Join(store, "lock.json"), `{"plugins": {"linked": {"source": `+jsonString(linked)+`}, "gone": {"source": `+jsonString(filepath.Join(req.Home, "missing"))+`}}}`)

	decision := EvaluateForeignHooks(req)
	if !decision.Deny || len(decision.Findings) != 2 || !strings.Contains(decision.Reason, hooks) {
		t.Fatalf("installed and linked Devin plugin hooks must deny: %+v", decision)
	}
	result, err := CleanUserForeignHooks(req, time.Now())
	if err != nil || len(result.Removed) != 0 || len(result.Reported) != 2 || readFile(t, hooks) == "" {
		t.Fatalf("Devin plugin hooks are reported, never removed: %+v %v", result, err)
	}

	// Every recorded path counts against the scan budget, missing ones too.
	var many []string
	for i := 0; i <= guardScanReferenceLimit; i++ {
		many = append(many, jsonString(fmt.Sprintf("/m/%d", i)))
	}
	writeFile(t, filepath.Join(store, "lock.json"), `{"paths": [`+strings.Join(many, ",")+`]}`)
	if decision := EvaluateForeignHooks(req); !decision.Incomplete || !decision.Deny {
		t.Fatalf("a record past the scan budget must stop the scan: %+v", decision.Findings)
	}
}
