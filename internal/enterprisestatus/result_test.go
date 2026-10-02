// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisestatus

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestResultExitCodesAndJSON(t *testing.T) {
	r := New("ensure", "standalone", "linux", "1.0.0")
	if code := r.Finish("linux", 0); code != ExitOK || !r.OK {
		t.Fatalf("clean result: code=%d ok=%v", code, r.OK)
	}
	r.AddError("gateway_not_ready", "gateway did not report ready")
	if code := r.Finish("linux", 0); code != UnixExitFailure || r.OK {
		t.Fatalf("failed unix result: code=%d ok=%v", code, r.OK)
	}
	if code := r.Finish("windows", 0); code != WindowsExitFailure {
		t.Fatalf("failed windows result code=%d", code)
	}
	if code := r.Finish("windows", BusyExitCode("windows")); code != WindowsExitBusy {
		t.Fatalf("busy windows code=%d", code)
	}
	if BusyExitCode("darwin") != UnixExitBusy || InvalidArgsExitCode("windows") != WindowsExitInvalidArgs {
		t.Fatal("unexpected exit code mapping")
	}
	r.Services = []Service{{Name: "z", Kind: "gateway"}, {Name: "a", Kind: "guardian"}}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, `"schema_version":2`) || strings.Index(text, `"name":"a"`) > strings.Index(text, `"name":"z"`) {
		t.Fatalf("unexpected JSON: %s", text)
	}
	empty, _ := json.Marshal(Result{})
	for _, key := range []string{`"services":[]`, `"machine_policy":{}`, `"errors":[]`} {
		if !strings.Contains(string(empty), key) {
			t.Fatalf("empty result must render %s: %s", key, empty)
		}
	}
}
