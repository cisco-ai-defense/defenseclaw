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
	"bytes"
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

// GAP-2504: the PowerShell call operator in a message stays a literal & when
// the CLI encodes a Result with SetEscapeHTML(false).
// A standard user cannot read the root-only deployment record, so a not_root
// result checked nothing. It reported installed: false, no services and every
// readiness flag false, which reads as "not installed" (GAP-0279).
func TestNotRootResultLeavesOutTheDeploymentState(t *testing.T) {
	r := New("ensure", "standalone", "linux", "1.4.0")
	r.AddError("not_root", "run this command as root (sudo or the MDM agent)")
	r.Finish("linux", 0)
	document, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(document, &fields); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"installed", "services", "readiness", "enrollment"} {
		if _, ok := fields[name]; ok {
			t.Errorf("a not_root result reports %s: %s", name, document)
		}
	}
	if fields["ok"] != false || fields["errors"] == nil {
		t.Fatalf("the refusal itself is missing: %s", document)
	}
	r.PreserveNotRootDeploymentState = true
	document, err = json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(document, &fields); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"installed", "services", "readiness", "enrollment"} {
		if _, ok := fields[name]; !ok {
			t.Errorf("Secure Client not_root result lacks %s: %s", name, document)
		}
	}
}

func TestResultMarshalJSONKeepsAmpersandLiteral(t *testing.T) {

	r := New("status", "standalone", "windows", "1.0.0")
	r.AddError("elevation_required", "run `& 'C:\\Program Files\\Cisco\\DefenseClaw\\bin\\defenseclaw.exe' enterprise windows status`")
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(r); err != nil {
		t.Fatal(err)
	}
	if out := buf.String(); strings.Contains(out, `\u0026`) || !strings.Contains(out, "`& '") {
		t.Fatalf("message must keep a literal &: %s", out)
	}
	var back Result
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil || len(back.Errors) != 1 {
		t.Fatalf("round trip: %v %+v", err, back.Errors)
	}
}
