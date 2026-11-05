// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	observabilityredaction "github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
)

// The folders a Claude Cowork session connected are a path-class field of
// the hook row's record body, so the strict profile removes them and the
// sensitive profile does not pass them through as content.
func TestCompatibilityAuditV8ClassifiesCoworkWorkspacePathsAsPath(t *testing.T) {
	logger := newTestLogger(t)
	runtime := newTestRuntimeV8Emitter(t, logger.store, router.AdmissionOrdinary)
	logger.SetRuntimeV8Emitter(runtime)
	paths := []string{"/Users/alice@corp.example/Desktop/cowork-work", "/Users/alice@corp.example/Documents/reports"}
	if err := logger.LogEventCtx(context.Background(), Event{
		Action: string(ActionConnectorHook), Target: "PreToolUse", Actor: "defenseclaw",
		Severity: "INFO", Connector: "claudecode", WorkspaceHostPaths: append(paths, "/bad\x07path"),
	}); err != nil {
		t.Fatalf("LogEventCtx: %v", err)
	}
	_, records := runtime.snapshot()
	if len(records) != 1 {
		t.Fatalf("records = %d, want 1", len(records))
	}
	body, _ := records[0].Body()
	object, err := body.Object()
	if err != nil {
		t.Fatal(err)
	}
	got, _ := object["workspace_host_paths"].([]any)
	if len(got) != 2 || got[0] != paths[0] || got[1] != paths[1] {
		t.Fatalf("workspace_host_paths = %#v, want %q", object["workspace_host_paths"], paths)
	}
	if records[0].FieldClasses()["/workspace_host_paths/0"] != observability.FieldClassPath ||
		records[0].FieldClasses()["/workspace_host_paths/1"] != observability.FieldClassPath {
		t.Fatalf("classes = %v", records[0].FieldClasses())
	}
	for _, profile := range []observabilityredaction.ProfileName{observabilityredaction.ProfileStrict, observabilityredaction.ProfileSensitive} {
		projection := projectV8HistoryRecord(t, records[0], profile)
		projected, err := projection.Payload().Object()
		if err != nil {
			t.Fatal(err)
		}
		if text := strings.Join(flattenStrings(projected), "\n"); strings.Contains(text, "alice@corp.example") {
			t.Errorf("%s projection kept the raw workspace path: %v", profile, projected)
		}
	}
}

// A row outside Cowork carries no workspace field.
func TestCompatibilityAuditV8OmitsAbsentWorkspacePaths(t *testing.T) {
	body, classes := compatibilityAuditV8Body(Event{Action: string(ActionConnectorHook), Connector: "claudecode"})
	if _, ok := body["workspace_host_paths"]; ok {
		t.Fatalf("body = %v", body)
	}
	if _, ok := classes["/workspace_host_paths/0"]; ok {
		t.Fatalf("classes = %v", classes)
	}
}

func flattenStrings(value any) []string {
	switch v := value.(type) {
	case string:
		return []string{v}
	case []any:
		var out []string
		for _, item := range v {
			out = append(out, flattenStrings(item)...)
		}
		return out
	case map[string]any:
		var out []string
		for _, item := range v {
			out = append(out, flattenStrings(item)...)
		}
		return out
	}
	return nil
}
