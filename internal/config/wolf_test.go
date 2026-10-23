// SPDX-License-Identifier: Apache-2.0
package config

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func TestWolfConfigDefaultsAndValidation(t *testing.T) {
	w := DefaultWolfConfig()
	if w.Enabled || w.Variant != "small" || w.Threshold != .5 || w.TimeoutMs != 500 {
		t.Fatalf("unexpected defaults: %+v", w)
	}
	if err := w.Validate(); err != nil {
		t.Fatal(err)
	}
	w.Enabled = true
	if w.Validate() == nil {
		t.Fatal("missing paths accepted")
	}
	w.ModelDir = "/models/wolf"
	w.PythonExecutable = "/runtime/bin/python"
	for _, v := range []string{"small", "full"} {
		w.Variant = v
		if err := w.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	w.Variant = "other"
	if w.Validate() == nil {
		t.Fatal("invalid variant accepted")
	}
	w.Variant = "small"
	w.OverlapTokens = w.WindowTokens
	if w.Validate() == nil {
		t.Fatal("invalid overlap accepted")
	}
}

func TestWolfConfigModeRefusalReportsGuardrailError(t *testing.T) {
	previous := ReportConfigLoadError
	t.Cleanup(func() { ReportConfigLoadError = previous })
	var reports []string
	ReportConfigLoadError = func(_ context.Context, reason string) { reports = append(reports, reason) }
	raw := []byte(`config_version: 9
guardrail:
  scanner_mode: remote
  wolf:
    enabled: true
    model_dir: /models/wolf
    python_executable: /runtime/bin/python
`)
	_, err := LoadRuntimeV8InspectionCandidateFromBytes(filepath.Join(t.TempDir(), "config.yaml"), raw)
	if err == nil || !strings.HasPrefix(err.Error(), "config: guardrail:") || !strings.Contains(err.Error(), "OSS local/both") {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(reports) != 1 || reports[0] != "guardrail_invalid" {
		t.Fatalf("reports=%v", reports)
	}
}
