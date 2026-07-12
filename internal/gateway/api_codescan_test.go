// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

func TestHandleCodeScan_ValidPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vuln.py")
	if err := os.WriteFile(path, []byte("os.system(cmd)\n"), 0644); err != nil {
		t.Fatal(err)
	}

	api := testAPIServerWithConfig(t, "action")
	body, _ := json.Marshal(map[string]string{"path": path})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/scan/code", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	api.handleCodeScan(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Result().StatusCode)
	}

	var result scanner.ScanResult
	if err := json.NewDecoder(w.Result().Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result.Scanner != "codeguard" {
		t.Errorf("scanner = %q, want codeguard", result.Scanner)
	}
	if len(result.Findings) == 0 {
		t.Error("expected findings for file with os.system")
	}
	if result.Findings[0].ID != "CG-EXEC-001" {
		t.Errorf("finding ID = %q, want CG-EXEC-001", result.Findings[0].ID)
	}
}

func TestHandleCodeScan_IncludesClawShieldMalware(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "payload.sh")
	payload := "#!/bin/sh\nexec 3<>/dev/" + "tcp/127.0.0.1/4444\n"
	if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
		t.Fatal(err)
	}

	api := testAPIServerWithConfig(t, "action")
	body, _ := json.Marshal(map[string]string{"path": path})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/scan/code", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	api.handleCodeScan(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Result().StatusCode)
	}

	var result scanner.ScanResult
	if err := json.NewDecoder(w.Result().Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result.Scanner != "codeguard" {
		t.Errorf("scanner = %q, want codeguard", result.Scanner)
	}
	for i := range result.Findings {
		if result.Findings[i].ID == "CS-MAL-RS-DEVTCP" && result.Findings[i].Scanner == "clawshield-malware" {
			return
		}
	}
	t.Fatalf("expected ClawShield malware finding in API response, got %+v", result.Findings)
}

func TestHandleCodeScan_MissingPath(t *testing.T) {
	api := testAPIServerWithConfig(t, "action")
	body := `{"path": ""}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/scan/code", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	api.handleCodeScan(w, req)

	if w.Result().StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Result().StatusCode)
	}
}

func TestHandleCodeScan_NonexistentPath(t *testing.T) {
	runtime, capture := newProxyGeneratedTraceRuntime(t)
	api := testAPIServerWithConfig(t, "action")
	api.bindObservabilityV8Runtimes(runtime, nil, nil, runtime)
	body := `{"path": "/nonexistent/does/not/exist.py"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/scan/code", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	api.handleCodeScan(w, req)

	if w.Result().StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Result().StatusCode)
	}
	metrics := generatedMetricByName(
		capture.metricSnapshot(), observability.TelemetryInstrumentDefenseClawScanErrors,
	)
	if len(metrics) != 1 || metrics[0].CanonicalRecord().Source() != observability.SourceScanner {
		t.Fatalf("generated scan error metrics=%v", metrics)
	}
	for key, want := range map[string]any{
		"defenseclaw.scan.scanner":       "codeguard",
		"defenseclaw.metric.target_type": "code",
		"defenseclaw.metric.error_type":  "not_found",
	} {
		if metrics[0].Attributes()[key] != want {
			t.Fatalf("scan error %s=%v want=%v attributes=%v", key, metrics[0].Attributes()[key], want, metrics[0].Attributes())
		}
	}
}

func TestHandleCodeScan_CleanFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "clean.py")
	if err := os.WriteFile(path, []byte("print('hello')\n"), 0644); err != nil {
		t.Fatal(err)
	}

	api := testAPIServerWithConfig(t, "action")
	body, _ := json.Marshal(map[string]string{"path": path})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/scan/code", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	api.handleCodeScan(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Result().StatusCode)
	}

	var result scanner.ScanResult
	if err := json.NewDecoder(w.Result().Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings for clean file, got %d", len(result.Findings))
	}
}
