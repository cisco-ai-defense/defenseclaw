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
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
	missingPath := filepath.Join(t.TempDir(), "does-not-exist.py")
	body, err := json.Marshal(map[string]string{"path": missingPath})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/scan/code", bytes.NewReader(body))
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

func TestHandleCodeScan_SubstringRedactionCannotBeDisabledByRequest(t *testing.T) {
	const secret = "sk-test1234567890abcdef1234567890abcdef1234567890ab"
	line := 17
	dataDir := t.TempDir()
	api := testAPIServerWithConfig(t, "action")
	api.scannerCfg.DataDir = dataDir
	raw := &scanner.ScanResult{
		Scanner: "codeguard", Target: "/work/repo/main.go", Timestamp: time.Now(),
		Findings: []scanner.Finding{{
			ID: "CUSTOM-OUTPUT", RuleID: "custom.output", Severity: scanner.SeverityHigh,
			Title: "Custom command rule", Description: "matched api_key=\"" + secret + "\"; keep context",
			Location: "/work/repo/main.go:17", Remediation: "rotate " + secret + " after triage",
			Scanner: "codeguard", LineNumber: &line,
		}},
	}
	api.codeScanner = func(context.Context, string, string) (*scanner.ScanResult, error) {
		return raw, nil
	}

	body, _ := json.Marshal(map[string]any{"path": raw.Target, "no_redact": true})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/scan/code", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	api.handleCodeScan(w, req)
	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body=%s", w.Result().StatusCode, w.Body.String())
	}
	if strings.Contains(w.Body.String(), secret) {
		t.Fatalf("API no_redact request leaked secret: %s", w.Body.String())
	}
	var result scanner.ScanResult
	if err := json.NewDecoder(w.Result().Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if result.Target != raw.Target || len(result.Findings) != 1 {
		t.Fatalf("response envelope changed: %+v", result)
	}
	finding := result.Findings[0]
	if finding.Title != "Custom command rule" || finding.Location != "/work/repo/main.go:17" ||
		finding.File != "/work/repo/main.go" || finding.LineNumber == nil || *finding.LineNumber != 17 {
		t.Fatalf("safe machine fields were not preserved: %+v", finding)
	}
	if !strings.HasPrefix(finding.Description, "matched api_key=\"") ||
		!strings.HasSuffix(finding.Description, "\"; keep context") ||
		!strings.Contains(finding.Description, "<redacted type=") ||
		!strings.HasPrefix(finding.Remediation, "rotate ") ||
		!strings.HasSuffix(finding.Remediation, " after triage") {
		t.Fatalf("substring context was not preserved: %+v", finding)
	}

	// Canonical logging happened before response projection. Generic custom
	// findings retain their local forensic text; only the detached response is
	// transformed.
	scans, err := api.store.ListScanResults(10)
	if err != nil || len(scans) == 0 {
		t.Fatalf("persisted scans=%+v err=%v", scans, err)
	}
	rows, err := api.store.ListScanFindings(scans[0].ID)
	if err != nil || len(rows) != 1 {
		t.Fatalf("persisted findings=%+v err=%v", rows, err)
	}
	if !rows[0].Description.Valid || !strings.Contains(rows[0].Description.String, secret) {
		t.Fatalf("canonical logger did not receive pre-projection facts: %+v", rows[0])
	}
}

func TestHandleCodeScan_SensitivePersistenceDoesNotEraseSafeResponseContext(t *testing.T) {
	const secret = "sk-test1234567890abcdef1234567890abcdef1234567890ab"
	tests := []struct {
		name        string
		id          string
		scannerName string
		description string
		tags        []string
	}{
		{name: "secret", id: "CS-SEC-NPM", scannerName: "clawshield-secrets", description: "matched " + secret, tags: []string{"secret"}},
		{name: "pii", id: "CS-PII-EMAIL", scannerName: "clawshield-pii", description: "owner alice@example.com", tags: []string{"pii"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			line := 31
			api := testAPIServerWithConfig(t, "action")
			api.scannerCfg.DataDir = t.TempDir()
			raw := &scanner.ScanResult{
				Scanner: "codeguard", Target: "/work/repo/safe.go", Timestamp: time.Now(),
				Findings: []scanner.Finding{{
					ID: tc.id, RuleID: tc.id, Severity: scanner.SeverityHigh,
					Title: "Sensitive source finding", Description: tc.description,
					Location: "/work/repo/safe.go:31", LineNumber: &line,
					Remediation: "Rotate the affected credential and review access",
					Scanner:     tc.scannerName, Tags: tc.tags,
				}},
			}
			api.codeScanner = func(context.Context, string, string) (*scanner.ScanResult, error) {
				return raw, nil
			}
			body := bytes.NewBufferString(`{"path":"/work/repo/safe.go"}`)
			w := httptest.NewRecorder()
			api.handleCodeScan(w, httptest.NewRequest(http.MethodPost, "/api/v1/scan/code", body))
			if w.Result().StatusCode != http.StatusOK {
				t.Fatalf("status=%d body=%s", w.Result().StatusCode, w.Body.String())
			}
			if strings.Contains(w.Body.String(), secret) || strings.Contains(w.Body.String(), "alice@example.com") {
				t.Fatalf("response leaked sensitive value: %s", w.Body.String())
			}
			var projected scanner.ScanResult
			if err := json.NewDecoder(w.Result().Body).Decode(&projected); err != nil {
				t.Fatal(err)
			}
			finding := projected.Findings[0]
			if finding.Location != "/work/repo/safe.go:31" || finding.File != "/work/repo/safe.go" ||
				finding.LineNumber == nil || *finding.LineNumber != line ||
				finding.Remediation != "Rotate the affected credential and review access" {
				t.Fatalf("logger mutation erased safe response context: %+v", finding)
			}

			scans, err := api.store.ListScanResults(10)
			if err != nil || len(scans) != 1 {
				t.Fatalf("persisted scans=%+v err=%v", scans, err)
			}
			rows, err := api.store.ListScanFindings(scans[0].ID)
			if err != nil || len(rows) != 1 {
				t.Fatalf("persisted findings=%+v err=%v", rows, err)
			}
			if !rows[0].Location.Valid || !strings.Contains(rows[0].Location.String, "<redacted-") {
				t.Fatalf("canonical persistence did not neutralize sensitive finding: %+v", rows[0])
			}
		})
	}
}

func TestHandleCodeScan_KeyFailureFailsResponseClosed(t *testing.T) {
	const secret = "sk-test1234567890abcdef1234567890abcdef1234567890ab"
	api := testAPIServerWithConfig(t, "action")
	api.scannerCfg.DataDir = filepath.Join(t.TempDir(), "missing", "data")
	api.codeScanner = func(context.Context, string, string) (*scanner.ScanResult, error) {
		return &scanner.ScanResult{Scanner: "codeguard", Target: "/safe/main.go", Findings: []scanner.Finding{{
			ID: "CUSTOM-OUTPUT", Severity: scanner.SeverityHigh, Scanner: "codeguard",
			Description: "api_key=\"" + secret + "\"", Location: "/safe/main.go:4",
		}}}, nil
	}
	body := bytes.NewBufferString(`{"path":"/safe/main.go"}`)
	w := httptest.NewRecorder()
	api.handleCodeScan(w, httptest.NewRequest(http.MethodPost, "/api/v1/scan/code", body))
	if w.Result().StatusCode != http.StatusOK || strings.Contains(w.Body.String(), secret) ||
		!strings.Contains(w.Body.String(), "key_unavailable") {
		t.Fatalf("key failure did not fail response closed: status=%d body=%s", w.Result().StatusCode, w.Body.String())
	}
}

func TestHandleCodeScan_KeyStoreRepairRecoversWithoutRestart(t *testing.T) {
	const secret = "sk-test1234567890abcdef1234567890abcdef1234567890ab"
	api := testAPIServerWithConfig(t, "action")
	dataDir := filepath.Join(t.TempDir(), "missing", "data")
	api.scannerCfg.DataDir = dataDir
	api.codeScanner = func(context.Context, string, string) (*scanner.ScanResult, error) {
		return &scanner.ScanResult{Scanner: "codeguard", Target: "/safe/main.go", Findings: []scanner.Finding{{
			ID: "CUSTOM-OUTPUT", Severity: scanner.SeverityHigh, Scanner: "codeguard",
			Description: "api_key=\"" + secret + "\"", Location: "/safe/main.go:4",
		}}}, nil
	}
	request := func() *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		api.handleCodeScan(w, httptest.NewRequest(
			http.MethodPost, "/api/v1/scan/code", bytes.NewBufferString(`{"path":"/safe/main.go"}`),
		))
		return w
	}
	first := request()
	if !strings.Contains(first.Body.String(), "key_unavailable") || strings.Contains(first.Body.String(), secret) {
		t.Fatalf("initial key failure did not fail closed: %s", first.Body.String())
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	second := request()
	if second.Result().StatusCode != http.StatusOK || strings.Contains(second.Body.String(), secret) ||
		strings.Contains(second.Body.String(), "key_unavailable") || !strings.Contains(second.Body.String(), "redacted type=") {
		t.Fatalf("repaired key store did not recover protected output: status=%d body=%s", second.Result().StatusCode, second.Body.String())
	}
}
