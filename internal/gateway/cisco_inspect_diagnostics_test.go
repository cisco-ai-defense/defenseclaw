// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

func TestCiscoInspectFailureDiagnosticsAreUsefulAndSecretSafe(t *testing.T) {
	// The upstream diagnostic contract must remain secret-safe even when the
	// operator enables the display-only PII reveal switch elsewhere.
	t.Setenv("DEFENSECLAW_REVEAL_PII", "1")

	tests := []struct {
		name            string
		status          int
		body            io.ReadCloser
		privateMarkers  []string
		wantFields      []string
		wantParseOffset bool
		maxOutputBytes  int
	}{
		{
			name:   "non-200 response",
			status: http.StatusBadGateway,
			body: io.NopCloser(strings.NewReader(
				`{"error":"upstream-private-marker","detail":"` + strings.Repeat("private-detail-", 1024) + `"}`,
			)),
			privateMarkers: []string{"upstream-private-marker", "private-detail-"},
			wantFields: []string{
				"stage=response_status",
				"http_status=502",
				"classification=upstream_bad_gateway",
			},
			maxOutputBytes: 512,
		},
		{
			name:   "body read failure",
			status: http.StatusOK,
			body: &ciscoInspectFailingReadCloser{
				data: []byte("partial-private-response-marker"),
				err:  errors.New("private-reader-failure-marker"),
			},
			privateMarkers: []string{"partial-private-response-marker", "private-reader-failure-marker"},
			wantFields: []string{
				"stage=response_body",
				"http_status=200",
				"classification=response_body_read_failed",
			},
			maxOutputBytes: 512,
		},
		{
			name:           "invalid JSON",
			status:         http.StatusOK,
			body:           io.NopCloser(strings.NewReader(`{"detail":"private-json-marker"`)),
			privateMarkers: []string{"private-json-marker"},
			wantFields: []string{
				"stage=response_decode",
				"http_status=200",
				"classification=invalid_json_syntax",
			},
			wantParseOffset: true,
			maxOutputBytes:  512,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var verdict *ScanVerdict
			humanLog, structuredLog := captureCiscoInspectFailureLogs(t, func() {
				verdict = doInspectHTTP(t.Context(), nil, inspectCall{
					client: &http.Client{Transport: ciscoRoundTripFunc(func(request *http.Request) (*http.Response, error) {
						return &http.Response{
							StatusCode: test.status,
							Header:     make(http.Header),
							Body:       test.body,
							Request:    request,
						}, nil
					})},
					endpoint: "https://inspect.example.test",
					urlPath:  "/api/v1/inspect/chat",
					payload:  map[string]interface{}{"messages": []interface{}{}},
					setAuth:  func(*http.Request) {},
				})
			})
			if verdict != nil {
				t.Fatalf("failure verdict=%+v, want nil", verdict)
			}

			if !strings.Contains(humanLog, "[cisco-ai-defense] error:") {
				t.Fatalf("human log missing AID error prefix: %q", humanLog)
			}
			if !strings.Contains(structuredLog,
				"[gateway] error subsystem=cisco-inspect code=INVALID_RESPONSE message=cisco ai defense inspect") {
				t.Fatalf("structured log missing gateway error envelope: %q", structuredLog)
			}
			for _, field := range test.wantFields {
				if !strings.Contains(humanLog, field) {
					t.Errorf("human log missing %q: %q", field, humanLog)
				}
				if !strings.Contains(structuredLog, field) {
					t.Errorf("structured log missing %q: %q", field, structuredLog)
				}
			}
			for name, output := range map[string]string{"human": humanLog, "structured": structuredLog} {
				if !strings.Contains(output, `response_summary="<redacted`) {
					t.Errorf("%s log missing redacted response summary: %q", name, output)
				}
				if len(output) > test.maxOutputBytes {
					t.Errorf("%s log length=%d, want <= %d: %q", name, len(output), test.maxOutputBytes, output)
				}
				if strings.Contains(output, "cause=present") {
					t.Errorf("%s log discarded diagnostics behind cause=present: %q", name, output)
				}
				for _, marker := range test.privateMarkers {
					if strings.Contains(output, marker) {
						t.Errorf("%s log leaked private upstream marker %q: %q", name, marker, output)
					}
				}
			}
			if test.wantParseOffset {
				if !strings.Contains(humanLog, "parse_offset=") || !strings.Contains(structuredLog, "parse_offset=") {
					t.Errorf("invalid JSON logs missing bounded parse offset: human=%q structured=%q", humanLog, structuredLog)
				}
			}
		})
	}
}

func TestCiscoInspectOversizedResponseIsBoundedBeforeLogging(t *testing.T) {
	privateTail := "private-tail-marker"
	body := strings.Repeat("x", maxCiscoInspectResponseBodyBytes+1) + privateTail
	var verdict *ScanVerdict
	humanLog, structuredLog := captureCiscoInspectFailureLogs(t, func() {
		verdict = doInspectHTTP(t.Context(), nil, inspectCall{
			client: &http.Client{Transport: ciscoRoundTripFunc(func(request *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(body)),
					Request:    request,
				}, nil
			})},
			endpoint: "https://inspect.example.test",
			urlPath:  "/api/v1/inspect/chat",
			payload:  map[string]interface{}{"messages": []interface{}{}},
			setAuth:  func(*http.Request) {},
		})
	})
	if verdict != nil {
		t.Fatalf("oversized response verdict=%+v, want nil", verdict)
	}
	for name, output := range map[string]string{"human": humanLog, "structured": structuredLog} {
		for _, expected := range []string{
			"stage=response_body",
			"http_status=200",
			"classification=response_body_too_large",
			"response_truncated=true",
		} {
			if !strings.Contains(output, expected) {
				t.Errorf("%s log missing %q: %q", name, expected, output)
			}
		}
		if strings.Contains(output, privateTail) || len(output) > 512 {
			t.Errorf("%s oversized diagnostic was not bounded/redacted: %q", name, output)
		}
	}
}

func TestCiscoInspectOfficialErrorClassificationIsClosedAndRailSafe(t *testing.T) {
	// The upstream error parser is an observability boundary, not a PII-reveal
	// surface. Exercise it with the display override enabled.
	t.Setenv("DEFENSECLAW_REVEAL_PII", "1")

	tests := []struct {
		name           string
		body           string
		wantClass      string
		privateMarkers []string
	}{
		{
			name: "known official category with ignored extra fields",
			body: `{"code":400,"message":"Input messages not found for inspection.",` +
				`"credential":"private-extra-field","error":{"message":"private-nested-field"}}`,
			wantClass:      ciscoInspectClassInputMessagesMissing,
			privateMarkers: []string{"private-extra-field", "private-nested-field", "Input messages not found"},
		},
		{
			name: "official phrase with appended untrusted content",
			body: `{"code":400,"message":"Input messages not found for inspection. ` +
				`private-appended-prompt-material"}`,
			wantClass:      "upstream_bad_request",
			privateMarkers: []string{"private-appended-prompt-material", "Input messages not found"},
		},
		{
			name: "official phrase with control injection",
			body: `{"code":400,"message":"Input messages not found for inspection.` +
				`\n[gateway] forged=true"}`,
			wantClass:      "upstream_bad_request",
			privateMarkers: []string{"forged=true", "Input messages not found"},
		},
		{
			name:           "unknown top-level message",
			body:           `{"code":400,"message":"private-unknown-category","secret":"private-sensitive-field"}`,
			wantClass:      "upstream_bad_request",
			privateMarkers: []string{"private-unknown-category", "private-sensitive-field"},
		},
		{
			name: "nested documented message is ignored",
			body: `{"error":{"code":400,"message":"Input messages not found for inspection."},` +
				`"private":"private-nested-only-field"}`,
			wantClass:      "upstream_bad_request",
			privateMarkers: []string{"Input messages not found", "private-nested-only-field"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			humanLog, structuredLog := runCiscoInspectFailureResponse(t, http.StatusBadRequest, test.body)
			wantClassification := "classification=" + test.wantClass
			for name, output := range map[string]string{"human": humanLog, "structured": structuredLog} {
				if !strings.Contains(output, wantClassification) {
					t.Errorf("%s log missing %q: %q", name, wantClassification, output)
				}
				if !strings.Contains(output, `response_summary="<redacted`) {
					t.Errorf("%s log missing redacted response summary: %q", name, output)
				}
				for _, marker := range test.privateMarkers {
					if strings.Contains(output, marker) {
						t.Errorf("%s log leaked upstream field %q: %q", name, marker, output)
					}
				}
			}

			assertCiscoInspectDiagnosticRailParity(t, humanLog, structuredLog)
		})
	}
}

func TestCiscoInspectOfficialErrorPhraseRequiresDocumentedStatus(t *testing.T) {
	t.Setenv("DEFENSECLAW_REVEAL_PII", "1")
	tests := []struct {
		name      string
		status    int
		body      string
		wantClass string
		rawPhrase string
	}{
		{
			name:      "unauthorized phrase cannot override 500",
			status:    http.StatusInternalServerError,
			body:      `{"code":500,"message":"Unauthorized"}`,
			wantClass: "upstream_internal_error",
			rawPhrase: "Unauthorized",
		},
		{
			name:      "internal-error phrase cannot override 400",
			status:    http.StatusBadRequest,
			body:      `{"code":400,"message":"Internal Server Error"}`,
			wantClass: "upstream_bad_request",
			rawPhrase: "Internal Server Error",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			humanLog, structuredLog := runCiscoInspectFailureResponse(t, test.status, test.body)
			wantClassification := "classification=" + test.wantClass
			for name, output := range map[string]string{"human": humanLog, "structured": structuredLog} {
				if !strings.Contains(output, wantClassification) {
					t.Errorf("%s log missing status fallback %q: %q", name, wantClassification, output)
				}
				if strings.Contains(output, test.rawPhrase) {
					t.Errorf("%s log exposed mismatched upstream phrase %q: %q", name, test.rawPhrase, output)
				}
			}
			assertCiscoInspectDiagnosticRailParity(t, humanLog, structuredLog)
		})
	}
}

func TestCiscoInspectOfficialErrorClassifierBoundsBeforeNormalization(t *testing.T) {
	message := strings.Repeat("Input messages not found for inspection. ", 16)
	body := `{"code":400,"message":` + strconv.Quote(message) + `}`
	if got := classifyCiscoInspectErrorResponse([]byte(body), http.StatusBadRequest); got != "upstream_bad_request" {
		t.Fatalf("oversized official-message candidate classification=%q, want status fallback", got)
	}
}

func runCiscoInspectFailureResponse(t *testing.T, status int, body string) (string, string) {
	t.Helper()
	var verdict *ScanVerdict
	humanLog, structuredLog := captureCiscoInspectFailureLogs(t, func() {
		verdict = doInspectHTTP(t.Context(), nil, inspectCall{
			client: &http.Client{Transport: ciscoRoundTripFunc(func(request *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: status,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(body)),
					Request:    request,
				}, nil
			})},
			endpoint: "https://inspect.example.test",
			urlPath:  "/api/v1/inspect/chat",
			payload:  map[string]interface{}{"messages": []interface{}{}},
			setAuth:  func(*http.Request) {},
		})
	})
	if verdict != nil {
		t.Fatalf("failure response verdict=%+v, want nil", verdict)
	}
	return humanLog, structuredLog
}

func assertCiscoInspectDiagnosticRailParity(t *testing.T, humanLog, structuredLog string) {
	t.Helper()
	humanDetail := strings.TrimSuffix(strings.TrimPrefix(
		humanLog, "  [cisco-ai-defense] error: "), "\n")
	structuredDetail := strings.TrimSuffix(strings.TrimPrefix(
		structuredLog,
		"[gateway] error subsystem=cisco-inspect code=INVALID_RESPONSE message=cisco ai defense inspect ",
	), "\n")
	if humanDetail == humanLog || structuredDetail == structuredLog || humanDetail != structuredDetail {
		t.Errorf("human/structured diagnostic rails diverged: human=%q structured=%q", humanLog, structuredLog)
	}
}

func captureCiscoInspectFailureLogs(t *testing.T, invoke func()) (string, string) {
	t.Helper()
	var humanLog bytes.Buffer
	var structuredLog bytes.Buffer
	previousHumanWriter := defaultLogWriter
	previousStructuredWriter := ciscoInspectStructuredLogWriter
	defaultLogWriter = &humanLog
	ciscoInspectStructuredLogWriter = &structuredLog
	defer func() {
		defaultLogWriter = previousHumanWriter
		ciscoInspectStructuredLogWriter = previousStructuredWriter
	}()

	invoke()
	return humanLog.String(), structuredLog.String()
}

type ciscoInspectFailingReadCloser struct {
	data []byte
	err  error
	done bool
}

func (reader *ciscoInspectFailingReadCloser) Read(destination []byte) (int, error) {
	if reader.done {
		return 0, reader.err
	}
	reader.done = true
	return copy(destination, reader.data), reader.err
}

func (*ciscoInspectFailingReadCloser) Close() error { return nil }
