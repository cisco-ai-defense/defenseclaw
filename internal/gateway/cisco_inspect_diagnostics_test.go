// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestCiscoInspectFailureDiagnosticsFollowLateStderrRedirect(t *testing.T) {
	// Both production writers are initialized before the Windows service host
	// replaces os.Stderr. Do not replace either writer in this regression: it
	// must prove that the package-initialized defaults resolve the redirected
	// process stream when the diagnostic is actually emitted.
	if _, ok := defaultLogWriter.(currentStderrWriter); !ok {
		t.Fatalf("defaultLogWriter type = %T, want currentStderrWriter", defaultLogWriter)
	}
	if _, ok := ciscoInspectStructuredLogWriter.(currentStderrWriter); !ok {
		t.Fatalf(
			"ciscoInspectStructuredLogWriter type = %T, want currentStderrWriter",
			ciscoInspectStructuredLogWriter,
		)
	}
	managedEnterpriseWasActive := ManagedEnterpriseActive()
	SetManagedEnterpriseActive(true)
	t.Cleanup(func() { SetManagedEnterpriseActive(managedEnterpriseWasActive) })

	serviceLog, err := os.CreateTemp(t.TempDir(), "gateway-*.log")
	if err != nil {
		t.Fatalf("create redirected gateway log: %v", err)
	}
	originalStderr := os.Stderr
	os.Stderr = serviceLog
	t.Cleanup(func() {
		os.Stderr = originalStderr
		_ = serviceLog.Close()
	})

	const privateResponseMarker = "private-tenant-response-marker"
	var verdict *ScanVerdict
	verdict = doInspectHTTP(t.Context(), nil, inspectCall{
		client: &http.Client{Transport: ciscoRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusForbidden,
				Header:     make(http.Header),
				Body: io.NopCloser(strings.NewReader(
					`{"code":403,"message":"Forbidden","detail":"` + privateResponseMarker + `"}`,
				)),
				Request: request,
			}, nil
		})},
		endpoint: "https://inspect.example.test",
		urlPath:  "/api/v1/inspect/chat",
		payload:  map[string]interface{}{"messages": []interface{}{}},
		setAuth:  func(*http.Request) {},
	})
	if verdict != nil {
		t.Fatalf("failure response verdict=%+v, want nil", verdict)
	}
	if err := serviceLog.Sync(); err != nil {
		t.Fatalf("sync redirected gateway log: %v", err)
	}
	contents, err := os.ReadFile(serviceLog.Name())
	if err != nil {
		t.Fatalf("read redirected gateway log: %v", err)
	}
	logText := string(contents)
	for _, expected := range []string{
		"[cisco-ai-defense] error:",
		"[gateway] error subsystem=cisco-inspect code=INVALID_RESPONSE",
		"stage=response_status",
		"http_status=403",
		"classification=permission_denied",
		`response_summary="<redacted`,
	} {
		if !strings.Contains(logText, expected) {
			t.Errorf("redirected gateway log missing %q: %q", expected, logText)
		}
	}
	if strings.Contains(logText, privateResponseMarker) {
		t.Fatalf("redirected gateway log leaked private response marker: %q", logText)
	}
	if strings.Contains(logText, "response_body=") {
		t.Fatalf("redirected gateway log exposed an unrestricted response body: %q", logText)
	}
	if len(contents) > 1024 {
		t.Fatalf("redirected diagnostic length=%d, want <= 1024", len(contents))
	}
}

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

func TestCiscoInspectManagedEnterpriseNon200KeepsResponseSecretSafe(t *testing.T) {
	// Managed enterprise mode must not turn support diagnostics into a response
	// transcript. Operators get the HTTP status, a closed classification, and a
	// bounded length/digest summary; arbitrary upstream fields remain private.
	t.Setenv("DEFENSECLAW_REVEAL_PII", "1")
	previous := ManagedEnterpriseActive()
	SetManagedEnterpriseActive(true)
	t.Cleanup(func() { SetManagedEnterpriseActive(previous) })

	const (
		credentialMarker = "private-upstream-credential-marker"
		piiMarker        = "private-upstream-pii-marker"
	)
	body := `{"code":403,"message":"Forbidden","credential":"` + credentialMarker +
		`","tenant_detail":"` + piiMarker + `"}`
	humanLog, structuredLog := runCiscoInspectFailureResponse(t, http.StatusForbidden, body)
	for name, output := range map[string]string{"human": humanLog, "structured": structuredLog} {
		for _, expected := range []string{
			"stage=response_status",
			"http_status=403",
			"classification=permission_denied",
			`response_summary="<redacted len=`,
			"sha=",
		} {
			if !strings.Contains(output, expected) {
				t.Errorf("%s log missing %q: %q", name, expected, output)
			}
		}
		for _, forbidden := range []string{"response_body=", credentialMarker, piiMarker, "Forbidden"} {
			if strings.Contains(output, forbidden) {
				t.Errorf("%s log leaked upstream response material %q: %q", name, forbidden, output)
			}
		}
		if len(output) > 512 {
			t.Errorf("%s diagnostic length=%d, want <= 512", name, len(output))
		}
	}
	assertCiscoInspectDiagnosticRailParity(t, humanLog, structuredLog)
}

func TestCiscoInspectManagedEnterpriseOversizedBodyStaysRedactedAndBounded(t *testing.T) {
	previous := ManagedEnterpriseActive()
	SetManagedEnterpriseActive(true)
	t.Cleanup(func() { SetManagedEnterpriseActive(previous) })

	const privateMarker = "private-oversized-response-marker"
	body := privateMarker + strings.Repeat("x", maxCiscoInspectResponseBodyBytes+1)
	humanLog, structuredLog := runCiscoInspectFailureResponse(t, http.StatusBadGateway, body)
	for name, output := range map[string]string{"human": humanLog, "structured": structuredLog} {
		for _, expected := range []string{
			"stage=response_status",
			"http_status=502",
			"classification=upstream_bad_gateway",
			"response_truncated=true",
			`response_summary="<redacted len=`,
			"sha=",
		} {
			if !strings.Contains(output, expected) {
				t.Errorf("%s log missing %q: %q", name, expected, output)
			}
		}
		for _, forbidden := range []string{"response_body=", privateMarker} {
			if strings.Contains(output, forbidden) {
				t.Errorf("%s log leaked oversized response material %q: %q", name, forbidden, output)
			}
		}
		if len(output) > 512 {
			t.Errorf("%s diagnostic length=%d, want <= 512", name, len(output))
		}
	}
	assertCiscoInspectDiagnosticRailParity(t, humanLog, structuredLog)
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
		// Cisco AI Defense's request-body-encoding error is documented as a
		// prefix + variable suffix ("Request body is not in base64: <err>").
		// Exact-match would misclassify the entire family as upstream_bad_request.
		// Classification token stays closed; the variable suffix never leaks
		// into the log line via this branch (the summary is redacted, and
		// managed_enterprise body-preview goes through a separate path).
		{
			name:           "documented variable-suffix phrase classifies via prefix",
			body:           `{"code":400,"message":"Request body is not in base64: invalid byte at offset 3"}`,
			wantClass:      ciscoInspectClassRequestBodyEncodingInvalid,
			privateMarkers: []string{"invalid byte at offset 3", "Request body is not in base64"},
		},
		{
			name:           "empty-suffix variant still classifies via prefix",
			body:           `{"code":400,"message":"Request body is not in base64:"}`,
			wantClass:      ciscoInspectClassRequestBodyEncodingInvalid,
			privateMarkers: []string{"Request body is not in base64"},
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
