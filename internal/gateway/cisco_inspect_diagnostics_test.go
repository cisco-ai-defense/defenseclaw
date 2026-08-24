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

func TestCiscoInspectManagedEnterpriseNon200IncludesVerbatimBody(t *testing.T) {
	// Managed_enterprise support engineers only ever see captured logs from
	// the customer endpoint, so INVALID_RESPONSE on a non-200 must carry the
	// actual response bytes (bounded + sanitized) — not a redacted length/hash
	// placeholder. Outside managed_enterprise the redacted placeholder stays
	// (safer default when Reveal() is available locally).
	previous := ManagedEnterpriseActive()
	t.Cleanup(func() { SetManagedEnterpriseActive(previous) })

	// The upstream body carries a diagnostic-shaped Cisco AID error envelope
	// AND an embedded control character to prove sanitize keeps the line
	// single-record. The full body is what customer support needs to see.
	upstreamBody := "{\"error\":{\"code\":\"quota_exceeded\",\"message\":\"tenant quota\x07exceeded\"}}"

	// -- managed_enterprise ON: verbatim body must appear ------------------
	SetManagedEnterpriseActive(true)
	var verdict *ScanVerdict
	humanLog, structuredLog := captureCiscoInspectFailureLogs(t, func() {
		verdict = doInspectHTTP(t.Context(), nil, inspectCall{
			client: &http.Client{Transport: ciscoRoundTripFunc(func(request *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusBadRequest,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(upstreamBody)),
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
		t.Fatalf("non-200 verdict=%+v, want nil", verdict)
	}
	// The verbatim body must appear on both rails so both operators tailing
	// stderr and downstream SIEM ingesting the structured line can debug the
	// same INVALID_RESPONSE.
	for name, output := range map[string]string{"human": humanLog, "structured": structuredLog} {
		if !strings.Contains(output, "stage=response_status") {
			t.Errorf("%s log missing response_status stage: %q", name, output)
		}
		if !strings.Contains(output, "response_body=") {
			t.Errorf("%s log missing verbatim response_body= field under managed_enterprise: %q", name, output)
		}
		// The Cisco error envelope's diagnostic tokens must be visible verbatim.
		for _, must := range []string{"quota_exceeded", "tenant quota", "exceeded"} {
			if !strings.Contains(output, must) {
				t.Errorf("%s log missing verbatim upstream marker %q: %q", name, must, output)
			}
		}
		// Control chars must be sanitized so a single log record stays a
		// single log record for downstream ingesters that key on newline framing.
		if strings.ContainsRune(output, '\x07') {
			t.Errorf("%s log leaked raw control character: %q", name, output)
		}
		// The redacted summary is still there — verbatim body is additive.
		if !strings.Contains(output, `response_summary="<redacted`) {
			t.Errorf("%s log lost the redacted response_summary field: %q", name, output)
		}
	}

	// -- managed_enterprise OFF: verbatim body must be absent --------------
	SetManagedEnterpriseActive(false)
	humanLog, structuredLog = captureCiscoInspectFailureLogs(t, func() {
		_ = doInspectHTTP(t.Context(), nil, inspectCall{
			client: &http.Client{Transport: ciscoRoundTripFunc(func(request *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusBadRequest,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(upstreamBody)),
					Request:    request,
				}, nil
			})},
			endpoint: "https://inspect.example.test",
			urlPath:  "/api/v1/inspect/chat",
			payload:  map[string]interface{}{"messages": []interface{}{}},
			setAuth:  func(*http.Request) {},
		})
	})
	for name, output := range map[string]string{"human": humanLog, "structured": structuredLog} {
		if strings.Contains(output, "response_body=") {
			t.Errorf("%s log leaked verbatim response_body= outside managed_enterprise: %q", name, output)
		}
		for _, banned := range []string{"quota_exceeded", "tenant quota"} {
			if strings.Contains(output, banned) {
				t.Errorf("%s log leaked upstream body %q outside managed_enterprise: %q", name, banned, output)
			}
		}
		if !strings.Contains(output, `response_summary="<redacted`) {
			t.Errorf("%s log missing redacted response_summary outside managed_enterprise: %q", name, output)
		}
	}
}

func TestCiscoInspectManagedEnterpriseBodyIsBoundedAndSanitized(t *testing.T) {
	// Pathological upstream responses (huge body, embedded newlines / control
	// chars) must not blow up the diagnostic line or break single-record
	// framing even when managed_enterprise unlocks verbatim body inclusion.
	previous := ManagedEnterpriseActive()
	t.Cleanup(func() { SetManagedEnterpriseActive(previous) })
	SetManagedEnterpriseActive(true)

	// 3 KB of body, mostly padding + a private tail marker past the bound.
	privateTail := "leaked-past-managed-bound-marker"
	body := strings.Repeat("a", maxCiscoInspectManagedResponseBodyBytes+256) +
		"\r\n\t\x00" + privateTail

	var verdict *ScanVerdict
	humanLog, structuredLog := captureCiscoInspectFailureLogs(t, func() {
		verdict = doInspectHTTP(t.Context(), nil, inspectCall{
			client: &http.Client{Transport: ciscoRoundTripFunc(func(request *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusInternalServerError,
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
		t.Fatalf("verdict=%+v, want nil", verdict)
	}
	for name, output := range map[string]string{"human": humanLog, "structured": structuredLog} {
		if strings.Contains(output, privateTail) {
			t.Errorf("%s log leaked bytes past managed body cap: %q", name, output)
		}
		if strings.ContainsAny(output, "\x00") {
			t.Errorf("%s log leaked NUL: %q", name, output)
		}
		// Newline in the record body must have been collapsed to a space,
		// otherwise downstream ingesters that key on '\n' as record separator
		// split the diagnostic.
		if newlines := strings.Count(output, "\n"); newlines > 1 {
			t.Errorf("%s log has %d newlines, want at most 1 (trailing): %q", name, newlines, output)
		}
	}
}

func TestCiscoInspectManagedEnterpriseBodyOnlyForNon200Path(t *testing.T) {
	// The verbatim body is meaningful only for the response_status stage
	// (upstream returned a non-200 with an error envelope). Body-read and
	// JSON-decode failures don't need it — the classification carries the
	// signal — and including it would leak bytes we specifically failed to
	// consume cleanly.
	previous := ManagedEnterpriseActive()
	t.Cleanup(func() { SetManagedEnterpriseActive(previous) })
	SetManagedEnterpriseActive(true)

	// Case A — JSON-decode failure (200 status + malformed JSON): response_body
	// must NOT be emitted verbatim.
	humanLog, structuredLog := captureCiscoInspectFailureLogs(t, func() {
		_ = doInspectHTTP(t.Context(), nil, inspectCall{
			client: &http.Client{Transport: ciscoRoundTripFunc(func(request *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(`{"detail":"partial-json-marker`)),
					Request:    request,
				}, nil
			})},
			endpoint: "https://inspect.example.test",
			urlPath:  "/api/v1/inspect/chat",
			payload:  map[string]interface{}{"messages": []interface{}{}},
			setAuth:  func(*http.Request) {},
		})
	})
	for name, output := range map[string]string{"human": humanLog, "structured": structuredLog} {
		if !strings.Contains(output, "stage=response_decode") {
			t.Errorf("%s log missing response_decode stage: %q", name, output)
		}
		if strings.Contains(output, "response_body=") {
			t.Errorf("%s log wrongly included response_body= on decode-failure path: %q", name, output)
		}
		if strings.Contains(output, "partial-json-marker") {
			t.Errorf("%s log leaked malformed body bytes: %q", name, output)
		}
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
