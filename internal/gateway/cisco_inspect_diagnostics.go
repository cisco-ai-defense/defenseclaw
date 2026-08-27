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
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/redaction"
)

const maxCiscoInspectResponseBodyBytes = 64 * 1024

const (
	// The public Cisco error schema uses a short top-level message. Bound both
	// the raw JSON token and decoded value before normalization so an upstream
	// response cannot turn classification into a large allocation/copy path.
	maxCiscoInspectErrorMessageRawBytes = 512
	maxCiscoInspectErrorMessageBytes    = 256
)

const (
	ciscoInspectStageResponseStatus = "response_status"
	ciscoInspectStageResponseBody   = "response_body"
	ciscoInspectStageResponseDecode = "response_decode"

	ciscoInspectClassResponseBodyTooLarge = "response_body_too_large"

	ciscoInspectClassRequestInvalid                = "request_invalid"
	ciscoInspectClassRequestInvalidJSON            = "request_invalid_json"
	ciscoInspectClassIntegrationTypeInvalid        = "integration_type_invalid"
	ciscoInspectClassRequestHeadersMissingMetadata = "request_headers_missing_metadata"
	ciscoInspectClassRequestContextHeaderInvalid   = "request_context_header_invalid"
	ciscoInspectClassInputMessagesMissing          = "input_messages_missing"
	ciscoInspectClassInputMessageEmpty             = "input_message_empty"
	ciscoInspectClassInputRoleInvalid              = "input_role_invalid"
	ciscoInspectClassPromptContentInvalid          = "prompt_content_invalid"
	ciscoInspectClassResponseContentInvalid        = "response_content_invalid"
	ciscoInspectClassAuthenticationFailed          = "authentication_failed"
	ciscoInspectClassPermissionDenied              = "permission_denied"
	ciscoInspectClassUpstreamInternalFailure       = "upstream_internal_failure"
	ciscoInspectClassHTTPRequestMissing            = "http_request_missing"
	ciscoInspectClassHTTPMetadataMissing           = "http_metadata_missing"
	ciscoInspectClassInspectionConfigMissing       = "inspection_config_missing"
	ciscoInspectClassDestinationURLMissing         = "destination_url_missing"
	ciscoInspectClassDestinationURLInvalid         = "destination_url_invalid"
	ciscoInspectClassRequestBodyEncodingInvalid    = "request_body_encoding_invalid"
	ciscoInspectClassRequestBodyFormatInvalid      = "request_body_format_invalid"
	ciscoInspectClassResponseBodyEncodingInvalid   = "response_body_encoding_invalid"
	ciscoInspectClassResponseBodyFormatInvalid     = "response_body_format_invalid"
)

// ciscoInspectStructuredLogWriter is the structured, line-oriented gateway
// error rail. It is a variable only so focused tests can capture the structured
// record independently from the human-readable defaultLogWriter output.
// Production never replaces it.
var ciscoInspectStructuredLogWriter io.Writer = currentStderrWriter{}

// ciscoInspectFailureDiagnostic contains only closed classifications, numeric
// metadata, and a bounded response body. renderCiscoInspectFailureDiagnostic
// always replaces the response bytes with the sink redactor's length/digest
// placeholder before either log rail sees them.
type ciscoInspectFailureDiagnostic struct {
	stage             string
	classification    string
	httpStatus        int
	responseBody      []byte
	responseTruncated bool
	parseOffset       int64
}

// readCiscoInspectResponseBody reads at most one byte beyond the accepted
// response limit so oversized bodies can be classified without allocating or
// logging an unbounded upstream response. The returned body is always capped at
// maxCiscoInspectResponseBodyBytes, including when the reader returns a partial
// body together with an error.
func readCiscoInspectResponseBody(body io.Reader) ([]byte, bool, error) {
	if body == nil {
		return nil, false, io.ErrUnexpectedEOF
	}
	limited := io.LimitReader(body, maxCiscoInspectResponseBodyBytes+1)
	responseBody, err := io.ReadAll(limited)
	truncated := len(responseBody) > maxCiscoInspectResponseBodyBytes
	if truncated {
		responseBody = responseBody[:maxCiscoInspectResponseBodyBytes]
	}
	return responseBody, truncated, err
}

func classifyCiscoInspectHTTPStatus(status int) string {
	switch status {
	case http.StatusBadRequest:
		return "upstream_bad_request"
	case http.StatusUnauthorized:
		return "upstream_unauthorized"
	case http.StatusForbidden:
		return "upstream_forbidden"
	case http.StatusNotFound:
		return "upstream_not_found"
	case http.StatusRequestTimeout:
		return "upstream_request_timeout"
	case http.StatusConflict:
		return "upstream_conflict"
	case http.StatusRequestEntityTooLarge:
		return "upstream_request_too_large"
	case http.StatusUnprocessableEntity:
		return "upstream_request_rejected"
	case http.StatusTooManyRequests:
		return "upstream_rate_limited"
	case http.StatusInternalServerError:
		return "upstream_internal_error"
	case http.StatusNotImplemented:
		return "upstream_not_implemented"
	case http.StatusBadGateway:
		return "upstream_bad_gateway"
	case http.StatusServiceUnavailable:
		return "upstream_unavailable"
	case http.StatusGatewayTimeout:
		return "upstream_gateway_timeout"
	case http.StatusHTTPVersionNotSupported:
		return "upstream_http_version_unsupported"
	}
	switch {
	case status >= 300 && status < 400:
		return "upstream_redirect"
	case status >= 400 && status < 500:
		return "upstream_client_error"
	case status >= 500 && status < 600:
		return "upstream_server_error"
	default:
		return "unexpected_http_status"
	}
}

// classifyCiscoInspectErrorResponse recognizes only the documented Cisco AI
// Defense top-level {code,message} error shape. Message text is never returned:
// an exact official phrase maps to a compile-time category token, while every
// unknown, malformed, nested, oversized, status-mismatched, or contaminated
// value falls back to the HTTP-status classification.
//
// Official phrase catalog:
// https://developer.cisco.com/docs/ai-defense-inspection/error-codes/
func classifyCiscoInspectErrorResponse(responseBody []byte, httpStatus int) string {
	classification, recognized := classifyOfficialCiscoInspectError(responseBody, httpStatus)
	if recognized {
		return classification
	}
	return classifyCiscoInspectHTTPStatus(httpStatus)
}

func classifyOfficialCiscoInspectError(responseBody []byte, httpStatus int) (string, bool) {
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(responseBody, &envelope); err != nil || envelope == nil {
		return "", false
	}

	rawCode, codePresent := envelope["code"]
	rawMessage, messagePresent := envelope["message"]
	if !codePresent || !messagePresent {
		return "", false
	}

	rawCode = bytes.TrimSpace(rawCode)
	if len(rawCode) == 0 || len(rawCode) > 3 {
		return "", false
	}
	responseCode, err := strconv.Atoi(string(rawCode))
	if err != nil || responseCode != httpStatus || responseCode < 100 || responseCode > 999 {
		return "", false
	}

	if len(rawMessage) == 0 || len(rawMessage) > maxCiscoInspectErrorMessageRawBytes {
		return "", false
	}
	var message string
	if err := json.Unmarshal(rawMessage, &message); err != nil ||
		len(message) == 0 || len(message) > maxCiscoInspectErrorMessageBytes {
		return "", false
	}
	normalized, ok := normalizeCiscoInspectOfficialMessage(message)
	if !ok {
		return "", false
	}

	// Keep phrases inside their documented HTTP-status branch. Matching the
	// body's code to the transport status above is not sufficient: without this
	// second binding, a forged {code:500,message:"Unauthorized"} could be
	// mislabeled as an authentication failure instead of a 500-class upstream
	// failure.
	switch httpStatus {
	case http.StatusBadRequest:
		// Variable-suffix documented phrases get a prefix check before the
		// exact-match switch. Cisco AI Defense's request-body-encoding error
		// is documented as "Request body is not in base64: <base64-decode-err>",
		// where the suffix is a libbase64 decoder error message. Exact-match
		// would never fire on real responses, silently falling through to
		// upstream_bad_request; the classification token itself stays the
		// closed constant so no upstream bytes reach the log line.
		if strings.HasPrefix(normalized, "request body is not in base64:") {
			return ciscoInspectClassRequestBodyEncodingInvalid, true
		}
		switch normalized {
		case "bad request":
			return ciscoInspectClassRequestInvalid, true
		case "bad request: invalid json":
			return ciscoInspectClassRequestInvalidJSON, true
		case "invalid integration type", "invalid integration type. this is for internal use only.":
			return ciscoInspectClassIntegrationTypeInvalid, true
		case "failed to parse request headers: failed to get metadata from incoming grpc context":
			return ciscoInspectClassRequestHeadersMissingMetadata, true
		case "failed to parse request headers: invalid context header: x-aidefense-context":
			return ciscoInspectClassRequestContextHeaderInvalid, true
		case "input messages not found for inspection", "input messages not found for inspection.":
			return ciscoInspectClassInputMessagesMissing, true
		case "failed to get content: last message in input list cannot be empty.":
			return ciscoInspectClassInputMessageEmpty, true
		case "failed to get content: given role is invalid, it should be one of assistant, user, or system.":
			return ciscoInspectClassInputRoleInvalid, true
		case "failed to get content: buildopenairesponsefrommessages: unable to parse prompt content.":
			return ciscoInspectClassPromptContentInvalid, true
		case "failed to get content: buildopenairesponsefrommessages: unable to parse response content.":
			return ciscoInspectClassResponseContentInvalid, true
		case "http request is missing.":
			return ciscoInspectClassHTTPRequestMissing, true
		case "http meta is missing.":
			return ciscoInspectClassHTTPMetadataMissing, true
		case "config is missing.":
			return ciscoInspectClassInspectionConfigMissing, true
		case "destination url is missing.":
			return ciscoInspectClassDestinationURLMissing, true
		case "invalid url":
			return ciscoInspectClassDestinationURLInvalid, true
		case "request body is not in valid format.":
			return ciscoInspectClassRequestBodyFormatInvalid, true
		case "response body is not base64.":
			return ciscoInspectClassResponseBodyEncodingInvalid, true
		case "response body is not in valid format.":
			return ciscoInspectClassResponseBodyFormatInvalid, true
		}
	case http.StatusUnauthorized:
		if normalized == "unauthorized" {
			return ciscoInspectClassAuthenticationFailed, true
		}
	case http.StatusForbidden:
		if normalized == "forbidden" {
			return ciscoInspectClassPermissionDenied, true
		}
	case http.StatusInternalServerError:
		if normalized == "internal server error" {
			return ciscoInspectClassUpstreamInternalFailure, true
		}
	}
	return "", false
}

// normalizeCiscoInspectOfficialMessage accepts only printable 7-bit ASCII and
// ordinary spaces. Rejecting controls and non-ASCII before case folding keeps
// newline/terminal injection and Unicode look-alikes from becoming an official
// phrase after normalization. The caller has already enforced the byte bound.
func normalizeCiscoInspectOfficialMessage(message string) (string, bool) {
	for index := 0; index < len(message); index++ {
		char := message[index]
		if char < 0x20 || char > 0x7e {
			return "", false
		}
	}
	normalized := strings.ToLower(strings.TrimSpace(message))
	normalized = strings.Join(strings.Fields(normalized), " ")
	if normalized == "" {
		return "", false
	}
	return normalized, true
}

func classifyCiscoInspectBodyReadError(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "response_body_timeout"
	case errors.Is(err, context.Canceled):
		return "response_body_canceled"
	case errors.Is(err, io.ErrUnexpectedEOF):
		return "response_body_unexpected_eof"
	default:
		return "response_body_read_failed"
	}
}

func classifyCiscoInspectJSONError(err error) string {
	var syntaxError *json.SyntaxError
	if errors.As(err, &syntaxError) {
		return "invalid_json_syntax"
	}
	var typeError *json.UnmarshalTypeError
	if errors.As(err, &typeError) {
		return "invalid_json_shape"
	}
	return "invalid_json"
}

func ciscoInspectJSONErrorOffset(err error) int64 {
	var syntaxError *json.SyntaxError
	if errors.As(err, &syntaxError) && syntaxError.Offset > 0 {
		return syntaxError.Offset
	}
	var typeError *json.UnmarshalTypeError
	if errors.As(err, &typeError) && typeError.Offset > 0 {
		return typeError.Offset
	}
	return 0
}

// renderCiscoInspectFailureDiagnostic creates an injection-safe field tail.
// stage and classification are constrained to a small token grammar even
// though all current callers pass constants. The response summary is always
// sink-redacted (the DEFENSECLAW_REVEAL_PII display switch cannot bypass it)
// and quoted so its spaces cannot be parsed as additional fields.
func renderCiscoInspectFailureDiagnostic(diagnostic ciscoInspectFailureDiagnostic) string {
	stage := canonicalCiscoInspectDiagnosticToken(diagnostic.stage, "unknown_stage")
	classification := canonicalCiscoInspectDiagnosticToken(diagnostic.classification, "unclassified_failure")

	var fields strings.Builder
	fmt.Fprintf(&fields, "stage=%s", stage)
	if diagnostic.httpStatus >= 100 && diagnostic.httpStatus <= 999 {
		fmt.Fprintf(&fields, " http_status=%d", diagnostic.httpStatus)
	}
	fmt.Fprintf(&fields, " classification=%s", classification)
	if diagnostic.parseOffset > 0 {
		fmt.Fprintf(&fields, " parse_offset=%d", diagnostic.parseOffset)
	}
	if diagnostic.responseTruncated {
		fields.WriteString(" response_truncated=true")
	}
	responseSummary := redaction.ForSinkMessageContent(string(diagnostic.responseBody))
	fmt.Fprintf(&fields, " response_summary=%s", strconv.Quote(responseSummary))
	return fields.String()
}

func canonicalCiscoInspectDiagnosticToken(value, fallback string) string {
	if value == "" || len(value) > 64 {
		return fallback
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '_' {
			continue
		}
		return fallback
	}
	return value
}

// emitCiscoInspectFailure writes the same sanitized diagnostic to both the
// human-readable AID log and the field-oriented gateway error line. It does not
// pass an error cause through emitError: that compatibility emitter deliberately
// collapses causes to cause=present, which is the information-loss defect this
// path closes.
func emitCiscoInspectFailure(
	ctx context.Context,
	code gatewaylog.ErrorCode,
	diagnostic ciscoInspectFailureDiagnostic,
) {
	_ = ctx // Correlation remains owned by the generated v8 metric emitted by the caller.
	detail := renderCiscoInspectFailureDiagnostic(diagnostic)
	fmt.Fprintf(defaultLogWriter, "  [cisco-ai-defense] error: %s\n", detail)
	fmt.Fprintf(ciscoInspectStructuredLogWriter,
		"[gateway] error subsystem=%s code=%s message=cisco ai defense inspect %s\n",
		sanitizeAlertField(string(gatewaylog.SubsystemCiscoInspect)),
		sanitizeAlertField(string(code)),
		detail,
	)
}
