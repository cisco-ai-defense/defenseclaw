// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package redaction

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/observability"
)

const (
	detectDomain   = "defenseclaw-redaction-detect-v1"
	wholeDomain    = "defenseclaw-redaction-whole-v1"
	oversizeDomain = "defenseclaw-redaction-oversize-v1"
)

// FailureCode is a bounded value-free redaction failure identity.
type FailureCode string

const (
	FailureInvalidUTF8      FailureCode = "invalid_utf8"
	FailureKeyUnavailable   FailureCode = "key_unavailable"
	FailureCandidateLimit   FailureCode = "candidate_limit"
	FailureFieldMatchLimit  FailureCode = "field_match_limit"
	FailureRecordMatchLimit FailureCode = "record_match_limit"
	FailureMatcher          FailureCode = "matcher_failed"
	FailureValidator        FailureCode = "validator_failed"
)

var registeredFailureCodes = map[FailureCode]struct{}{
	FailureInvalidUTF8: {}, FailureKeyUnavailable: {}, FailureCandidateLimit: {},
	FailureFieldMatchLimit: {}, FailureRecordMatchLimit: {}, FailureMatcher: {},
	FailureValidator: {},
}

// DetectorError is deliberately value-free. It carries no input, interval, key,
// digest, parser detail, or wrapped exception.
type DetectorError struct{ Code FailureCode }

func (e *DetectorError) Error() string { return "observability redaction failed: " + string(e.Code) }

// IsDetectorError reports whether err is a safe detector failure with code.
func IsDetectorError(err error, code FailureCode) bool {
	var target *DetectorError
	return errors.As(err, &target) && target.Code == code
}

func detectorError(code FailureCode) error { return &DetectorError{Code: code} }

// FailedClosedToken returns the exact non-correlating failure placeholder.
func FailedClosedToken(code FailureCode) (string, error) {
	if _, ok := registeredFailureCodes[code]; !ok {
		return "", detectorError(FailureValidator)
	}
	return fmt.Sprintf("<redacted type=failed_closed v=1 code=%s>", code), nil
}

// DetectedToken creates the exact substring-correlation token.
func DetectedToken(id DetectorID, matched string, key []byte) (string, error) {
	if _, ok := catalogDefinitionFor(id); !ok {
		return "", detectorError(FailureValidator)
	}
	return correlationToken(detectDomain, string(id), matched, key)
}

// WholeToken creates a whole-field correlation token for a field class.
func WholeToken(class observability.FieldClass, value string, key []byte) (string, error) {
	if !observability.IsFieldClass(class) {
		return "", detectorError(FailureValidator)
	}
	return correlationToken(wholeDomain, "field."+string(class), value, key)
}

// OversizeToken creates a scan-limit token without scanning any prefix or suffix.
func OversizeToken(class observability.FieldClass, value string, key []byte) (string, error) {
	if !observability.IsFieldClass(class) {
		return "", detectorError(FailureValidator)
	}
	return correlationToken(oversizeDomain, "oversize."+string(class), value, key)
}

func correlationToken(domain, tokenType, value string, key []byte) (string, error) {
	if !utf8.ValidString(value) {
		return "", detectorError(FailureInvalidUTF8)
	}
	if len(key) != hashV1KeySize {
		return "", detectorError(FailureKeyUnavailable)
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(domain))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(tokenType))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(value))
	digest := mac.Sum(nil)
	return fmt.Sprintf(
		"<redacted type=%s v=1 key=%s len=%d hmac=%s>",
		tokenType,
		hashV1KeyID(key),
		len(value),
		hex.EncodeToString(digest[:8]),
	), nil
}
