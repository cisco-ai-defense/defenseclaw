// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"strconv"

	"github.com/defenseclaw/defenseclaw/internal/redaction"
)

// appendRawTelemetryDetails appends a raw payload field only when the
// operator has explicitly disabled redaction. The value is quoted so raw
// prompts/tool JSON remain a single structured-ish details token instead of
// injecting arbitrary newlines into downstream log files.
func appendRawTelemetryDetails(details, key string, raw []byte) string {
	if !redaction.DisableAll() || key == "" || len(raw) == 0 {
		return details
	}
	return fmt.Sprintf("%s %s=%s", details, key, strconv.Quote(string(raw)))
}

type rawTelemetryField struct {
	key string
	raw []byte
}

func rawTelemetryString(key, value string) rawTelemetryField {
	return rawTelemetryField{key: key, raw: []byte(value)}
}

func appendRawTelemetryFields(details string, fields ...rawTelemetryField) string {
	for _, field := range fields {
		details = appendRawTelemetryDetails(details, field.key, field.raw)
	}
	return details
}
