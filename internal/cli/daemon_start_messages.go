// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// errGatewayExitedBeforeReadiness marks a start whose gateway process exited
// before it answered health.
var errGatewayExitedBeforeReadiness = errors.New("gateway process exited before readiness")

// gatewayLogExitReasonMaxBytes bounds how much of gateway.log a failed start
// reads back.
const gatewayLogExitReasonMaxBytes = 64 << 10

// gatewayLogSize is where this start's gateway.log output begins (the log is
// opened for append), so an older run's error is never reported.
func gatewayLogSize(path string) int64 {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return 0
	}
	return info.Size()
}

// gatewayLogExitReason returns the last "Error: " line the gateway wrote to
// gateway.log after offset (the error it exited on), or "".
func gatewayLogExitReason(path string, offset int64) string {
	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return ""
	}
	if offset < 0 || offset > info.Size() {
		offset = 0
	}
	if info.Size()-offset > gatewayLogExitReasonMaxBytes {
		offset = info.Size() - gatewayLogExitReasonMaxBytes
	}
	tail := make([]byte, info.Size()-offset)
	if _, err := file.ReadAt(tail, offset); err != nil && !errors.Is(err, io.EOF) {
		return ""
	}
	reason := ""
	for _, line := range strings.Split(string(tail), "\n") {
		if line = strings.TrimSpace(line); strings.HasPrefix(line, "Error: ") {
			reason = strings.TrimSpace(strings.TrimPrefix(line, "Error: "))
		}
	}
	if len(reason) > 400 {
		reason = strings.ToValidUTF8(reason[:400], "") + "..."
	}
	return reason
}

// gatewayExitedBeforeReadinessError names the error the gateway exited on
// instead of the last health probe's "connection refused" (GAP-1864): a
// locked audit database was reported only in gateway.log.
func gatewayExitedBeforeReadinessError(err error, logPath string, offset int64) error {
	if !errors.Is(err, errGatewayExitedBeforeReadiness) {
		return err
	}
	reason := gatewayLogExitReason(logPath, offset)
	if reason == "" {
		return err
	}
	if strings.Contains(reason, "database is locked") || strings.Contains(reason, "SQLITE_BUSY") {
		return fmt.Errorf("%w: another program has the audit database locked (%s); "+
			"close that program or try again in a moment", errGatewayExitedBeforeReadiness, reason)
	}
	return fmt.Errorf("%w: %s", errGatewayExitedBeforeReadiness, reason)
}

// configEnumProblem renders an invalid enum value the way 'defenseclaw config
// validate' does, 'line 13: guardrail.mode is "x"; allowed values: observe,
// action', instead of the raw schema diagnostic (GAP-1914).
func configEnumProblem(err error) (string, bool) {
	var schemaErr *config.V8SchemaError
	if !errors.As(err, &schemaErr) || schemaErr.Keyword != "enum" ||
		!strings.HasPrefix(schemaErr.Expected, "one of ") {
		return "", false
	}
	var choices []any
	if json.Unmarshal([]byte(strings.TrimPrefix(schemaErr.Expected, "one of ")), &choices) != nil || len(choices) == 0 {
		return "", false
	}
	names := make([]string, len(choices))
	for i, choice := range choices {
		names[i] = fmt.Sprint(choice)
	}
	where := config.ConfigPath()
	if schemaErr.Line > 0 {
		where += fmt.Sprintf(" line %d", schemaErr.Line)
	}
	field := strings.TrimPrefix(schemaErr.Path, "$.")
	is := "is not an allowed value"
	if schemaErr.Value != "" {
		is = fmt.Sprintf("is %q", schemaErr.Value)
	}
	return fmt.Sprintf("%s: %s %s; allowed values: %s", where, field, is, strings.Join(names, ", ")), true
}

// gatewayStatusNextVerb is the gateway command that applies a fixed config.
func gatewayStatusNextVerb(running bool) string {
	if running {
		return "restart"
	}
	return "start"
}
