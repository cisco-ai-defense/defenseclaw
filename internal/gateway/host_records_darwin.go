// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package gateway

import (
	"context"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

// readHostRecordLines reads the hook records of the unified log since since.
// The hook sends a syslog datagram to /var/run/syslog; the unified log keeps
// it as eventMessage. The predicate matches the record line, not the sender,
// and the parser removes a kept "tag[pid]: " (GAP-2042; pinned by fixture).
func readHostRecordLines(ctx context.Context, source string, since time.Time) (hostRecordRead, error) {
	out, capped, err := hostRecordCommand(ctx, "/usr/bin/log", "show",
		"--style", "ndjson",
		"--start", since.Local().Format("2006-01-02 15:04:05"),
		"--predicate", `eventMessage CONTAINS "component=\"hook\""`)
	if err != nil {
		return hostRecordRead{}, err
	}
	return hostRecordRead{lines: parseUnifiedLogRecords(out, source), capped: capped}, nil
}

// hostRecordSource is the tag the managed hook writes under: the default
// gateway service name (the Linux and macOS hooks have no other).
func hostRecordSource() string { return hookexec.ManagedHookDecisionRecordSource("") }
