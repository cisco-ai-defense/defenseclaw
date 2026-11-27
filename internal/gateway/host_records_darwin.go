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
// it as eventMessage of the hook process. log show reads oldest first with
// no entry limit, so the reader keeps the newest hostRecordReadMax+2 lines
// of its output (the last one is the summary object), and the parser removes
// a kept "tag[pid]: " (GAP-2042; pinned by fixture).
func readHostRecordLines(ctx context.Context, source string, since time.Time) (hostRecordRead, error) {
	tail := &hostRecordTail{max: hostRecordReadMax + 2}
	err := runHostRecordReader(ctx, tail, "/usr/bin/log", "show",
		"--style", "ndjson",
		"--start", since.Local().Format("2006-01-02 15:04:05"),
		"--predicate", hostRecordUnifiedLogPredicate)
	if err != nil {
		return hostRecordRead{}, err
	}
	return hostRecordRead{lines: parseUnifiedLogRecords(tail.newestFirst(), source), capped: tail.evicted}, nil
}

// hostRecordSource is the tag the managed hook writes under: the default
// gateway service name (the Linux and macOS hooks have no other).
func hostRecordSource() string { return hookexec.ManagedHookDecisionRecordSource("") }
