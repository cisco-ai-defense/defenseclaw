// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package gateway

import (
	"context"
	"errors"
	"os"
	"strconv"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

// hostRecordJournalctl are the journald readers, in the order tried.
var hostRecordJournalctl = []string{"/usr/bin/journalctl", "/bin/journalctl"}

// readHostRecordLines reads the newest hook records of the journal since
// since: the hook's syslog datagram carries the gateway service name as its
// tag (SYSLOG_IDENTIFIER) and the record line as MESSAGE (GAP-2042).
func readHostRecordLines(ctx context.Context, source string, since time.Time) (hostRecordRead, error) {
	path := ""
	for _, p := range hostRecordJournalctl {
		if info, err := os.Stat(p); err == nil && info.Mode().IsRegular() {
			path = p
			break
		}
	}
	if path == "" {
		return hostRecordRead{}, errors.New("no journald on this host")
	}
	out, capped, err := hostRecordCommand(ctx, path,
		"--identifier="+source,
		"--since=@"+strconv.FormatInt(since.Unix(), 10),
		"--output=json", "--output-fields=MESSAGE",
		"--reverse", "--lines="+strconv.Itoa(hostRecordReadMax+1),
		"--no-pager", "--quiet")
	if err != nil {
		return hostRecordRead{}, err
	}
	return hostRecordRead{lines: parseJournalRecords(out), capped: capped}, nil
}

// hostRecordSource is the tag the managed hook writes under: the default
// gateway service name (the Linux and macOS hooks have no other).
func hostRecordSource() string { return hookexec.ManagedHookDecisionRecordSource("") }
