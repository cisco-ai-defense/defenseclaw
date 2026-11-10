// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookexec

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// managedHookSyslogSockets are the local syslog datagram sockets, in the order
// the platform libraries try them: journald's and rsyslog's /dev/log on Linux,
// syslogd's on macOS. A variable for tests.
var managedHookSyslogSockets = []string{"/dev/log", "/var/run/syslog", "/var/run/log"}

// managedHookRecordWriteWait bounds the whole write of a decision record. A
// full syslog socket never holds the hook past its answer.
const managedHookRecordWriteWait = 100 * time.Millisecond

// managedHookRecordMaxBytes keeps one record inside the 1024 bytes a syslog
// datagram may carry (RFC 3164).
const managedHookRecordMaxBytes = 1000

// syslog priorities: facility daemon (3), severity error (3) or warning (4).
const (
	managedHookRecordBoundaryPriority = 3<<3 | 3
	managedHookRecordDegradedPriority = 3<<3 | 4
)

// writeManagedHookDecisionRecord sends line to the local syslog (journald on
// Linux) under source, the platform's durable record of a managed hook's
// decision as the Application event log is on Windows. A managed standard
// account often has no DefenseClaw folder to hold hook-failures.jsonl
// (hookFailureLogFolderReady), and a call the gateway shed or never read has
// no gateway row, so without this record a denial after the retry budget
// leaves no trace on the host (GAP-1029). Best-effort and bounded: a failure
// or a full socket never changes the hook's decision.
func writeManagedHookDecisionRecord(source, marker, line string) {
	priority := managedHookRecordDegradedPriority
	if marker == managed.MarkerBoundary {
		priority = managedHookRecordBoundaryPriority
	}
	message := fmt.Sprintf("<%d>%s %s[%d]: %s", priority, time.Now().Format(time.Stamp), source, os.Getpid(),
		strings.ToValidUTF8(strings.NewReplacer("\n", " ", "\r", " ").Replace(line), ""))
	if len(message) > managedHookRecordMaxBytes {
		message = strings.ToValidUTF8(message[:managedHookRecordMaxBytes], "")
	}
	deadline := time.Now().Add(managedHookRecordWriteWait)
	for _, path := range managedHookSyslogSockets {
		conn, err := net.DialTimeout("unixgram", path, time.Until(deadline))
		if err != nil {
			continue
		}
		_ = conn.SetWriteDeadline(deadline)
		_, err = conn.Write([]byte(message))
		_ = conn.Close()
		if err == nil {
			return
		}
	}
}

func managedHookDecisionRecordSource(serviceName string) string {
	if serviceName == "" {
		return managedHookDecisionRecordDefaultSource
	}
	return serviceName
}
