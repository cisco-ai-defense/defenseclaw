// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"syscall"
	"testing"
	"time"
)

// NativeOutageCellAllowsForTest runs one Codex PreToolUse hook call through
// the native hook decision for the outage table and reports whether the call
// may run. install is "oss", "managed" or "secure_client"; answer is "up",
// "down", "timeout", "truncated" or "malformed". failMode is the mode a
// managed render records; outageNow is a per-user hook's call-time outage
// resolver (OutageFailModeNow). The modes come from the caller's real config
// resolvers, never from this helper.
func NativeOutageCellAllowsForTest(t *testing.T, install, answer, failMode string, outageNow func() string) bool {
	t.Helper()
	fastRestartRetries(t)
	var rt *stubRT
	switch answer {
	case "up":
		rt = ok(`{"action":"allow","raw_action":"allow"}`)
	case "down":
		rt = &stubRT{err: syscall.ECONNREFUSED}
		if install != "oss" {
			rt.err = fmt.Errorf("%w: %w", errManagedGatewayPeerUnverified, errManagedGatewayNotRunning)
		}
	case "timeout":
		rt = &stubRT{err: fmt.Errorf("%w: %w", errGatewayTookCallNoAnswer, context.DeadlineExceeded)}
	case "truncated":
		rt = &stubRT{onRequest: func(_ *stubRT, _ *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Header: make(http.Header),
				Body: io.NopCloser(failingBody{strings.NewReader(`{"action":"al`), io.ErrUnexpectedEOF})}, nil
		}}
	case "malformed":
		rt = ok(`{"action":"allow" garbage`)
	default:
		t.Fatalf("unknown answer %q", answer)
	}
	result := run(t, "codex", rt, func(opts *Options) {
		switch install {
		case "oss":
			opts.FailMode = "closed"
			opts.OutageFailModeNow = outageNow
		case "managed":
			managedWindowsStandalone(opts)
			opts.FailMode = failMode
		case "secure_client":
			managedCodex(opts)
			opts.SecureClient = true
			opts.FailMode = failMode
		default:
			t.Fatalf("unknown install %q", install)
		}
		if answer == "down" {
			opts.StartedAt = time.Now().Add(-gatewayRestartBudget)
		}
	})
	return !nativeOutageBlocked(result)
}
