// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package harness

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"syscall"
	"testing"
)

// GAP-0915: the vendor reachability check skipped on every network error, so a
// vendor that resets, refuses or fails TLS passed it. Only an error that says
// this runner has no path to the vendor is a skip.
func TestGAP0915OnlyNoNetworkPathSkipsTheReachabilityCheck(t *testing.T) {
	timeout := &net.OpError{Op: "dial", Err: timeoutErr{}}
	for _, tc := range []struct {
		name string
		err  error
		skip bool
	}{
		{"dns", &net.DNSError{Err: "no such host", Name: "static.devin.ai", IsNotFound: true}, true},
		{"network unreachable", &net.OpError{Op: "dial", Err: syscall.ENETUNREACH}, true},
		{"host unreachable", fmt.Errorf("Head: %w", &net.OpError{Op: "dial", Err: syscall.EHOSTUNREACH}), true},
		{"dial timeout", timeout, true},
		{"refused", &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}, false},
		{"reset", &net.OpError{Op: "read", Err: syscall.ECONNRESET}, false},
		{"read timeout", &net.OpError{Op: "read", Err: timeoutErr{}}, false},
		{"tls", tls.RecordHeaderError{Msg: "first record does not look like a TLS handshake"}, false},
		{"other", errors.New("boom"), false},
	} {
		if got := networkUnreachable(tc.err); got != tc.skip {
			t.Errorf("%s: networkUnreachable = %v, want %v", tc.name, got, tc.skip)
		}
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }
