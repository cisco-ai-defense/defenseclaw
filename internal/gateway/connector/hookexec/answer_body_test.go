// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

// partialAllowGateway answers every hook call with headers that declare a
// longer body than it sends: a complete-looking allow, then it stalls until
// the call ends (drop false) or drops the connection (drop true).
func partialAllowGateway(t *testing.T, drop bool) string {
	t.Helper()
	release := make(chan struct{})
	addr := gatewayAt(t, func(w http.ResponseWriter, r *http.Request) {
		const partial = `{"action":"allow"}`
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(len(partial)+64))
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, partial)
		w.(http.Flusher).Flush()
		if drop {
			panic(http.ErrAbortHandler)
		}
		select {
		case <-r.Context().Done():
		case <-release:
		}
	})
	// Cleanups run last in, first out: the handlers return before the
	// server closes.
	t.Cleanup(func() { close(release) })
	return addr
}

// B-40 (B-01 merge review item 1): a gateway that sent its headers and a
// complete-looking allow, then stalled or dropped the connection before the
// body it declared, has not decided. The call fails at the answer budget:
// closed for a managed hook whatever its fail mode, and for a per-user hook
// whose fail mode is closed or not set. The partial bytes are never an allow.
func TestAPartialGatewayBodyIsNotADecision(t *testing.T) {
	shortAnswerBudget(t, 300*time.Millisecond)
	for _, test := range []struct {
		name string
		drop bool
	}{{"stalls after a partial allow", false}, {"drops after a partial allow", true}} {
		t.Run(test.name, func(t *testing.T) {
			for _, mode := range []string{"closed", ""} {
				for _, connector := range []string{"codex", "claudecode"} {
					result, elapsed := runAgainstGateway(t, connector, partialAllowGateway(t, test.drop), func(opts *Options) {
						opts.FailMode = mode
					})
					if elapsed > time.Second || !blocked(result) || !strings.Contains(result.stdout+result.stderr, perUserGatewayNoAnswerReason) {
						t.Fatalf("per-user %s fail mode %q: after %s code=%d stdout=%q stderr=%q, want a block naming the gateway that did not answer",
							connector, mode, elapsed, result.code, result.stdout, result.stderr)
					}
				}
			}
			managed, elapsed := runAgainstGateway(t, "codex", partialAllowGateway(t, test.drop), func(opts *Options) {
				managedCodex(opts)
			})
			if elapsed > time.Second || !blocked(managed) || !strings.Contains(managed.stdout+managed.stderr, managedGatewayNoAnswerReason) {
				t.Fatalf("managed: after %s code=%d stdout=%q stderr=%q, want a block naming %s",
					elapsed, managed.code, managed.stdout, managed.stderr, managedGatewayNoAnswerReason)
			}
			// Open is the operator's own choice for a per-user hook: the
			// call goes ahead with the notice, not because of the bytes.
			open, _ := runAgainstGateway(t, "claudecode", partialAllowGateway(t, test.drop), func(opts *Options) {
				opts.FailMode = "open"
			})
			if open.code != 0 || !strings.Contains(open.stdout, perUserGatewayNoAnswerReason) {
				t.Fatalf("per-user open: code=%d stdout=%q stderr=%q, want the fail-open notice", open.code, open.stdout, open.stderr)
			}
		})
	}
}

// erroringBody returns its bytes together with err, like a connection that
// ends before the declared length (io.ErrUnexpectedEOF).
type erroringBody struct {
	data string
	err  error
	read bool
}

func (b *erroringBody) Read(p []byte) (int, error) {
	if b.read {
		return 0, b.err
	}
	b.read = true
	return copy(p, b.data), b.err
}

func (*erroringBody) Close() error { return nil }

func answering(status int, body io.ReadCloser) *stubRT {
	return &stubRT{onRequest: func(*stubRT, *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: status, Body: body, Header: make(http.Header)}, nil
	}}
}

// A body read error, a truncated decision and an oversized body are not
// decisions either: they fail closed (managed, per-user closed or not set).
func TestAnUnreadableOrIncompleteGatewayBodyFailsClosed(t *testing.T) {
	for _, test := range []struct {
		name string
		rt   func() *stubRT
	}{
		{"read error after an allow", func() *stubRT {
			return answering(http.StatusOK, &erroringBody{data: `{"action":"allow"}`, err: io.ErrUnexpectedEOF})
		}},
		{"truncated JSON", func() *stubRT { return ok(`{"action":"allow"`) }},
		{"oversized body", func() *stubRT {
			return ok(`{"action":"allow"}` + strings.Repeat(" ", int(defaultMaxBody)))
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, mode := range []string{"closed", ""} {
				for _, connector := range []string{"codex", "claudecode"} {
					result := run(t, connector, test.rt(), func(opts *Options) { opts.FailMode = mode })
					if !blocked(result) {
						t.Fatalf("per-user %s fail mode %q: code=%d stdout=%q stderr=%q, want a block",
							connector, mode, result.code, result.stdout, result.stderr)
					}
				}
			}
			managed := run(t, "codex", test.rt(), func(opts *Options) {
				managedCodex(opts)
			})
			if !blocked(managed) {
				t.Fatalf("managed: code=%d stdout=%q stderr=%q, want a block", managed.code, managed.stdout, managed.stderr)
			}
		})
	}
}

// B-40 (B-01 merge review item 2): only an explicit "open" opens a hook, as
// in the config resolver; a hook given no fail mode (a Windows native command
// whose sidecar is missing or names none) fails closed.
func TestOnlyAnExplicitOpenFailModeOpens(t *testing.T) {
	for mode, want := range map[string]string{
		"": "closed", "  ": "closed", "closed": "closed", "CLOSED": "closed", "opne": "closed",
		"open": "open", " Open ": "open",
	} {
		if got := normalizeFailMode(mode); got != want {
			t.Errorf("normalizeFailMode(%q) = %q, want %q", mode, got, want)
		}
	}
	unset := run(t, "codex", &stubRT{status: http.StatusInternalServerError, body: "{}"}, func(opts *Options) { opts.FailMode = "" })
	if !blocked(unset) {
		t.Fatalf("a hook with no fail mode was allowed on a gateway error: code=%d stdout=%q stderr=%q", unset.code, unset.stdout, unset.stderr)
	}
}
