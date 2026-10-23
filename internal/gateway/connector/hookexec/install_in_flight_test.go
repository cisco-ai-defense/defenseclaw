// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// installOnRead is an agent payload whose writing takes long enough for an
// install or upgrade of the account to start: the installer takes the lock
// before the hook has the payload.
type installOnRead struct {
	t       *testing.T
	home    *string
	payload *strings.Reader
	taken   bool
}

func (r *installOnRead) Read(p []byte) (int, error) {
	if !r.taken {
		r.taken = true
		mkdirInstallLock(r.t, *r.home)
	}
	return r.payload.Read(p)
}

// GAP-0893, GAP-0894: a native hook call that started before an install or
// upgrade, in fail mode open, met the failure after the installer had taken
// the account's data directory, and answered with the mode it read when it
// started. Every failure answer of every native tool hook form now reads
// the install state when it answers: while the agent writes its payload
// (too large, or no hook credential), and once the gateway has answered or
// failed to (no connection, an outage or error status, no verdict, no JSON).
// Without an install the account's open choice still applies.
func TestNativeHookAnswersClosedWhenAnInstallStartsDuringTheCall(t *testing.T) {
	failures := []struct {
		name    string
		status  int
		body    string
		err     error
		big     bool // the payload exceeds the hook's cap
		noToken bool // the hook credential is missing
	}{
		{name: "gateway connection fails", err: errors.New("connection reset by peer")},
		{name: "gateway answers HTTP 503", status: http.StatusServiceUnavailable, body: `{"error":"down"}`},
		{name: "gateway answers HTTP 401", status: http.StatusUnauthorized, body: `{"error":"unauthorized"}`},
		{name: "gateway answers HTTP 404", status: http.StatusNotFound, body: `{}`},
		{name: "gateway answers no verdict", status: http.StatusOK, body: `{"action":"maybe"}`},
		{name: "gateway answers no JSON", status: http.StatusOK, body: `not json`},
		{name: "payload too large", big: true},
		{name: "hook credential missing", noToken: true},
	}
	for _, form := range nativeToolHookForms {
		for _, failure := range failures {
			for _, install := range []bool{false, true} {
				name := form.String() + "/" + failure.name + "/no install"
				if install {
					name = form.String() + "/" + failure.name + "/install starts during the call"
				}
				t.Run(name, func(t *testing.T) {
					var home string
					rt := &stubRT{onRequest: func(_ *stubRT, _ *http.Request) (*http.Response, error) {
						if install {
							mkdirInstallLock(t, home)
						}
						if failure.err != nil {
							return nil, failure.err
						}
						return &http.Response{StatusCode: failure.status, Header: make(http.Header),
							Body: io.NopCloser(strings.NewReader(failure.body))}, nil
					}}
					payload := `{"hook_event_name":"` + form.event + `","tool_name":"Bash","tool_input":{"command":"echo ok"}}`
					if failure.big {
						payload = `{"hook_event_name":"` + form.event + `","tool_input":{"command":"` + strings.Repeat("a", 4096) + `"}}`
					}
					result := run(t, form.connector, rt, func(opts *Options) {
						home = opts.Home
						opts.Event = form.event
						opts.HookSurface = form.surface
						opts.FailMode = "open"
						if failure.big {
							opts.MaxBody = 512
						}
						if failure.noToken {
							if err := os.Remove(filepath.Join(opts.HookDir, ".token")); err != nil {
								t.Fatal(err)
							}
						}
						// A failure before the request meets an install that
						// started while the agent wrote the payload.
						early := failure.big || failure.noToken
						opts.Stdin = &installOnRead{t: t, home: &home, payload: strings.NewReader(payload), taken: !install || !early}
					})
					if got := nativeAnswerBlocks(result.code, result.stdout); got != install {
						t.Fatalf("exit %d stdout %q stderr %q blocks=%v, want blocks=%v",
							result.code, result.stdout, result.stderr, got, install)
					}
				})
			}
		}
	}
}
