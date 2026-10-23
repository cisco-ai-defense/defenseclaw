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
// Without an install the account's open choice still applies to an outage;
// an unusable answer (no verdict, no JSON) and input too large to read close
// outside Secure Client in every fail mode (fix/r104-sa-hook-pause, the
// hookexec oversized-input rule), so those block either way.
func TestNativeHookAnswersClosedWhenAnInstallStartsDuringTheCall(t *testing.T) {
	failures := []struct {
		name    string
		status  int
		body    string
		err     error
		big     bool // the payload exceeds the hook's cap
		noToken bool // the hook credential is missing
		closed  bool // blocks outside Secure Client in every fail mode
	}{
		{name: "gateway connection fails", err: errors.New("connection reset by peer")},
		{name: "gateway answers HTTP 503", status: http.StatusServiceUnavailable, body: `{"error":"down"}`},
		{name: "gateway answers HTTP 401", status: http.StatusUnauthorized, body: `{"error":"unauthorized"}`},
		{name: "gateway answers HTTP 404", status: http.StatusNotFound, body: `{}`},
		{name: "gateway answers no verdict", status: http.StatusOK, body: `{"action":"maybe"}`, closed: true},
		{name: "gateway answers no JSON", status: http.StatusOK, body: `not json`, closed: true},
		{name: "payload too large", big: true, closed: true},
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
					want := install || failure.closed
					if form.connector == "hermes" && failure.status == http.StatusOK && failure.body != "not json" {
						// Hermes reads a JSON answer without a verdict as no decision,
						// which its open mode lets through (the train, as before).
						want = install
					}
					if got := nativeAnswerBlocks(result.code, result.stdout); got != want {
						t.Fatalf("exit %d stdout %q stderr %q blocks=%v, want blocks=%v",
							result.code, result.stdout, result.stderr, got, want)
					}
				})
			}
		}
	}
}

// installOnBodyRead is a gateway answer body whose reading takes long
// enough for an install or upgrade of the account to start: the installer
// takes the lock after the gateway sent its status line and before the hook
// has the whole body.
type installOnBodyRead struct {
	t     *testing.T
	home  string
	body  *strings.Reader
	err   error
	taken bool
}

func (r *installOnBodyRead) Read(p []byte) (int, error) {
	if !r.taken {
		r.taken = true
		mkdirInstallLock(r.t, r.home)
	}
	if r.err != nil {
		return 0, r.err
	}
	return r.body.Read(p)
}

func (r *installOnBodyRead) Close() error { return nil }

// nativeAllowOutput is a connector-native output that lets the tool run in
// every dialect, without the words the block checks look for.
const nativeAllowOutput = `{"permissionDecision":"allow","decision":"allow","behavior":"allow","permission":"allow","continue":true}`

// GAP-0916: an install that started while the hook read the gateway's
// answer body left the call in the mode Run had read before the request. A
// body whose action was block but whose native output allowed reached
// decide in fail mode open, which skips the consistency check, and the
// allow was forwarded. Every answer the body can carry (a contradictory
// allow, no verdict, no JSON, a body cut off, an error status, a body too
// large) is now checked with the install state of when it was read, for
// every native tool hook form: during an install the call answers as fail
// mode closed answers it, and the failures block. Without an install the
// account's open choice still applies to an outage or error status; an
// answered body DefenseClaw cannot use (no verdict, no JSON, cut off, too
// large) blocks outside Secure Client in every fail mode on the train
// (fix/r104-sa-hook-pause), except a Hermes answer without a verdict.
func TestNativeHookAnswersClosedWhenAnInstallStartsWhileTheAnswerIsRead(t *testing.T) {
	failures := []struct {
		name   string
		status int
		body   func(sp spec) string
		err    error
		// failure: a failed check, which fail mode closed blocks and open
		// lets run. The contradictory allow is a policy answer, which fail
		// mode closed refuses where the connector can block the event.
		failure bool
		// unusable: an answered body DefenseClaw cannot use.
		unusable bool
	}{
		{name: "block with a native allow", status: http.StatusOK, body: func(sp spec) string {
			field := sp.outputField
			if field == "" {
				field = "hook_output"
			}
			return `{"action":"block","reason":"policy","` + field + `":` + nativeAllowOutput + `,"hook_output":` + nativeAllowOutput + `}`
		}},
		{name: "no verdict", status: http.StatusOK, body: func(spec) string { return `{"action":"maybe"}` }, failure: true, unusable: true},
		{name: "no JSON", status: http.StatusOK, body: func(spec) string { return `not json` }, failure: true, unusable: true},
		{name: "body cut off", status: http.StatusOK, body: func(spec) string { return `` }, err: io.ErrUnexpectedEOF, failure: true, unusable: true},
		{name: "HTTP 503", status: http.StatusServiceUnavailable, body: func(spec) string { return `{"error":"down"}` }, failure: true},
		{name: "HTTP 401", status: http.StatusUnauthorized, body: func(spec) string { return `{"error":"unauthorized"}` }, failure: true},
		{name: "body too large", status: http.StatusOK, body: func(spec) string { return strings.Repeat("a", int(defaultMaxBody)+2) }, failure: true, unusable: true},
	}
	for _, form := range nativeToolHookForms {
		sp, ok := specFor(form.connector)
		if !ok {
			t.Fatalf("no spec for %s", form.connector)
		}
		for _, failure := range failures {
			answer := func(t *testing.T, failMode string, install bool) runResult {
				var home string
				rt := &stubRT{onRequest: func(_ *stubRT, _ *http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: failure.status, Header: make(http.Header), Body: &installOnBodyRead{
						t: t, home: home, body: strings.NewReader(failure.body(sp)), err: failure.err, taken: !install,
					}}, nil
				}}
				payload := `{"hook_event_name":"` + form.event + `","tool_name":"Bash","tool_input":{"command":"echo ok"}}`
				return run(t, form.connector, rt, func(opts *Options) {
					home = opts.Home
					opts.Event = form.event
					opts.HookSurface = form.surface
					opts.FailMode = failMode
					opts.Stdin = strings.NewReader(payload)
				})
			}
			t.Run(form.String()+"/"+failure.name, func(t *testing.T) {
				closed := answer(t, "closed", false)
				closedBlocks := nativeAnswerBlocks(closed.code, closed.stdout)
				if failure.failure && !closedBlocks {
					t.Fatalf("fail mode closed: exit %d stdout %q stderr %q, want a block", closed.code, closed.stdout, closed.stderr)
				}
				installing := answer(t, "open", true)
				if got := nativeAnswerBlocks(installing.code, installing.stdout); got != closedBlocks {
					t.Fatalf("install started while the body was read: exit %d stdout %q stderr %q blocks=%v, want blocks=%v as in fail mode closed",
						installing.code, installing.stdout, installing.stderr, got, closedBlocks)
				}
				open := answer(t, "open", false)
				closesOpen := failure.unusable && !(form.connector == "hermes" && failure.name == "no verdict")
				if got := nativeAnswerBlocks(open.code, open.stdout); failure.failure && got != closesOpen {
					t.Fatalf("fail mode open without an install: exit %d stdout %q stderr %q blocks=%v, want blocks=%v", open.code, open.stdout, open.stderr, got, closesOpen)
				}
			})
		}
	}
}
