// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// readCapped reads up to max bytes from r. It returns overflow=true (and the
// first max bytes, which no caller hands on as the payload) when the input
// exceeds max, mirroring
// defenseclaw_read_stdin_capped: refuse, don't truncate. A 1-byte probe past
// the cap detects the overflow without buffering an unbounded body.
func readCapped(r io.Reader, max int64) (payload []byte, overflow bool, err error) {
	if r == nil {
		return nil, false, nil
	}
	limited := io.LimitReader(r, max+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, false, err
	}
	if int64(len(data)) > max {
		// The prefix the cap kept: callers read only its leading fields.
		return data[:max], true, nil
	}
	return data, false, nil
}

// validTraceparent mirrors defenseclaw_validate_traceparent: a 55-char W3C
// traceparent (version-traceid-parentid-flags) with dashes at the fixed
// positions, strictly hex elsewhere, and non-zero trace-id / parent-id.
func validTraceparent(v string) bool {
	if len(v) != 55 {
		return false
	}
	if v[2] != '-' || v[35] != '-' || v[52] != '-' {
		return false
	}
	for i := 0; i < len(v); i++ {
		if i == 2 || i == 35 || i == 52 {
			continue
		}
		if !isHex(v[i]) {
			return false
		}
	}
	if v[3:35] == "00000000000000000000000000000000" {
		return false
	}
	if v[36:52] == "0000000000000000" {
		return false
	}
	return true
}

// validTracestate mirrors defenseclaw_validate_tracestate: <=512 bytes and
// only the W3C tracestate ABNF characters (no log-injectable bytes).
func validTracestate(v string) bool {
	if len(v) > 512 {
		return false
	}
	for i := 0; i < len(v); i++ {
		if !isTracestateChar(v[i]) {
			return false
		}
	}
	return true
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func isTracestateChar(c byte) bool {
	switch {
	case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		return true
	case c == '=' || c == ',' || c == '@' || c == '_' || c == '/' || c == '.' || c == '-':
		return true
	case c == ' ' || c == '\t':
		return true
	default:
		return false
	}
}

// managedOpenCodeBackgroundEvent names callbacks that can report runtime
// health but cannot admit a tool. Their failures are diagnostics even when
// the native hook's unused answer happens to be allow- or block-shaped.
func managedOpenCodeBackgroundEvent(opts Options, sp spec) bool {
	if sp.connector != "opencode" || !managedNativeDecision(opts) || secureClientHook(opts) {
		return false
	}
	if NeutralLifecycleEvent(sp.connector, opts.Event) {
		return true
	}
	switch strings.TrimSpace(opts.Event) {
	case "defenseclaw.plugin.loaded", "tool.execute.after":
		return true
	}
	return false
}

// logHookFailure appends one JSON line to Home/logs/hook-failures.jsonl,
// when Home exists, mirroring defenseclaw_log_hook_failure. Best-effort: any
// error is ignored so a read-only home or full disk never changes the hook's
// decision. blocked is the delivery outcome the caller applies; a connector
// without a fail-closed contract records what the call got instead
// (loggedFailMode), so the fail-open report finds the calls that ran. Managed
// OpenCode callbacks that cannot admit a tool are diagnostics.
func logHookFailure(opts Options, sp spec, reason, category, failMode string, blocked bool) {
	if sp.failOpenOnly {
		blocked = loggedFailMode(opts, sp, failMode) == "closed"
	}
	if w := opts.answerWatch; w != nil {
		// Before anything below can block: a closed failure keeps the
		// watchdog's answer closed (claimFailureLog).
		done, claimed := w.claimFailureLog(opts, sp, blocked)
		if !claimed {
			return
		}
		defer close(done)
	}
	outcome := "fail_closed"
	if managedOpenCodeBackgroundEvent(opts, sp) {
		outcome = "diagnostic"
	} else if !blocked {
		outcome = "fail_open"
		// Quote diagnostics so an unexpected transport error cannot forge lines.
		// Never include request/response bodies or authentication credentials.
		fmt.Fprintf(opts.Stderr, "defenseclaw: WARNING hook fail-open; inspection bypassed (connector=%s hook=%s category=%s): %q\n", sp.connector, sp.hookName, category, reason)
	}
	home := opts.Home
	if opts.ManagedEnterprise {
		// A managed row goes only to the invoking user's diagnostic
		// directory, never to the administrator-owned enforcement home: an
		// account the lookup does not resolve writes no row.
		home = ""
		if opts.FailureLogHome != nil {
			home = opts.FailureLogHome()
		}
	}
	if home == "" {
		return
	}
	// Never create the DefenseClaw folder for a log line: a managed hook whose
	// protected folder was missing recreated it here, user-owned with the
	// profile's inherited access control, and the next event's hook found a
	// folder and no longer said it was missing (GAP-0154, rel-1-0-4
	// GAP-0593). A managed account with no such folder writes no row.
	// Mkdir creates only logs, so a purge that removes the folder while the
	// call runs is not undone either (GAP-0654).
	if info, err := os.Stat(home); err != nil || !info.IsDir() {
		return
	}
	failMode = loggedFailMode(opts, sp, failMode)
	logDir := filepath.Join(home, "logs")
	if err := os.Mkdir(logDir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return
	}
	entry := struct {
		TS        string `json:"ts"`
		Connector string `json:"connector"`
		Hook      string `json:"hook"`
		// Event names the hook event, so a neutral stop event's allow
		// reads apart from a tool call's fail-open (GAP-0527).
		Event    string `json:"event,omitempty"`
		Reason   string `json:"reason"`
		Category string `json:"category"`
		FailMode string `json:"fail_mode"`
		Outcome  string `json:"outcome"`
	}{
		TS:        opts.Now().UTC().Format("2006-01-02T15:04:05Z"),
		Connector: sp.connector,
		Hook:      sp.hookName,
		Event:     strings.TrimSpace(opts.Event),
		Reason:    reason,
		Category:  category,
		FailMode:  failMode,
		Outcome:   outcome,
	}
	line, err := json.Marshal(entry)
	if err != nil {
		return
	}
	f, err := os.OpenFile(filepath.Join(logDir, "hook-failures.jsonl"),
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(append(line, '\n'))
}
