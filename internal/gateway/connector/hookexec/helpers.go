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
	"io"
	"os"
	"path/filepath"
)

// readCapped reads up to max bytes from r. It returns overflow=true (and an
// empty payload) when the input exceeds max, mirroring
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
		return nil, true, nil
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

// logHookFailure appends one JSON line to Home/logs/hook-failures.jsonl,
// mirroring defenseclaw_log_hook_failure. Best-effort: any error is ignored so
// a read-only home or full disk never changes the hook's decision.
func logHookFailure(opts Options, sp spec, reason, category, failMode string) {
	if opts.Home == "" {
		return
	}
	logDir := filepath.Join(opts.Home, "logs")
	if err := os.MkdirAll(logDir, 0o700); err != nil {
		return
	}
	entry := struct {
		TS        string `json:"ts"`
		Connector string `json:"connector"`
		Hook      string `json:"hook"`
		Reason    string `json:"reason"`
		Category  string `json:"category"`
		FailMode  string `json:"fail_mode"`
	}{
		TS:        opts.Now().UTC().Format("2006-01-02T15:04:05Z"),
		Connector: sp.connector,
		Hook:      sp.hookName,
		Reason:    reason,
		Category:  category,
		FailMode:  failMode,
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
