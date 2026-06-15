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

package connector

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestHardening_ValidateTraceparent locks the W3C format check
// _hardening.sh v6 enforces on inbound traceparent values. The
// gateway extends the same allow-list on the Go side (see
// extractIncomingTraceContext); a mismatch between the shell-side
// and Go-side validators would let one half emit headers the other
// half ignores, which is harder to debug than a 415.
func TestHardening_ValidateTraceparent(t *testing.T) {
	helperPath := materializeHardeningHelper(t)

	cases := []struct {
		name string
		val  string
		want bool
	}{
		{"valid", "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01", true},
		{"empty", "", false},
		{"short", "00-deadbeef-cafef00d-01", false},
		{"all_zero_trace", "00-00000000000000000000000000000000-b7ad6b7169203331-01", false},
		{"all_zero_span", "00-0af7651916cd43dd8448eb211c80319c-0000000000000000-01", false},
		{"non_hex", "zz-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01", false},
		{"too_long", "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01-extra", false},
		{"missing_dashes", "000af7651916cd43dd8448eb211c80319cb7ad6b716920333101", false},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command("bash", "-c",
				`source "$0" >/dev/null 2>&1; defenseclaw_validate_traceparent "$1"; echo $?`,
				helperPath, tc.val)
			out, err := cmd.CombinedOutput()
			if err != nil && len(out) == 0 {
				t.Fatalf("run bash: %v", err)
			}
			rc := strings.TrimSpace(string(out))
			got := rc == "0"
			if got != tc.want {
				t.Errorf("defenseclaw_validate_traceparent(%q) returned rc=%q (treated as %v), want=%v",
					tc.val, rc, got, tc.want)
			}
		})
	}
}

// TestHardening_ExtractTraceContext locks the helper's output shape.
// On a valid env it emits "-H\ntraceparent: <value>\n"; on a missing
// env it emits nothing. Hostile env values are silently dropped (the
// hook still posts; trace propagation just skips).
func TestHardening_ExtractTraceContext(t *testing.T) {
	helperPath := materializeHardeningHelper(t)

	cases := []struct {
		name        string
		traceparent string
		tracestate  string
		wantTP      string // empty = expect dropped
		wantTS      string
	}{
		{
			name:        "valid traceparent only",
			traceparent: "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
			tracestate:  "",
			wantTP:      "traceparent: 00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
			wantTS:      "",
		},
		{
			name:        "valid both",
			traceparent: "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
			tracestate:  "rojo=00f067aa0ba902b7,congo=t61rcWkgMzE",
			wantTP:      "traceparent: 00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
			wantTS:      "tracestate: rojo=00f067aa0ba902b7,congo=t61rcWkgMzE",
		},
		{
			name:        "invalid traceparent dropped",
			traceparent: "00-zzz-yyy-01",
			tracestate:  "",
			wantTP:      "",
			wantTS:      "",
		},
		{
			name:        "missing both",
			traceparent: "",
			tracestate:  "",
			wantTP:      "",
			wantTS:      "",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command("bash", "-c",
				`source "$0"; defenseclaw_extract_trace_context`, helperPath)
			env := []string{
				"PATH=" + os.Getenv("PATH"),
				"HOME=" + t.TempDir(),
				"DEFENSECLAW_HOME=" + t.TempDir(),
			}
			if tc.traceparent != "" {
				env = append(env, "DEFENSECLAW_TRACEPARENT="+tc.traceparent)
			}
			if tc.tracestate != "" {
				env = append(env, "DEFENSECLAW_TRACESTATE="+tc.tracestate)
			}
			cmd.Env = env
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("bash run: %v\n%s", err, out)
			}
			s := string(out)
			if tc.wantTP == "" {
				if strings.Contains(s, "traceparent:") {
					t.Errorf("expected no traceparent header for %q; got=%q", tc.traceparent, s)
				}
			} else if !strings.Contains(s, tc.wantTP) {
				t.Errorf("expected %q in output; got=%q", tc.wantTP, s)
			}
			if tc.wantTS == "" {
				if strings.Contains(s, "tracestate:") {
					t.Errorf("expected no tracestate header; got=%q", s)
				}
			} else if !strings.Contains(s, tc.wantTS) {
				t.Errorf("expected %q in output; got=%q", tc.wantTS, s)
			}
		})
	}
}

// materializeHardeningHelper writes the embedded _hardening.sh to a
// temp dir and returns the path. Used by every shell-side test that
// needs to source the helper without dragging in the rest of the
// hook install pipeline.
func materializeHardeningHelper(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	helperBytes, err := hookFS.ReadFile("hooks/_hardening.sh")
	if err != nil {
		t.Fatalf("read embed: %v", err)
	}
	dir := t.TempDir()
	helperPath := filepath.Join(dir, "_hardening.sh")
	if err := os.WriteFile(helperPath, helperBytes, 0o600); err != nil {
		t.Fatalf("write helper: %v", err)
	}
	return helperPath
}
