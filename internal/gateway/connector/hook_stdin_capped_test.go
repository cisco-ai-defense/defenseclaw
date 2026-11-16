// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// stdinCappedScript sources _hardening.sh, records the reader's log lines on
// stderr and reads stdin under the cap.
const stdinCappedScript = `. "$1"
defenseclaw_log_hook_failure() { printf 'LOG:%s\n' "$3" >&2; }
defenseclaw_read_stdin_capped
`

// TestHardeningReadStdinCappedRefusesNULAndOverflowExactly checks that
// defenseclaw_read_stdin_capped sees the raw bytes: a bash variable drops
// NUL, so a NUL inside the first cap+1 bytes used to shrink an oversized body
// under the cap and pass it truncated, with the bytes past the cap never
// inspected. The reader is bash's own read on every host: the head(1),
// python3 and bare tiers this test once forced are gone (issue #1130).
func TestHardeningReadStdinCappedRefusesNULAndOverflowExactly(t *testing.T) {
	if _, err := os.Stat("/bin/bash"); err != nil {
		t.Skip("bash is required")
	}
	helper, err := hookFS.ReadFile("hooks/_hardening.sh")
	if err != nil {
		t.Fatalf("read hardening helper: %v", err)
	}
	helperPath := filepath.Join(t.TempDir(), "_hardening.sh")
	if err := os.WriteFile(helperPath, helper, 0o700); err != nil {
		t.Fatalf("write hardening helper: %v", err)
	}
	full := strings.Repeat("a", 1<<20)
	cases := []struct {
		name, cap, in string
		refusal       string // "" = accepted unchanged, else the log reason
	}{
		{"trailing newlines kept", "16", "ab\ncd\n\n", ""},
		{"exactly the cap", "4", "abcd", ""},
		{"one byte over", "4", "abcde", "stdin body exceeded 4 byte cap"},
		{"NUL within the cap", "16", "ab\x00cd", "stdin body has a NUL byte"},
		{"NUL hides an oversized body", "8", "a\x00\x00\x00bcdef" + "SECRET-PAST-THE-CAP", "stdin body has a NUL byte"},
		{"NUL past the cap", "4", "abcdefgh\x00", "stdin body exceeded 4 byte cap"},
		{"default cap, full", "", full, ""},
		{"default cap, leading NUL", "", "\x00" + full[1:], "stdin body has a NUL byte"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command("/bin/bash", "-c", stdinCappedScript, "bash", helperPath)
			cmd.Env = sanitizedTestEnv()
			if tc.cap != "" {
				cmd.Env = append(cmd.Env, "DEFENSECLAW_HOOK_MAX_BODY="+tc.cap)
			}
			cmd.Stdin = strings.NewReader(tc.in)
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			runErr := cmd.Run()
			if tc.refusal == "" {
				if runErr != nil {
					t.Fatalf("refused an acceptable body: %v\n%s", runErr, stderr.String())
				}
				if stdout.String() != tc.in {
					t.Fatalf("body altered: got %d bytes, want %d", stdout.Len(), len(tc.in))
				}
				return
			}
			if runErr == nil {
				t.Fatalf("accepted a body it must refuse (%s): got %d bytes on stdout", tc.refusal, stdout.Len())
			}
			if strings.Contains(stderr.String(), "LOG:stdin body exceeded") {
				capBytes, _ := strconv.Atoi(tc.cap)
				if got, want := stdout.String(), tc.in[:capBytes]; got != want {
					t.Fatalf("bounded refusal prefix = %q, want %q", got, want)
				}
			} else if stdout.Len() != 0 {
				t.Fatalf("NUL refusal printed %d bytes of body", stdout.Len())
			}
			if want := "LOG:" + tc.refusal; !strings.Contains(stderr.String(), want) {
				t.Fatalf("missing log %q:\n%s", want, stderr.String())
			}
		})
	}
}
