// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// rel-1-0-10:GAP-1222: with ~/.defenseclaw on a full disk the per-user
// gateway answered every Claude Code prompt HTTP 503 "hook audit is
// unavailable" (it keeps a durable record of each call before it answers),
// and the hook's own failure line could not be appended either. The prompt
// was refused, as designed, but the agent showed only "local failure record
// could not be appended" and "gateway returned HTTP 503": nothing said the
// disk was full or what to do. The call stays blocked in fail mode open; the
// block and both stderr lines now name the full disk, the folder and the
// step. /dev/full makes the hook-failure log write fail with a real ENOSPC.
func TestPerUserAuditUnavailableOnAFullDiskSaysSo(t *testing.T) {
	orig := openHookFailureLog
	openHookFailureLog = func(name string, flag int, perm os.FileMode) (*os.File, error) {
		return os.OpenFile("/dev/full", os.O_WRONLY, 0)
	}
	t.Cleanup(func() { openHookFailureLog = orig })

	for _, tc := range []struct {
		name, body string
		want       []string
	}{
		{"disk full", `{"error":"hook audit is unavailable","cause":"disk_full"}`,
			[]string{"DefenseClaw blocked this prompt: the disk that holds DefenseClaw's data folder (", ") is full",
				"Free space on that disk, then try again", "defenseclaw doctor"}},
		{"cause unknown", `{"error":"hook audit is unavailable"}`,
			[]string{"DefenseClaw blocked this prompt: the DefenseClaw gateway could not write the audit record",
				"A full disk under DefenseClaw's data folder (", "free space there, then try again", "defenseclaw doctor"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			saved := os.Stderr
			os.Stderr = w
			res := run(t, "claudecode", &stubRT{status: 503, body: tc.body}, func(o *Options) { o.Event = "UserPromptSubmit" })
			os.Stderr = saved
			_ = w.Close()
			processStderr, _ := io.ReadAll(r)

			// Still refused in fail mode open: the gateway has no record of the call.
			if res.code != 0 || !strings.HasPrefix(res.stdout, `{"decision":"block","reason":"`) {
				t.Fatalf("code=%d stdout=%q, want the structured prompt block", res.code, res.stdout)
			}
			for _, want := range tc.want {
				if !strings.Contains(res.stdout, want) {
					t.Fatalf("block %q does not say %q", res.stdout, want)
				}
			}
			if strings.Contains(res.stderr, "gateway returned HTTP 503") ||
				!strings.Contains(res.stderr, "gateway could not write the hook audit record (HTTP 503)") {
				t.Fatalf("hook stderr = %q, want the audit-record cause", res.stderr)
			}
			line := string(processStderr)
			if !strings.Contains(line, "local failure record could not be appended: the disk that holds ") ||
				!strings.Contains(line, string(filepath.Separator)+"logs is full; free space on it, then try again") {
				t.Fatalf("failure-record line = %q, want it to name the full disk and folder", line)
			}
		})
	}
}
