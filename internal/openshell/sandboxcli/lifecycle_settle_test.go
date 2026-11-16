// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package sandboxcli

import (
	"context"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// A gateway that restarts resumes a sandbox it kept, so a `start` or `pull`
// right after it found the sandbox starting and failed with "is starting,
// not stopped; stop it before starting a new session", which a stop could
// not do either (rel-1-0-3 BR-04 pass point A). Both wait for it to settle:
// a sandbox that comes up is running, one that stops is started as usual.
func TestStartAndPullWaitForASandboxOpenShellIsStarting(t *testing.T) {
	bg := context.Background()
	settleAfter := func(ta *testApp, gets int, phase string) {
		seen := 0
		ta.daemon.onGet = func(sb *sandboxapi.Sandbox) {
			if sb.Phase != "starting" {
				return
			}
			if seen++; seen > gets {
				sb.Phase = phase
			}
		}
	}

	t.Run("start of a sandbox that comes up", func(t *testing.T) {
		sb := copySandbox("copybox")
		sb.Phase = "starting"
		ta := newTestApp(t, "", sb)
		settleAfter(ta, 2, "ready")
		ta.ok(t, ta.Start(bg, "copybox", StartOptions{}))
		ta.wantCalls(t, 0, "POST", "copybox/start")
		if out := ta.output() + ta.err.String(); !strings.Contains(out, "copybox is already running") || !strings.Contains(out, "waiting for it") {
			t.Fatalf("start did not wait for the starting sandbox:\n%s", out)
		}
	})

	t.Run("start of a sandbox that stops", func(t *testing.T) {
		sb := copySandbox("copybox")
		sb.Phase = "starting"
		ta := newTestApp(t, "", sb)
		settleAfter(ta, 1, "stopped")
		ta.ok(t, ta.Start(bg, "copybox", StartOptions{}))
		ta.wantCalls(t, 1, "POST", "copybox/start")
	})

	t.Run("pull of a sandbox that comes up", func(t *testing.T) {
		sb := copySandbox("copybox")
		sb.Phase = "starting"
		ta := newTestApp(t, "", sb)
		settleAfter(ta, 2, "ready")
		ta.ok(t, ta.Pull(bg, PullOptions{Name: "copybox"}))
		ta.wantCalls(t, 0, "POST", "copybox/start")
	})
}
