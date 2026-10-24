// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

func TestMacOSPendingLaunchAgentAdvice(t *testing.T) {
	h, _, _ := newLaunchdTestHost(t)
	setConsoleOwner(h, h.alice.UID)
	entry := pending{Kind: "launchd", User: "sample-user", UID: h.alice.UID, Since: "2026-10-14T12:00:00Z", Reason: "the signed gateway binary changed", Sandboxes: 2}
	r := &enterprisestatus.Result{}
	(&lifecycle{env: h.env, result: r}).describePending(context.Background(), entry)
	message := messagesOf(r.Warnings, codeSandboxPending)
	for _, want := range []string{"sudo " + h.env.lifecycleCommand(ActionRepair), "root ensure, repair or reconcile", "first sandbox started after the running ones stop", "reloads the job itself", "If that reload fails, the start reports it"} {
		if !strings.Contains(message, want) {
			t.Fatalf("pending LaunchAgent advice %q misses %q", message, want)
		}
	}
	if strings.Contains(message, "does not apply the reload") || strings.Contains(message, "can fail with a code-signing exit") {
		t.Fatalf("LaunchAgent advice retains the old first-use window: %q", message)
	}

	entry.Kind = "restart"
	r = &enterprisestatus.Result{}
	(&lifecycle{env: h.env, result: r}).describePending(context.Background(), entry)
	want := fmt.Sprintf("pending restart for user sample-user since %s (the signed gateway binary changed): 2 sandboxes run (or are starting, stopping, or a MicroVM that OpenShell does not report stopped); it is applied by the first run of `%s` or the user's next `defenseclaw sandbox` command that finds no sandbox running. Save or sync any accessible guest work first; the user's `defenseclaw sandbox stop NAME` requests a disk sync before stopping a running one (a failed sync can lose later changes); a MicroVM whose workload completed or that is in OpenShell's error state, which OpenShell does not stop and whose VM may still run, holds the change until OpenShell reports it stopped (the user's `defenseclaw sandbox stop NAME` says how) or, after saving accessible work outside the guest, the user deletes it (`defenseclaw sandbox delete NAME`)\n",
		entry.Since, h.env.lifecycleCommand(ActionEnsure))
	if got := messagesOf(r.Warnings, codeSandboxPending); got != want {
		t.Fatalf("restart advice changed: got %q, want %q", got, want)
	}
}
