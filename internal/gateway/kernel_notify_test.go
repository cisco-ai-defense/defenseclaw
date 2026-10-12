// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/notifier"
	"github.com/defenseclaw/defenseclaw/internal/sensor"
	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
)

// A kernel denial notifies like a hook block (spec 9.1): block_enforced,
// the hook source, labelled kernel, with the control and the connector and
// nothing a user did. A would-block is not notified.
func TestKernelDenialsReachTheNotifier(t *testing.T) {
	d, rec := newWiringDispatcher()
	uid := 1001
	notifyKernelBlocks(d, sensor.Snapshot{KernelEvents: []sensor.KernelEvent{
		{At: time.Now(), Outcome: plane.OutcomeWouldBlock, Control: "kernel.persistence_write", Process: "sh",
			Path: "/home/alice/.bashrc", UID: &uid},
		{At: time.Now(), Outcome: plane.OutcomeBlocked, Control: "kernel.ssh_private_key_read",
			RuleID: "kernel.ssh_private_key_read", Process: "cat", Path: "/home/alice/.ssh/dccert-block-marker",
			UID: &uid, AgentName: "claude", Connector: "claudecode"},
	}})
	got := rec.WaitFor(t, 1)
	if len(got) != 1 {
		t.Fatalf("notifications = %+v", got)
	}
	n := got[0]
	if !strings.Contains(n.Title, "blocked kernel control kernel.ssh_private_key_read") ||
		n.Subtitle != "hook · HIGH · claudecode · kernel" || !strings.Contains(n.Body, "SSH private key") {
		t.Fatalf("notification = %+v", n)
	}
	if strings.Contains(n.Title+n.Subtitle+n.Body, "dccert-block-marker") {
		t.Fatalf("the path reached the notification: %+v", n)
	}

	// Silenced with the hook source, like every other hook block.
	cfg := fullyEnabledNotificationsConfig()
	cfg.Sources.Hook = false
	silent := newRecordingSender()
	notifyKernelBlocks(notifier.NewWithSender(cfg, silent.Send), sensor.Snapshot{KernelEvents: []sensor.KernelEvent{
		{Outcome: plane.OutcomeBlocked, Control: "kernel.ssh_private_key_read", Process: "cat"}}})
	time.Sleep(50 * time.Millisecond)
	silent.mu.Lock()
	defer silent.mu.Unlock()
	if len(silent.sent) != 0 {
		t.Fatalf("the hook source switch did not silence a kernel denial: %+v", silent.sent)
	}
	notifyKernelBlocks(nil, sensor.Snapshot{}) // no dispatcher: no-op
}
