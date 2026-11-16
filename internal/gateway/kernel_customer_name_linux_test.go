//go:build linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os/user"
	"strconv"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	"github.com/defenseclaw/defenseclaw/internal/sensor"
	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
)

// A native customer policy event often has only the kernel UID. The record
// still needs the OS account name when NSS can resolve that UID.
func TestCustomerKernelEventResolvesKnownUIDName(t *testing.T) {
	account, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil {
		t.Fatal(err)
	}
	adapter, emitter := newKernelTestAdapter(router.AdmissionOrdinary)
	event := sensor.CustomerKernelEvent{
		At: time.Now().UTC(), Policy: "customer-file-observe", HookType: "lsm",
		Function: "file_open", Action: "post", PolicyMode: "monitor", Outcome: plane.OutcomeObserved,
		PID: 1234, Process: "cat", UID: &uid, AgentName: "claude",
	}
	if err := adapter.EmitSnapshot(t.Context(), sensor.Snapshot{CustomerKernelEvents: []sensor.CustomerKernelEvent{event}}); err != nil {
		t.Fatal(err)
	}
	records := recordsNamed(emitter.records, "ai.runtime.kernel_event")
	if len(records) != 1 {
		t.Fatalf("kernel_event records = %d, want 1", len(records))
	}
	if got := kernelRecordBody(t, records[0])["defenseclaw.user.name"]; got != account.Username {
		t.Fatalf("defenseclaw.user.name = %v, want %q for uid %d", got, account.Username, uid)
	}
	// A sensor-provided qualified name is still recorded as the account
	// part, as the field's documented contract requires.
	adapter, emitter = newKernelTestAdapter(router.AdmissionOrdinary)
	event.User = "directory-user@example.test"
	if err := adapter.EmitSnapshot(t.Context(), sensor.Snapshot{CustomerKernelEvents: []sensor.CustomerKernelEvent{event}}); err != nil {
		t.Fatal(err)
	}
	records = recordsNamed(emitter.records, "ai.runtime.kernel_event")
	if len(records) != 1 || kernelRecordBody(t, records[0])["defenseclaw.user.name"] != "directory-user" {
		t.Fatalf("qualified sensor name was not reduced to the OS account: %v", records)
	}
}
