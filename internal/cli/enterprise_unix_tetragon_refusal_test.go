// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

func TestTetragonNotRootRefusalIsReported(t *testing.T) {
	previous := reportManagedCommandRefusal
	defer func() { reportManagedCommandRefusal = previous }()
	var calls []string
	reportManagedCommandRefusal = func(command, reason string) { calls = append(calls, command+":"+reason) }
	reportTetragonNotRoot("pause", []enterprisestatus.Message{{Code: "not_root"}})
	reportTetragonNotRoot("pause", []enterprisestatus.Message{{Code: "not_ready"}})
	if len(calls) != 1 || calls[0] != "enterprise linux tetragon pause:not_root" {
		t.Fatalf("reported %v", calls)
	}
}
