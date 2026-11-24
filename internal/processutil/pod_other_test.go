// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package processutil

import (
	"errors"
	"os/exec"
	"strings"
	"testing"
)

// Off Linux the pod-contained runner refuses every call with one plain
// reason, and the refusal keeps the fail-closed sentinels (GAP-1035).
func TestGAP1035PodRunnerRefusesOffLinux(t *testing.T) {
	p := NewPodRunner("/tmp", "/dev/shm")
	for name, err := range map[string]error{
		"Check":  p.Check(),
		"Run":    p.Run(exec.Command("true")),
		"RunJob": p.RunJob(exec.Command("true"), "/tmp/job"),
		"Reset":  p.Reset(),
	} {
		if err == nil || !errors.Is(err, ErrContainmentUnavailable) || !errors.Is(err, ErrNotContained) ||
			!strings.Contains(err.Error(), "runs only on Linux") {
			t.Fatalf("%s off Linux = %v, want a plain refusal", name, err)
		}
	}
}
