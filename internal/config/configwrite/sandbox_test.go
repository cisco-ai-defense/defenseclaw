// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package configwrite

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestCommonSandboxWriterRefusesUnqualifiedAXISWithoutChangingGeneration(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	path := writeTestConfig(t, "openshell: {enabled: true, profile: strict}\nsandbox: {enabled: false, runtime: axis}\n")
	opt := Options{Actor: "cli:test", Reason: "common sandbox test"}
	first, err := Apply(context.Background(), path,
		[]Change{{Path: "sandbox.runtimes.axis.enabled", Value: true}}, opt)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Apply(context.Background(), path, []Change{{Path: "sandbox.enabled", Value: true}}, opt)
	if err == nil || !strings.Contains(err.Error(), "AXIS runtime is not available") {
		t.Fatalf("active AXIS write = %v; want an explicit unavailable refusal", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != string(before) {
		t.Fatal("rejected runtime activation changed configuration bytes")
	}
	state, err := ReadGenerationState(path)
	if err != nil || state.Generation != first.Generation || state.ConfigSHA256 != first.SHA256 {
		t.Fatalf("rejected runtime activation changed the accepted generation: %v, %v", state, err)
	}
}

func TestCommonSandboxChangesApplyWithoutProcessRestart(t *testing.T) {
	changed := []string{"sandbox.enabled", "sandbox.runtime", "sandbox.runtimes.axis.enabled",
		"sandbox.ingress_port", "sandbox.egress_port", "sandbox.egress.block", "sandbox.admin.allowed"}
	if got := RestartRequired(changed); len(got) != 0 {
		t.Fatalf("RestartRequired = %v; common sandbox listeners rebind in process", got)
	}
	if got := ManagedRestartRequired(changed); len(got) != 0 {
		t.Fatalf("ManagedRestartRequired = %v; common sandbox settings do not restart the process", got)
	}
}
