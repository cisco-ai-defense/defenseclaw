//go:build linux || darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package openshell

import (
	"context"
	"os"
	"testing"
)

func TestGAP0617ProcessImagePathUsesRunningFile(t *testing.T) {
	pid, image := startSandboxImageProbe(t)
	path, err := sandboxDaemonProcessPath(context.Background(), pid)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.Stat(image)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.Stat(path)
	if err != nil || !os.SameFile(got, want) {
		t.Fatalf("process image path = %q, want running file %q: %v", path, image, err)
	}
}
