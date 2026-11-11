// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// TestAgentHookConfigRegistrationPathsEndAtTheVolumeRoot pins that the
// registration set of a project outside the home is built in bounded time
// and never holds a volume root (/, C:\): the parent walk of a project hook
// file ends at the root on every host.
func TestAgentHookConfigRegistrationPathsEndAtTheVolumeRoot(t *testing.T) {
	t.Parallel()
	home, project := t.TempDir(), t.TempDir()
	done := make(chan []string, 1)
	go func() { done <- agentHookConfigRegistrationPaths(newAgentHookConfigGuard(project, home)) }()
	select {
	case paths := <-done:
		root := filepath.VolumeName(project) + string(filepath.Separator)
		if slices.Contains(paths, root) {
			t.Fatalf("registration paths hold the volume root %s", root)
		}
		if !slices.Contains(paths, filepath.Join(project, ".claude")) {
			t.Fatalf("registration paths miss the project hook folder: %v", paths)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the registration set of a project outside the home did not finish")
	}
}
