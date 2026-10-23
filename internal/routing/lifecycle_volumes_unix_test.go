// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package routing

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-0842: each restart removed the router container but not the anonymous
// /app/models volume Docker created for it, so restarts accumulated orphaned
// volumes. Start (which replaces the previous container) and Stop both remove
// the container's anonymous volumes.
func TestLifecycleRemovesTheContainersAnonymousVolumes(t *testing.T) {
	bin := t.TempDir()
	calls := filepath.Join(t.TempDir(), "calls")
	fake := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '" + calls + "'\nexit 0\n"
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(fake), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	dir := t.TempDir()
	lc := NewLifecycle(LifecycleConfig{ConfigPath: filepath.Join(dir, "config.yaml"), Port: 9191, DataDir: dir})
	if err := lc.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := lc.Stop(); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(calls)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	remove := "rm -f -v " + lc.containerName
	if len(lines) != 3 || lines[0] != remove || !strings.HasPrefix(lines[1], "run ") || lines[2] != remove {
		t.Fatalf("docker calls = %q; want %q, run, %q", lines, remove, remove)
	}
}
