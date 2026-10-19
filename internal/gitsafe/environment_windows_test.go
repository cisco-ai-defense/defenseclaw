// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gitsafe

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestCommandWindowsMixedCaseConfigCannotOverrideSafeguards(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("native Git is required for the Windows environment boundary test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	dir := t.TempDir()
	// Positive control: a fixed public-only value, no repo, host config,
	// network or provider credentials. Native Git must actually honor it.
	plain := exec.CommandContext(ctx, "git", "config", "--get", "test.canary")
	plain.Dir = dir
	plain.Env = []string{"PATH=" + os.Getenv("PATH"), "SYSTEMROOT=" + os.Getenv("SYSTEMROOT"),
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=NUL", "GIT_CONFIG_COUNT=0",
		"gIt_CONFIG_PARAMETERS='test.canary=fixed-public'"}
	if out, err := plain.CombinedOutput(); err != nil || strings.TrimSpace(string(out)) != "fixed-public" {
		t.Fatalf("native mixed-case positive control failed: %v, %q", err, out)
	}
	t.Setenv("gIt_CONFIG_PARAMETERS", "'test.canary=fixed-public'")
	cmd, cleanup, err := Command(ctx, dir, "config", "--get", "test.canary")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	for _, entry := range cmd.Env {
		key, _, _ := strings.Cut(entry, "=")
		if strings.EqualFold(key, "GIT_CONFIG_PARAMETERS") {
			t.Fatal("mixed-case inherited config reached safe native Git")
		}
	}
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 1 || len(out) != 0 {
		t.Fatalf("safe native Git accepted inherited canary: %v, %q", err, out)
	}
}
