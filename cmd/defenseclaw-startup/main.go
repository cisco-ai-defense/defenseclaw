// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// DefenseClaw's Windows logon launcher is built with the windowsgui subsystem.
// It pins the installed data directory and invokes the adjacent gateway without
// allocating a console window.
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/processutil"
)

const startupTimeout = 90 * time.Second

func main() {
	if runtime.GOOS != "windows" {
		return
	}
	if err := runStartup(); err != nil {
		os.Exit(1)
	}
}

func runStartup() error {
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve startup launcher: %w", err)
	}
	home, err := currentUserProfile()
	if err != nil {
		return fmt.Errorf("resolve user profile: %w", err)
	}
	gatewayPath, dataRoot, err := startupPaths(executable, home)
	if err != nil {
		return err
	}
	if info, err := os.Stat(gatewayPath); err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("installed gateway is unavailable: %s", gatewayPath)
	}
	if info, err := os.Stat(dataRoot); err != nil || !info.IsDir() {
		return fmt.Errorf("DefenseClaw data directory is unavailable: %s", dataRoot)
	}

	ctx, cancel := context.WithTimeout(context.Background(), startupTimeout)
	defer cancel()
	cmd := processutil.CommandContext(ctx, gatewayPath, "start")
	cmd.Dir = dataRoot
	cmd.Env = withDefenseClawHome(os.Environ(), dataRoot)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("start DefenseClaw gateway: %w", err)
	}
	return nil
}

func startupPaths(executable, home string) (gatewayPath, dataRoot string, err error) {
	executable = strings.TrimSpace(executable)
	home = strings.TrimSpace(home)
	if executable == "" || home == "" {
		return "", "", fmt.Errorf("startup launcher paths are incomplete")
	}
	executable, err = filepath.Abs(executable)
	if err != nil {
		return "", "", fmt.Errorf("resolve startup launcher path: %w", err)
	}
	home, err = filepath.Abs(home)
	if err != nil {
		return "", "", fmt.Errorf("resolve user profile path: %w", err)
	}
	return filepath.Join(filepath.Dir(executable), "defenseclaw-gateway.exe"), filepath.Join(home, ".defenseclaw"), nil
}

func withDefenseClawHome(environ []string, dataRoot string) []string {
	const key = "DEFENSECLAW_HOME="
	clean := make([]string, 0, len(environ)+1)
	for _, entry := range environ {
		if !strings.HasPrefix(strings.ToUpper(entry), key) {
			clean = append(clean, entry)
		}
	}
	return append(clean, key+dataRoot)
}
