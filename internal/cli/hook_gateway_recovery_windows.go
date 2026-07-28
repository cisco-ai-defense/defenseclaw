// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/hookruntime"
	"github.com/defenseclaw/defenseclaw/internal/processutil"
)

const gatewayStartDiagnosticMaxBytes = 4 << 10

func trustedNativeGatewayRecovery() func(context.Context, error) error {
	executable := nativeHookExecutable()
	state, recognized, err := hookruntime.ReadTrustedForExecutable(executable)
	if err != nil || !recognized || !state.ColdStartCapable() {
		return nil
	}
	return func(ctx context.Context, _ error) error {
		return recoverTrustedNativeGateway(ctx, executable)
	}
}

func recoverTrustedNativeGateway(ctx context.Context, executable string) error {
	return hookruntime.WithGatewayStartLock(ctx, func() error {
		// Setup publishes and disables state under this same lock. Re-read only
		// after acquisition so an invocation queued behind uninstall cannot start
		// a removed gateway from its earlier in-memory snapshot.
		state, recognized, err := hookruntime.ReadTrustedForExecutable(executable)
		if err != nil {
			return fmt.Errorf("revalidate protected hook runtime: %w", err)
		}
		if !recognized || !state.ColdStartCapable() {
			return errors.New("protected hook runtime no longer authorizes gateway cold start")
		}
		return runTrustedNativeGatewayStart(ctx, state)
	})
}

func runTrustedNativeGatewayStart(ctx context.Context, state hookruntime.State) error {
	if !state.ColdStartCapable() {
		return errors.New("protected hook runtime does not authorize gateway cold start")
	}
	info, err := os.Stat(state.DataRoot)
	if err != nil {
		return fmt.Errorf("protected DefenseClaw data root is unavailable: %w", err)
	}
	if !info.IsDir() {
		return errors.New("protected DefenseClaw data root is not a directory")
	}
	if !windowsHookPathHasNoReparsePoints(state.DataRoot) {
		return errors.New("protected DefenseClaw data root traverses an unsafe reparse point")
	}

	lockedGateway, err := hookruntime.LockVerifiedGateway(state)
	if err != nil {
		return err
	}
	defer lockedGateway.Close()

	cmd := newTrustedNativeGatewayStartCommand(ctx, state)
	output, err := cmd.CombinedOutput()
	if ctxErr := ctx.Err(); ctxErr != nil {
		return fmt.Errorf("gateway cold start exceeded the hook deadline: %w", ctxErr)
	}
	if err != nil {
		detail := strings.TrimSpace(string(output))
		if len(detail) > gatewayStartDiagnosticMaxBytes {
			detail = detail[len(detail)-gatewayStartDiagnosticMaxBytes:]
		}
		if detail == "" {
			return fmt.Errorf("installer-owned gateway start failed: %w", err)
		}
		return fmt.Errorf("installer-owned gateway start failed: %w: %s", err, detail)
	}
	return nil
}

func newTrustedNativeGatewayStartCommand(ctx context.Context, state hookruntime.State) *exec.Cmd {
	cmd := processutil.CommandContext(ctx, state.GatewayPath, "start")
	cmd.Dir = filepath.Clean(state.DataRoot)
	cmd.Env = trustedNativeGatewayStartEnvironment(os.Environ(), state.DataRoot)
	return cmd
}

func trustedNativeGatewayStartEnvironment(environ []string, dataRoot string) []string {
	clean := make([]string, 0, len(environ)+3)
	for _, entry := range environ {
		name, _, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		upper := strings.ToUpper(strings.TrimSpace(name))
		if strings.HasPrefix(upper, "DEFENSECLAW_") || strings.HasPrefix(upper, "OPENCLAW_") ||
			upper == "PYTHONHOME" || upper == "PYTHONPATH" || upper == "PYTHONIOENCODING" || upper == "PYTHONUTF8" {
			continue
		}
		clean = append(clean, entry)
	}
	return append(
		clean,
		"DEFENSECLAW_HOME="+filepath.Clean(dataRoot),
		"PYTHONUTF8=1",
		"PYTHONIOENCODING=utf-8",
	)
}
