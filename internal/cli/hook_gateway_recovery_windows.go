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
	"github.com/defenseclaw/defenseclaw/internal/nativeinstallstate"
	"github.com/defenseclaw/defenseclaw/internal/processutil"
)

const gatewayStartDiagnosticMaxBytes = 4 << 10

var (
	nativePreparedHookRuntimeRevalidator = hookruntime.RevalidatePreparedGenerationForExecutable
	nativeGatewayStartLock               = hookruntime.WithGatewayStartLock
	nativeGatewayStartRunner             = runTrustedNativeGatewayStart
	nativeGatewayInstallStateReader      = nativeinstallstate.LoadForExecutable
)

func trustedNativeGatewayRecovery() func(context.Context, error) error {
	executable := nativeHookExecutable()
	state, recognized, err, prepared := preparedNativeHookRuntime(executable)
	if !prepared {
		state, recognized, err = nativeHookRuntimeReader(executable)
	}
	if err != nil || !recognized || !state.ColdStartCapable() {
		return nil
	}
	return func(ctx context.Context, _ error) error {
		return recoverTrustedNativeGateway(ctx, executable)
	}
}

func recoverTrustedNativeGateway(ctx context.Context, executable string) error {
	return nativeGatewayStartLock(ctx, func() error {
		// Setup publishes and disables state under this same lock. Re-read only
		// after acquisition so an invocation queued behind uninstall cannot start
		// a removed gateway from its earlier in-memory snapshot.
		state, recognized, err := refreshedNativeHookRuntimeForRecovery(executable)
		if err != nil {
			return fmt.Errorf("revalidate protected hook runtime: %w", err)
		}
		if !recognized || !state.ColdStartCapable() {
			return errors.New("protected hook runtime no longer authorizes gateway cold start")
		}
		return nativeGatewayStartRunner(ctx, state)
	})
}

func refreshedNativeHookRuntimeForRecovery(executable string) (hookruntime.State, bool, error) {
	preparedState, preparedRecognized, preparedErr, prepared := preparedNativeHookRuntime(executable)
	if prepared {
		if preparedErr != nil || !preparedRecognized {
			return preparedState, preparedRecognized, preparedErr
		}
		if preparedState.DelegationCapable() && preparedState.DelegatesTo(executable) {
			current, err := nativePreparedHookRuntimeRevalidator(executable, preparedState)
			return current, true, err
		}
	}
	// Legacy full launchers and callers that did not enter through main retain
	// the complete executable admission path. Only an already-admitted
	// trampoline child can use the exact-generation refresh above.
	return nativeHookRuntimeReader(executable)
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

	cmd, err := newTrustedNativeGatewayStartCommand(ctx, state)
	if err != nil {
		return fmt.Errorf("prepare installer-owned gateway start: %w", err)
	}
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

func newTrustedNativeGatewayStartCommand(ctx context.Context, state hookruntime.State) (*exec.Cmd, error) {
	cmd := processutil.CommandContext(ctx, state.GatewayPath, "start")
	cmd.Dir = filepath.Dir(filepath.Clean(state.GatewayPath))
	environment, err := trustedNativeGatewayStartEnvironment(os.Environ(), state)
	if err != nil {
		return nil, err
	}
	cmd.Env = environment
	return cmd, nil
}

func trustedNativeGatewayStartEnvironment(environ []string, runtimeState hookruntime.State) ([]string, error) {
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
	installState, recognized, err := nativeGatewayInstallStateReader(runtimeState.GatewayPath)
	if err != nil {
		return nil, fmt.Errorf("load native install state for gateway recovery: %w", err)
	}
	if recognized {
		if !sameHookRecoveryPath(installState.DataRoot, runtimeState.DataRoot) {
			return nil, errors.New("native install state data root does not match protected hook runtime")
		}
		clean = installState.Environment(clean)
	} else {
		clean = append(clean, "DEFENSECLAW_HOME="+filepath.Clean(runtimeState.DataRoot))
	}
	return append(
		clean,
		"PYTHONUTF8=1",
		"PYTHONIOENCODING=utf-8",
	), nil
}

func sameHookRecoveryPath(left, right string) bool {
	left = filepath.Clean(left)
	right = filepath.Clean(right)
	return strings.EqualFold(left, right)
}
