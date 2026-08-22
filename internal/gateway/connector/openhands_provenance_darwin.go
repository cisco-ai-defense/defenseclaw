// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package connector

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

var runOpenHandsDarwinIdentityCommand = func(path string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, path, args...).CombinedOutput()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return "", fmt.Errorf("%s timed out", path)
	}
	if len(output) > 64<<10 {
		return "", fmt.Errorf("%s output exceeds 65536 bytes", path)
	}
	return string(output), err
}

func validateOpenHandsDarwinFileACLPlatform(path string) error {
	return hookAPIValidateDirectoryACL(path)
}

func validateOpenHandsDarwinArchitecturePlatform(path string) error {
	if runtime.GOARCH != "arm64" {
		return fmt.Errorf("OpenHands native launch is supported only on macOS arm64, not %s", runtime.GOARCH)
	}
	architectures, err := runOpenHandsDarwinIdentityCommand("/usr/bin/lipo", "-archs", path)
	if err != nil {
		return fmt.Errorf("inspect OpenHands Mach-O architectures: %w: %s", err, strings.TrimSpace(architectures))
	}
	if !openHandsArchitectureListContains(architectures, "arm64") {
		return fmt.Errorf("OpenHands Mach-O does not contain the native arm64 architecture: %s", strings.TrimSpace(architectures))
	}
	return nil
}
