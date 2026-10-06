// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// A gateway that fails to start during install or upgrade usually says why
// (for example a rule pack that does not load), but the rollback removes
// what the transaction created, including the log directory of a first
// install. The lifecycle therefore keeps the gateway's last output: a short
// excerpt goes into the lifecycle result, and the captured output is kept
// root-only in the lifecycle directory, which rollback does not remove.
const (
	activationFailureFileName = "last-activation-failure.log"
	gatewayOutputTailBytes    = 16 << 10
	gatewayExcerptLines       = 12
	gatewayExcerptLineBytes   = 300
)

func (e *Env) activationFailurePath() string {
	return filepath.Join(e.P(e.Layout.LifecycleDir), activationFailureFileName)
}

// gatewayErrorLogPath is where the macOS LaunchDaemon sends the gateway's
// standard error (packaging/launchd-standalone/com.cisco.defenseclaw.gateway.plist).
func (e *Env) gatewayErrorLogPath() string {
	return filepath.Join(e.Layout.LogDir, "gateway", "gateway.err.log")
}

// gatewayRecentOutput returns the tail of the gateway's own output: its
// systemd journal on Linux, its error log on macOS.
func (e *Env) gatewayRecentOutput(ctx context.Context, unit Unit) string {
	if e.GOOS == "linux" {
		result, err := e.Runner.Run(ctx, "journalctl", "--unit", unit.Name, "--lines", "40", "--no-pager", "--output", "cat")
		if err != nil {
			return ""
		}
		return tailString(string(result.Stdout), gatewayOutputTailBytes)
	}
	data, err := readLogTail(e.P(e.gatewayErrorLogPath()), gatewayOutputTailBytes)
	if err != nil {
		return ""
	}
	return string(data)
}

// readLogTail reads at most limit bytes from the end of a log file in a
// directory the service account owns. The lifecycle runs as root, so the
// file is opened without following a symlink (another account's link would
// copy a root-readable file into the result) and without blocking (a FIFO
// would hang the run while it holds the lifecycle lock), and only a regular
// file is read.
func readLogTail(path string, limit int64) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if info.Size() > limit {
		if _, err := file.Seek(info.Size()-limit, io.SeekStart); err != nil {
			return nil, err
		}
	}
	return io.ReadAll(io.LimitReader(file, limit))
}

func tailString(value string, limit int) string {
	if len(value) > limit {
		return value[len(value)-limit:]
	}
	return value
}

// gatewayOutputExcerpt keeps the last few printable lines, each bounded, for
// the lifecycle result.
func gatewayOutputExcerpt(output string) string {
	lines := []string{}
	for _, line := range strings.Split(output, "\n") {
		line = strings.Map(func(r rune) rune {
			if r == '\t' {
				return ' '
			}
			if r < 0x20 || r == 0x7f {
				return -1
			}
			return r
		}, line)
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if len(line) > gatewayExcerptLineBytes {
			line = line[:gatewayExcerptLineBytes] + "..."
		}
		lines = append(lines, line)
	}
	if len(lines) > gatewayExcerptLines {
		lines = lines[len(lines)-gatewayExcerptLines:]
	}
	return strings.Join(lines, " | ")
}

// configRefusal asks the installed gateway binary whether it accepts the
// installed config. `policy digest` builds the configuration the gateway
// builds at start, so its refusal (a custom rule pack whose files no longer
// match guardrail.custom_packs.<name>.digest, say) is why the gateway exits
// at start. It returns the refusal, or "" when the binary accepts the config
// or cannot be asked (an earlier release, an unreadable input).
func (l *lifecycle) configRefusal(ctx context.Context) string {
	out, err := l.env.runGatewayCLI(ctx, "policy", "digest", "--json")
	if err == nil {
		return ""
	}
	for _, line := range strings.Split(string(out.Stderr), "\n") {
		if reason, ok := strings.CutPrefix(strings.TrimSpace(line), "Error: policy digest: "); ok {
			return gatewayOutputExcerpt(reason)
		}
	}
	return ""
}

// configRefusedMessage says that the installed gateway refuses the config,
// why, and what fixes it. A repair applies the same config again, so the fix
// is a corrected config.
func (e *Env) configRefusedMessage(reason string) string {
	ensure := e.lifecycleCommand(ActionEnsure)
	return fmt.Sprintf("the installed gateway refuses the configuration: %s; correct that setting (in %s, or in the file passed to `%s --config`) and apply it with `%s`; repair applies the same configuration again and fails the same way",
		reason, e.Layout.ConfigPath, ensure, ensure)
}

// recordActivationFailure keeps the gateway's output across the rollback
// and returns a result excerpt ("" when the gateway printed nothing).
func (l *lifecycle) recordActivationFailure(ctx context.Context) string {
	env := l.env
	var unit *Unit
	for _, candidate := range env.Services.Units() {
		if candidate.Kind == "gateway" {
			candidate := candidate
			unit = &candidate
			break
		}
	}
	if unit == nil {
		return ""
	}
	output := env.gatewayRecentOutput(ctx, *unit)
	if strings.TrimSpace(output) == "" {
		return ""
	}
	if err := os.MkdirAll(env.P(env.Layout.LifecycleDir), 0o700); err == nil {
		_ = env.writeFileAtomic(env.activationFailurePath(), []byte(output), 0o600, rootOwner())
	}
	return gatewayOutputExcerpt(output)
}
