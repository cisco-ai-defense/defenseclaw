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
	"regexp"
	"strings"
	"syscall"
	"unicode/utf8"
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

// gatewayBannerRow matches the indented rows of the gateway's start banner
// (runSidecar in internal/cli/sidecar.go).
var gatewayBannerRow = regexp.MustCompile(`^ {2,}(Gateway|Auto-approve|Auth|API port|Watcher|Guardrail|Skill|Skill dirs|Model|API key|Judge):\s`)

// isGatewayBannerLine reports whether a line of the gateway's output belongs
// to its start banner: the box and its settings rows. The banner says nothing
// about why the gateway failed to start, and an older gateway prints its
// token there masked to the first and last characters. That belongs in
// neither the lifecycle result, which the package manager copies into its own
// log, nor the kept output.
func isGatewayBannerLine(line string) bool {
	trimmed := strings.TrimSpace(line)
	if r, _ := utf8.DecodeRuneInString(trimmed); r >= 0x2500 && r <= 0x257f {
		return true
	}
	return gatewayBannerRow.MatchString(line)
}

// withoutGatewayBanner returns the gateway's output without its start banner.
func withoutGatewayBanner(output string) string {
	lines := strings.Split(output, "\n")
	kept := lines[:0]
	for _, line := range lines {
		if !isGatewayBannerLine(line) {
			kept = append(kept, line)
		}
	}
	return strings.Join(kept, "\n")
}

// gatewayOutputExcerpt keeps the last few distinct printable lines, each
// bounded, for the lifecycle result. A gateway that systemd restarts prints
// the same error on every attempt; it is listed once.
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
	distinct := make([]string, 0, gatewayExcerptLines)
	seen := map[string]bool{}
	for i := len(lines) - 1; i >= 0 && len(distinct) < gatewayExcerptLines; i-- {
		if !seen[lines[i]] {
			seen[lines[i]] = true
			distinct = append(distinct, lines[i])
		}
	}
	for i, j := 0, len(distinct)-1; i < j; i, j = i+1, j-1 {
		distinct[i], distinct[j] = distinct[j], distinct[i]
	}
	return strings.Join(distinct, " | ")
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
	output := withoutGatewayBanner(env.gatewayRecentOutput(ctx, *unit))
	if strings.TrimSpace(output) == "" {
		return ""
	}
	if err := os.MkdirAll(env.P(env.Layout.LifecycleDir), 0o700); err == nil {
		_ = env.writeFileAtomic(env.activationFailurePath(), []byte(output), 0o600, rootOwner())
	}
	if env.GOOS == "linux" {
		return gatewayOutputExcerpt(lastStartAttempt(output))
	}
	return gatewayOutputExcerpt(output)
}

// lastStartAttempt keeps the journal lines of the last start attempt that
// say why it failed: the gateway Error line and the systemd lines about the
// failure. The journal tail also holds the previous gateway instance (its
// reload errors, the stop, its CPU accounting), which buried the cause in a
// 2 KB result line (GAP-0175). The kept output file keeps everything.
func lastStartAttempt(output string) string {
	lines := strings.Split(output, "\n")
	start := 0
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "Starting ") {
			start = i + 1
		}
	}
	window := lines[start:]
	kept := []string{}
	for _, line := range window {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "Error:") || strings.HasPrefix(trimmed, "Failed to start") ||
			strings.Contains(trimmed, "Main process exited") || strings.Contains(trimmed, "Failed with result") {
			kept = append(kept, line)
		}
	}
	if len(kept) == 0 {
		return strings.Join(window, "\n")
	}
	return strings.Join(kept, "\n")
}
