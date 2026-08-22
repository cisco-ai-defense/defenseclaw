// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package connector

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

var (
	protectedDarwinCodexVersionRE = regexp.MustCompile(
		`(?i)^(?:codex(?:-cli)?[[:space:]]+)?v?([0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z][0-9A-Za-z.-]*)?(?:\+[0-9A-Za-z][0-9A-Za-z.-]*)?)$`,
	)
	protectedDarwinClaudeVersionRE = regexp.MustCompile(
		`(?i)^(?:claude(?:[[:space:]]+code)?[[:space:]]+)?v?([0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z][0-9A-Za-z.-]*)?(?:\+[0-9A-Za-z][0-9A-Za-z.-]*)?)(?:[[:space:]]+\(claude[[:space:]]+code\))?$`,
	)
)

const (
	protectedDarwinVersionProbeTimeout     = 10 * time.Second
	protectedDarwinVersionProbeWaitDelay   = 2 * time.Second
	protectedDarwinVersionProbeOutputLimit = 32 << 10
)

type protectedDarwinVersionProbeBuffer struct {
	bytes.Buffer
	limit int
}

func (buffer *protectedDarwinVersionProbeBuffer) Write(data []byte) (int, error) {
	remaining := buffer.limit - buffer.Len()
	if remaining <= 0 {
		return 0, fmt.Errorf("version probe output exceeds %d bytes", buffer.limit)
	}
	if len(data) > remaining {
		written, _ := buffer.Buffer.Write(data[:remaining])
		return written, fmt.Errorf("version probe output exceeds %d bytes", buffer.limit)
	}
	return buffer.Buffer.Write(data)
}

// runProtectedDarwinAgentVersionProbe executes only an executable that its
// connector-specific caller has already admitted by custody, native
// architecture, quarantine, and pinned vendor signature. It deliberately
// inherits neither the privileged guardian's recoverable identity nor the
// caller's environment or working directory.
func runProtectedDarwinAgentVersionProbe(connectorName, path, expectedDigest string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), protectedDarwinVersionProbeTimeout)
	defer cancel()
	command := exec.CommandContext(ctx, path, "--version")
	command.WaitDelay = protectedDarwinVersionProbeWaitDelay
	command.Dir = "/"
	command.Env = []string{
		"HOME=/var/empty",
		"LANG=C",
		"LC_ALL=C",
		"NO_COLOR=1",
		"PATH=/usr/bin:/bin",
		"TMPDIR=/tmp",
		"XDG_CACHE_HOME=/var/empty",
		"XDG_CONFIG_HOME=/var/empty",
		"XDG_DATA_HOME=/var/empty",
	}
	stdout := &protectedDarwinVersionProbeBuffer{limit: protectedDarwinVersionProbeOutputLimit}
	stderr := &protectedDarwinVersionProbeBuffer{limit: protectedDarwinVersionProbeOutputLimit}
	command.Stdout = stdout
	command.Stderr = stderr
	if err := startProtectedDarwinAgentCommand(command, connectorName, expectedDigest); err != nil {
		return "", fmt.Errorf("start version probe: %w", err)
	}
	if err := command.Wait(); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return "", fmt.Errorf("version probe timed out after %s", protectedDarwinVersionProbeTimeout)
		}
		return "", fmt.Errorf("version probe exited unsuccessfully: %w", err)
	}
	raw := strings.TrimSpace(stdout.String())
	if raw == "" {
		raw = strings.TrimSpace(stderr.String())
	}
	if raw == "" || strings.ContainsAny(raw, "\x00\r\n") {
		return "", errors.New("version probe returned empty or multiline output")
	}
	return raw, nil
}

func validateProtectedDarwinAgentVersion(connectorName, expectedRaw, probedRaw string) error {
	expectedToken := protectedDarwinExactVersionToken(connectorName, expectedRaw)
	probedToken := protectedDarwinExactVersionToken(connectorName, probedRaw)
	expected := ResolveHookContract(connectorName, expectedRaw)
	probed := ResolveHookContract(connectorName, probedRaw)
	if expectedToken == "" || probedToken == "" || expectedToken != probedToken ||
		expected.Status != HookCompatibilityKnown || probed.Status != HookCompatibilityKnown ||
		expected.NormalizedVersion == "" || probed.NormalizedVersion != expected.NormalizedVersion ||
		expected.Contract.ContractID == "" || probed.Contract.ContractID != expected.Contract.ContractID {
		return fmt.Errorf(
			"selected %s executable reports version %q, which does not match protected version %q",
			connectorName,
			probed.RawVersion,
			expected.RawVersion,
		)
	}
	return nil
}

func protectedDarwinExactVersionToken(connectorName, raw string) string {
	var expression *regexp.Regexp
	switch normalizeConnectorName(connectorName) {
	case "codex":
		expression = protectedDarwinCodexVersionRE
	case "claudecode":
		expression = protectedDarwinClaudeVersionRE
	default:
		return ""
	}
	match := expression.FindStringSubmatch(strings.TrimSpace(raw))
	if len(match) != 2 {
		return ""
	}
	return match[1]
}
