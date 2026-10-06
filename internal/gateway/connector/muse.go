// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

var MuseHooksPathOverride string

var museHookEvents = []string{
	"PreToolUse",
	"PostToolUse",
	"SessionStart",
	"SessionEnd",
}

var museBlockEvents = []string{
	"PreToolUse",
}

// NewMuseConnector integrates Meta's Muse Gadget SDK. Muse turns ESP32
// and Linux devices into AI-controlled gadgets that execute shell commands,
// read/write files, and tunnel network traffic. The connector intercepts
// link.invoke commands before execution on the gadget and posts them to
// DefenseClaw for policy evaluation.
//
// On Linux gadgets the connector runs as a systemd service alongside
// musegadget. On ESP32 devices the edge-connector C library is linked
// directly into the firmware and calls dclaw_evaluate() from the Muse
// Executor dispatch loop.
func NewMuseConnector() *hookOnlyConnector {
	return &hookOnlyConnector{
		name:        "muse",
		description: "Muse Gadget SDK command interception for ESP32 and Linux devices",
		apiPath:     "/api/v1/muse/hook",
		scriptName:  "muse-hook.sh",
		configPath:  museConfigPath,
		capability: func(opts SetupOpts) HookCapability {
			return HookCapability{
				CanBlock:           true,
				CanAskNative:       false,
				BlockEvents:        append([]string(nil), museBlockEvents...),
				SupportsFailClosed: true,
				Scope:              "user",
				ConfigPath:         museConfigPath(opts),
			}
		},
	}
}

func museConfigRoot(opts SetupOpts) string {
	return museConfigRootFor(runtime.GOOS, opts)
}

func museConfigRootFor(goos string, opts SetupOpts) string {
	if root := strings.TrimSpace(opts.ConfigHome); root != "" {
		return filepath.Clean(root)
	}
	if goos == "linux" {
		return "/etc/musegadget"
	}
	if goos == "darwin" {
		if root := strings.TrimSpace(os.Getenv("XDG_CONFIG_HOME")); filepath.IsAbs(root) {
			return filepath.Join(filepath.Clean(root), "musegadget")
		}
		return homePath(".config", "musegadget")
	}
	if root, err := os.UserConfigDir(); err == nil && strings.TrimSpace(root) != "" {
		return filepath.Join(filepath.Clean(root), "musegadget")
	}
	return homePath(".config", "musegadget")
}

func museConfigPath(opts SetupOpts) string {
	if MuseHooksPathOverride != "" {
		return MuseHooksPathOverride
	}
	return filepath.Join(museConfigRoot(opts), "hooks.json")
}

// MuseHooksConfigPath returns the Muse hook config file Setup writes for
// opts. Exported for operator-facing messages.
func MuseHooksConfigPath(opts SetupOpts) string { return museConfigPath(opts) }
