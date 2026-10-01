// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// The Gateway subsystem publishes these when the OpenClaw fleet uplink is off
// because OpenClaw is not installed (see openClawImpliedButNotInstalled). The
// Python CLI mirrors the reason and summary in openclaw_presence.py; doctor,
// the TUI and the macOS app show the summary and hint as they are.
const (
	fleetOffReasonOpenClawNotInstalled  = "openclaw_not_installed"
	fleetOffSummaryOpenClawNotInstalled = "OpenClaw gateway off (OpenClaw is not installed)"
	fleetOffHintOpenClawNotInstalled    = "hooks and the local audit continue; to use OpenClaw, install it and restart the gateway, or set gateway.fleet_mode: enabled"
)

// openClawImpliedButNotInstalled reports the one case where the OpenClaw
// connector is only implied and nothing on this machine could answer the dial:
//
//   - gateway.fleet_mode is unset ("" or the loader default "auto"; any other
//     value, typos included, keeps the connector + host derivation),
//   - gateway.host is loopback,
//   - guardrail.connector is empty and guardrail.connectors has no openclaw
//     entry, so "openclaw" comes only from claw.mode (init's default, and the
//     loader default when config.yaml has no claw block), and
//   - no openclaw.json exists at claw.config_file or claw.home_dir, and no
//     openclaw binary is found.
//
// Sandbox-only and hook-only installs that never set a connector hit exactly
// this, and without the check the fleet client retried 127.0.0.1:18789 for
// the life of the process. An installed or configured OpenClaw, an explicit
// openclaw connector, a non-loopback host and an explicit fleet_mode all keep
// the previous behaviour. The configuration checks run first so the
// filesystem is only consulted in the narrow case.
func openClawImpliedButNotInstalled(cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(cfg.Gateway.FleetMode)) {
	case "", "auto":
	default:
		return false
	}
	if !isLoopbackGatewayHost(cfg.Gateway.Host) {
		return false
	}
	if strings.TrimSpace(cfg.Guardrail.Connector) != "" {
		return false
	}
	for name := range cfg.Guardrail.Connectors {
		if strings.EqualFold(strings.TrimSpace(name), "openclaw") {
			return false
		}
	}
	if !strings.EqualFold(strings.TrimSpace(string(cfg.Claw.Mode)), "openclaw") {
		return false
	}
	return !openClawConfigPresent(cfg) && !openClawBinaryInstalled()
}

// openClawConfigPresent reports whether any openclaw.json candidate exists.
// A stat error other than "does not exist" (for example a permission error)
// counts as present, so an unreadable OpenClaw home keeps the dial loop.
func openClawConfigPresent(cfg *config.Config) bool {
	for _, path := range cfg.OpenClawConfigCandidates() {
		if _, err := os.Stat(path); err == nil || !errors.Is(err, fs.ErrNotExist) {
			return true
		}
	}
	return false
}

// openClawBinaryInstalled reports whether an openclaw executable is on PATH or
// in one of the npm/Homebrew locations a daemon started without the login
// shell's PATH would miss. Mirrors openclaw_presence.openclaw_binary_installed
// in the Python CLI. A variable so tests do not depend on the host's PATH.
var openClawBinaryInstalled = func() bool {
	if _, err := exec.LookPath("openclaw"); err == nil {
		return true
	}
	for _, path := range openClawBinaryFallbacks() {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return true
		}
	}
	return false
}

func openClawBinaryFallbacks() []string {
	paths := []string{"/usr/local/bin/openclaw", "/opt/homebrew/bin/openclaw"}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		paths = append(paths,
			filepath.Join(home, ".npm-global", "bin", "openclaw"),
			filepath.Join(home, ".local", "bin", "openclaw"),
		)
	}
	return paths
}
