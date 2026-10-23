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

import "github.com/defenseclaw/defenseclaw/internal/config"

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
//   - guardrail.connector and the connector roster are empty, so "openclaw"
//     comes only from claw.mode (init's default, and the
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
	return cfg.OpenClawImpliedButNotInstalled()
}
