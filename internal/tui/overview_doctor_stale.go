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

package tui

import "strings"

// liveHealthContradicts reports whether a cached doctor check claims a
// subsystem is broken while the current /health snapshot says that
// same subsystem is running.
//
// Why: the doctor cache lives on disk and only refreshes when the user
// presses [d]. Once they bring the sidecar / guardrail back up the
// next session the dashboard pulls live /health (every few seconds)
// but the doctor cache may still be a day old, so the user sees a
// red "[FAIL] Sidecar API" right next to a green "Sidecar API
// RUNNING" row in the SERVICES box. That's the screenshot they sent
// us asking "why is it showing not working but status shows working".
//
// We don't try to be clever about every probe — only the small set
// the live /health response actually covers. The match is by check
// label (the strings emitted by cli/defenseclaw/commands/cmd_doctor.py
// _emit() calls); we intentionally use containment rather than exact
// equality so future detail-suffix tweaks in cmd_doctor don't quietly
// break the suppression.
func liveHealthContradicts(check DoctorCheck, h *HealthSnapshot) bool {
	if h == nil {
		return false
	}
	if check.Status != "fail" && check.Status != "warn" {
		return false
	}
	label := strings.ToLower(strings.TrimSpace(check.Label))

	// "Sidecar API" — REST API server on the gateway.
	// cmd_doctor's pass-path: _emit("pass", "Sidecar API", "host:port", …)
	if label == "sidecar api" {
		return strings.EqualFold(h.API.State, "running")
	}
	// "Guardrail proxy" — built-in HTTP reverse proxy at :4000.
	// cmd_doctor's pass-path: _emit("pass", "Guardrail proxy", "healthy on port N", …)
	if label == "guardrail proxy" {
		return strings.EqualFold(h.Guardrail.State, "running")
	}
	// "OpenClaw gateway" / "Gateway" — the sidecar gateway loop.
	if label == "openclaw gateway" || label == "gateway" {
		return strings.EqualFold(h.Gateway.State, "running")
	}
	// OTel checks: when the gateway thinks telemetry is healthy
	// (running) we suppress stale "no endpoint configured" / "OTLP"
	// failures so the user isn't told something is broken when
	// /health disagrees. When telemetry is off in /health too, we
	// preserve the failure — that's the agreed-on "you don't have
	// telemetry" signal.
	if strings.HasPrefix(label, "otel") {
		return strings.EqualFold(h.Telemetry.State, "running")
	}
	return false
}

// partitionDoctorChecks splits a slice of cached checks into "still
// believable" (no contradicting live data) and "contradicted by live
// health". Renderers use the contradicted set to render a dim
// "[STALE]" badge instead of "[FAIL]" and to subtract from the red
// fail count so the summary line ("3 fail") doesn't lie when the
// world has actually recovered.
func partitionDoctorChecks(checks []DoctorCheck, h *HealthSnapshot) (live, stale []DoctorCheck) {
	for _, ck := range checks {
		if liveHealthContradicts(ck, h) {
			stale = append(stale, ck)
		} else {
			live = append(live, ck)
		}
	}
	return live, stale
}
