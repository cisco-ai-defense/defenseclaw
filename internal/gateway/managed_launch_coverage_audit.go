// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

var managedLaunchReasons = map[string]map[string]bool{
	"opencode": {"opencode_pure": true, "opencode_managed_config_relocated": true,
		"opencode_user_config_relocated": true,
		"launch_arguments_unverified":    true, "launch_environment_unverified": true,
		// An OpenCode V1 copy, which cannot run the V2 plugin (rel-1-0-6
		// GAP-0037, GAP-0057).
		"unsupported_installed_version": true, "installed_version_unverified": true},
	"amp": {"amp_plugin_config_relocated": true, "launch_arguments_unverified": true,
		"launch_environment_unverified": true},
	"kiro": {"kiro_hook_config_relocated": true, "kiro_alternate_agent": true,
		"kiro_cloud_session": true, "kiro_resume_placement_unverified": true, "launch_arguments_unverified": true,
		"launch_environment_unverified": true},
	"devin": {"devin_config_override": true, "user_config_relocated": true,
		"launch_arguments_unverified": true, "launch_environment_unverified": true},
	"hermes": {"hermes_safe_mode": true, "hermes_config_relocated": true,
		"user_config_relocated": true, "launch_arguments_unverified": true,
		"launch_environment_unverified": true, "session_only_hermes_home_unobservable": true,
		// An installed Hermes the enumerator could not enroll (GAP-1420).
		"unsupported_installed_version": true, "installed_version_unverified": true},
	"antigravity": {"user_config_relocated": true, "launch_arguments_unverified": true,
		"launch_environment_unverified": true},
	"claudecode": {"unsupported_installed_version": true, "installed_version_unverified": true,
		"claude_npm_launch_unverified": true, "claude_version_unverified": true,
		"launch_arguments_unverified": true},
	"codex":   {"unsupported_installed_version": true, "installed_version_unverified": true},
	"copilot": {"unsupported_installed_version": true, "installed_version_unverified": true},
}

// The root lifecycle reports what it saw in the OS process table. The
// skipped plugin can emit neither a tool event nor a load heartbeat itself.
func (a *APIServer) handleManagedLaunchCoverageAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	peer, ok := managedHookPeerFromContext(r.Context())
	if !ok || peer.UID != 0 {
		writeManagedHookRefusal(w, http.StatusForbidden, managedHookReasonGuardianOnly)
		return
	}
	if a.logger == nil {
		http.Error(w, "audit unavailable", http.StatusServiceUnavailable)
		return
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
	decoder.DisallowUnknownFields()
	var report managed.LaunchCoverageReport
	var extra any
	if decoder.Decode(&report) != nil || decoder.Decode(&extra) != io.EOF ||
		report.UID < 0 || uint64(report.UID) > uint64(^uint32(0)) ||
		!managedLaunchReasons[report.Connector][report.Reason] {
		http.Error(w, "invalid launch coverage report", http.StatusBadRequest)
		return
	}
	install := report.Reason == "unsupported_installed_version" || report.Reason == "installed_version_unverified"
	sessionHome := report.Connector == "hermes" && report.Reason == "session_only_hermes_home_unobservable"
	if sessionHome {
		if report.UID != 0 || report.PID != 0 || report.StartedAt != "" || report.InstallPath != "" || report.Version != "" {
			http.Error(w, "invalid Hermes coverage report", http.StatusBadRequest)
			return
		}
	} else if install {
		if report.PID != 0 || report.StartedAt != "" || !filepath.IsAbs(report.InstallPath) ||
			len(report.InstallPath) > 512 || strings.ContainsAny(report.InstallPath, "\x00\r\n") || len(report.Version) > 128 {
			http.Error(w, "invalid install coverage report", http.StatusBadRequest)
			return
		}
	} else {
		started, err := time.Parse(time.RFC3339Nano, report.StartedAt)
		if report.PID <= 0 || err != nil || started.IsZero() || report.InstallPath != "" || report.Version != "" {
			http.Error(w, "invalid process start", http.StatusBadRequest)
			return
		}
	}
	details := map[string]any{"connector": report.Connector, "coverage_reason": report.Reason,
		"coverage_state": "incomplete", "actor_id_kind": string(useridentity.KindPOSIXUID),
		"actor_id": report.UID}
	source, summary := "managed-launch-coverage", "managed_launch_uninspected"
	if sessionHome {
		source, summary = "managed-install-coverage", "managed_hermes_session_home_not_covered"
	} else if install {
		details["agent_install_path"] = report.InstallPath
		details["agent_version"] = report.Version
		source, summary = "managed-install-coverage", "managed_agent_install_unprotected"
	} else {
		details["process_pid"] = report.PID
		details["process_started_at"] = report.StartedAt
	}
	if err := a.logger.LogAlert(source, "HIGH", summary, details); err != nil {
		http.Error(w, "audit emission failed", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
