// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"time"

	"gopkg.in/yaml.v3"
)

// Admin endpoints for sink and webhook list / actions.
//
// Reads come straight from the in-memory config. Mutations delegate to the
// CLI (`defenseclaw setup observability {enable|disable|remove|test} <name>`
// and the matching webhook verbs) so the wire format and audit trail match
// every other operator path.

var (
	sinkActions    = []string{"enable", "disable", "remove", "test", "migrate-splunk"}
	webhookActions = []string{"enable", "disable", "remove", "test"}
)

// handleListSinks returns the configured audit sinks as JSON. The shape
// matches the on-disk YAML keys (snake_case) via a yaml→map round-trip,
// since the Config struct only carries yaml tags.
func (a *APIServer) handleListSinks(w http.ResponseWriter, _ *http.Request) {
	if a.scannerCfg == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "config not loaded"})
		return
	}
	a.cfgMu.RLock()
	sinks := append([]any{}, sliceToAny(a.scannerCfg.AuditSinks)...)
	a.cfgMu.RUnlock()

	payload, err := yamlToMaps(sinks)
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "marshal: " + err.Error()})
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"sinks": payload})
}

func (a *APIServer) handleListWebhooks(w http.ResponseWriter, _ *http.Request) {
	if a.scannerCfg == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "config not loaded"})
		return
	}
	a.cfgMu.RLock()
	hooks := append([]any{}, sliceToAny(a.scannerCfg.Webhooks)...)
	a.cfgMu.RUnlock()

	payload, err := yamlToMaps(hooks)
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "marshal: " + err.Error()})
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"webhooks": payload})
}

// handleSinkAction shells `defenseclaw setup observability <action> <name>`
// synchronously and returns a single-shot {ok, exit_code, output} JSON.
//
// Synchronous (not streamed) because these are short admin verbs — the
// client gets a clean status without having to wire a stream parser.
// `test` may take a few seconds (network round-trip), so the timeout is
// 60 seconds.
func (a *APIServer) handleSinkAction(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	action := r.PathValue("action")
	if !contains(sinkActions, action) {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": fmt.Sprintf("unknown sink action %q (allowed: %v)", action, sinkActions),
		})
		return
	}
	if name == "" {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "sink name required"})
		return
	}
	// migrate-splunk is the one verb that does not address an existing sink
	// by name; it converts the legacy `splunk:` block. Skip the existence
	// check for it.
	if action != "migrate-splunk" && !sinkExists(a, name) {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "no sink named: " + name})
		return
	}
	a.runAdminCommand(w, r, "sink-action", "setup", "observability", action, name)
}

func (a *APIServer) handleWebhookAction(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	action := r.PathValue("action")
	if !contains(webhookActions, action) {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": fmt.Sprintf("unknown webhook action %q (allowed: %v)", action, webhookActions),
		})
		return
	}
	if name == "" {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "webhook name required"})
		return
	}
	if !webhookExists(a, name) {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "no webhook named: " + name})
		return
	}
	a.runAdminCommand(w, r, "webhook-action", "setup", "webhook", action, name)
}

// runAdminCommand shells `defenseclaw <args...> --non-interactive`, captures
// combined stdout+stderr, and returns a JSON summary. Used by sink/webhook
// action verbs that are short-lived enough to not need streaming.
func (a *APIServer) runAdminCommand(w http.ResponseWriter, r *http.Request, auditAction string, args ...string) {
	binary, err := exec.LookPath("defenseclaw")
	if err != nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "defenseclaw CLI not found on PATH",
		})
		return
	}

	args = append(args, "--non-interactive")
	ctx, cancel := contextWithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, binary, args...)
	// Same self-immolation guard as /v1/setup/run — the sink/webhook
	// admin verbs also mutate config.yaml and would trigger the CLI's
	// auto-restart hook against our own parent process.
	cmd.Env = append(os.Environ(), "DEFENSECLAW_NO_AUTO_RESTART=1")
	out, err := cmd.CombinedOutput()
	exitCode := 0
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			exitCode = ee.ExitCode()
		} else {
			exitCode = -1
		}
	}

	if a.logger != nil {
		_ = a.logger.LogActionCtx(r.Context(), "api-"+auditAction, args[len(args)-2],
			fmt.Sprintf("ran %s exit=%d", join(args), exitCode))
	}

	a.writeJSON(w, http.StatusOK, map[string]any{
		"ok":        exitCode == 0,
		"exit_code": exitCode,
		"argv":      append([]string{binary}, args...),
		"output":    string(out),
	})
}

// --- helpers ---

func sinkExists(a *APIServer, name string) bool {
	a.cfgMu.RLock()
	defer a.cfgMu.RUnlock()
	for _, s := range a.scannerCfg.AuditSinks {
		if s.Name == name {
			return true
		}
	}
	return false
}

func webhookExists(a *APIServer, name string) bool {
	a.cfgMu.RLock()
	defer a.cfgMu.RUnlock()
	for _, hook := range a.scannerCfg.Webhooks {
		if hook.Name == name {
			return true
		}
	}
	return false
}

// sliceToAny boxes a typed slice into []any so we can hand it to a generic
// yaml marshal step. yaml.Marshal handles concrete slice types fine, but
// going through []any makes the round-trip downstream uniform.
func sliceToAny[T any](xs []T) []any {
	out := make([]any, 0, len(xs))
	for _, x := range xs {
		out = append(out, x)
	}
	return out
}

// yamlToMaps marshals a value to YAML and unmarshals back into a generic
// map/slice tree so JSON output reads with snake_case keys. This is the
// same trick handleConfigGet uses for the full Config.
func yamlToMaps(v any) (any, error) {
	raw, err := yaml.Marshal(v)
	if err != nil {
		return nil, err
	}
	var out any
	if err := yaml.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func join(xs []string) string {
	out := ""
	for i, s := range xs {
		if i > 0 {
			out += " "
		}
		out += s
	}
	return out
}
