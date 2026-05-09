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
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Query endpoints — read-only views over audit, log, and inventory state
// that the dashboard polls. None of these mutate; all are GET.
//
// /v1/audit          — recent audit events (filter client-side for v1)
// /v1/audit/counts   — aggregate counters used on the Overview tiles
// /v1/logs           — tail of ~/.defenseclaw/gateway.log
// /v1/plugins        — registered plugins (read from PluginDir)

// handleV1Audit returns the most recent audit events. Optional ?limit=N
// (default 200, max 1000). Server returns the rows untouched so the client
// can apply the TUI's compound-filter syntax in-browser.
func (a *APIServer) handleV1Audit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.store == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "audit store not configured"})
		return
	}
	limit := 200
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 {
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "limit must be a positive integer"})
			return
		}
		limit = parsed
	}
	if limit > 1000 {
		limit = 1000
	}
	events, err := a.store.ListEvents(limit)
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]any{
		"events": events,
		"count":  len(events),
		"limit":  limit,
	})
}

// handleV1AuditCounts returns the aggregate counters that the Overview
// page renders as stat tiles. Wraps audit.Store.GetCounts() one-to-one,
// re-keyed to snake_case for the wire.
func (a *APIServer) handleV1AuditCounts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.store == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "audit store not configured"})
		return
	}
	c, err := a.store.GetCounts()
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]any{
		"blocked_skills":       c.BlockedSkills,
		"allowed_skills":       c.AllowedSkills,
		"blocked_mcps":         c.BlockedMCPs,
		"allowed_mcps":         c.AllowedMCPs,
		"alerts":               c.Alerts,
		"total_scans":          c.TotalScans,
		"blocked_egress_calls": c.BlockedEgressCalls,
	})
}

// handleV1Logs returns the last N lines of ~/.defenseclaw/gateway.log.
//
// gateway.log is a plain-text file (not JSONL); we tail it by seeking
// from the end and reading just enough bytes to satisfy the requested
// line count. For huge files (this one is ~150 MB on a long-running
// instance), this is roughly O(N) instead of O(filesize).
func (a *APIServer) handleV1Logs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.scannerCfg == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "config not loaded"})
		return
	}
	tail := 200
	if raw := r.URL.Query().Get("tail"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 {
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "tail must be a positive integer"})
			return
		}
		tail = parsed
	}
	if tail > 5000 {
		tail = 5000
	}

	a.cfgMu.RLock()
	logPath := filepath.Join(a.scannerCfg.DataDir, "gateway.log")
	a.cfgMu.RUnlock()

	lines, total, err := tailLogFile(logPath, tail)
	if err != nil {
		if os.IsNotExist(err) {
			a.writeJSON(w, http.StatusOK, map[string]any{
				"path":  logPath,
				"lines": []string{},
				"size":  0,
				"note":  "log file does not exist yet",
			})
			return
		}
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]any{
		"path":  logPath,
		"size":  total,
		"lines": lines,
	})
}

// tailLogFile reads the last n lines of the file at path. Uses a backwards
// chunk read so it stays cheap on large logs.
func tailLogFile(path string, n int) ([]string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil {
		return nil, 0, err
	}
	size := stat.Size()
	if size == 0 {
		return []string{}, 0, nil
	}

	// Initial chunk: 16 KB. If we don't have enough lines, grow up to ~2 MB.
	const chunkSize = 16 * 1024
	const maxRead = 2 * 1024 * 1024
	bufSize := int64(chunkSize)
	for {
		readFrom := size - bufSize
		if readFrom < 0 {
			readFrom = 0
			bufSize = size
		}
		buf := make([]byte, bufSize)
		if _, err := f.ReadAt(buf, readFrom); err != nil {
			return nil, 0, err
		}
		lines := strings.Split(string(buf), "\n")
		// If we read from the middle of a line, drop the partial first line.
		if readFrom > 0 && len(lines) > 0 {
			lines = lines[1:]
		}
		// Drop a trailing empty line caused by a final "\n".
		if len(lines) > 0 && lines[len(lines)-1] == "" {
			lines = lines[:len(lines)-1]
		}
		if len(lines) >= n || readFrom == 0 || bufSize >= int64(maxRead) {
			if len(lines) > n {
				lines = lines[len(lines)-n:]
			}
			return lines, size, nil
		}
		bufSize *= 2
	}
}

// handleV1Plugins lists plugin directories under PluginDir. v1 returns
// only names + paths; install/disable state and version are surfaced
// later when the watcher exposes a structured plugin registry.
func (a *APIServer) handleV1Plugins(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.scannerCfg == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "config not loaded"})
		return
	}
	a.cfgMu.RLock()
	dir := a.scannerCfg.PluginDir
	a.cfgMu.RUnlock()

	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			a.writeJSON(w, http.StatusOK, map[string]any{
				"plugins": []any{},
				"dir":     dir,
				"note":    "plugin dir does not exist yet",
			})
			return
		}
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	type plugin struct {
		Name      string `json:"name"`
		Path      string `json:"path"`
		HasManifest bool `json:"has_manifest"`
	}
	out := []plugin{}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if strings.HasPrefix(e.Name(), ".") {
			continue
		}
		fullPath := filepath.Join(dir, e.Name())
		_, manifestErr := os.Stat(filepath.Join(fullPath, "manifest.json"))
		out = append(out, plugin{
			Name:        e.Name(),
			Path:        fullPath,
			HasManifest: manifestErr == nil,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	a.writeJSON(w, http.StatusOK, map[string]any{
		"plugins": out,
		"dir":     dir,
		"count":   len(out),
	})
}

// (helper for json-tag-bearing structs is the standard library's
// json.Marshal — the audit.Event already has json tags, so it serializes
// directly; sliceToAny / yamlToMaps used elsewhere are not needed here.)

var _ = fmt.Sprintf // keep fmt usable for future error formatting

// handleV1InventoryAction is a placeholder for a unified action verb
// router (skill | mcp | plugin → scan / allow / block / quarantine /
// restore). It currently delegates to runAdminCommand for parity with the
// sink/webhook verbs, but the per-target argv shape varies enough that
// each kind likely needs its own typed handler. Wire this when the UI
// needs more than the existing /skill/{enable,disable} + /v1/{skill,mcp,
// plugin}/scan endpoints.

// handleV1SkillAction delegates {scan, allow, block, quarantine, restore,
// disable, enable} to the CLI for a named skill. The TUI does the same
// thing — every operator action shells the CLI so the audit trail lives
// in one place. Synchronous response with combined output.
func (a *APIServer) handleV1SkillAction(w http.ResponseWriter, r *http.Request) {
	allowed := []string{"scan", "allow", "block", "quarantine", "restore", "disable", "enable"}
	a.handleTargetAction(w, r, "skill", allowed)
}

// handleV1MCPAction delegates {scan, allow, block, quarantine, restore,
// disable, enable} for a named MCP server.
func (a *APIServer) handleV1MCPAction(w http.ResponseWriter, r *http.Request) {
	allowed := []string{"scan", "allow", "block", "quarantine", "restore", "disable", "enable"}
	a.handleTargetAction(w, r, "mcp", allowed)
}

// handleV1PluginAction delegates {scan, install, disable, enable} for a
// named plugin.
func (a *APIServer) handleV1PluginAction(w http.ResponseWriter, r *http.Request) {
	allowed := []string{"scan", "install", "disable", "enable"}
	a.handleTargetAction(w, r, "plugin", allowed)
}

func (a *APIServer) handleTargetAction(w http.ResponseWriter, r *http.Request, kind string, allowed []string) {
	name := r.PathValue("name")
	action := r.PathValue("action")
	if !contains(allowed, action) {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": fmt.Sprintf("unknown %s action %q (allowed: %v)", kind, action, allowed),
		})
		return
	}
	if name == "" {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": kind + " name required"})
		return
	}
	// Argv: defenseclaw <kind> <action> <name> --non-interactive
	a.runAdminCommand(w, r, kind+"-action", kind, action, name)
}

// --- silence unused import linters when build tags strip features ---
var _ = json.Marshal
