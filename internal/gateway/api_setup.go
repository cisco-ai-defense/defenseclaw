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
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"
)

// wizardSpec describes a CLI setup flow that the web UI is allowed to trigger.
//
// The list mirrors the eight TUI wizard buttons (Skill Scanner, MCP Scanner,
// Gateway, Guardrail, Splunk, Observability, Webhook, Sandbox). The web UI
// builds the same argv the TUI would build; the gateway shells the binary
// with --non-interactive appended.
//
// argvPrefix is the fixed prefix after the binary name, e.g. {"setup",
// "skill-scanner"} or {"sandbox", "setup"} (sandbox uses a different verb
// path). RequirePositional enforces that one positional arg follows the
// prefix; AllowedPositional, when non-empty, restricts the value to a
// known set (e.g. observability presets).
type wizardSpec struct {
	Name              string
	ArgvPrefix        []string
	RequirePositional bool
	AllowedPositional []string
	// SkipNonInteractive suppresses the `--non-interactive` flag the
	// runner otherwise appends. Set true for verbs that don't accept it
	// (e.g. `mcp set`, which is part of the `mcp` group, not `setup`).
	SkipNonInteractive bool
}

var wizardCatalog = map[string]wizardSpec{
	"skill-scanner": {
		Name:       "skill-scanner",
		ArgvPrefix: []string{"setup", "skill-scanner"},
	},
	"mcp-scanner": {
		Name:       "mcp-scanner",
		ArgvPrefix: []string{"setup", "mcp-scanner"},
	},
	"gateway": {
		Name:       "gateway",
		ArgvPrefix: []string{"setup", "gateway"},
	},
	"guardrail": {
		Name:       "guardrail",
		ArgvPrefix: []string{"setup", "guardrail"},
	},
	"splunk": {
		Name:       "splunk",
		ArgvPrefix: []string{"setup", "splunk"},
	},
	"observability": {
		Name:              "observability",
		ArgvPrefix:        []string{"setup", "observability", "add"},
		RequirePositional: true,
		AllowedPositional: []string{
			"splunk-o11y", "splunk-hec", "datadog", "honeycomb",
			"newrelic", "grafana-cloud", "local-otlp", "otlp", "webhook",
		},
	},
	"webhook": {
		Name:              "webhook",
		ArgvPrefix:        []string{"setup", "webhook", "add"},
		RequirePositional: true,
		AllowedPositional: []string{"slack", "pagerduty", "webex", "generic"},
	},
	"sandbox": {
		Name:       "sandbox",
		ArgvPrefix: []string{"sandbox", "setup"},
	},
	// `defenseclaw mcp set NAME [options]` — the canonical "register an
	// MCP server" verb. Positional is the server name. Flags: --command,
	// --args, --url, --transport, --env (repeatable), --skip-scan.
	// Lives outside the `setup` group, so the auto-restart hook never
	// fires; also doesn't accept --non-interactive.
	"mcp-set": {
		Name:               "mcp-set",
		ArgvPrefix:         []string{"mcp", "set"},
		RequirePositional:  true,
		SkipNonInteractive: true,
	},
}

// flagNameRE constrains flag keys to the standard CLI form so we never emit
// argv items that look like injected switches. Values can be arbitrary text
// (including paths, env-var names, JSON blobs) but we use the --flag=value
// form so a leading "-" in the value is interpreted as part of the value,
// not a new switch.
var flagNameRE = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

// handleV1SetupWizards lists the registered wizard catalog so the web UI
// can render its 8 cards without hard-coding the same list client-side.
func (a *APIServer) handleV1SetupWizards(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	type wizardOut struct {
		Name              string   `json:"name"`
		ArgvPrefix        []string `json:"argv_prefix"`
		RequirePositional bool     `json:"require_positional"`
		AllowedPositional []string `json:"allowed_positional,omitempty"`
	}
	out := make([]wizardOut, 0, len(wizardCatalog))
	for _, spec := range wizardCatalog {
		out = append(out, wizardOut{
			Name:              spec.Name,
			ArgvPrefix:        append([]string{}, spec.ArgvPrefix...),
			RequirePositional: spec.RequirePositional,
			AllowedPositional: append([]string{}, spec.AllowedPositional...),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	a.writeJSON(w, http.StatusOK, map[string]any{"wizards": out})
}

type setupRunRequest struct {
	Wizard     string            `json:"wizard"`
	Positional string            `json:"positional,omitempty"`
	Flags      map[string]string `json:"flags,omitempty"`
}

// handleV1SetupRun executes one of the allowlisted setup wizards as a
// `defenseclaw` subprocess and streams stdout/stderr to the client as
// newline-delimited JSON. Final event includes exit code.
//
// Wire format (response, Content-Type: application/x-ndjson):
//
//	{"event":"start","argv":["defenseclaw","setup","..."]}
//	{"event":"stdout","line":"..."}
//	{"event":"stderr","line":"..."}
//	{"event":"exit","code":0}
//
// Errors before the subprocess starts (validation, binary lookup) are
// returned as a single JSON object with HTTP 4xx/5xx status. Errors during
// the run are surfaced via the "stderr" stream and a non-zero "exit" code.
func (a *APIServer) handleV1SetupRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req setupRunRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}

	spec, ok := wizardCatalog[req.Wizard]
	if !ok {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "unknown wizard: " + req.Wizard,
		})
		return
	}

	argv, err := buildWizardArgv(spec, req)
	if err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	binary, err := exec.LookPath("defenseclaw")
	if err != nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "defenseclaw CLI not found on PATH; install with `make cli-install`",
		})
		return
	}

	// Past this point we commit to streaming: we must write a valid NDJSON
	// stream regardless of what happens, because the client has already been
	// told (via 200 OK + Content-Type) to expect one.
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "no-cache, no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)

	flusher, _ := w.(http.Flusher)
	emit := func(event map[string]any) {
		buf, err := json.Marshal(event)
		if err != nil {
			return
		}
		_, _ = w.Write(buf)
		_, _ = w.Write([]byte("\n"))
		if flusher != nil {
			flusher.Flush()
		}
	}

	fullArgv := append([]string{binary}, argv...)
	emit(map[string]any{"event": "start", "argv": fullArgv})

	ctx, cancel := r.Context(), func() {}
	if _, ok := ctx.Deadline(); !ok {
		// Wizard runs occasionally make outbound calls (provider verification,
		// Splunk endpoint test). Cap at 10 minutes to bound runaway processes
		// while leaving room for slow-but-legitimate flows.
		ctx, cancel = contextWithTimeout(ctx, 10*time.Minute)
	}
	defer cancel()

	cmd := exec.CommandContext(ctx, binary, argv...)

	// The CLI's setup result callback auto-restarts the gateway when
	// config.yaml mtime changes. Running from inside the gateway means
	// that restart would kill our own parent process mid-stream and abort
	// the run. The CLI honors this env var to skip the restart and emit a
	// "restart required" hint instead.
	cmd.Env = append(os.Environ(), "DEFENSECLAW_NO_AUTO_RESTART=1")

	stdoutPipe, _ := cmd.StdoutPipe()
	stderrPipe, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		emit(map[string]any{"event": "exit", "code": -1, "error": err.Error()})
		return
	}

	done := make(chan struct{}, 2)
	go pumpLines(stdoutPipe, "stdout", emit, done)
	go pumpLines(stderrPipe, "stderr", emit, done)
	<-done
	<-done

	exitCode := 0
	if err := cmd.Wait(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			exitCode = ee.ExitCode()
		} else {
			exitCode = -1
			emit(map[string]any{"event": "stderr", "line": "wait: " + err.Error()})
		}
	}
	emit(map[string]any{"event": "exit", "code": exitCode})

	if a.logger != nil {
		_ = a.logger.LogActionCtx(r.Context(), "api-setup-run", req.Wizard,
			fmt.Sprintf("ran %s exit=%d", strings.Join(argv, " "), exitCode))
	}
}

func buildWizardArgv(spec wizardSpec, req setupRunRequest) ([]string, error) {
	argv := append([]string{}, spec.ArgvPrefix...)

	if spec.RequirePositional {
		pos := strings.TrimSpace(req.Positional)
		if pos == "" {
			return nil, fmt.Errorf("wizard %q requires a positional argument", spec.Name)
		}
		if len(spec.AllowedPositional) > 0 && !contains(spec.AllowedPositional, pos) {
			return nil, fmt.Errorf("positional %q is not in the allowed set for %q", pos, spec.Name)
		}
		argv = append(argv, pos)
	} else if req.Positional != "" {
		return nil, fmt.Errorf("wizard %q does not accept a positional argument", spec.Name)
	}

	// Sort flag names for deterministic argv (helps audit log diffing and
	// makes test fixtures stable).
	keys := make([]string, 0, len(req.Flags))
	for k := range req.Flags {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		if !flagNameRE.MatchString(k) {
			return nil, fmt.Errorf("flag name %q is not in the form [a-z][a-z0-9-]*", k)
		}
		v := req.Flags[k]
		if strings.ContainsAny(v, "\n\r\x00") {
			return nil, fmt.Errorf("flag %q value contains newline or null byte", k)
		}
		// --flag=value form so a leading "-" in the value never reads as a
		// new switch.
		argv = append(argv, "--"+k+"="+v)
	}

	if !spec.SkipNonInteractive {
		argv = append(argv, "--non-interactive")
	}
	return argv, nil
}

func pumpLines(rc io.Reader, stream string, emit func(map[string]any), done chan<- struct{}) {
	defer func() { done <- struct{}{} }()
	br := bufio.NewReader(rc)
	for {
		line, err := br.ReadString('\n')
		if line != "" {
			emit(map[string]any{
				"event":  stream,
				"line":   strings.TrimRight(line, "\r\n"),
			})
		}
		if err != nil {
			return
		}
	}
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// contextWithTimeout is split out so test code can swap in a fake clock if
// needed; runtime delegates to the standard lib.
func contextWithTimeout(parent context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, d)
}
