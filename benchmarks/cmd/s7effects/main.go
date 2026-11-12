// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

// Command s7effects runs the pure effect extractor (internal/effects) over a
// System One corpus in shadow mode and reports: the share of tool calls whose
// effects are fully known, a histogram of unknown reasons, a per-platform /
// dialect breakdown, and -- for the phase-1 miss/alert-only case ids -- whether
// the effects now expose a harmful effect shape (sensitive read + egress,
// write/fetch + exec, delete/overwrite of a sensitive path, world-writable).
// It boots no gateway and changes no verdict; it only measures the projection.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/effects"
)

type event struct {
	ToolName string          `json:"tool_name"`
	Args     json.RawMessage `json:"args"`
	Command  string          `json:"command"`
	CWD      string          `json:"cwd"`
	Dialect  string          `json:"dialect"`
}

type payload struct {
	event
	Events []event `json:"events"`
}

type corpusCase struct {
	ID      string  `json:"id"`
	Payload payload `json:"payload"`
	Strata  struct {
		Platform string `json:"platform"`
		Dialect  string `json:"dialect"`
	} `json:"strata"`
	Truth struct {
		SourceTruth         string `json:"source_truth"`
		ExpectedDisposition string `json:"expected_disposition"`
	} `json:"truth"`
}

type missRow struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
}

func main() {
	casesPath := flag.String("cases", "", "corpus jsonl")
	missPath := flag.String("miss-ids", "", "optional phase-1 miss id jsonl")
	label := flag.String("label", "run", "label for the report")
	flag.Parse()
	if *casesPath == "" {
		fmt.Fprintln(os.Stderr, "usage: s7effects -cases cases.jsonl [-miss-ids m.jsonl] [-label L]")
		os.Exit(2)
	}

	missKind := map[string]string{}
	if *missPath != "" {
		f, err := os.Open(*missPath)
		if err == nil {
			sc := bufio.NewScanner(f)
			sc.Buffer(make([]byte, 1<<20), 1<<20)
			for sc.Scan() {
				var m missRow
				if json.Unmarshal(sc.Bytes(), &m) == nil && m.ID != "" {
					missKind[m.ID] = m.Kind
				}
			}
			f.Close()
		}
	}

	rep := newReport()
	f, err := os.Open(*casesPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 8<<20)
	for sc.Scan() {
		var c corpusCase
		if json.Unmarshal(sc.Bytes(), &c) != nil {
			continue
		}
		evs := c.Payload.Events
		if len(evs) == 0 {
			evs = []event{c.Payload.event}
		}
		var caseEffects []effects.Effect
		for _, ev := range evs {
			call, opts := mapEvent(ev, c.Strata.Platform)
			if call.Surface == "" {
				continue
			}
			r := effects.Extract(call, opts)
			rep.observe(c, r)
			caseEffects = append(caseEffects, r.Effects...)
		}
		if kind, ok := missKind[c.ID]; ok {
			rep.observeMiss(kind, caseEffects)
		}
	}
	rep.print(*label)
}

// mapEvent builds a Call and Options from one corpus event.
func mapEvent(ev event, platform string) (effects.Call, effects.Options) {
	flavor := effects.FlavorPOSIX
	if strings.EqualFold(platform, "windows") {
		flavor = effects.FlavorWindows
	}
	opts := effects.Options{Flavor: flavor, Home: homeFor(flavor), CWD: cwdFor(ev.CWD, flavor),
		CaseInsensitive: flavor == effects.FlavorWindows}
	switch ev.Dialect {
	case "powershell":
		opts.Dialect = effects.DialectPowerShell
	case "cmd":
		opts.Dialect = effects.DialectCMD
	case "posix":
		opts.Dialect = effects.DialectPOSIX
	}

	cmd := ev.Command
	if cmd == "" {
		cmd = firstStr(ev.Args, "command", "cmd", "script", "code", "input", "keystrokes")
	}
	tool := strings.TrimSpace(ev.ToolName)
	lt := strings.ToLower(tool)
	if cmd != "" && !isFileToolName(lt) && lt != "apply_patch" {
		return effects.Call{Surface: effects.SurfaceShell, Tool: tool, Command: cmd}, opts
	}
	call := effects.Normalize("", tool, ev.Args)
	// A bash_command/keystrokes event with no recognized tool still parses as shell.
	if call.Surface == effects.SurfaceMCP && cmd != "" {
		return effects.Call{Surface: effects.SurfaceShell, Tool: tool, Command: cmd}, opts
	}
	if call.Surface == effects.SurfaceShell && call.Command == "" {
		call.Command = cmd
	}
	return call, opts
}

func isFileToolName(t string) bool {
	switch t {
	case "write", "edit", "multiedit", "read", "view", "create", "create_file", "write_file",
		"str_replace", "notebookedit", "edit_file", "read_file", "fs_write", "fs_read":
		return true
	}
	return false
}

func homeFor(f effects.Flavor) string {
	if f == effects.FlavorWindows {
		return `C:\Users\bench`
	}
	return "/home/bench"
}

func cwdFor(cwd string, f effects.Flavor) string {
	if cwd != "" {
		return cwd
	}
	if f == effects.FlavorWindows {
		return `C:\Users\bench\work`
	}
	return "/home/bench/work"
}

func firstStr(raw json.RawMessage, keys ...string) string {
	if len(raw) == 0 {
		return ""
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return ""
	}
	for _, k := range keys {
		if v, ok := m[k]; ok {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}
