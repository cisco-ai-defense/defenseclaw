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

package sandboxcli

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// DiscoverOptions are `sandbox discover`'s.
type DiscoverOptions struct {
	Name   string
	Output OutputFormat
}

// Discover runs the AI discovery of a ready sandbox now and prints what it
// found: the MCP servers, skills, plugins, CLIs, packages and agents the
// sandbox holds. The gateway's AI inventory (`defenseclaw agent usage
// --sandbox NAME`) takes it in on its next scan.
func (a *App) Discover(ctx context.Context, o DiscoverOptions) error {
	api, err := a.api()
	if err != nil {
		return err
	}
	res, err := api.Discover(ctx, o.Name)
	if err != nil {
		return apiError(err)
	}
	if o.Output == OutputJSON {
		return writeJSON(a.IO.Out, res)
	}
	if len(res.Signals) == 0 {
		a.note(fmt.Sprintf("no AI components found in sandbox %s (%d entries read)", res.Name, res.Entries))
	} else {
		rows := make([][]string, 0, len(res.Signals))
		for _, sig := range res.Signals {
			rows = append(rows, []string{sig.Category, firstNonEmpty(sig.Product, "-"), sig.Detector, discoveryNames(sig.Names),
				discoveryNames(sig.Evidence)})
		}
		a.table([]string{"CATEGORY", "PRODUCT", "FOUND BY", "NAMES", "EVIDENCE"}, rows)
	}
	if res.Result != "ok" {
		a.warn("the scan was partial: " + strings.Join(res.Problems, "; "))
	}
	a.note(fmt.Sprintf("scanned in %dms; `defenseclaw agent usage --sandbox %s` shows them in the AI inventory after its next scan", res.DurationMs, res.Name))
	return nil
}

// PsOptions are `sandbox ps`'s.
type PsOptions struct {
	Name   string
	Tree   bool
	Output OutputFormat
}

// Ps prints a sandbox's process tree: its live processes by pid, or with
// Tree each under its parent. The agent chooses its processes' names and
// arguments: they are shown, never acted on.
func (a *App) Ps(ctx context.Context, o PsOptions) error {
	api, err := a.api()
	if err != nil {
		return err
	}
	list, err := api.Processes(ctx, o.Name)
	if err != nil {
		return apiError(err)
	}
	if o.Output == OutputJSON {
		return writeJSON(a.IO.Out, list)
	}
	if !list.Enabled {
		a.note("the process tree of sandbox " + list.Name + " is off; `" + CommandName + " run --process-tree` or a pack's " +
			"observe.process_tree: true turns it on for a new sandbox")
		return nil
	}
	if len(list.Processes) == 0 {
		a.note("no processes sampled yet in sandbox " + list.Name + " (it is sampled while it runs)")
		return nil
	}
	now := time.Now()
	row := func(p sandboxapi.Process, depth int) []string {
		command := strings.TrimSpace(firstNonEmpty(p.Cmdline, p.Comm, p.Exe, "?"))
		return []string{strconv.Itoa(p.PID), strconv.Itoa(p.PPID), psUptime(now, p.StartedAt), strings.Repeat("  ", depth) + command}
	}
	var rows [][]string
	if o.Tree {
		for _, n := range processTree(list.Processes) {
			rows = append(rows, row(n.p, n.depth))
		}
	} else {
		for _, p := range list.Processes {
			rows = append(rows, row(p, 0))
		}
	}
	a.table([]string{"PID", "PPID", "UP", "COMMAND"}, rows)
	if list.Truncated {
		a.warn("the last sample stopped at its bound; some processes are not listed")
	}
	a.note(fmt.Sprintf("sampled every %ds; a process that starts and ends between two samples is not seen", list.IntervalSeconds))
	return nil
}

// treeRow is one process of a tree walk and its depth.
type treeRow struct {
	p     sandboxapi.Process
	depth int
}

// processTree orders processes parent first, each one's children by pid
// under it; a process whose parent is not listed starts a tree of its own.
func processTree(procs []sandboxapi.Process) []treeRow {
	byPID := map[int]bool{}
	children := map[int][]sandboxapi.Process{}
	for _, p := range procs {
		byPID[p.PID] = true
	}
	var roots []sandboxapi.Process
	for _, p := range procs {
		if p.PPID == p.PID || !byPID[p.PPID] {
			roots = append(roots, p)
			continue
		}
		children[p.PPID] = append(children[p.PPID], p)
	}
	byPid := func(list []sandboxapi.Process) {
		sort.Slice(list, func(i, j int) bool { return list[i].PID < list[j].PID })
	}
	byPid(roots)
	var out []treeRow
	seen := map[int]bool{}
	var walk func(p sandboxapi.Process, depth int)
	walk = func(p sandboxapi.Process, depth int) {
		if seen[p.PID] || depth > 64 {
			return
		}
		seen[p.PID] = true
		out = append(out, treeRow{p: p, depth: depth})
		kids := children[p.PID]
		byPid(kids)
		for _, c := range kids {
			walk(c, depth+1)
		}
	}
	for _, r := range roots {
		walk(r, 0)
	}
	// A loop of parents (ids the sandbox reused) has no root: list it flat.
	for _, p := range procs {
		if !seen[p.PID] {
			walk(p, 0)
		}
	}
	return out
}

func psUptime(now, started time.Time) string {
	if started.IsZero() {
		return "-"
	}
	return humanDuration(now.Sub(started))
}

// discoveryNames is a signal's names or evidence cell: the first few, and
// how many more.
func discoveryNames(names []string) string {
	const show = 3
	switch {
	case len(names) == 0:
		return "-"
	case len(names) <= show:
		return strings.Join(names, ", ")
	}
	return strings.Join(names[:show], ", ") + fmt.Sprintf(" (+%d)", len(names)-show)
}
