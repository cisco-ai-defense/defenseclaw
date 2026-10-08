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

package sandboxapi

import (
	"context"
	"net/http"
	"time"
)

// DiscoveryResult is POST /sandboxes/{name}/discover: what the AI discovery
// of a ready sandbox found in it. Every text field is the sandbox's, made
// safe to print.
type DiscoveryResult struct {
	Name       string    `json:"name"`
	ScannedAt  time.Time `json:"scanned_at"`
	DurationMs int64     `json:"duration_ms"`
	// Result is ok, or partial when the scan fell short of reading
	// everything (Problems say where: a bound, records refused).
	Result   string   `json:"result"`
	Problems []string `json:"problems,omitempty"`
	// Entries are the files and folders the sandbox reported, and Files the
	// files the detectors read.
	Entries int               `json:"entries"`
	Files   int               `json:"files"`
	Signals []DiscoverySignal `json:"signals"`
}

// DiscoverySignal is one AI component found in a sandbox.
type DiscoverySignal struct {
	// Category is the signal category (mcp_server, skill, ai_cli, ...),
	// Detector what found it (mcp, skill, binary, process, ...).
	Category string `json:"category"`
	Product  string `json:"product"`
	Vendor   string `json:"vendor,omitempty"`
	Detector string `json:"detector"`
	// Names are the components the evidence names (MCP servers, skills,
	// rules, plugins), Evidence the files and folders it was found in (a
	// config file, a skills folder, a binary).
	Names      []string `json:"names,omitempty"`
	Evidence   []string `json:"evidence,omitempty"`
	Confidence float64  `json:"confidence"`
}

// MaxExitedProcesses bounds the ended processes a ProcessList carries.
const MaxExitedProcesses = 256

// ProcessList is GET /sandboxes/{name}/processes: a sandbox's process tree,
// while its process tree is on (observe.process_tree, `sandbox run
// --process-tree`). Processes are the live ones by pid; Exited the ones that
// ended most recently, newest first. Every text field is the sandbox's, made
// safe to print: the agent chooses its processes' names, paths and
// arguments.
type ProcessList struct {
	Name string `json:"name"`
	// Enabled reports the sandbox's process tree on.
	Enabled bool `json:"enabled"`
	// SampledAt is the last sample of the sandbox's processes, and
	// IntervalSeconds how often they are sampled.
	SampledAt       time.Time `json:"sampled_at,omitzero"`
	IntervalSeconds int       `json:"interval_seconds,omitempty"`
	Processes       []Process `json:"processes"`
	Exited          []Process `json:"exited,omitempty"`
	// Truncated reports a sample that stopped at its bound.
	Truncated bool `json:"truncated,omitempty"`
	// Kernel is the sandbox kernel feed, on a Linux docker sandbox whose
	// host has it installed: Tetragon's exec and exit records join the
	// tree (source tetragon).
	Kernel *ProcessKernelFeed `json:"kernel,omitempty"`
}

// ProcessKernelFeed is the sandbox kernel feed as a sandbox's process tree
// sees it.
type ProcessKernelFeed struct {
	// Source is the records' source: tetragon.
	Source string `json:"source"`
	// Connected reports the gateway reading the feed now; Reason says why
	// not (kernel_feed_version_skew, kernel_feed_not_permitted, ...).
	Connected bool   `json:"connected"`
	Reason    string `json:"reason,omitempty"`
	// Build is the feed's release; Tetragon whether its Tetragon stream is
	// up, and TetragonReason why not.
	Build          string `json:"build,omitempty"`
	Tetragon       string `json:"tetragon,omitempty"`
	TetragonReason string `json:"tetragon_reason,omitempty"`
	// Execs counts the execs this tree took from the feed, Pinned those
	// whose in-sandbox pid the feed captured (the rest are in the tree by
	// exec id and host pid only); SupervisorExecs OpenShell's supervisor's
	// summarized exec loop; CollectorExecs DefenseClaw's own collector's
	// execs, left out of the tree.
	Execs           int64 `json:"execs"`
	Pinned          int64 `json:"pinned"`
	SupervisorExecs int64 `json:"supervisor_execs,omitempty"`
	CollectorExecs  int64 `json:"collector_execs,omitempty"`
	// Dropped counts records the feed lost (Tetragon's rate limit or
	// throttle, or this gateway reading too slowly).
	Dropped int64 `json:"dropped,omitempty"`
	// UpdateCommand updates a feed that is older than this gateway or
	// speaks a protocol it does not read.
	UpdateCommand string `json:"update_command,omitempty"`
}

// Process is one process of a sandbox's process tree.
type Process struct {
	PID       int       `json:"pid"`
	PPID      int       `json:"ppid"`
	UID       int       `json:"uid"`
	StartedAt time.Time `json:"started_at,omitzero"`
	ExitedAt  time.Time `json:"exited_at,omitzero"`
	// ExitCode is the exit status OpenShell reported, when it did.
	ExitCode *int   `json:"exit_code,omitempty"`
	Comm     string `json:"comm"`
	Exe      string `json:"exe,omitempty"`
	Cwd      string `json:"cwd,omitempty"`
	// Cmdline is the first arguments, joined, the values of arguments that
	// name secrets replaced.
	Cmdline string `json:"cmdline,omitempty"`
	// Source is what saw it first: sample (DefenseClaw's sample of the
	// sandbox's /proc), ocsf (an OpenShell PROC record) or tetragon (the
	// sandbox kernel feed).
	Source string `json:"source"`
	// HostPID is the host's pid of a process the kernel feed reported. PID
	// is 0 for one whose in-sandbox pid it could not read.
	HostPID int `json:"host_pid,omitempty"`
}

// Processes returns a sandbox's process tree.
func (c *Client) Processes(ctx context.Context, name string) (*ProcessList, error) {
	var out ProcessList
	if err := c.do(ctx, http.MethodGet, sandboxPath(name, "processes"), nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Discover runs the AI discovery of a ready sandbox now.
func (c *Client) Discover(ctx context.Context, name string) (*DiscoveryResult, error) {
	var out DiscoveryResult
	if err := c.do(ctx, http.MethodPost, sandboxPath(name, "discover"), nil, struct{}{}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
