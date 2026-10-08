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

// Package sandboxfeed is the sandbox kernel feed: a small root service
// (defenseclaw-sensor-helper --sandbox-feed) that reads the host's Tetragon
// and streams the exec and exit of every process in the caller's own
// OpenShell docker sandboxes to the caller's per-user gateway, which adds
// them to the sandbox process tree (source tetragon).
//
// It exists apart from the managed sensor helper on purpose. The managed
// helper ships only in the enterprise package, answers host-wide questions
// to its one gateway account, and is never dialed by a per-user gateway; an
// OSS host with docker sandboxes has none of that. The per-user gateway, in
// turn, must never hold Tetragon's socket: it is root-only and grants kernel
// policy control. So the feed is root, consume-only (GetVersion and
// GetEvents; never a policy call), and answers one fieldless question on a
// socket only docker-group members reach. Docker-group members are
// root-equivalent already, so the feed gives them nothing new; the filter
// to the caller's own sandboxes (the image's io.defenseclaw.uid label) is a
// courtesy between users of one host, not a security boundary.
//
// The protocol is newline-delimited JSON on a unix socket: the client sends
// one Request line, the feed answers one Header line and then Frames until
// either side closes. The protocol carries its own version (ProtocolVersion),
// independent of the release: a gateway accepts its own version and the one
// before it, and otherwise falls back to the sampler
// (ReasonVersionSkew).
package sandboxfeed

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"time"
)

// ProtocolVersion is the feed protocol this build speaks. Bump it when a
// frame changes meaning; adding an optional field does not need a bump.
const ProtocolVersion = 1

// MinProtocolVersion is the oldest client protocol the feed still answers.
const MinProtocolVersion = 1

// OpSandboxExecs is the feed's one operation: a stream of the exec and exit
// of the processes in the caller's own sandboxes. It takes no argument.
const OpSandboxExecs = "sandbox_execs"

// Fixed locations. Nothing about the feed is configurable: the unit runs the
// helper with --sandbox-feed and no other argument.
const (
	// DefaultSocketPath is the feed's socket: root:docker 0660 in a
	// root:docker 0750 runtime directory.
	DefaultSocketPath = "/run/defenseclaw-sandbox-feed/feed.sock"
	// DefaultDockerSocket is the Docker Engine API the feed reads container
	// labels from.
	DefaultDockerSocket = "/var/run/docker.sock"
	// DockerGroup is the group whose members may read the feed.
	DockerGroup = "docker"
)

// Frame kinds.
const (
	FrameExec    = "exec"
	FrameExit    = "exit"
	FrameSummary = "summary"
	FrameStatus  = "status"
)

// Tetragon states a status frame and the header report.
const (
	TetragonConnected   = "connected"
	TetragonUnavailable = "unavailable"
)

// Container roles of an OpenShell docker sandbox (openshell.ai/isolation-role).
const (
	RoleSandbox    = "sandbox"
	RoleSupervisor = "supervisor"
)

// Reason codes a gateway reports for the feed.
const (
	// ReasonVersionSkew: the feed speaks a protocol this gateway does not.
	ReasonVersionSkew = "kernel_feed_version_skew"
	// ReasonNotInstalled: there is no feed socket on this host.
	ReasonNotInstalled = "kernel_feed_not_installed"
	// ReasonNotPermitted: the caller is not in the docker group.
	ReasonNotPermitted = "kernel_feed_not_permitted"
	// ReasonUntrusted: the socket or the process serving it is not root's.
	ReasonUntrusted = "kernel_feed_untrusted"
	// ReasonUnavailable: the feed is installed but does not answer.
	ReasonUnavailable = "kernel_feed_unavailable"
	// ReasonUnsupported: not Linux.
	ReasonUnsupported = "kernel_feed_unsupported"
)

// Request is the one line a client sends. It names the operation and the
// client's protocol and nothing else: the feed decides what a caller sees
// from the kernel's credentials of the connection, never from the request.
type Request struct {
	Version int    `json:"version"`
	Op      string `json:"op"`
}

// Header is the feed's first line.
type Header struct {
	// Protocol is the feed's protocol; the frames that follow use it.
	Protocol int `json:"protocol"`
	// Build is the feed's release (the helper's version).
	Build string `json:"build,omitempty"`
	// Tetragon is whether the feed's Tetragon stream is up now, and Reason
	// why not.
	Tetragon string `json:"tetragon,omitempty"`
	Reason   string `json:"reason,omitempty"`
	// Error refuses the request (version_skew, unknown_op); no frame
	// follows.
	Error string `json:"error,omitempty"`
}

// Errors a header carries.
const (
	HeaderErrorVersionSkew = "version_skew"
	HeaderErrorUnknownOp   = "unknown_op"
)

// Frame is one record of the stream. Exec and exit frames name one process
// of one sandbox's workload container; summary frames count the execs of a
// sandbox's supervisor container (OpenShell's own exec loop, about three a
// second, which is not forwarded one by one); status frames say whether the
// feed's Tetragon stream is up and how many records it lost.
//
// Every text field is what the process chose (its binary path, arguments
// and folder): display text, never a decision. The command line is redacted
// in the feed, before it leaves the root process.
type Frame struct {
	Kind string    `json:"kind"`
	At   time.Time `json:"at"`

	SandboxID   string `json:"sandbox_id,omitempty"`
	SandboxName string `json:"sandbox_name,omitempty"`
	ContainerID string `json:"container_id,omitempty"`
	Role        string `json:"role,omitempty"`

	// ExecID and ParentExecID are Tetragon's ids of this image and of its
	// parent's; HostPID and ParentHostPID the host's process ids.
	ExecID        string `json:"exec_id,omitempty"`
	ParentExecID  string `json:"parent_exec_id,omitempty"`
	HostPID       int    `json:"host_pid,omitempty"`
	ParentHostPID int    `json:"parent_host_pid,omitempty"`
	// PID and PPID are the process ids inside the sandbox, read from the
	// process's /proc status (NSpid) when the exec was seen; 0 when the
	// process was gone by then (most live for milliseconds) or its pid
	// could no longer be tied to this image.
	PID  int `json:"pid,omitempty"`
	PPID int `json:"ppid,omitempty"`
	// UID is the process's uid, as the kernel saw it.
	UID     *int   `json:"uid,omitempty"`
	Binary  string `json:"binary,omitempty"`
	Cmdline string `json:"cmdline,omitempty"`
	Cwd     string `json:"cwd,omitempty"`
	// StartNS is the exec time Tetragon reported, unix nanoseconds.
	StartNS int64 `json:"start_ns,omitempty"`
	// Injected marks a process outside the container's init tree: one an
	// exec into the container started (docker exec, OpenShell exec), never
	// one the workload started itself.
	Injected bool `json:"injected,omitempty"`
	// Collector marks DefenseClaw's own collector (the process sample and
	// AI discovery the gateway execs into the sandbox) and its children:
	// injected, and named defenseclaw-collect. The gateway leaves these out
	// of the tree, as the sample leaves itself out.
	Collector bool `json:"collector,omitempty"`
	// ExitCode is the exit status, or Signal the signal that ended it.
	ExitCode *int   `json:"exit_code,omitempty"`
	Signal   string `json:"signal,omitempty"`

	// Execs counts a supervisor container's execs since Since.
	Execs int64     `json:"execs,omitempty"`
	Since time.Time `json:"since,omitzero"`

	// Tetragon, Reason: the stream's state (status frames). Dropped counts
	// the records lost since the last status frame: Tetragon's rate limit
	// and throttle, and records this connection read too slowly to take.
	Tetragon string `json:"tetragon,omitempty"`
	Reason   string `json:"reason,omitempty"`
	Dropped  int64  `json:"dropped,omitempty"`
}

// maxLineBytes bounds one line either way. A frame is well under 12 KiB
// (the command line is cut to 1 KiB, paths to 4 KiB).
const maxLineBytes = 64 << 10

// Bounds of a frame's text fields, which the feed applies.
const (
	MaxPathBytes = 4096
	MaxIDBytes   = 256
)

// accepts reports whether this build reads a feed speaking server.
func accepts(server int) bool { return acceptsFor(ProtocolVersion, server) }

// acceptsFor reports whether a client speaking client reads a feed speaking
// server: its own version and the one before it.
func acceptsFor(client, server int) bool {
	return server == client || (server == client-1 && server >= 1)
}

// SkewError is a feed speaking a protocol this build does not read.
type SkewError struct {
	Server, Client int
	Build          string
}

func (e *SkewError) Error() string {
	build := ""
	if e.Build != "" {
		build = " (" + e.Build + ")"
	}
	return fmt.Sprintf("the sandbox kernel feed%s speaks protocol %d; this gateway reads %d and %d", build, e.Server, e.Client, e.Client-1)
}

// Is makes errors.Is(err, ErrVersionSkew) true.
func (e *SkewError) Is(target error) bool { return target == ErrVersionSkew }

// Errors of Dial and of a connection.
var (
	ErrVersionSkew  = errors.New("sandboxfeed: protocol version skew")
	ErrNotInstalled = errors.New("sandboxfeed: no feed socket")
	ErrNotPermitted = errors.New("sandboxfeed: not permitted to read the feed")
	ErrUntrusted    = errors.New("sandboxfeed: the feed socket is not root's")
	ErrUnsupported  = errors.New("sandboxfeed: the sandbox kernel feed is Linux only")
)

// ReasonFor names an error of Dial or of a connection as a reason code.
func ReasonFor(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrVersionSkew):
		return ReasonVersionSkew
	case errors.Is(err, ErrNotInstalled):
		return ReasonNotInstalled
	case errors.Is(err, ErrNotPermitted):
		return ReasonNotPermitted
	case errors.Is(err, ErrUntrusted):
		return ReasonUntrusted
	case errors.Is(err, ErrUnsupported):
		return ReasonUnsupported
	}
	return ReasonUnavailable
}

// WriteLine writes v as one JSON line.
func WriteLine(w io.Writer, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(data) >= maxLineBytes {
		return fmt.Errorf("sandboxfeed: a %d-byte line is over the %d-byte bound", len(data), maxLineBytes)
	}
	_, err = w.Write(append(data, '\n'))
	return err
}

// NewLineScanner reads lines of at most 64 KiB.
func NewLineScanner(r io.Reader) *bufio.Scanner {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 4096), maxLineBytes)
	return scanner
}

// ReadLine decodes the next line into v; io.EOF at the end.
func ReadLine(scanner *bufio.Scanner, v any) error {
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return err
		}
		return io.EOF
	}
	return json.Unmarshal(scanner.Bytes(), v)
}

// CollectorName is the name DefenseClaw's collector runs under inside a
// sandbox (bash's $0: `bash -p -c SCRIPT defenseclaw-collect MODE ...`).
const CollectorName = "defenseclaw-collect"

// IsCollectorCommand reports whether argv (the program first) is
// DefenseClaw's collector as the gateway runs it in a sandbox: `/usr/bin/env
// -i PATH=/usr/bin:/bin HOME=... LC_ALL=C /bin/bash -p -c SCRIPT
// defenseclaw-collect ...`, possibly under timeout(1) and its options, and
// possibly inside the shell OpenShell's exec runs a command with
// (`/bin/bash -c "timeout -k 5 10 /usr/bin/env -i 'PATH=/usr/bin:/bin' ..."`,
// whose quotes a text command line keeps). Nothing else may come before the
// env. The feed marks such a process and its children, so the gateway can
// leave its own sampling out of the tree. An argument list cut short keeps
// its start, so the shape is matched there.
func IsCollectorCommand(argv []string) bool {
	words := make([]string, len(argv))
	for i, word := range argv {
		words[i] = strings.Trim(word, `"'`)
	}
	if len(words) >= 2 && isCollectorShell(words[0]) && words[1] == "-c" {
		words = words[2:]
	}
	if len(words) > 0 && path.Base(words[0]) == "timeout" {
		words = words[1:]
		for len(words) > 0 && strings.HasPrefix(words[0], "-") {
			option := words[0]
			words = words[1:]
			if (option == "-k" || option == "-s" || option == "--kill-after" || option == "--signal") && len(words) > 0 {
				words = words[1:]
			}
		}
		if len(words) == 0 {
			return false
		}
		words = words[1:] // the duration
	}
	return len(words) >= 8 && words[0] == "/usr/bin/env" && words[1] == "-i" && words[2] == "PATH=/usr/bin:/bin" &&
		strings.HasPrefix(words[3], "HOME=") && words[4] == "LC_ALL=C" && words[5] == "/bin/bash" && words[6] == "-p" && words[7] == "-c"
}

func isCollectorShell(program string) bool {
	return program == "/bin/bash" || program == "/usr/bin/bash" || program == "/bin/sh" || program == "/usr/bin/sh"
}

// CollectorProgram reports whether a program is one the collector runs: the
// shells and wrappers it starts under and the tools its script calls. A
// collector the workload could have started itself (OpenShell's exec starts
// it below the container's init, like the workload) hides only these: any
// other program below it stays in the tree.
func CollectorProgram(binary string) bool {
	switch path.Base(binary) {
	case "bash", "sh", "timeout", "env", "find", "tr", "head", "tail", "base64", "readlink":
		return true
	}
	return false
}
