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

package feed

import (
	"path"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sensor/sandboxfeed"
	pb "github.com/defenseclaw/defenseclaw/third_party/tetragon/api/v1/tetragon"
)

// These are the command rendered into Claude's root-owned managed settings
// and the script copied into the sandbox image by the connector.
const sandboxClaudeHook = "/usr/local/lib/defenseclaw/hooks/claude-code-hook.sh"

type hookRole uint8

const (
	hookNone hookRole = iota
	hookLauncher
	hookVerified
	hookTool
	hookUnexpected
)

type hookProcess struct {
	binary, args, parentID string
	uid                    int
	uidKnown               bool
	// nsPID is the process's pid in the sandbox (0 when it was not read),
	// injected a process started into the container from outside it, and
	// hostPID its pid on the host.
	nsPID, hostPID int
	injected       bool
	// container is the process's container id, as Tetragon reports it.
	container string
	role      hookRole
	hook      *hookProcess
	tools     int
	verified  bool
	pending   *sandboxfeed.Frame
	frames    []Item
	opened    time.Time
	tainted   bool
	finished  bool
	owner     int
}

func hookInfo(p *pb.Process) *hookProcess {
	i := &hookProcess{
		binary: p.GetBinary(), args: p.GetArguments(), parentID: p.GetParentExecId(),
		hostPID: int(p.GetPid().GetValue()), container: strings.TrimSpace(p.GetDocker()),
	}
	if p.GetUid() != nil {
		i.uid, i.uidKnown = int(p.GetUid().GetValue()), true
	}
	return i
}

func hookSameUID(a, b *hookProcess) bool {
	return a != nil && b != nil && a.uidKnown && b.uidKnown && a.uid == b.uid
}

var sandboxHookTools = map[string]bool{
	"chmod": true, "curl": true, "date": true, "find": true, "head": true,
	"id": true, "jq": true, "mkdir": true, "mktemp": true, "od": true,
	"readlink": true, "rm": true, "sed": true, "tail": true, "tr": true,
}

func sandboxHookTool(binary string) bool {
	return (path.Dir(binary) == "/usr/bin" || path.Dir(binary) == "/bin" ||
		path.Dir(binary) == "/usr/sbin" || path.Dir(binary) == "/sbin") && sandboxHookTools[path.Base(binary)]
}

func sandboxClaudeAgent(binary string) bool {
	return path.Base(binary) == "claude" && (path.Dir(binary) == "/usr/bin" || path.Dir(binary) == "/usr/local/bin")
}

func shellCommand(args string) bool {
	for _, word := range strings.Fields(args) {
		if !strings.HasPrefix(word, "-") || strings.HasPrefix(word, "--") {
			return false
		}
		if strings.Contains(word, "c") {
			return true
		}
	}
	return false
}

func isShell(binary string) bool {
	switch path.Base(binary) {
	case "sh", "bash", "dash", "zsh", "ksh", "ash":
		return true
	}
	return false
}

// sandboxInit reports the sandbox's own supervisor: OpenShell's
// openshell-sandbox as the container's pid 1, read from /proc when its exec
// was seen. The workload can neither start a process at pid 1 nor make one
// a child of it, so a program it names openshell-sandbox does not pass.
func (h *hookProcess) sandboxInit() bool {
	return h != nil && h.nsPID == 1 && !h.injected && path.Base(h.binary) == "openshell-sandbox"
}

// agentRoot reports a Claude Code the sandbox started, not a tool call.
// The walk up its ancestry must reach the sandbox's supervisor without
// passing another Claude Code (one a tool call or an MCP server started) or
// a command shell whose parent is neither a shell nor the supervisor (an
// agent runs each tool command as `sh -c ...`). The supervisor's own launch
// shell, `bash -c "cd ... && claudecode-launch ..."`, passes: it was taken
// for a tool call's shell, so no hook call of a real sandbox was ever
// folded (GAP-0063). Missing ancestry refuses the optimization, preserving
// normal visibility.
func (m *Mapper) agentRoot(agent *hookProcess) bool {
	if agent == nil || !sandboxClaudeAgent(agent.binary) || agent.parentID == "" {
		return false
	}
	ancestorID := agent.parentID
	for depth := 0; depth < 16 && ancestorID != ""; depth++ {
		ancestor, ok := m.hookProcs.get(ancestorID)
		if !ok || sandboxClaudeAgent(ancestor.binary) {
			return false
		}
		if ancestor.sandboxInit() {
			return true
		}
		if isShell(ancestor.binary) && shellCommand(ancestor.args) {
			parent, ok := m.hookProcs.get(ancestor.parentID)
			if !ok || !(isShell(parent.binary) || parent.sandboxInit()) {
				return false
			}
		}
		ancestorID = ancestor.parentID
	}
	return false
}

// forkOfHook recognizes a fork that never execed by its inherited program
// and parent exec id. Only a fork of a verified hook or its known tools can
// carry their mark; an unrelated child remains visible.
//
// Tetragon reports a fork only with its exit or as the parent of a process
// it starts, so a fork whose own parent is a fork the feed has not seen yet
// (a pipeline stage in a command substitution, `$(printf ... | jq ...)`,
// where the hook script runs jq, head and curl) is placed by hookCallOf.
func (m *Mapper) forkOfHook(parent *pb.Process) *hookProcess {
	if !m.hookTrust {
		return nil
	}
	if parent == nil || parent.GetExecId() == "" {
		return nil
	}
	if existing, ok := m.hookProcs.get(parent.GetExecId()); ok {
		return existing
	}
	info := hookInfo(parent)
	ancestor, ok := m.hookProcs.get(parent.GetParentExecId())
	switch {
	case ok:
		if (ancestor.role != hookVerified && ancestor.role != hookTool) || ancestor.binary != parent.GetBinary() || !hookSameUID(info, ancestor) {
			return nil
		}
		info.hook = ancestor.hook
		if ancestor.role == hookVerified {
			info.hook = ancestor
		}
	case parent.GetBinary() == sandboxClaudeHook && parent.GetParentExecId() != "":
		if info.hook = m.hookCallOf(info); info.hook == nil {
			return nil
		}
		// The unseen parent is a fork of the same call: its other children
		// and its own exit join the call directly.
		m.hookProcs.put(parent.GetParentExecId(), &hookProcess{
			binary: sandboxClaudeHook, uid: info.uid, uidKnown: info.uidKnown, container: info.container,
			role: hookTool, hook: info.hook,
		})
	default:
		return nil
	}
	info.role = hookTool
	m.hookProcs.put(parent.GetExecId(), info)
	return info
}

// hookCallOf names the hook call a fork of the hook script belongs to when
// the forks between it and the script were not seen: the verified call of
// the fork's container and user that is still running. A fork runs the
// image it was forked from, so it descends from a run of the hook script in
// its container (every run is in hookScripts until it ends). Nothing is
// placed while that container and user have another run of the script that
// was not verified (one the workload started) or that was released.
func (m *Mapper) hookCallOf(fork *hookProcess) *hookProcess {
	if m.hookScriptsFull || fork.container == "" || !fork.uidKnown {
		return nil
	}
	var call *hookProcess
	for _, run := range m.hookScripts {
		if run.container != fork.container || !hookSameUID(run, fork) || run.finished {
			continue
		}
		if run.role != hookVerified || run.tainted {
			return nil
		}
		if call == nil || run.opened.After(call.opened) {
			call = run
		}
	}
	return call
}

// forgetHookProcess drops a process that ended from the ancestry table: its
// image, and the images it replaced in the same pid (an exec without a
// fork), which report no exit of their own. A process that ended is no live
// agent's ancestor. Without this every process of every sandbox stayed in
// the table, which filled after about 16k processes and turned hook folding
// off for as long as the Tetragon stream lasted (GAP-0063).
func (m *Mapper) forgetHookProcess(execID string, hostPID int) {
	info, ok := m.hookProcs.get(execID)
	m.hookProcs.remove(execID)
	delete(m.hookScripts, execID)
	for depth := 0; ok && hostPID > 0 && depth < 16; depth++ {
		parentID := info.parentID
		if info, ok = m.hookProcs.get(parentID); !ok || info.hostPID != hostPID {
			return
		}
		m.hookProcs.remove(parentID)
		delete(m.hookScripts, parentID)
	}
}

// The exec-id table can add both a previously unseen fork and its child in
// one event. Release pending calls before its eviction bound is reached.
func (m *Mapper) hookCapacity() []Item {
	if m.hookTrust && len(m.hookProcs.m) > tracked-2 {
		return m.DisableHooks()
	}
	return nil
}

func (m *Mapper) classifyHook(p, rawParent *pb.Process, frame *sandboxfeed.Frame) {
	info := hookInfo(p)
	info.nsPID, info.injected = frame.PID, frame.Injected
	parent := m.forkOfHook(rawParent)
	if parent == nil {
		parent, _ = m.hookProcs.get(p.GetParentExecId())
	}
	switch {
	case !frame.Injected && (p.GetBinary() == "/bin/sh" || p.GetBinary() == "/usr/bin/sh") &&
		p.GetArguments() == "-c "+sandboxClaudeHook && parent != nil &&
		m.agentRoot(parent) && hookSameUID(info, parent):
		info.role = hookLauncher
	case !frame.Injected && p.GetBinary() == sandboxClaudeHook &&
		p.GetArguments() == "-p "+sandboxClaudeHook && parent != nil &&
		parent.role == hookLauncher && hookSameUID(info, parent):
		parent.verified = true
		info.role, info.hook = hookVerified, info
		parent.hook = info
		info.opened = frame.At
		if parent.pending != nil {
			info.frames = append(info.frames, Item{Frame: *parent.pending})
		}
		frame.Hook = true
	case parent != nil && parent.hook != nil:
		info.hook = parent.hook
		if !info.hook.finished && parent.role != hookUnexpected && hookSameUID(info, info.hook) && sandboxHookTool(p.GetBinary()) {
			info.role = hookTool
			info.hook.tools++
			frame.HookTool = true
		} else {
			info.role = hookUnexpected
			frame.HookUnexpected = true
		}
	}
	if frame.ExecID != "" {
		m.hookProcs.put(frame.ExecID, info)
		if p.GetBinary() == sandboxClaudeHook {
			if len(m.hookScripts) >= tracked {
				m.hookScriptsFull = true
			} else {
				m.hookScripts[frame.ExecID] = info
			}
		}
	}
}

const (
	hookFrameLimit = 128
	hookWaitLimit  = 30 * time.Second
)

// ordinaryHookFrames releases the original events when a call cannot be
// summarized. No event from a surprising or long-running subtree is lost.
func ordinaryHookFrames(hook *hookProcess, owner int) []Item {
	frames := hook.frames
	hook.frames = nil
	for i := range frames {
		frames[i].Owner = owner
		frames[i].Frame.Hook = false
		frames[i].Frame.HookTool = false
		frames[i].Frame.HookTools = 0
	}
	return frames
}

func (m *Mapper) hookExecItems(info *hookProcess, frame sandboxfeed.Frame, owner int) []Item {
	item := Item{Frame: frame, Owner: owner}
	if info == nil || info.hook == nil {
		return []Item{item}
	}
	hook := info.hook
	hook.owner = owner
	if hook.finished {
		item.Frame.HookTool = false
		return []Item{item}
	}
	if hook.tainted {
		item.Frame.HookTool = false
		return []Item{item}
	}
	if info.role == hookUnexpected {
		hook.tainted = true
		return append(ordinaryHookFrames(hook, owner), item)
	}
	hook.frames = append(hook.frames, item)
	if len(hook.frames) > hookFrameLimit {
		hook.tainted = true
		return ordinaryHookFrames(hook, owner)
	}
	return nil
}

func (m *Mapper) hookExitItems(info *hookProcess, frame sandboxfeed.Frame, owner int) []Item {
	item := Item{Frame: frame, Owner: owner}
	if info == nil || info.hook == nil {
		return []Item{item}
	}
	hook := info.hook
	if hook.finished {
		if info.role == hookTool {
			return nil
		}
		item.Frame.Hook = false
		return []Item{item}
	}
	if hook.tainted {
		item.Frame.Hook = false
		item.Frame.HookTool = false
		return []Item{item}
	}
	if info.role == hookVerified {
		var anchor sandboxfeed.Frame
		for _, buffered := range hook.frames {
			if buffered.Frame.Hook {
				anchor = buffered.Frame
				break
			}
		}
		hook.frames = nil
		hook.finished = true
		if anchor.Kind == sandboxfeed.FrameExec {
			return []Item{{Frame: anchor, Owner: owner}, item}
		}
		// A missing anchor means the call cannot be summarized safely.
		item.Frame.Hook = false
		return []Item{item}
	}
	hook.frames = append(hook.frames, item)
	if len(hook.frames) > hookFrameLimit {
		hook.tainted = true
		return ordinaryHookFrames(hook, owner)
	}
	return nil
}

func (m *Mapper) staleHooks(now time.Time) []Item {
	var out []Item
	for _, info := range m.hookProcs.m {
		if info.role == hookLauncher && !info.verified && info.pending != nil && now.Sub(info.pending.At) >= hookWaitLimit {
			out = append(out, Item{Frame: *info.pending, Owner: info.owner})
			info.pending = nil
			info.role = hookNone
		}
		if info.role != hookVerified || info.tainted || info.finished || info.opened.IsZero() || now.Sub(info.opened) < hookWaitLimit {
			continue
		}
		info.tainted = true
		out = append(out, ordinaryHookFrames(info, info.owner)...)
	}
	return out
}

// FlushHooks releases calls held when the Tetragon stream ends. An exit may
// have been lost, so retaining them for another stream would hide work.
func (m *Mapper) FlushHooks() []Item {
	var out []Item
	for _, info := range m.hookProcs.m {
		if info.role == hookLauncher && !info.verified && info.pending != nil {
			out = append(out, Item{Frame: *info.pending, Owner: info.owner})
			info.pending = nil
			info.role = hookNone
		}
		if info.role == hookVerified && !info.tainted && !info.finished {
			info.tainted = true
			out = append(out, ordinaryHookFrames(info, info.owner)...)
		}
	}
	return out
}

// DisableHooks releases pending calls and leaves subsequent processes
// visible: a lost Tetragon event could have been an unexpected child.
func (m *Mapper) DisableHooks() []Item {
	m.hookTrust = false
	return m.FlushHooks()
}

// ResumeHooks starts a fresh ancestry table with a new complete stream.
// Processes already running lack verified ancestry and remain visible.
func (m *Mapper) ResumeHooks() {
	m.hookProcs = newBoundedMap[string, *hookProcess](tracked)
	m.hookScripts, m.hookScriptsFull = map[string]*hookProcess{}, false
	m.hookTrust = true
}

func (m *Mapper) classifyHookExit(p *pb.Process, frame *sandboxfeed.Frame) {
	info, ok := m.hookProcs.get(frame.ExecID)
	if !ok {
		info = m.forkOfHook(p)
	}
	if info == nil {
		return
	}
	switch info.role {
	case hookVerified:
		frame.Hook, frame.HookTools = true, info.tools
	case hookTool:
		frame.HookTool = true
	case hookUnexpected:
		frame.HookUnexpected = true
	}
}
