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

package tetragon

import (
	"fmt"
	"net"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/redaction"
	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
	pb "github.com/defenseclaw/defenseclaw/third_party/tetragon/api/v1/tetragon"
)

// MaxCmdlineBytes bounds a forwarded command line.
const MaxCmdlineBytes = 1024

// unsetAUID is the kernel's "no login uid" (4294967295).
const unsetAUID = ^uint32(0)

// Control ids of the controls policy.
const (
	ControlSSHPrivateKeyRead = "kernel.ssh_private_key_read"
	ControlPersistenceWrite  = "kernel.persistence_write"
)

// MapperConfig configures a Mapper.
type MapperConfig struct {
	// Homes are the enrolled homes. A per-user hook script is recognized
	// only under one of them.
	Homes []string
	// BinDir is the managed install's binary directory: the native hook
	// and DefenseClaw's own executables live there, root-owned.
	BinDir string
	// PolicyMode is the current mode of a loaded policy (enforce, monitor,
	// monitor_only, unknown; "" when not listed). It decides whether a
	// controls event was blocked or only would have been.
	PolicyMode func(name string) string
	// Now is the clock (tests).
	Now func() time.Time
}

// Mapper turns Tetragon responses into plane events. It keeps a bounded
// table of the processes it has seen, keyed by exec id, which is what the
// self-filter (verified hooks) and the parent lookup need. Raw arguments
// live only in that table, in the helper's memory; everything emitted is
// redacted. Safe for one goroutine.
type Mapper struct {
	config     MapperConfig
	hookBinary string
	self       map[string]bool
	table      processTable
	mu         sync.Mutex
	stats      MapperStats
}

// MapperStats count what the mapper consumed without forwarding.
type MapperStats struct {
	// Foreign are kprobe and LSM events of policies DefenseClaw did not
	// load (the customer's own). They are not forwarded.
	Foreign int64
	// Summarized are a verified hook's own tool processes, counted on the
	// hook's exit instead of forwarded.
	Summarized int64
}

// NewMapper returns a mapper.
func NewMapper(config MapperConfig) *Mapper {
	if config.BinDir == "" {
		config.BinDir = "/opt/defenseclaw/bin"
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	homes := make([]string, 0, len(config.Homes))
	for _, home := range config.Homes {
		if home = strings.TrimRight(path.Clean(strings.TrimSpace(home)), "/"); home != "" && home != "." {
			homes = append(homes, home)
		}
	}
	config.Homes = homes
	return &Mapper{
		config:     config,
		hookBinary: path.Join(config.BinDir, "defenseclaw-hook"),
		self: map[string]bool{
			path.Join(config.BinDir, "defenseclaw-gateway"):       true,
			path.Join(config.BinDir, "defenseclaw-sensor-helper"): true,
			path.Join(config.BinDir, "defenseclaw-acp"):           true,
		},
		table: processTable{entries: map[string]*procInfo{}},
	}
}

// Stats returns the counters.
func (m *Mapper) Stats() MapperStats {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.stats
}

// Map maps one response.
func (m *Mapper) Map(response *pb.GetEventsResponse) plane.KernelBatch {
	at := m.config.Now()
	if ts := response.GetTime(); ts != nil && ts.IsValid() {
		at = ts.AsTime()
	}
	var batch plane.KernelBatch
	switch event := response.GetEvent().(type) {
	case *pb.GetEventsResponse_ProcessExec:
		batch.Events = m.mapExec(event.ProcessExec, at)
	case *pb.GetEventsResponse_ProcessExit:
		batch.Events = m.mapExit(event.ProcessExit, at)
	case *pb.GetEventsResponse_ProcessKprobe:
		k := event.ProcessKprobe
		batch.Events = m.mapHook(k.GetProcess(), k.GetParent(), k.GetPolicyName(), k.GetFunctionName(), k.GetArgs(), at)
	case *pb.GetEventsResponse_ProcessLsm:
		l := event.ProcessLsm
		batch.Events = m.mapHook(l.GetProcess(), l.GetParent(), l.GetPolicyName(), l.GetFunctionName(), l.GetArgs(), at)
	case *pb.GetEventsResponse_ProcessThrottle:
		switch event.ProcessThrottle.GetType() {
		case pb.ThrottleType_THROTTLE_START:
			batch.ThrottleStart = true
		case pb.ThrottleType_THROTTLE_STOP:
			batch.ThrottleStop = true
		}
	case *pb.GetEventsResponse_RateLimitInfo:
		batch.Dropped = int64(event.RateLimitInfo.GetNumberOfDroppedProcessEvents())
	}
	return batch
}

// base fills the process fields every event carries.
func (m *Mapper) base(kind plane.Kind, process, parent *pb.Process, at time.Time) plane.Event {
	event := plane.Event{
		Kind:         kind,
		PID:          int(process.GetPid().GetValue()),
		Name:         path.Base(process.GetBinary()),
		Exe:          process.GetBinary(),
		ExecID:       process.GetExecId(),
		ParentExecID: process.GetParentExecId(),
		ContainerID:  containerID(process),
		Source:       plane.SourceTetragon,
		User:         process.GetUser().GetName(),
		At:           at,
		Self:         m.self[process.GetBinary()],
	}
	if event.Exe == "" {
		event.Name = ""
	}
	if uid := process.GetUid(); uid != nil {
		value := int(uid.GetValue())
		event.UID = &value
	}
	if auid := process.GetAuid(); auid != nil && auid.GetValue() != unsetAUID {
		value := int(auid.GetValue())
		event.AUID = &value
	}
	if start := process.GetStartTime(); start != nil && start.IsValid() {
		event.StartNS = start.AsTime().UnixNano()
	}
	if parent != nil && parent.GetPid() != nil {
		event.PPID = int(parent.GetPid().GetValue())
	} else if info := m.table.get(event.ParentExecID); info != nil {
		event.PPID = info.pid
	}
	event.ResponsiblePID = event.PPID
	return event
}

// containerID is the container a process runs in: Tetragon's cgroup-derived
// id, or the pod's container id on Kubernetes.
func containerID(process *pb.Process) string {
	if id := strings.TrimSpace(process.GetDocker()); id != "" {
		return id
	}
	return strings.TrimSpace(process.GetPod().GetContainer().GetId())
}

func (m *Mapper) mapExec(exec *pb.ProcessExec, at time.Time) []plane.Event {
	process, parent := exec.GetProcess(), exec.GetParent()
	if process == nil {
		return nil
	}
	if parent != nil && parent.GetExecId() != "" && m.table.get(parent.GetExecId()) == nil {
		m.table.put(infoOf(parent, at))
	}
	info := m.table.put(infoOf(process, at))
	if info.role == roleNone {
		m.classify(info)
	}

	event := m.base(plane.KindExec, process, parent, at)
	switch info.role {
	case roleHookTool:
		m.mu.Lock()
		m.stats.Summarized++
		m.mu.Unlock()
		return nil
	case roleVerifiedHook:
		event.Hook = plane.HookVerified
		event.Cmdline = redaction.CommandLine(info.argv, MaxCmdlineBytes)
	case roleUnexpected:
		event.Hook = plane.HookUnexpected
		event.Cmdline = commandLine(process)
	default:
		event.Cmdline = commandLine(process)
	}
	events := []plane.Event{event}
	if detail := privilegeAtExec(process.GetBinaryProperties()); detail != "" {
		privilege := event
		privilege.Kind, privilege.Detail = plane.KindPrivilege, detail
		privilege.Hook = ""
		events = append(events, privilege)
	}
	return events
}

func (m *Mapper) mapExit(exit *pb.ProcessExit, at time.Time) []plane.Event {
	process := exit.GetProcess()
	if process == nil {
		return nil
	}
	event := m.base(plane.KindExit, process, exit.GetParent(), at)
	info := m.table.get(process.GetExecId())
	if info != nil {
		info.exitedAt = at
		switch info.role {
		case roleHookTool:
			return nil
		case roleVerifiedHook:
			event.Hook, event.HookTools = plane.HookVerified, info.tools
		case roleUnexpected:
			event.Hook = plane.HookUnexpected
		}
	}
	return []plane.Event{event}
}

// commandLine is the forwarded command line of a process: its binary and
// arguments, redacted, or the program and the withheld marker for a Codex
// notify program (redaction.CommandLine).
//
// Tetragon renders the arguments with spaces, wrapping the ones that contain
// a space in double quotes; they are split on white space here, as the
// sandbox process tree splits OpenShell's command lines, so every word is
// checked by the redaction rules. redaction.CommandLine sets aside the quotes
// a word starts or ends with (Tetragon's, or the shell's inside
// `-c "... eval '...'"`) while it checks the word, so a quoted secret
// (`-c "--token=..."`) is caught and the line keeps its shape.
func commandLine(process *pb.Process) string {
	fields := strings.Fields(process.GetArguments())
	argv := make([]string, 0, len(fields)+1)
	if binary := process.GetBinary(); binary != "" {
		argv = append(argv, binary)
	}
	return redaction.CommandLine(append(argv, fields...), MaxCmdlineBytes)
}

// privilegeAtExec describes a privilege change Tetragon saw at exec: a
// setuid or setgid binary, or file capabilities raising the process's set.
// This is how the Tetragon backend reports what cn_proc's uid and gid change
// events report on the native one.
func privilegeAtExec(properties *pb.BinaryProperties) string {
	if properties == nil {
		return ""
	}
	var parts []string
	if setuid := properties.GetSetuid(); setuid != nil {
		parts = append(parts, fmt.Sprintf("uid change at exec: euid=%d", setuid.GetValue()))
	}
	if setgid := properties.GetSetgid(); setgid != nil {
		parts = append(parts, fmt.Sprintf("gid change at exec: egid=%d", setgid.GetValue()))
	}
	for _, change := range properties.GetPrivilegesChanged() {
		if change != pb.ProcessPrivilegesChanged_PRIVILEGES_CHANGED_UNSET {
			parts = append(parts, "privileges raised at exec: "+strings.ToLower(strings.TrimPrefix(change.String(), "PRIVILEGES_")))
		}
	}
	return strings.Join(parts, "; ")
}

// mapHook maps a kprobe or LSM event. Only DefenseClaw's own policies are
// forwarded; the customer's policy events are counted and dropped (their
// actions are theirs to report, and fanotify keeps the file half until
// DefenseClaw's observe policy takes it over).
func (m *Mapper) mapHook(process, parent *pb.Process, policy, function string, args []*pb.KprobeArgument, at time.Time) []plane.Event {
	family, own := OwnPolicyFamily(policy)
	if !own || process == nil {
		m.mu.Lock()
		m.stats.Foreign++
		m.mu.Unlock()
		return nil
	}
	event := m.base(plane.KindFileRead, process, parent, at)
	event.Cmdline = commandLine(process)
	event.Policy = policy
	if info := m.table.get(process.GetExecId()); info != nil {
		switch info.role {
		case roleVerifiedHook:
			event.Hook = plane.HookVerified
			event.Cmdline = redaction.CommandLine(info.argv, MaxCmdlineBytes)
		case roleUnexpected:
			event.Hook = plane.HookUnexpected
		}
	}

	if remote, ok := connectPeer(args); ok {
		event.Kind, event.Remote, event.Outcome = plane.KindConnect, remote, plane.OutcomeObserved
		return []plane.Event{event}
	}
	file, write := fileArgument(function, args)
	if file == "" {
		return nil
	}
	event.Path = file
	switch family {
	case "controls", "controls-burnin":
		event.Control = controlFor(file)
		if event.Control == ControlPersistenceWrite {
			write = true
		}
		event.Outcome = plane.OutcomeWouldBlock
		if family == "controls" && m.config.PolicyMode != nil && m.config.PolicyMode(policy) == "enforce" {
			event.Outcome = plane.OutcomeBlocked
		}
	default:
		event.Outcome = plane.OutcomeObserved
	}
	if write {
		event.Kind = plane.KindFileWrite
	}
	return []plane.Event{event}
}

// connectPeer is the peer of a tcp_connect (sock) or socket_connect
// (sockaddr) argument, as host:port. Unix sockets and unparsable addresses
// are not peers.
func connectPeer(args []*pb.KprobeArgument) (string, bool) {
	for _, arg := range args {
		if sock := arg.GetSockArg(); sock != nil {
			if ip := net.ParseIP(sock.GetDaddr()); ip != nil {
				return net.JoinHostPort(ip.String(), strconv.Itoa(int(sock.GetDport()))), true
			}
		}
		if addr := arg.GetSockaddrArg(); addr != nil {
			if ip := net.ParseIP(addr.GetAddr()); ip != nil {
				return net.JoinHostPort(ip.String(), strconv.Itoa(int(addr.GetPort()))), true
			}
		}
	}
	return "", false
}

// FModeWrite is FMODE_WRITE in struct file's f_mode; the observe and
// controls policies label that argument "f_mode".
const FModeWrite = 0x2

// mayWrite is MAY_WRITE|MAY_APPEND in security_file_permission's mask.
const mayWrite = 0x2 | 0x8

// fileArgument is the file an event concerns and whether it was opened for
// writing.
func fileArgument(function string, args []*pb.KprobeArgument) (string, bool) {
	file, write := "", false
	for _, arg := range args {
		switch {
		case arg.GetFileArg() != nil && file == "":
			file = arg.GetFileArg().GetPath()
			write = write || writeFlags(arg.GetFileArg().GetFlags())
		case arg.GetPathArg() != nil && file == "":
			file = arg.GetPathArg().GetPath()
			write = write || writeFlags(arg.GetPathArg().GetFlags())
		case arg.GetLabel() == "f_mode":
			if value, ok := intArgument(arg); ok && value&FModeWrite != 0 {
				write = true
			}
		case strings.HasSuffix(function, "file_permission"):
			if value, ok := intArgument(arg); ok && value&mayWrite != 0 {
				write = true
			}
		}
	}
	return file, write
}

func intArgument(arg *pb.KprobeArgument) (int64, bool) {
	switch value := arg.GetArg().(type) {
	case *pb.KprobeArgument_UintArg:
		return int64(value.UintArg), true
	case *pb.KprobeArgument_IntArg:
		return int64(value.IntArg), true
	case *pb.KprobeArgument_LongArg:
		return value.LongArg, true
	case *pb.KprobeArgument_SizeArg:
		return int64(value.SizeArg), true
	}
	return 0, false
}

func writeFlags(flags string) bool {
	for _, flag := range []string{"O_WRONLY", "O_RDWR", "O_TRUNC", "O_APPEND", "O_CREAT"} {
		if strings.Contains(flags, flag) {
			return true
		}
	}
	return false
}

// controlFor names the control a controls-policy path belongs to: the SSH
// private key names, or the persistence paths.
func controlFor(file string) string {
	switch path.Base(file) {
	case "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa":
		if path.Base(path.Dir(file)) == ".ssh" {
			return ControlSSHPrivateKeyRead
		}
	}
	return ControlPersistenceWrite
}
