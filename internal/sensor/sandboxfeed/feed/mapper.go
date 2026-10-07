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
	"context"
	"encoding/base64"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/redaction"
	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
	"github.com/defenseclaw/defenseclaw/internal/sensor/sandboxfeed"
	"github.com/defenseclaw/defenseclaw/internal/sensor/tetragon"
	pb "github.com/defenseclaw/defenseclaw/third_party/tetragon/api/v1/tetragon"
)

// ContainerResolver names the OpenShell sandbox a container belongs to.
type ContainerResolver interface {
	Resolve(ctx context.Context, id string) (Container, bool)
}

// ProcReader reads a live host process's pid in its own pid namespace and
// its start, both from one look at /proc (see HostProc).
type ProcReader interface {
	NSPid(hostPID int) (nsPID int, startTicks int64, ok bool)
}

// MapperConfig configures a Mapper.
type MapperConfig struct {
	Containers ContainerResolver
	Proc       ProcReader
	Now        func() time.Time
}

// MapperStats count what the mapper consumed.
type MapperStats struct {
	// Execs are the sandbox workload execs forwarded; Pinned those whose
	// in-sandbox pid was captured.
	Execs, Pinned int64
	// Reused are execs whose pid already named another process when it was
	// read (the exec's process was gone): no in-sandbox pid is guessed.
	Reused int64
	// Supervisor are the supervisor containers' execs, summarized; Runtime
	// the container runtime's own init that starts every exec into a
	// container (runc's /proc/self/fd/N init), counted and not forwarded.
	Supervisor, Runtime int64
	// Other are execs of containers that are not DefenseClaw's OpenShell
	// sandboxes (or that no reader owns), and of host processes.
	Other int64
}

// Mapper turns Tetragon's exec and exit events into feed items. It is used
// by one goroutine (the source's), except Stats.
type Mapper struct {
	config MapperConfig
	// redact is the helper's Tetragon mapper, used for its command lines
	// only: the same redaction, Codex notify withholding and quote handling
	// as the managed helper's. With no enrolled home it verifies no hook
	// script, so it summarizes nothing away.
	redact *tetragon.Mapper

	// pinned is the in-sandbox pid of the images whose pid was captured;
	// collectors the images of DefenseClaw's collector; images the latest
	// image of each host pid (an exec without a fork replaces it).
	pinned     boundedMap[string, int]
	collectors boundedMap[string, bool]
	images     boundedMap[int, string]

	supervisors map[string]*supervisorCount

	mu    sync.Mutex
	stats MapperStats
}

type supervisorCount struct {
	name  string
	owner int
	execs int64
	since time.Time
}

// tracked bounds each of the mapper's tables: a lost exit leaves an entry
// behind, and the bound keeps that from growing without end.
const tracked = 16384

// NewMapper returns a mapper.
func NewMapper(config MapperConfig) *Mapper {
	if config.Now == nil {
		config.Now = time.Now
	}
	return &Mapper{
		config:      config,
		redact:      tetragon.NewMapper(tetragon.MapperConfig{Now: config.Now}),
		pinned:      newBoundedMap[string, int](tracked),
		collectors:  newBoundedMap[string, bool](tracked),
		images:      newBoundedMap[int, string](tracked),
		supervisors: map[string]*supervisorCount{},
	}
}

// Stats returns the counters.
func (m *Mapper) Stats() MapperStats {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.stats
}

func (m *Mapper) count(f func(*MapperStats)) {
	m.mu.Lock()
	f(&m.stats)
	m.mu.Unlock()
}

// Map maps one Tetragon response.
func (m *Mapper) Map(ctx context.Context, response *pb.GetEventsResponse) []Item {
	at := m.config.Now()
	if ts := response.GetTime(); ts != nil && ts.IsValid() {
		at = ts.AsTime()
	}
	switch event := response.GetEvent().(type) {
	case *pb.GetEventsResponse_ProcessExec:
		return m.exec(ctx, response, event.ProcessExec, at)
	case *pb.GetEventsResponse_ProcessExit:
		return m.exit(ctx, response, event.ProcessExit, at)
	}
	return nil
}

// container is the sandbox container of a process, when it runs in one a
// reader owns.
func (m *Mapper) container(ctx context.Context, process *pb.Process) (Container, bool) {
	id := strings.TrimSpace(process.GetDocker())
	if id == "" || m.config.Containers == nil {
		return Container{}, false
	}
	return m.config.Containers.Resolve(ctx, id)
}

func (m *Mapper) exec(ctx context.Context, response *pb.GetEventsResponse, exec *pb.ProcessExec, at time.Time) []Item {
	process, parent := exec.GetProcess(), exec.GetParent()
	if process == nil {
		return nil
	}
	// The redacting mapper keeps its own table of the processes it saw (for
	// the parent lookup), so it sees every exec.
	cmdline := ""
	for _, event := range m.redact.Map(response).Events {
		if event.Kind == plane.KindExec {
			cmdline = event.Cmdline
			break
		}
	}
	container, ok := m.container(ctx, process)
	switch {
	case !ok:
		m.count(func(s *MapperStats) { s.Other++ })
		return nil
	case container.Role == sandboxfeed.RoleSupervisor:
		m.countSupervisor(container, at)
		return nil
	case container.Role != sandboxfeed.RoleSandbox || container.Owner < 0:
		m.count(func(s *MapperStats) { s.Other++ })
		return nil
	}

	execID := redaction.TruncateUTF8(process.GetExecId(), sandboxfeed.MaxIDBytes)
	hostPID := int(process.GetPid().GetValue())
	frame := sandboxfeed.Frame{
		Kind: sandboxfeed.FrameExec, At: at,
		SandboxID: container.SandboxID, SandboxName: container.SandboxName, ContainerID: container.ID, Role: container.Role,
		ExecID: execID, ParentExecID: redaction.TruncateUTF8(process.GetParentExecId(), sandboxfeed.MaxIDBytes),
		HostPID: hostPID, Binary: redaction.TruncateUTF8(process.GetBinary(), sandboxfeed.MaxPathBytes), Cmdline: cmdline,
		Cwd:      redaction.TruncateUTF8(process.GetCwd(), sandboxfeed.MaxPathBytes),
		Injected: process.GetInInitTree() != nil && !process.GetInInitTree().GetValue(),
	}
	if parent != nil {
		frame.ParentHostPID = int(parent.GetPid().GetValue())
	}
	if uid := process.GetUid(); uid != nil {
		value := int(uid.GetValue())
		frame.UID = &value
	}
	if start := process.GetStartTime(); start != nil && start.IsValid() {
		frame.StartNS = start.AsTime().UnixNano()
	}
	if frame.Injected && runtimeInit(process) {
		m.images.put(hostPID, execID)
		m.count(func(s *MapperStats) { s.Runtime++ })
		return nil
	}
	frame.Collector = m.collector(process, frame)

	if pid, ok := m.capture(hostPID, process.GetExecId()); ok {
		frame.PID = pid
		m.pinned.put(execID, pid)
	}
	// The parent's in-sandbox pid, when it runs in the same container: the
	// container's init has a host parent (containerd-shim), whose pid is in
	// another namespace and is not the sandbox's to name.
	if parent != nil && strings.TrimSpace(parent.GetDocker()) == strings.TrimSpace(process.GetDocker()) {
		if pid, ok := m.pinned.get(frame.ParentExecID); ok {
			frame.PPID = pid
		} else if pid, ok := m.capture(frame.ParentHostPID, parent.GetExecId()); ok {
			frame.PPID = pid
			m.pinned.put(frame.ParentExecID, pid)
		}
	}
	m.images.put(hostPID, execID)
	m.count(func(s *MapperStats) {
		s.Execs++
		if frame.PID > 0 {
			s.Pinned++
		}
	})
	return []Item{{Frame: frame, Owner: container.Owner}}
}

// collector reports whether an exec is DefenseClaw's collector or one of its
// processes: an injected process with the collector's command, a child of
// one, or a later image of one's pid.
func (m *Mapper) collector(process *pb.Process, frame sandboxfeed.Frame) bool {
	if !frame.Injected {
		return false
	}
	previous, _ := m.images.get(frame.HostPID)
	if (frame.ParentExecID != "" && m.collectors.has(frame.ParentExecID)) || (previous != "" && m.collectors.has(previous)) ||
		sandboxfeed.IsCollectorCommand(append([]string{process.GetBinary()}, strings.Fields(process.GetArguments())...)) {
		if frame.ExecID != "" {
			m.collectors.put(frame.ExecID, true)
		}
		return true
	}
	return false
}

// runtimeInit reports the container runtime's init process of an exec into a
// container (runc runs itself from a file descriptor: /proc/self/fd/N
// init), which the exec's command then replaces. Only an injected process is
// asked: the workload cannot start one outside the container's init tree.
func runtimeInit(process *pb.Process) bool {
	return strings.HasPrefix(process.GetBinary(), "/proc/self/fd/") && strings.TrimSpace(process.GetArguments()) == "init"
}

func (m *Mapper) exit(ctx context.Context, response *pb.GetEventsResponse, exit *pb.ProcessExit, at time.Time) []Item {
	process := exit.GetProcess()
	if process == nil {
		return nil
	}
	m.redact.Map(response)
	container, ok := m.container(ctx, process)
	if !ok || container.Role != sandboxfeed.RoleSandbox || container.Owner < 0 {
		return nil
	}
	execID := redaction.TruncateUTF8(process.GetExecId(), sandboxfeed.MaxIDBytes)
	hostPID := int(process.GetPid().GetValue())
	frame := sandboxfeed.Frame{
		Kind: sandboxfeed.FrameExit, At: at,
		SandboxID: container.SandboxID, SandboxName: container.SandboxName, ContainerID: container.ID, Role: container.Role,
		ExecID: execID, HostPID: hostPID, Binary: redaction.TruncateUTF8(process.GetBinary(), sandboxfeed.MaxPathBytes),
		Collector: m.collectors.has(execID),
	}
	frame.PID, _ = m.pinned.get(execID)
	if signal := strings.TrimSpace(exit.GetSignal()); signal != "" {
		frame.Signal = redaction.TruncateUTF8(signal, 32)
	} else {
		code := int(exit.GetStatus())
		frame.ExitCode = &code
	}
	m.pinned.remove(execID)
	m.collectors.remove(execID)
	if image, _ := m.images.get(hostPID); image == execID {
		m.images.remove(hostPID)
	}
	return []Item{{Frame: frame, Owner: container.Owner}}
}

// countSupervisor counts an exec of a sandbox's supervisor container: its
// exec loop runs about three times a second for as long as the sandbox
// lives, so it is summarized (Summaries) instead of forwarded.
func (m *Mapper) countSupervisor(container Container, at time.Time) {
	m.count(func(s *MapperStats) { s.Supervisor++ })
	if container.Owner < 0 || container.SandboxID == "" {
		return
	}
	count := m.supervisors[container.SandboxID]
	if count == nil {
		if len(m.supervisors) >= tracked {
			return
		}
		count = &supervisorCount{since: at}
		m.supervisors[container.SandboxID] = count
	}
	count.name, count.owner = container.SandboxName, container.Owner
	count.execs++
}

// Summaries returns one summary frame per sandbox whose supervisor ran
// anything since the last call, and starts the next window.
func (m *Mapper) Summaries(now time.Time) []Item {
	var out []Item
	for id, count := range m.supervisors {
		out = append(out, Item{Owner: count.owner, Frame: sandboxfeed.Frame{
			Kind: sandboxfeed.FrameSummary, At: now, SandboxID: id, SandboxName: count.name, Role: sandboxfeed.RoleSupervisor,
			Execs: count.execs, Since: count.since,
		}})
	}
	clear(m.supervisors)
	return out
}

// Capturing a pid. Tetragon's exec id is base64("<node>:<ktime>:<pid>"),
// ktime the exec's time in nanoseconds since boot. A process now at that pid
// that started (forked) after that time is not the image the event names:
// its pid was reused, and nothing is taken from it.
const (
	nsPerTick    = int64(time.Second / 100) // USER_HZ, fixed at 100 in /proc's ABI
	captureSlack = int64(20 * time.Millisecond)
)

// capture returns the in-sandbox pid of hostPID when the process at that pid
// is the image execID names.
func (m *Mapper) capture(hostPID int, execID string) (int, bool) {
	if hostPID <= 0 || m.config.Proc == nil {
		return 0, false
	}
	ktime, pid, ok := execKtime(execID)
	if !ok || pid != hostPID {
		return 0, false
	}
	nsPID, startTicks, ok := m.config.Proc.NSPid(hostPID)
	if !ok || nsPID <= 0 {
		return 0, false
	}
	if startTicks*nsPerTick > ktime+captureSlack {
		m.count(func(s *MapperStats) { s.Reused++ })
		return 0, false
	}
	return nsPID, true
}

// execKtime decodes Tetragon's exec id.
func execKtime(execID string) (ktime int64, pid int, ok bool) {
	raw, err := base64.StdEncoding.DecodeString(execID)
	if err != nil {
		return 0, 0, false
	}
	text := string(raw)
	last := strings.LastIndexByte(text, ':')
	if last <= 0 {
		return 0, 0, false
	}
	middle := strings.LastIndexByte(text[:last], ':')
	if middle < 0 {
		return 0, 0, false
	}
	ktime, err = strconv.ParseInt(text[middle+1:last], 10, 64)
	if err != nil || ktime <= 0 {
		return 0, 0, false
	}
	pid, err = strconv.Atoi(text[last+1:])
	if err != nil || pid <= 0 {
		return 0, 0, false
	}
	return ktime, pid, true
}

// boundedMap is a map that forgets entries once it holds limit of them: a
// quarter of them, arbitrarily, which only costs a pid or a collector mark
// of a process whose exit was lost.
type boundedMap[K comparable, V any] struct {
	limit int
	m     map[K]V
}

func newBoundedMap[K comparable, V any](limit int) boundedMap[K, V] {
	return boundedMap[K, V]{limit: limit, m: map[K]V{}}
}

func (b *boundedMap[K, V]) put(k K, v V) {
	if _, ok := b.m[k]; !ok && len(b.m) >= b.limit {
		drop := b.limit / 4
		for key := range b.m {
			if drop == 0 {
				break
			}
			delete(b.m, key)
			drop--
		}
	}
	b.m[k] = v
}

func (b *boundedMap[K, V]) get(k K) (V, bool) {
	v, ok := b.m[k]
	return v, ok
}

func (b *boundedMap[K, V]) has(k K) bool {
	_, ok := b.m[k]
	return ok
}

func (b *boundedMap[K, V]) remove(k K) { delete(b.m, k) }
