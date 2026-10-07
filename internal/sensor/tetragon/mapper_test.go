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
	"bufio"
	"os"
	"strings"
	"testing"
	"unicode/utf8"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/defenseclaw/defenseclaw/internal/redaction"
	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
	pb "github.com/defenseclaw/defenseclaw/third_party/tetragon/api/v1/tetragon"
)

const fixtureHome = "/home/dcr-std1"

// loadFixture reads a Tetragon JSON export (one GetEventsResponse per line).
// testdata/tg2-session.jsonl is shaped on records captured from Tetragon
// 1.7.1 on the RHEL 9 test host (dc-fc-rhel-tg2), sanitized: marker files and
// marker values only, TEST-NET addresses, no real key, prompt or token.
func loadFixture(t *testing.T, name string) []*pb.GetEventsResponse {
	t.Helper()
	file, err := os.Open("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var out []*pb.GetEventsResponse
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1<<20), 1<<20)
	for scanner.Scan() {
		var response pb.GetEventsResponse
		if err := protojson.Unmarshal(scanner.Bytes(), &response); err != nil {
			t.Fatalf("fixture line %d: %v", len(out)+1, err)
		}
		out = append(out, &response)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

type mapped struct {
	line  int
	batch plane.KernelBatch
}

func mapFixture(t *testing.T, mapper *Mapper, name string) []mapped {
	t.Helper()
	var out []mapped
	for i, response := range loadFixture(t, name) {
		out = append(out, mapped{line: i + 1, batch: mapper.Map(response)})
	}
	return out
}

func fixtureMapper(modes map[string]string) *Mapper {
	return NewMapper(MapperConfig{
		Homes:      []string{fixtureHome},
		PolicyMode: func(name string) string { return modes[name] },
	})
}

func one(t *testing.T, m mapped) plane.Event {
	t.Helper()
	if len(m.batch.Events) != 1 {
		t.Fatalf("line %d: %d events, want 1: %+v", m.line, len(m.batch.Events), m.batch.Events)
	}
	return m.batch.Events[0]
}

func TestMapperMapsTheRecordedSession(t *testing.T) {
	mapper := fixtureMapper(map[string]string{"defenseclaw-controls-0a1b2c3d": "enforce"})
	lines := mapFixture(t, mapper, "tg2-session.jsonl")
	if len(lines) != 26 {
		t.Fatalf("%d fixture lines", len(lines))
	}

	claude := one(t, lines[0])
	if claude.Kind != plane.KindExec || claude.PID != 72403 || claude.PPID != 72348 || claude.ResponsiblePID != 72348 ||
		claude.Name != "claude" || claude.Exe != fixtureHome+"/.local/bin/claude" || claude.Source != plane.SourceTetragon {
		t.Fatalf("claude exec %+v", claude)
	}
	if claude.UID == nil || *claude.UID != 1001 || claude.AUID == nil || *claude.AUID != 1000 || claude.User != "dcr-std1" {
		t.Fatalf("identity %+v", claude)
	}
	if claude.ExecID == "" || claude.ParentExecID == "" || claude.StartNS == 0 || claude.At.IsZero() || claude.ContainerID != "" {
		t.Fatalf("ids %+v", claude)
	}

	// The native install runs as a version-numbered file: Exe keeps the
	// path identity needs, Name is the basename the kernel has.
	version := one(t, lines[1])
	if version.Name != "2.1.292" || version.Exe != fixtureHome+"/.local/share/claude/versions/2.1.292" ||
		version.Cmdline != fixtureHome+"/.local/share/claude/versions/2.1.292 --version" || version.PPID != 72403 {
		t.Fatalf("version exec %+v", version)
	}
	if exit := one(t, lines[2]); exit.Kind != plane.KindExit || exit.PID != 72425 || exit.ExecID != version.ExecID {
		t.Fatalf("exit %+v", exit)
	}

	// The short-lived cat is named and has its argv: the cn_proc race is
	// gone.
	if cat := one(t, lines[4]); cat.Name != "cat" || cat.Cmdline != "/usr/bin/cat "+fixtureHome+"/tg2work/dccert-block-marker" || cat.PPID != 72934 {
		t.Fatalf("cat %+v", cat)
	}

	denied := one(t, lines[7])
	if denied.Kind != plane.KindFileRead || denied.Path != fixtureHome+"/.ssh/id_ed25519" ||
		denied.Policy != "defenseclaw-controls-0a1b2c3d" || denied.Control != ControlSSHPrivateKeyRead ||
		denied.Outcome != plane.OutcomeBlocked {
		t.Fatalf("controls deny %+v", denied)
	}
	burnin := one(t, lines[8])
	if burnin.Kind != plane.KindFileWrite || burnin.Path != fixtureHome+"/.bashrc" ||
		burnin.Control != ControlPersistenceWrite || burnin.Outcome != plane.OutcomeWouldBlock {
		t.Fatalf("burn-in would-block %+v", burnin)
	}
	observed := one(t, lines[9])
	if observed.Kind != plane.KindFileRead || observed.Path != fixtureHome+"/.aws/credentials" ||
		observed.Outcome != plane.OutcomeObserved || observed.Control != "" {
		t.Fatalf("observe %+v", observed)
	}

	curl := one(t, lines[10])
	if strings.Contains(curl.Cmdline, "dccertvalue") || !strings.Contains(curl.Cmdline, "--token=<redacted") {
		t.Fatalf("curl argv not redacted in the helper: %q", curl.Cmdline)
	}
	connect := one(t, lines[11])
	if connect.Kind != plane.KindConnect || connect.Remote != "203.0.113.10:443" || connect.Name != "curl" ||
		connect.Outcome != plane.OutcomeObserved {
		t.Fatalf("connect %+v", connect)
	}

	if len(lines[12].batch.Events) != 0 || mapper.Stats().Foreign != 1 {
		t.Fatalf("a customer policy's event was forwarded: %+v, stats %+v", lines[12].batch, mapper.Stats())
	}

	container := one(t, lines[13])
	if container.ContainerID != "de1ac97706c124a9b5e56b74da1e629" || container.UID == nil || *container.UID != 0 ||
		container.AUID != nil {
		t.Fatalf("container exec %+v", container)
	}

	if !lines[14].batch.ThrottleStart || lines[15].batch.Dropped != 7 || !lines[16].batch.ThrottleStop {
		t.Fatalf("loss signals %+v %+v %+v", lines[14].batch, lines[15].batch, lines[16].batch)
	}

	notify := one(t, lines[17])
	if strings.Contains(notify.Cmdline, "dccert-payload-marker") || strings.Contains(notify.Cmdline, "agent-turn") ||
		notify.Cmdline != "/usr/bin/bash "+fixtureHome+"/.defenseclaw/notify-bridge.sh "+redaction.WithheldArgv {
		t.Fatalf("notify argv %q", notify.Cmdline)
	}

	if launcher := one(t, lines[18]); launcher.Hook != "" || launcher.Name != "sh" {
		t.Fatalf("launcher %+v", launcher)
	}
	hook := one(t, lines[19])
	if hook.Hook != plane.HookVerified || hook.Cmdline != fixtureHome+"/.defenseclaw/hooks/claude-code-hook.sh" {
		t.Fatalf("hook %+v", hook)
	}
	for _, i := range []int{20, 21, 22, 23} {
		if len(lines[i].batch.Events) != 0 {
			t.Fatalf("line %d: the hook's own tool was forwarded: %+v", i+1, lines[i].batch.Events)
		}
	}
	hookExit := one(t, lines[24])
	if hookExit.Kind != plane.KindExit || hookExit.Hook != plane.HookVerified || hookExit.HookTools != 2 {
		t.Fatalf("hook exit %+v", hookExit)
	}
	if mapper.Stats().Summarized != 2 {
		t.Fatalf("stats %+v", mapper.Stats())
	}

	sudo := lines[25].batch.Events
	if len(sudo) != 2 || sudo[0].Kind != plane.KindExec || sudo[1].Kind != plane.KindPrivilege ||
		sudo[1].Detail != "uid change at exec: euid=0" || sudo[1].PID != 73300 {
		t.Fatalf("setuid exec %+v", sudo)
	}
}

// TestMapperMonitorModeIsNeverBlocked pins that only a controls policy
// listed in enforce mode reports blocked: monitor, monitor_only, unknown and
// an unlisted policy all count as not enforcing.
func TestMapperMonitorModeIsNeverBlocked(t *testing.T) {
	for _, mode := range []string{"monitor", "monitor_only", "unknown", ""} {
		lines := mapFixture(t, fixtureMapper(map[string]string{"defenseclaw-controls-0a1b2c3d": mode}), "tg2-session.jsonl")
		if got := one(t, lines[7]).Outcome; got != plane.OutcomeWouldBlock {
			t.Fatalf("mode %q: outcome %s", mode, got)
		}
	}
	// The burn-in copy never blocks, whatever its listed mode.
	lines := mapFixture(t, fixtureMapper(map[string]string{"defenseclaw-controls-burnin-4e5f6a7b": "enforce"}), "tg2-session.jsonl")
	if got := one(t, lines[8]).Outcome; got != plane.OutcomeWouldBlock {
		t.Fatalf("burn-in outcome %s", got)
	}
}

func TestMapperMarksDefenseClawsOwnProcesses(t *testing.T) {
	mapper := NewMapper(MapperConfig{})
	for binary, self := range map[string]bool{
		"/opt/defenseclaw/bin/defenseclaw-gateway":       true,
		"/opt/defenseclaw/bin/defenseclaw-sensor-helper": true,
		"/home/dcr-std1/bin/defenseclaw-gateway":         false, // a look-alike outside the root-owned install
		"/opt/defenseclaw/bin/defenseclaw-hook":          false, // the hook is the join anchor, not self
	} {
		batch := mapper.Map(execOf(&pb.Process{ExecId: "x-" + binary, Binary: binary, Pid: u32(9)}, nil))
		if len(batch.Events) != 1 || batch.Events[0].Self != self {
			t.Fatalf("%s: %+v", binary, batch.Events)
		}
	}
}

func TestNotifyPrefix(t *testing.T) {
	for _, tc := range []struct {
		binary, args, want string
	}{
		{"/usr/bin/bash", fixtureHome + "/.defenseclaw/notify-bridge.sh {\"k\":\"dccert-payload-marker\"}", "/usr/bin/bash " + fixtureHome + "/.defenseclaw/notify-bridge.sh " + redaction.WithheldArgv},
		{fixtureHome + "/.defenseclaw/notify-bridge.sh", fixtureHome + "/.defenseclaw/notify-bridge.sh {\"k\":\"dccert-payload-marker\"}", fixtureHome + "/.defenseclaw/notify-bridge.sh " + redaction.WithheldArgv},
		{"/opt/defenseclaw/bin/defenseclaw-hook", "notify {\"k\":\"dccert-payload-marker\"}", "/opt/defenseclaw/bin/defenseclaw-hook notify " + redaction.WithheldArgv},
		{"/usr/local/bin/defenseclaw-hook", "notify {\"k\":\"dccert-payload-marker\"}", "/usr/local/bin/defenseclaw-hook notify " + redaction.WithheldArgv},
		{"/usr/bin/cat", "notes.txt", "/usr/bin/cat notes.txt"},
	} {
		got := commandLine(&pb.Process{Binary: tc.binary, Arguments: tc.args})
		if got != tc.want || strings.Contains(got, "dccert-payload-marker") {
			t.Fatalf("%s %s: %q, want %q", tc.binary, tc.args, got, tc.want)
		}
	}
}

// TestCommandLineRedactsQuotedWords: a secret at the edge of a quoted
// argument is still redacted, and the quotes stay where they were.
func TestCommandLineRedactsQuotedWords(t *testing.T) {
	for args, want := range map[string]string{
		`-c "--token=dccertvalue"`:                                         `/usr/bin/bash -c "--token=<redacted`,
		`-c "source x && eval 'tool --api-key dccertvalue' < /dev/null"`:   `eval 'tool --api-key <redacted`,
		`-c "curl -u dccert:dccertpass https://example.invalid/"`:          `-u dccert:<redacted`,
		`-c "git clone 'https://dccert:dccertpass@example.invalid/r.git'"`: `'https://dccert:<redacted`,
		`-c "cat /home/dcr-std1/tg2work/dccert-block-marker"`:              `-c "cat /home/dcr-std1/tg2work/dccert-block-marker"`,
	} {
		got := commandLine(&pb.Process{Binary: "/usr/bin/bash", Arguments: args})
		if strings.Contains(got, "dccertvalue") || strings.Contains(got, "dccertpass") || !strings.Contains(got, want) {
			t.Fatalf("%s: %q, want it to contain %q", args, got, want)
		}
	}
	long := commandLine(&pb.Process{Binary: "/usr/bin/bash", Arguments: strings.Repeat("é ", 2000)})
	if len(long) > MaxCmdlineBytes || !utf8.ValidString(long) {
		t.Fatalf("bound: %d bytes, valid %v", len(long), utf8.ValidString(long))
	}
}

func TestParseLossCounters(t *testing.T) {
	text := `# HELP tetragon_notify_overflowed_events_total Number of events dropped.
# TYPE tetragon_notify_overflowed_events_total counter
tetragon_notify_overflowed_events_total 12731
tetragon_bpf_missed_events_total{msg_op="5"} 400
tetragon_bpf_missed_events_total{msg_op="23"} 77
tetragon_ringbuf_queue_events_lost_total 3
tetragon_events_total{type="PROCESS_EXEC"} 999999
other_missed_events_total 5
`
	total, found := parseLossCounters(strings.NewReader(text))
	if !found || total != 12731+400+77+3 {
		t.Fatalf("total %d found %v", total, found)
	}
	if _, found := parseLossCounters(strings.NewReader("tetragon_events_total 1\n")); found {
		t.Fatal("counted a non-loss metric")
	}
}

func u32(v uint32) *wrapperspb.UInt32Value { return wrapperspb.UInt32(v) }

func execOf(process, parent *pb.Process) *pb.GetEventsResponse {
	return &pb.GetEventsResponse{Event: &pb.GetEventsResponse_ProcessExec{ProcessExec: &pb.ProcessExec{Process: process, Parent: parent}}}
}

func exitOf(process *pb.Process) *pb.GetEventsResponse {
	return &pb.GetEventsResponse{Event: &pb.GetEventsResponse_ProcessExit{ProcessExit: &pb.ProcessExit{Process: process}}}
}
