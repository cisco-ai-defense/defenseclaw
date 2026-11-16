// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func macAgentSessionHost(t *testing.T) (*testHost, time.Time, time.Time) {
	t.Helper()
	h := newTestHost(t, "darwin")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	record, err := h.env.loadDeployment()
	if err != nil || record == nil {
		t.Fatalf("no deployment: %v", err)
	}
	activationTime := record.ActivatedAt
	if activationTime == "" {
		activationTime = record.InstalledAt
	}
	activated, err := time.Parse(time.RFC3339Nano, activationTime)
	if err != nil {
		t.Fatal(err)
	}
	restored := activated.Add(10 * time.Minute)
	h.env.Now = func() time.Time { return activated.Add(12 * time.Minute) }
	uid := os.Getuid()
	writeHostFile(t, h, filepath.Join(h.env.Layout.DataDir, guardianRestoresFile), fmt.Sprintf(
		`{"version":1,"targets":[{"uid":%d,"connector":"hermes","restored_at":%q}]}`,
		uid, restored.UTC().Format(time.RFC3339Nano)))
	return h, activated, restored
}

func setDarwinProcessArgv(t *testing.T, read func(int) ([]string, error)) {
	t.Helper()
	previous := darwinProcessArgv
	darwinProcessArgv = read
	t.Cleanup(func() { darwinProcessArgv = previous })
}

func TestMacHermesSessionBeforeGuardianRestore(t *testing.T) {
	for _, tc := range []struct {
		name string
		read func(int) ([]string, error)
	}{
		{"real argv", func(int) ([]string, error) {
			return []string{"/Users/u/.hermes/tools/python/bin/python3", "-I", "-c", "import os\nfrom hermes_cli.main import main\nmain()"}, nil
		}},
		{"ps fallback", func(int) ([]string, error) { return nil, errors.New("argv unavailable") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, _, restored := macAgentSessionHost(t)
			setDarwinProcessArgv(t, tc.read)
			uid := os.Getuid()
			psLine := func(pid int, elapsed string) string {
				return fmt.Sprintf("%d %d %s /Users/u/.hermes/tools/python/bin/python3 -I -c import os from hermes_cli.main import main", pid, uid, elapsed)
			}
			h.runner.ps = strings.Join([]string{psLine(6001, "00:11:00"), psLine(6002, "00:01:00")}, "\n")
			sessions := h.env.agentSessionsStartedBefore(context.Background(), restored, 0)
			if len(sessions) != 1 || sessions[0].Agent != "hermes" || sessions[0].PID != 6001 {
				t.Fatalf("sessions before restore: %+v", sessions)
			}
			for _, action := range []string{ActionStatus, ActionVerify} {
				result := h.run(Options{Action: action})
				warning := messagesOf(result.Warnings, codeAgentSessionsRestart)
				if !strings.Contains(warning, "hermes (pid 6001)") || strings.Contains(warning, "6002") || !strings.Contains(warning, "put back") {
					t.Fatalf("%s warning: %q", action, warning)
				}
				if result.SecurityComplete {
					t.Fatalf("%s marked security complete with an older Hermes session", action)
				}
			}
			if tc.name == "real argv" {
				// The sysctl vector is authoritative even when ps cannot show the code.
				h.runner.ps = fmt.Sprintf("6001 %d 00:11:00 python3 -I -c import os", uid)
				if got := h.env.agentSessionsStartedBefore(context.Background(), restored, 0); len(got) != 1 || got[0].Agent != "hermes" {
					t.Fatalf("real argv was not used when ps omitted the module: %+v", got)
				}
			}
			h.runner.ps = psLine(6002, "00:01:00")
			if warning := messagesOf(h.run(Options{Action: ActionStatus}).Warnings, codeAgentSessionsRestart); warning != "" {
				t.Fatalf("newer Hermes session named: %q", warning)
			}
		})
	}
}

func TestMacUnreadableAgentShapedSession(t *testing.T) {
	h, activated, _ := macAgentSessionHost(t)
	setDarwinProcessArgv(t, func(int) ([]string, error) { return nil, errors.New("argv unavailable") })
	for _, tc := range []struct {
		name      string
		elapsed   string
		command   string
		wantAlert bool
	}{
		{"before restore", "00:11:00", "(python3)", true},
		{"before activation", "00:13:00", "(node)", true},
		{"after restore", "00:01:00", "(python3)", false},
		{"readable nonagent", "00:11:00", "python3 -c print(1)", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h.runner.ps = fmt.Sprintf("6101 %d %s %s", os.Getuid(), tc.elapsed, tc.command)
			for _, action := range []string{ActionStatus, ActionVerify} {
				result := h.run(Options{Action: action})
				warning := messagesOf(result.Warnings, codeAgentSessionsRestart)
				if tc.wantAlert {
					if !strings.Contains(warning, "restart status unknown") || !strings.Contains(warning, "unknown agent (pid 6101)") || result.SecurityComplete {
						t.Fatalf("%s missing unknown warning: %q (security_complete=%v)", action, warning, result.SecurityComplete)
					}
				} else if warning != "" {
					t.Fatalf("%s named a classified or newer process: %q", action, warning)
				}
			}
		})
	}
	h.runner.ps = fmt.Sprintf("6101 %d 00:11:00 (python3)\n6102 %d 00:11:00 (node)", os.Getuid(), os.Getuid())
	result := h.run(Options{Action: ActionStatus})
	count := 0
	for _, warning := range result.Warnings {
		if warning.Code == codeAgentSessionsRestart {
			count++
		}
	}
	if count != 1 || !strings.Contains(messagesOf(result.Warnings, codeAgentSessionsRestart), "pid 6102") {
		t.Fatalf("unknown sessions should share one account warning: %+v", result.Warnings)
	}
	writeHostFile(t, h, filepath.Join(h.env.Layout.DataDir, guardianRestoresFile), fmt.Sprintf(
		`{"version":1,"targets":[{"uid":%d,"connector":"codex","restored_at":%q}]}`,
		os.Getuid(), activated.Add(10*time.Minute).UTC().Format(time.RFC3339Nano)))
	h.runner.ps = fmt.Sprintf("6101 %d 00:11:00 (python3)", os.Getuid())
	if warning := messagesOf(h.run(Options{Action: ActionStatus}).Warnings, codeAgentSessionsRestart); !strings.Contains(warning, "restart status unknown") {
		t.Fatalf("unknown session omitted for a restore of another connector: %q", warning)
	}
}

func TestParseProcArgs2(t *testing.T) {
	valid := make([]byte, 4)
	binary.LittleEndian.PutUint32(valid, 3)
	valid = append(valid, []byte("/usr/bin/python3\x00\x00\x00/usr/bin/python3\x00-c\x00import os\nfrom hermes_cli.main import main\x00")...)
	tooMany := append([]byte(nil), valid...)
	binary.LittleEndian.PutUint32(tooMany, 1000)
	zeroArgs := append([]byte(nil), valid...)
	binary.LittleEndian.PutUint32(zeroArgs, 0)
	for _, tc := range []struct {
		name string
		data []byte
		want []string
	}{
		{"valid", valid, []string{"/usr/bin/python3", "-c", "import os\nfrom hermes_cli.main import main"}},
		{"argc larger than data", tooMany, nil},
		{"zero argc", zeroArgs, nil},
		{"empty", nil, nil},
		{"truncated", valid[:len(valid)-1], nil},
		{"oversized", make([]byte, maxProcArgs2Bytes+5), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseProcArgs2(tc.data)
			if tc.want == nil {
				if err == nil {
					t.Fatalf("accepted malformed procargs2: %q", got)
				}
			} else if err != nil || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("parseProcArgs2 = %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

func TestAgentCLIOfScriptControls(t *testing.T) {
	for _, tc := range []struct {
		name string
		argv []string
		want string
	}{
		{"unrelated code", []string{"python3", "-c", "print(1)"}, ""},
		{"unrelated module", []string{"python3", "-m", "http.server"}, ""},
		{"claude", []string{"claude", "--resume"}, "claude"},
		{"codex", []string{"codex", "exec"}, "codex"},
		{"Antigravity CLI", []string{"agy", "--headless"}, "agy"},
		{"Antigravity IDE", []string{"antigravity", "--type=renderer"}, ""},
		{"Antigravity IDE helper", []string{"/opt/Antigravity/antigravity", "--type=gpu-process"}, ""},
		{"hermes module", []string{"python3", "-m", "hermes_cli"}, "hermes"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := agentCLIOf(tc.argv); got != tc.want {
				t.Fatalf("agentCLIOf(%q) = %q, want %q", tc.argv, got, tc.want)
			}
		})
	}
}

func TestDarwinRestartScanKeepsPsRowsOnNonzeroExit(t *testing.T) {
	h, _, restored := macAgentSessionHost(t)
	setDarwinProcessArgv(t, func(int) ([]string, error) { return []string{"hermes"}, nil })
	h.runner.replies = map[string]fakeReply{
		"ps -axww -o pid=,uid=,etime=,args=": {
			result: CommandResult{Stdout: []byte(fmt.Sprintf("6101 %d 00:11:00 hermes\n", os.Getuid()))},
			err:    errors.New("ps exited after printing rows"),
		},
	}
	if sessions := h.env.agentSessionsStartedBefore(context.Background(), restored, 0); len(sessions) != 1 || sessions[0].PID != 6101 {
		t.Fatalf("restart scan dropped ps output: %+v", sessions)
	}
	if _, err := h.env.darwinAgentSessionsWithError(context.Background()); err == nil {
		t.Fatal("launch coverage scan treated a nonzero ps exit as verified")
	}
}
