// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

func TestStrictSensitivePathPrecision(t *testing.T) {
	const connector = "strict-sensitive-path-precision"
	installToolCallCorpusProfileConnector(t, connector, "strict")

	tests := []struct {
		name    string
		input   actionfacts.Input
		present string
		absent  string
	}{
		{
			name:   "authorized keys read is quiet",
			input:  sensitivePathShellInput("cat /home/alice/.ssh/authorized_keys"),
			absent: "PATH-SSH-DIR",
		},
		{
			name: "structured authorized keys write remains visible",
			input: actionfacts.Input{
				Tool:       "write_file",
				Args:       sensitivePathArgs(t, "/home/alice/.ssh/authorized_keys", "fixture key"),
				ActiveHome: "/home/alice",
			},
			present: "PATH-SSH-DIR",
		},
		{
			name: "structured authorized keys delete remains visible",
			input: actionfacts.Input{
				Tool:       "delete_file",
				Args:       sensitivePathArgs(t, "/home/alice/.ssh/authorized_keys", ""),
				ActiveHome: "/home/alice",
			},
			present: "PATH-SSH-DIR",
		},
		{
			name:   "sudoers read is quiet",
			input:  sensitivePathShellInput("cat /etc/sudoers"),
			absent: "PATH-ETC-SUDOERS",
		},
		{
			name:    "sudoers mutation remains visible",
			input:   sensitivePathShellInput("printf configured > /etc/sudoers.d/opsbot"),
			present: "PATH-ETC-SUDOERS",
		},
		{
			name:    "sudoers delete remains visible",
			input:   sensitivePathShellInput("rm /etc/sudoers.d/opsbot"),
			present: "PATH-ETC-SUDOERS",
		},
		{
			name:   "passwd full read is quiet",
			input:  sensitivePathShellInput("cat /etc/passwd"),
			absent: "PATH-ETC-PASSWD",
		},
		{
			name:   "passwd targeted lookup is quiet",
			input:  sensitivePathShellInput("grep -q '^opsbot:' /etc/passwd"),
			absent: "PATH-ETC-PASSWD",
		},
		{
			name: "structured passwd mutation remains visible",
			input: actionfacts.Input{
				Tool: "write_file",
				Args: sensitivePathArgs(t, "/etc/passwd", "service account record"),
			},
			present: "PATH-ETC-PASSWD",
		},
		{
			name: "structured passwd delete remains visible",
			input: actionfacts.Input{
				Tool: "delete_file",
				Args: sensitivePathArgs(t, "/etc/passwd", ""),
			},
			present: "PATH-ETC-PASSWD",
		},
		{
			name:   "shadow targeted account check is quiet",
			input:  sensitivePathShellInput("grep -q '^opsbot:' /etc/shadow"),
			absent: "PATH-ETC-SHADOW",
		},
		{
			name:    "shadow full credential read remains visible",
			input:   sensitivePathShellInput("cat /etc/shadow"),
			present: "PATH-ETC-SHADOW",
		},
		{
			name: "structured shadow read remains visible",
			input: actionfacts.Input{
				Tool: "read_file",
				Args: sensitivePathArgs(t, "/etc/shadow", ""),
			},
			present: "PATH-ETC-SHADOW",
		},
		{
			name: "structured shadow mutation remains visible",
			input: actionfacts.Input{
				Tool: "write_file",
				Args: sensitivePathArgs(t, "/etc/shadow", "locked account record"),
			},
			present: "PATH-ETC-SHADOW",
		},
		{
			name: "structured shadow delete remains visible",
			input: actionfacts.Input{
				Tool: "delete_file",
				Args: sensitivePathArgs(t, "/etc/shadow", ""),
			},
			present: "PATH-ETC-SHADOW",
		},
		{
			name:   "shadow path mention is quiet",
			input:  sensitivePathShellInput("printf '%s\\n' '/etc/shadow'"),
			absent: "PATH-ETC-SHADOW",
		},
		{
			name: "environment file read remains visible",
			input: actionfacts.Input{
				Tool: "read_file",
				Args: sensitivePathArgs(t, "/repo/.env", ""),
				CWD:  "/repo",
			},
			present: "PATH-ENV-FILE",
		},
		{
			name: "environment file write is quiet",
			input: actionfacts.Input{
				Tool: "write_file",
				Args: sensitivePathArgs(t, "/repo/.env", "example configuration"),
				CWD:  "/repo",
			},
			absent: "PATH-ENV-FILE",
		},
		{
			name: "fixture environment read is quiet",
			input: actionfacts.Input{
				Tool: "read_file",
				Args: sensitivePathArgs(t, "/repo/testdata/.env", ""),
				CWD:  "/repo",
			},
			absent: "PATH-ENV-FILE",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input:              test.input,
				LegacyText:         test.input.Command,
				Connector:          connector,
				EnforcementCapable: true,
			})
			if test.present != "" && findingWithID(findings, test.present) == nil {
				t.Fatalf("missing %s finding: %+v", test.present, findings)
			}
			if test.absent != "" && findingWithID(findings, test.absent) != nil {
				t.Fatalf("unexpected %s finding: %+v", test.absent, findings)
			}
		})
	}
}

func sensitivePathShellInput(command string) actionfacts.Input {
	return actionfacts.Input{
		Tool:        "shell",
		Command:     command,
		CWD:         "/repo",
		ActiveHome:  "/home/alice",
		DialectHint: actionfacts.DialectPOSIX,
	}
}

func sensitivePathArgs(t *testing.T, target, content string) json.RawMessage {
	t.Helper()
	args := map[string]string{"path": target}
	if content != "" {
		args["content"] = content
	}
	encoded, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
