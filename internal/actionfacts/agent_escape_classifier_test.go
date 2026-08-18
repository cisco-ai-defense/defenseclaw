// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

func TestGitReadOutputOwnership(t *testing.T) {
	tests := []struct {
		name     string
		argv     []string
		status   ParseStatus
		wantPath string
	}{
		{
			name: "show writes before revision",
			argv: []string{
				"git", "show", "--format=[diff]external=bash", "--no-patch",
				"--output=./.git/config", "HEAD",
			},
			status: StatusComplete, wantPath: "./.git/config",
		},
		{
			name: "log separated output",
			argv: []string{
				"git", "log", "--output", ".git-alt/config", "HEAD",
			},
			status: StatusComplete, wantPath: ".git-alt/config",
		},
		{
			name: "diff writes hook",
			argv: []string{
				"git", "diff", "--output=.git/hooks/pre-commit", "HEAD^", "HEAD",
			},
			status: StatusComplete, wantPath: ".git/hooks/pre-commit",
		},
		{
			name: "diff writes hook after revisions",
			argv: []string{
				"git", "diff", "HEAD^", "HEAD", "--output=.git/hooks/pre-push",
			},
			status: StatusComplete, wantPath: ".git/hooks/pre-push",
		},
		{
			name: "whatchanged writes output",
			argv: []string{
				"git", "whatchanged", "--output=audit.txt", "HEAD",
			},
			status: StatusComplete, wantPath: "audit.txt",
		},
		{
			name: "output after revision remains a write",
			argv: []string{
				"git", "show", "HEAD", "--output=.git/config",
			},
			status: StatusComplete, wantPath: ".git/config",
		},
		{
			name: "unknown option makes output partial",
			argv: []string{
				"git", "show", "--output=.git/config", "--future-mode", "HEAD",
			},
			status: StatusPartial,
		},
		{
			name: "log-only option is not accepted by diff",
			argv: []string{
				"git", "diff", "--format=oneline", "--output=.git/config",
				"HEAD^", "HEAD",
			},
			status: StatusPartial,
		},
		{
			name: "delimiter makes output text an operand",
			argv: []string{
				"git", "show", "--", "--output=.git/config",
			},
			status: StatusComplete,
		},
		{
			name: "format value is not an output option",
			argv: []string{
				"git", "show", "--format=--output=.git/config", "HEAD",
			},
			status: StatusComplete,
		},
		{
			name: "short o is not the output option",
			argv: []string{
				"git", "show", "-o", ".git/config", "HEAD",
			},
			status: StatusPartial,
		},
		{
			name: "missing output value",
			argv: []string{
				"git", "show", "--output",
			},
			status: StatusPartial,
		},
		{
			name: "repeated output remains fallback",
			argv: []string{
				"git", "show", "--output=first", "--output=second", "HEAD",
			},
			status: StatusPartial,
		},
		{
			name: "format patch output directory is not read output",
			argv: []string{
				"git", "format-patch", "-o", ".git/hooks", "HEAD~3",
			},
			status: StatusPartial,
		},
		{
			name: "global paginate is not a write",
			argv: []string{
				"git", "--paginate", "show", "HEAD",
			},
			status: StatusComplete,
		},
		{
			name: "global working directory resolves output",
			argv: []string{
				"git", "-C", "project", "show", "--output=.git/config", "HEAD",
			},
			status: StatusComplete, wantPath: "project/.git/config",
		},
		{
			name: "joined global working directory resolves output",
			argv: []string{
				"git", "-Cproject", "diff", "--output=.git/hooks/pre-commit", "HEAD",
			},
			status: StatusComplete, wantPath: "project/.git/hooks/pre-commit",
		},
		{
			name: "joined git directory preserves output cwd",
			argv: []string{
				"git", "--git-dir=.git", "show", "--output=.git/config", "HEAD",
			},
			status: StatusComplete, wantPath: ".git/config",
		},
		{
			name: "separate git directory preserves output cwd",
			argv: []string{
				"git", "--git-dir", ".git", "show", "--output=.git/config", "HEAD",
			},
			status: StatusComplete, wantPath: ".git/config",
		},
		{
			name: "bare repository output path remains exact",
			argv: []string{
				"git", "--bare", "show", "--output=.git/config", "HEAD",
			},
			status: StatusComplete, wantPath: ".git/config",
		},
		{
			name: "dynamic global working directory stays unresolved",
			argv: []string{
				"git", "-C", "$PROJECT", "show", "--output=.git/config", "HEAD",
			},
			status: StatusPartial,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			out := classifyTestArgv(test.argv)
			if out.status != test.status || len(out.commands) != 1 {
				t.Fatalf("output=%#v", out)
			}
			command := out.commands[0]
			if test.wantPath != "" {
				if !commandHasOperation(command, OperationWrite) ||
					!outputHasPath(out, PathAccessWrite, test.wantPath) {
					t.Fatalf("output=%#v", out)
				}
				return
			}
			if commandHasOperation(command, OperationWrite) || len(out.paths) != 0 {
				t.Fatalf("non-owned output became a write: %#v", out)
			}
		})
	}
}

func TestGitReadOutputPathNormalization(t *testing.T) {
	inputs := map[string]Input{
		"structured argv": {
			Tool: "exec",
			Argv: []string{
				"git", "show", "--format=[diff]external=bash", "--no-patch",
				"--output=./metadata/../.git/config", "HEAD",
			},
			CWD: "/repo",
		},
		"raw POSIX": {
			Tool: "exec",
			Command: "git show --format='[diff]external=bash' --no-patch " +
				"--output=./metadata/../.git/config HEAD",
			CWD: "/repo",
		},
	}
	for name, input := range inputs {
		t.Run(name, func(t *testing.T) {
			facts := Analyze(input)
			if !facts.Authoritative() ||
				!factsHaveOperation(facts, OperationWrite) ||
				len(facts.Paths) != 1 {
				t.Fatalf("facts=%#v", facts)
			}
			got := facts.Paths[0]
			if got.Access != PathAccessWrite ||
				got.Normalized != ".git/config" ||
				got.Resolved != "/repo/.git/config" {
				t.Fatalf("path=%#v", got)
			}
		})
	}
}

func TestGitReadOutputWorkingDirectoryNormalization(t *testing.T) {
	for _, test := range []struct {
		name    string
		command string
		want    string
	}{
		{
			name:    "separate working directory",
			command: "git -C project diff --output=.git/hooks/pre-commit HEAD^ HEAD",
			want:    "/repo/project/.git/hooks/pre-commit",
		},
		{
			name:    "joined working directory",
			command: "git -Cproject show --output=.git/config HEAD",
			want:    "/repo/project/.git/config",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{
				Tool:    "exec",
				Command: test.command,
				CWD:     "/repo",
			})
			if !facts.Authoritative() || len(facts.Paths) != 1 {
				t.Fatalf("facts=%#v", facts)
			}
			if got := facts.Paths[0].Resolved; got != test.want {
				t.Fatalf("resolved path=%q, want %q", got, test.want)
			}
		})
	}
}

func TestGitReadOutputWindowsWorkingDirectoryNormalization(t *testing.T) {
	facts := Analyze(Input{
		Tool:        "powershell",
		Command:     `git -C project show --output=.git\config HEAD`,
		CWD:         `C:\repo`,
		DialectHint: DialectPowerShell,
	})
	if !facts.Authoritative() || len(facts.Paths) != 1 {
		t.Fatalf("facts=%#v", facts)
	}
	if got := facts.Paths[0].Resolved; got != "C:/repo/project/.git/config" {
		t.Fatalf("resolved path=%q", got)
	}
}

func TestContainerRuntimeSocketBindOwnership(t *testing.T) {
	tests := []struct {
		name      string
		argv      []string
		wantPath  string
		wantWrite bool
	}{
		{
			name: "docker socket volume",
			argv: []string{
				"docker", "run", "-v",
				"/var/run/docker.sock:/var/run/docker.sock", "alpine",
			},
			wantPath: "/var/run/docker.sock", wantWrite: true,
		},
		{
			name: "readonly containerd socket mount",
			argv: []string{
				"docker", "run", "--mount",
				"type=bind,source=/run/containerd/containerd.sock,target=/run/containerd/containerd.sock,readonly",
				"alpine",
			},
			wantPath: "/run/containerd/containerd.sock",
		},
		{
			name: "rootless podman socket mount",
			argv: []string{
				"podman", "run", "--mount",
				"type=bind,src=/run/user/1000/podman/podman.sock,dst=/run/podman/podman.sock",
				"alpine",
			},
			wantPath: "/run/user/1000/podman/podman.sock", wantWrite: true,
		},
		{
			name: "rootless docker socket mount",
			argv: []string{
				"docker", "run", "--mount",
				"type=bind,src=/run/user/1000/docker.sock,dst=/run/docker.sock",
				"alpine",
			},
			wantPath: "/run/user/1000/docker.sock", wantWrite: true,
		},
		{
			name: "normalized docker socket mount",
			argv: []string{
				"docker", "run", "-v",
				"/var/run/../run/docker.sock:/run/docker.sock", "alpine",
			},
			wantPath: "/var/run/../run/docker.sock", wantWrite: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			out := classifyTestArgv(test.argv)
			if out.status != StatusComplete || len(out.commands) != 1 ||
				!commandHasOperation(out.commands[0], OperationContainerRun) ||
				!commandHasOperation(out.commands[0], OperationConnect) ||
				!outputHasPath(out, PathAccessRead, test.wantPath) ||
				!outputHasPath(out, PathAccessConnect, test.wantPath) ||
				(outputHasPath(out, PathAccessWrite, test.wantPath) != test.wantWrite) {
				t.Fatalf("output=%#v", out)
			}
		})
	}

	nearMiss := classifyTestArgv([]string{
		"docker", "run", "-v", "/tmp/docker.sock:/run/docker.sock", "alpine",
	})
	if nearMiss.status != StatusComplete ||
		commandHasOperation(nearMiss.commands[0], OperationConnect) ||
		outputHasPath(nearMiss, PathAccessConnect, "/tmp/docker.sock") {
		t.Fatalf("near-miss socket became a connection: %#v", nearMiss)
	}

	for name, argv := range map[string][]string{
		"destination-only volume": {
			"docker", "run", "-v", "/var/run/docker.sock", "alpine",
		},
		"named volume mount": {
			"docker", "run", "--mount",
			"type=volume,source=/var/run/docker.sock,target=/run/docker.sock",
			"alpine",
		},
	} {
		t.Run(name, func(t *testing.T) {
			out := classifyTestArgv(argv)
			if out.status != StatusComplete ||
				commandHasOperation(out.commands[0], OperationConnect) ||
				len(out.paths) != 0 {
				t.Fatalf("non-bind socket text became a connection: %#v", out)
			}
		})
	}
}

func TestContainerPrivilegedBooleanGrammar(t *testing.T) {
	for _, value := range []string{
		"true", "TRUE", "True", "1", "t", "T",
		"false", "FALSE", "False", "0", "f", "F",
	} {
		t.Run(value, func(t *testing.T) {
			out := classifyTestArgv([]string{
				"docker", "run", "--privileged=" + value, "alpine",
			})
			if out.status != StatusComplete || len(out.commands) != 1 ||
				!commandHasOperation(out.commands[0], OperationContainerRun) ||
				commandHasOperation(out.commands[0], OperationConnect) {
				t.Fatalf("output=%#v", out)
			}
		})
	}

	invalid := classifyTestArgv([]string{
		"docker", "run", "--privileged=maybe", "alpine",
	})
	if invalid.status != StatusPartial {
		t.Fatalf("invalid boolean became authoritative: %#v", invalid)
	}
}
