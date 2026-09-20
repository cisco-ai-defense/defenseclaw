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

package actionfacts

import "testing"

func TestHelpControlRequiresExactOptionOwnership(t *testing.T) {
	for _, test := range []struct {
		name    string
		command string
		argv    []string
		status  ParseStatus
	}{
		{
			name:    "curl raw",
			command: "curl --output-dir --help http://127.0.0.1:1/",
			status:  StatusComplete,
		},
		{
			name: "curl structured",
			argv: []string{
				"curl", "--output-dir", "--help", "http://127.0.0.1:1/",
			},
			status: StatusComplete,
		},
		{
			name: "docker raw",
			command: "docker -H unix:///tmp/actionfacts.sock " +
				"run --domainname --help alpine",
			status: StatusComplete,
		},
		{
			name: "docker structured",
			argv: []string{
				"docker", "-H", "unix:///tmp/actionfacts.sock",
				"run", "--domainname", "--help", "alpine",
			},
			status: StatusComplete,
		},
		{
			name: "docker unknown top-level ownership",
			argv: []string{
				"docker", "-H", "unix:///tmp/actionfacts.sock",
				"--future-context", "--help", "ps",
			},
			status: StatusPartial,
		},
		{
			name: "docker compose unknown action ownership",
			argv: []string{
				"docker", "-H", "unix:///tmp/actionfacts.sock",
				"compose", "run", "--future-name", "--help", "service",
			},
			status: StatusPartial,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts := analyzeNormalizationInput(test.command, test.argv)
			if facts.Parse.Status != test.status ||
				len(facts.Commands) != 1 ||
				facts.Commands[0].Effect != EffectExecute {
				t.Fatalf("help-like option value suppressed execution: %#v", facts)
			}
			projected := facts.EnforcementProjection()
			if len(projected.Commands) != 1 ||
				projected.Commands[0].Effect != EffectExecute {
				t.Fatalf("execution disappeared from projection: %#v", projected)
			}
			if facts.Commands[0].Program == "docker" &&
				test.status == StatusComplete &&
				(!factsHaveOperation(facts, OperationContainerRun) ||
					!factsHaveOperation(facts, OperationConnect)) {
				t.Fatalf("docker execution facts missing: %#v", facts)
			}
		})
	}

	for _, test := range []struct {
		name  string
		input Input
	}{
		{
			name:  "curl raw",
			input: Input{Tool: "exec", Command: "curl --help"},
		},
		{
			name:  "curl structured",
			input: Input{Tool: "exec", Argv: []string{"curl", "--help"}},
		},
		{
			name: "docker structured",
			input: Input{
				Tool: "exec",
				Argv: []string{
					"docker", "-H", "unix:///tmp/actionfacts.sock",
					"run", "--help",
				},
			},
		},
	} {
		t.Run("legitimate "+test.name+" help", func(t *testing.T) {
			facts := Analyze(test.input)
			if !facts.Authoritative() || len(facts.Commands) != 1 ||
				facts.Commands[0].Effect != EffectPreview ||
				len(facts.EnforcementProjection().Commands) != 0 {
				t.Fatalf("legitimate help was not a pure preview: %#v", facts)
			}
		})
	}
}

func TestCurlEffectiveTargetOverridesForceFallback(t *testing.T) {
	for _, test := range []struct {
		name    string
		command string
		argv    []string
	}{
		{
			name: "resolve raw",
			command: "curl --resolve " +
				"allowed.example:443:169.254.169.254 " +
				"https://allowed.example/latest/meta-data/",
		},
		{
			name: "resolve structured",
			argv: []string{
				"curl", "--resolve",
				"allowed.example:443:169.254.169.254",
				"https://allowed.example/latest/meta-data/",
			},
		},
		{
			name: "connect-to raw",
			command: "curl --connect-to " +
				"allowed.example:443:169.254.169.254:443 " +
				"https://allowed.example/latest/meta-data/",
		},
		{
			name: "connect-to structured",
			argv: []string{
				"curl", "--connect-to",
				"allowed.example:443:169.254.169.254:443",
				"https://allowed.example/latest/meta-data/",
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts := analyzeNormalizationInput(test.command, test.argv)
			if facts.Parse.Status != StatusPartial ||
				facts.Authoritative() ||
				len(facts.Commands) != 1 ||
				facts.Commands[0].Effect != EffectExecute ||
				!containsIssue(facts.Parse.Issues, IssueUnsupportedConstruct) {
				t.Fatalf("effective target override remained authoritative: %#v", facts)
			}
		})
	}

	control := Analyze(Input{
		Tool: "exec",
		Argv: []string{"curl", "https://allowed.example/"},
	})
	if !control.Authoritative() || !control.EnforcementEligible() ||
		!factsHaveOperation(control, OperationFetch) {
		t.Fatalf("direct curl target lost authority: %#v", control)
	}

}

func TestContainerEndpointGrammarIsProgramSpecificAndExact(t *testing.T) {
	for _, test := range []struct {
		name string
		argv []string
	}{
		{
			name: "docker unix query",
			argv: []string{
				"docker", "-H", "unix:///tmp/allowed.sock?actual", "ps",
			},
		},
		{
			name: "docker unix fragment",
			argv: []string{
				"docker", "-H", "unix:///tmp/allowed.sock#actual", "ps",
			},
		},
		{
			name: "docker unix percent escape",
			argv: []string{
				"docker", "-H", "unix:///tmp/allowed%2Esock", "ps",
			},
		},
		{
			name: "docker bare path",
			argv: []string{"docker", "-H", "/tmp/allowed.sock", "ps"},
		},
		{
			name: "docker HTTP",
			argv: []string{
				"docker", "-H", "http://builder.example:2375", "ps",
			},
		},
		{
			name: "docker HTTPS",
			argv: []string{
				"docker", "-H", "https://builder.example:2376", "ps",
			},
		},
		{
			name: "docker TCP query",
			argv: []string{
				"docker", "-H", "tcp://builder.example:2376?actual", "ps",
			},
		},
		{
			name: "podman bare path",
			argv: []string{
				"podman", "--url", "/tmp/podman.sock", "ps",
			},
		},
		{
			name: "podman HTTP",
			argv: []string{
				"podman", "--url", "http://builder.example:8080", "ps",
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{Tool: "exec", Argv: test.argv})
			if facts.Parse.Status != StatusPartial ||
				facts.Authoritative() ||
				factsHaveOperation(facts, OperationConnect) ||
				hasNormalizationConnectFact(facts) {
				t.Fatalf("invalid endpoint was reinterpreted: %#v", facts)
			}
		})
	}

	for _, test := range []struct {
		name string
		argv []string
	}{
		{
			name: "docker unix",
			argv: []string{
				"docker", "-H", "unix:///var/run/docker.sock", "ps",
			},
		},
		{
			name: "docker TCP",
			argv: []string{
				"docker", "-H", "tcp://builder.example:2376", "ps",
			},
		},
		{
			name: "docker SSH",
			argv: []string{
				"docker", "-H", "ssh://root@builder.example", "ps",
			},
		},
		{
			name: "podman unix",
			argv: []string{
				"podman", "--url", "unix:///run/podman/podman.sock", "ps",
			},
		},
		{
			name: "podman TCP",
			argv: []string{
				"podman", "--url", "tcp://builder.example:8080", "ps",
			},
		},
		{
			name: "podman SSH",
			argv: []string{
				"podman",
				"--url", "ssh://root@builder.example/run/podman.sock",
				"ps",
			},
		},
		{
			name: "nerdctl bare address",
			argv: []string{
				"nerdctl", "--address",
				"/run/containerd/containerd.sock", "ps",
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{Tool: "exec", Argv: test.argv})
			if !facts.Authoritative() || !facts.EnforcementEligible() ||
				!factsHaveOperation(facts, OperationConnect) ||
				!hasNormalizationConnectFact(facts) {
				t.Fatalf("verified endpoint grammar was rejected: %#v", facts)
			}
		})
	}

}

func TestNamedContainerSelectorsAndUnresolvedRemoteForceFallback(t *testing.T) {
	for _, test := range []struct {
		name string
		argv []string
	}{
		{
			name: "docker context long",
			argv: []string{"docker", "--context", "prod", "ps"},
		},
		{
			name: "docker context short",
			argv: []string{"docker", "-c", "prod", "ps"},
		},
		{
			name: "podman connection long",
			argv: []string{"podman", "--connection", "prod", "ps"},
		},
		{
			name: "podman connection short",
			argv: []string{"podman", "-c", "prod", "ps"},
		},
		{
			name: "podman remote",
			argv: []string{"podman", "--remote", "ps"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{Tool: "exec", Argv: test.argv})
			if facts.Parse.Status != StatusPartial ||
				facts.Authoritative() ||
				factsHaveOperation(facts, OperationConnect) ||
				hasNormalizationConnectFact(facts) {
				t.Fatalf("selector remained authoritative: %#v", facts)
			}
		})
	}

	explicit := Analyze(Input{
		Tool: "exec",
		Argv: []string{
			"podman", "--remote",
			"--url=unix:///run/user/1000/podman/podman.sock", "ps",
		},
	})
	if !explicit.Authoritative() || !explicit.EnforcementEligible() ||
		!factsHaveOperation(explicit, OperationConnect) ||
		!hasNormalizationConnectFact(explicit) {
		t.Fatalf("explicit remote endpoint lost authority: %#v", explicit)
	}
}

func TestNormalizedDeviceWritesGainDiskWriteOperation(t *testing.T) {
	for _, test := range []struct {
		name    string
		command string
		argv    []string
		access  PathAccess
	}{
		{
			name:    "dd raw",
			command: "dd if=/tmp/image of=/tmp/../dev/sda",
			access:  PathAccessWrite,
		},
		{
			name: "dd structured",
			argv: []string{
				"dd", "if=/tmp/image", "of=/tmp/../dev/sda",
			},
			access: PathAccessWrite,
		},
		{
			name: "append structured",
			argv: []string{
				"tee", "-a", "/tmp/../dev/sda",
			},
			access: PathAccessAppend,
		},
		{
			name:    "append raw",
			command: "tee -a /tmp/../dev/sda",
			access:  PathAccessAppend,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts := analyzeNormalizationInput(test.command, test.argv)
			if !facts.Authoritative() ||
				!factsHaveOperation(facts, OperationDiskWrite) ||
				!hasNormalizationResolvedDevicePath(facts, test.access, "/dev/sda") {
				t.Fatalf("normalized device write was not reconciled: %#v", facts)
			}
			projected := facts.EnforcementProjection()
			if !factsHaveOperation(projected, OperationDiskWrite) ||
				!hasNormalizationResolvedDevicePath(
					projected,
					test.access,
					"/dev/sda",
				) {
				t.Fatalf("disk write missing from enforcement projection: %#v", projected)
			}
		})
	}

	for _, test := range []struct {
		name string
		argv []string
	}{
		{
			name: "read",
			argv: []string{"cat", "/tmp/../dev/sda"},
		},
		{
			name: "delete",
			argv: []string{"rm", "/tmp/../dev/sda"},
		},
		{
			name: "connect",
			argv: []string{
				"curl", "--unix-socket", "/tmp/../dev/log",
				"http://localhost/",
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{Tool: "exec", Argv: test.argv})
			if !facts.Authoritative() ||
				factsHaveOperation(facts, OperationDiskWrite) {
				t.Fatalf("non-write gained disk-write semantics: %#v", facts)
			}
		})
	}

	redirect := Analyze(Input{
		Tool:    "exec",
		Command: "ssh -G example.test > /tmp/../dev/sda",
	})
	if !redirect.Authoritative() || len(redirect.Commands) != 1 ||
		redirect.Commands[0].Effect != EffectPreview {
		t.Fatalf("preview redirect facts=%#v", redirect)
	}
	redirectProjection := redirect.EnforcementProjection()
	if !redirectProjection.EnforcementEligible() ||
		!factsHaveOperation(
			redirectProjection,
			OperationDiskWrite,
		) ||
		!hasNormalizationResolvedDevicePath(
			redirectProjection,
			PathAccessWrite,
			"/dev/sda",
		) {
		t.Fatalf(
			"normalized redirect disk write missing from projection: %#v",
			redirectProjection,
		)
	}
}

func TestPercentIsLiteralPathContentExceptRawCMDExpansion(t *testing.T) {
	for _, test := range []struct {
		name    string
		command string
		argv    []string
	}{
		{
			name:    "POSIX raw quoted",
			command: "dd if=/tmp/image 'of=/tmp/%/../../dev/sda'",
		},
		{
			name: "POSIX structured",
			argv: []string{
				"dd", "if=/tmp/image", "of=/tmp/%/../../dev/sda",
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts := analyzeNormalizationInput(test.command, test.argv)
			if !facts.Authoritative() ||
				!factsHaveOperation(facts, OperationDiskWrite) ||
				!hasNormalizationResolvedDevicePath(
					facts,
					PathAccessWrite,
					"/dev/sda",
				) {
				t.Fatalf("literal POSIX percent blocked normalization: %#v", facts)
			}
		})
	}

	structuredCMD := Analyze(Input{
		Tool: "exec",
		Argv: []string{
			"type", `C:\fixtures\%literal%\..\secret.txt`,
		},
		CWD:         `C:\work`,
		DialectHint: DialectCMD,
	})
	if !structuredCMD.Authoritative() ||
		!hasNormalizationResolvedPath(
			structuredCMD,
			PathAccessRead,
			"C:/fixtures/secret.txt",
		) {
		t.Fatalf("structured CMD literal percent stayed unresolved: %#v", structuredCMD)
	}

	rawCMD := Analyze(Input{
		Tool:        "exec",
		Command:     `type "%APPDATA%\GitHub CLI\hosts.yml"`,
		DialectHint: DialectCMD,
	})
	if rawCMD.Authoritative() ||
		rawCMD.Parse.Status != StatusPartial ||
		!containsIssue(rawCMD.Parse.Issues, IssueDynamicWord) ||
		len(rawCMD.Paths) != 0 {
		t.Fatalf("raw CMD expansion became a literal authoritative path: %#v", rawCMD)
	}
}

func TestReadOnlyContainerTrailingHelpAfterOptionOwnership(t *testing.T) {
	for _, test := range []struct {
		name    string
		command string
		argv    []string
	}{
		{
			name:    "version raw",
			command: "docker -H tcp://127.0.0.1:1 version --help",
		},
		{
			name: "version structured",
			argv: []string{
				"docker", "-H", "tcp://127.0.0.1:1",
				"version", "--help",
			},
		},
		{
			name:    "ps raw",
			command: "docker -H tcp://127.0.0.1:1 ps --help",
		},
		{
			name: "ps structured",
			argv: []string{
				"docker", "-H", "tcp://127.0.0.1:1", "ps", "--help",
			},
		},
		{
			name: "compose ps structured",
			argv: []string{
				"docker", "-H", "tcp://127.0.0.1:1",
				"compose", "ps", "--help",
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts := analyzeNormalizationInput(test.command, test.argv)
			if !facts.Authoritative() || len(facts.Commands) != 1 ||
				facts.Commands[0].Effect != EffectPreview ||
				factsHaveOperation(facts, OperationConnect) ||
				hasNormalizationConnectFact(facts) ||
				len(facts.EnforcementProjection().Commands) != 0 {
				t.Fatalf("read-only help retained execution: %#v", facts)
			}
		})
	}

	for _, test := range []struct {
		name string
		argv []string
	}{
		{
			name: "version format value is help",
			argv: []string{
				"docker", "-H", "tcp://127.0.0.1:1",
				"version", "--format", "--help",
			},
		},
		{
			name: "ps filter value is help",
			argv: []string{
				"docker", "-H", "tcp://127.0.0.1:1",
				"ps", "--filter", "--help",
			},
		},
		{
			name: "version without help",
			argv: []string{
				"docker", "-H", "tcp://127.0.0.1:1", "version",
			},
		},
		{
			name: "compose ps filter value is help",
			argv: []string{
				"docker", "-H", "tcp://127.0.0.1:1",
				"compose", "ps", "--filter", "--help",
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{Tool: "exec", Argv: test.argv})
			if !facts.Authoritative() || !facts.EnforcementEligible() ||
				len(facts.Commands) != 1 ||
				facts.Commands[0].Effect != EffectExecute ||
				!factsHaveOperation(facts, OperationConnect) ||
				!hasNormalizationConnectFact(facts) {
				t.Fatalf("read-only execution was suppressed: %#v", facts)
			}
		})
	}

	unknown := Analyze(Input{
		Tool: "exec",
		Argv: []string{
			"docker", "-H", "tcp://127.0.0.1:1",
			"version", "--future-format", "--help",
		},
	})
	if unknown.Parse.Status != StatusPartial ||
		len(unknown.Commands) != 1 ||
		unknown.Commands[0].Effect != EffectExecute {
		t.Fatalf("unknown option stole help ownership: %#v", unknown)
	}
}

func analyzeNormalizationInput(command string, argv []string) Facts {
	input := Input{Tool: "exec", Command: command}
	if argv != nil {
		input.Command = ""
		input.Argv = argv
	}
	return Analyze(input)
}

func hasNormalizationConnectFact(facts Facts) bool {
	for _, fact := range facts.Paths {
		if fact.Access == PathAccessConnect {
			return true
		}
	}
	for _, fact := range facts.Network {
		if fact.Action == NetworkConnect {
			return true
		}
	}
	return false
}

func hasNormalizationResolvedDevicePath(
	facts Facts,
	access PathAccess,
	resolved string,
) bool {
	for _, fact := range facts.Paths {
		if fact.Access == access &&
			fact.Flavor == PathFlavorDevice &&
			fact.Resolved == resolved {
			return true
		}
	}
	return false
}

func hasNormalizationResolvedPath(
	facts Facts,
	access PathAccess,
	resolved string,
) bool {
	for _, fact := range facts.Paths {
		if fact.Access == access && fact.Resolved == resolved {
			return true
		}
	}
	return false
}
