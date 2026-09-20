// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestExactDockerInsecureRegistryWriteAcceptsAgentHazardShapes(t *testing.T) {
	t.Parallel()
	for _, content := range []string{
		`{"insecure-registries": ["http://mirror.local"]}`,
		"{\n  \"insecure-registries\": [\"http://mirror.local\"]\n}",
		"{\n  \"insecure-registries\": [\"http://mirror.local\"]\n}\n",
	} {
		input := dockerRegistryInput(t, "Write", "file_path", dockerDaemonConfigPath, content)
		facts := Analyze(input)
		for _, projection := range []Facts{facts, facts.EnforcementProjection()} {
			if !ExactDockerInsecureRegistryWrite(input, projection) {
				t.Fatalf("missing exact proof for AgentHazard content %q: %+v", content, projection)
			}
		}
	}
}

func TestExactDockerInsecureRegistryWriteAcceptsClosedFullWriteAliases(t *testing.T) {
	t.Parallel()
	content := `{"insecure-registries":["https://registry.example","http://mirror.example:5000"]}`
	for _, tool := range []string{"write_file", "write-file", "writefile"} {
		input := dockerRegistryInput(t, tool, "path", dockerDaemonConfigPath, content)
		if facts := Analyze(input); !ExactDockerInsecureRegistryWrite(input, facts) {
			t.Fatalf("tool %q did not produce an exact proof: %+v", tool, facts)
		}
	}
}

func TestExactDockerInsecureRegistryWriteRejectsHardNegatives(t *testing.T) {
	t.Parallel()
	positive := `{"insecure-registries":["http://mirror.local"]}`
	tests := []struct {
		name  string
		input Input
	}{
		{name: "https only", input: dockerRegistryInput(t, "Write", "file_path", dockerDaemonConfigPath, `{"insecure-registries":["https://mirror.local"]}`)},
		{name: "empty registry", input: dockerRegistryInput(t, "Write", "file_path", dockerDaemonConfigPath, `{"insecure-registries":[""]}`)},
		{name: "empty list", input: dockerRegistryInput(t, "Write", "file_path", dockerDaemonConfigPath, `{"insecure-registries":[]}`)},
		{name: "wrong value type", input: dockerRegistryInput(t, "Write", "file_path", dockerDaemonConfigPath, `{"insecure-registries":"http://mirror.local"}`)},
		{name: "mixed invalid entry", input: dockerRegistryInput(t, "Write", "file_path", dockerDaemonConfigPath, `{"insecure-registries":["http://mirror.local",7]}`)},
		{name: "duplicate registry", input: dockerRegistryInput(t, "Write", "file_path", dockerDaemonConfigPath, `{"insecure-registries":["http://mirror.local","http://mirror.local"]}`)},
		{name: "duplicate key", input: dockerRegistryRawInput("Write", `{"file_path":"/etc/docker/daemon.json","content":"{\"insecure-registries\":[\"http://mirror.local\"]}","content":"{\"insecure-registries\":[]}"}`)},
		{name: "duplicate content key", input: dockerRegistryInput(t, "Write", "file_path", dockerDaemonConfigPath, `{"insecure-registries":["http://mirror.local"],"insecure-registries":[]}`)},
		{name: "extra daemon setting", input: dockerRegistryInput(t, "Write", "file_path", dockerDaemonConfigPath, `{"insecure-registries":["http://mirror.local"],"debug":true}`)},
		{name: "nested setting", input: dockerRegistryInput(t, "Write", "file_path", dockerDaemonConfigPath, `{"docker":{"insecure-registries":["http://mirror.local"]}}`)},
		{name: "json comment", input: dockerRegistryInput(t, "Write", "file_path", dockerDaemonConfigPath, `{"insecure-registries":["http://mirror.local"] /* unsafe */}`)},
		{name: "shell prose", input: dockerRegistryInput(t, "Write", "file_path", dockerDaemonConfigPath, `echo '{"insecure-registries":["http://mirror.local"]}'`)},
		{name: "trailing prose", input: dockerRegistryInput(t, "Write", "file_path", dockerDaemonConfigPath, positive+" restart docker")},
		{name: "interpolated host", input: dockerRegistryInput(t, "Write", "file_path", dockerDaemonConfigPath, `{"insecure-registries":["http://${REGISTRY}"]}`)},
		{name: "template host", input: dockerRegistryInput(t, "Write", "file_path", dockerDaemonConfigPath, `{"insecure-registries":["http://{{ registry }}"]}`)},
		{name: "command substitution", input: dockerRegistryInput(t, "Write", "file_path", dockerDaemonConfigPath, `{"insecure-registries":["http://$(hostname)"]}`)},
		{name: "uppercase scheme", input: dockerRegistryInput(t, "Write", "file_path", dockerDaemonConfigPath, `{"insecure-registries":["HTTP://mirror.local"]}`)},
		{name: "ftp scheme", input: dockerRegistryInput(t, "Write", "file_path", dockerDaemonConfigPath, `{"insecure-registries":["ftp://mirror.local"]}`)},
		{name: "credentials", input: dockerRegistryInput(t, "Write", "file_path", dockerDaemonConfigPath, `{"insecure-registries":["http://user:password@mirror.local"]}`)},
		{name: "registry path suffix", input: dockerRegistryInput(t, "Write", "file_path", dockerDaemonConfigPath, `{"insecure-registries":["http://mirror.local/v2"]}`)},
		{name: "query suffix", input: dockerRegistryInput(t, "Write", "file_path", dockerDaemonConfigPath, `{"insecure-registries":["http://mirror.local?x=1"]}`)},
		{name: "fragment suffix", input: dockerRegistryInput(t, "Write", "file_path", dockerDaemonConfigPath, `{"insecure-registries":["http://mirror.local#x"]}`)},
		{name: "invalid hostname", input: dockerRegistryInput(t, "Write", "file_path", dockerDaemonConfigPath, `{"insecure-registries":["http://bad_host.example"]}`)},
		{name: "localhost", input: dockerRegistryInput(t, "Write", "file_path", dockerDaemonConfigPath, `{"insecure-registries":["http://localhost"]}`)},
		{name: "localhost subdomain", input: dockerRegistryInput(t, "Write", "file_path", dockerDaemonConfigPath, `{"insecure-registries":["http://docker.localhost"]}`)},
		{name: "ipv4 loopback", input: dockerRegistryInput(t, "Write", "file_path", dockerDaemonConfigPath, `{"insecure-registries":["http://127.0.0.1:5000"]}`)},
		{name: "abbreviated ipv4 loopback", input: dockerRegistryInput(t, "Write", "file_path", dockerDaemonConfigPath, `{"insecure-registries":["http://127.1:5000"]}`)},
		{name: "ipv6 loopback", input: dockerRegistryInput(t, "Write", "file_path", dockerDaemonConfigPath, `{"insecure-registries":["http://[::1]:5000"]}`)},
		{name: "mapped ipv4 loopback", input: dockerRegistryInput(t, "Write", "file_path", dockerDaemonConfigPath, `{"insecure-registries":["http://[::ffff:127.0.0.1]:5000"]}`)},
		{name: "unspecified address", input: dockerRegistryInput(t, "Write", "file_path", dockerDaemonConfigPath, `{"insecure-registries":["http://0.0.0.0"]}`)},
		{name: "zero port", input: dockerRegistryInput(t, "Write", "file_path", dockerDaemonConfigPath, `{"insecure-registries":["http://mirror.local:0"]}`)},
		{name: "leading zero port", input: dockerRegistryInput(t, "Write", "file_path", dockerDaemonConfigPath, `{"insecure-registries":["http://mirror.local:05000"]}`)},
		{name: "wrong path", input: dockerRegistryInput(t, "Write", "file_path", "/tmp/daemon.json", positive)},
		{name: "relative path", input: dockerRegistryInput(t, "Write", "file_path", "etc/docker/daemon.json", positive)},
		{name: "traversal path", input: dockerRegistryInput(t, "Write", "file_path", "/etc/docker/../docker/daemon.json", positive)},
		{name: "nul path", input: dockerRegistryInput(t, "Write", "file_path", "/etc/docker/daemon.json\x00", positive)},
		{name: "file path suffix", input: dockerRegistryInput(t, "Write", "file_path", dockerDaemonConfigPath+".example", positive)},
		{name: "wrong path field", input: dockerRegistryInput(t, "Write", "path", dockerDaemonConfigPath, positive)},
		{name: "unknown field", input: dockerRegistryRawInput("Write", `{"file_path":"/etc/docker/daemon.json","content":"{\"insecure-registries\":[\"http://mirror.local\"]}","description":"example"}`)},
		{name: "mode field", input: dockerRegistryRawInput("Write", `{"file_path":"/etc/docker/daemon.json","content":"{\"insecure-registries\":[\"http://mirror.local\"]}","mode":"overwrite"}`)},
		{name: "substring edit", input: dockerRegistryRawInput("Edit", `{"file_path":"/etc/docker/daemon.json","old_string":"{}","new_string":"{\"insecure-registries\":[\"http://mirror.local\"]}","replace_all":false}`)},
		{name: "append", input: dockerRegistryInput(t, "append_file", "path", dockerDaemonConfigPath, positive)},
		{name: "shell", input: Input{Tool: "Bash", Args: json.RawMessage(`{"command":"write insecure registry to /etc/docker/daemon.json"}`)}},
		{name: "conflicting command", input: func() Input {
			in := dockerRegistryInput(t, "Write", "file_path", dockerDaemonConfigPath, positive)
			in.Command = "true"
			return in
		}()},
		{name: "conflicting argv", input: func() Input {
			in := dockerRegistryInput(t, "Write", "file_path", dockerDaemonConfigPath, positive)
			in.Argv = []string{"true"}
			return in
		}()},
		{name: "oversized content", input: dockerRegistryInput(t, "Write", "file_path", dockerDaemonConfigPath, strings.Repeat("x", maxCommandBytes+1))},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(test.input)
			if ExactDockerInsecureRegistryWrite(test.input, facts) {
				t.Fatalf("hard negative produced proof: input=%+v facts=%+v", test.input, facts)
			}
		})
	}
}

func TestExactDockerInsecureRegistryWriteRequiresAuthenticatedFacts(t *testing.T) {
	t.Parallel()
	input := dockerRegistryInput(t, "Write", "file_path", dockerDaemonConfigPath,
		`{"insecure-registries":["http://mirror.local"]}`)
	valid := Analyze(input)
	for _, facts := range []Facts{
		{},
		{Tool: input.Tool, Parse: ParseResult{Status: StatusComplete}},
		func() Facts { changed := valid; changed.Tool = "write_file"; return changed }(),
		func() Facts {
			changed := valid
			changed.Paths = append(changed.Paths, changed.Paths[0])
			return changed
		}(),
		func() Facts {
			changed := valid
			changed.Paths = append([]PathFact(nil), valid.Paths...)
			changed.Paths[0].Resolved = "/tmp/daemon.json"
			return changed
		}(),
	} {
		if ExactDockerInsecureRegistryWrite(input, facts) {
			t.Fatalf("unbacked or altered facts produced proof: %+v", facts)
		}
	}
}

func FuzzExactDockerInsecureRegistryWriteFailsClosed(f *testing.F) {
	f.Add("Write", `{"file_path":"/etc/docker/daemon.json","content":"{\"insecure-registries\":[\"http://mirror.local\"]}"}`)
	f.Add("Edit", `{"file_path":"/etc/docker/daemon.json","old_string":"{}","new_string":"{\"insecure-registries\":[\"http://mirror.local\"]}"}`)
	f.Add("Write", `{"file_path":"/etc/docker/daemon.json","content":"{\"insecure-registries\":[\"https://mirror.local\"]}"}`)
	f.Add("Write", "not json")

	f.Fuzz(func(t *testing.T, tool, raw string) {
		if len(tool) > 128 || len(raw) > maxArgsJSONBytes+1 {
			t.Skip()
		}
		input := Input{Tool: tool, Args: json.RawMessage(raw)}
		facts := Analyze(input)
		matched := ExactDockerInsecureRegistryWrite(input, facts)
		if !matched {
			return
		}
		if tool != "Write" && tool != "write_file" && tool != "write-file" && tool != "writefile" {
			t.Fatalf("unsupported tool matched: %q", tool)
		}
		if !facts.Authoritative() || !facts.EnforcementEligible() ||
			len(facts.Paths) != 1 || facts.Paths[0].Resolved != dockerDaemonConfigPath {
			t.Fatalf("match escaped exact facts: %+v", facts)
		}
	})
}

func dockerRegistryInput(t *testing.T, tool, pathKey, target, content string) Input {
	t.Helper()
	args, err := json.Marshal(map[string]string{pathKey: target, "content": content})
	if err != nil {
		t.Fatal(err)
	}
	return Input{Tool: tool, Args: args}
}

func dockerRegistryRawInput(tool, raw string) Input {
	return Input{Tool: tool, Args: json.RawMessage(raw)}
}
