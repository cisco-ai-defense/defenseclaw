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
		{name: "empty registry", input: dockerRegistryInput(t, "Write", "file_path", dockerDaemonConfigPath, `{"insecure-registries":[""]}`)},
		{name: "empty list", input: dockerRegistryInput(t, "Write", "file_path", dockerDaemonConfigPath, `{"insecure-registries":[]}`)},
		{name: "wrong value type", input: dockerRegistryInput(t, "Write", "file_path", dockerDaemonConfigPath, `{"insecure-registries":"http://mirror.local"}`)},
		{name: "mixed invalid entry", input: dockerRegistryInput(t, "Write", "file_path", dockerDaemonConfigPath, `{"insecure-registries":["http://mirror.local",7]}`)},
		{name: "duplicate key", input: dockerRegistryRawInput("Write", `{"file_path":"/etc/docker/daemon.json","content":"{\"insecure-registries\":[\"http://mirror.local\"]}","content":"{\"insecure-registries\":[]}"}`)},
		{name: "duplicate content key", input: dockerRegistryInput(t, "Write", "file_path", dockerDaemonConfigPath, `{"insecure-registries":["http://mirror.local"],"insecure-registries":[]}`)},
		{name: "nested setting", input: dockerRegistryInput(t, "Write", "file_path", dockerDaemonConfigPath, `{"docker":{"insecure-registries":["http://mirror.local"]}}`)},
		{name: "json comment", input: dockerRegistryInput(t, "Write", "file_path", dockerDaemonConfigPath, `{"insecure-registries":["http://mirror.local"] /* unsafe */}`)},
		{name: "shell prose", input: dockerRegistryInput(t, "Write", "file_path", dockerDaemonConfigPath, `echo '{"insecure-registries":["http://mirror.local"]}'`)},
		{name: "trailing prose", input: dockerRegistryInput(t, "Write", "file_path", dockerDaemonConfigPath, positive+" restart docker")},
		{name: "interpolated host", input: dockerRegistryInput(t, "Write", "file_path", dockerDaemonConfigPath, `{"insecure-registries":["http://${REGISTRY}"]}`)},
		{name: "template host", input: dockerRegistryInput(t, "Write", "file_path", dockerDaemonConfigPath, `{"insecure-registries":["http://{{ registry }}"]}`)},
		{name: "command substitution", input: dockerRegistryInput(t, "Write", "file_path", dockerDaemonConfigPath, `{"insecure-registries":["http://$(hostname)"]}`)},
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
		{name: "wrong path", input: dockerRegistryInput(t, "Write", "file_path", "/tmp/daemon.json", positive)},
		{name: "relative path", input: dockerRegistryInput(t, "Write", "file_path", "etc/docker/daemon.json", positive)},
		{name: "nul path", input: dockerRegistryInput(t, "Write", "file_path", "/etc/docker/daemon.json\x00", positive)},
		{name: "file path suffix", input: dockerRegistryInput(t, "Write", "file_path", dockerDaemonConfigPath+".example", positive)},
		{name: "wrong path field", input: dockerRegistryInput(t, "Write", "path", dockerDaemonConfigPath, positive)},
		{name: "unknown field", input: dockerRegistryRawInput("Write", `{"file_path":"/etc/docker/daemon.json","content":"{\"insecure-registries\":[\"http://mirror.local\"]}","description":"example"}`)},
		{name: "mode field", input: dockerRegistryRawInput("Write", `{"file_path":"/etc/docker/daemon.json","content":"{\"insecure-registries\":[\"http://mirror.local\"]}","mode":"overwrite"}`)},
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
		if len(nativeFileWrites(tool, input.Args)) == 0 {
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

// dockerInsecureRegistrySpellings are the forms Docker accepts for a
// non-loopback insecure registry.
var dockerInsecureRegistrySpellings = []string{
	"http://198.51.100.7:5000",
	"https://198.51.100.7:5000",
	"https://mirror.example",
	"198.51.100.7:5000",
	"198.51.100.7",
	"mirror.example",
	"Mirror.Example:5000",
	"registry.corp.example:443",
	"[2001:db8::7]:5000",
	"2001:db8::7",
	"http://[2001:db8::7]:5000",
	"198.51.100.0/24",
	"10.0.0.0/8",
	"192.168.0.5/16",
	"0.0.0.0/0",
	"126.0.0.0/7",
	"2001:db8::/32",
	"::/0",
	"::ffff:198.51.100.0/120",
	"::ffff:0:0/80",
	"::ffff:198.51.100.7",
	// Docker lower-cases the scheme and reads the port as a decimal number.
	"HTTP://198.51.100.7:5000",
	"HTTPS://Mirror.Example",
	"Http://198.51.100.7:5000",
	"http://198.51.100.7:5000/",
	"http://mirror.example:05000",
	"198.51.100.7:05000",
	"198.51.100.7:0005000",
	"198.51.100.7:00000000000000000005000",
	"http://198.51.100.7:00000000000000000005000",
	"[2001:db8::7]:00000000000000000005000",
	"198.51.100.7:+5000",
	"198.51.100.7:0",
	"mirror.example:00080",
}

// TestExactDockerInsecureRegistryWriteReadsEverySpelling pins that the
// spelling of an insecure-registries entry never decides the verdict: every
// form Docker accepts for a non-loopback registry is proved, the http:// URL
// form included.
func TestExactDockerInsecureRegistryWriteReadsEverySpelling(t *testing.T) {
	t.Parallel()
	for _, entry := range dockerInsecureRegistrySpellings {
		content := `{"insecure-registries":[` + jsonString(t, entry) + `]}`
		input := dockerRegistryInput(t, "Write", "file_path", dockerDaemonConfigPath, content)
		facts := Analyze(input)
		for _, projection := range []Facts{facts, facts.EnforcementProjection()} {
			if !ExactDockerInsecureRegistryWrite(input, projection) {
				t.Errorf("entry %q: missing exact proof", entry)
			}
		}
	}
}

// dockerAllowedRegistrySpellings are loopback entries, which Docker already
// trusts, and entries the closed grammar cannot prove.
var dockerAllowedRegistrySpellings = []string{
	"localhost",
	"localhost:5000",
	"docker.localhost:5000",
	"127.0.0.1",
	"127.0.0.1:5000",
	"127.1.2.3:5000",
	"[::1]:5000",
	"::1",
	"::ffff:127.0.0.1",
	"127.0.0.0/8",
	"127.0.0.0/24",
	"127.0.0.1/32",
	"::1/128",
	"::ffff:127.0.0.0/104",
	"0.0.0.0",
	"0.0.0.0:5000",
	"0.0.0.0/32",
	"http://localhost:5000",
	"https://127.0.0.1:5000",
	// Not provable in the closed grammar, so the document is not proven.
	"",
	":5000",
	"198.51.100.7:",
	"198.51.100.7:70000",
	"198.51.100.7:5000:5000",
	"[198.51.100.7]:5000",
	"[2001:db8::7]",
	"fe80::1%eth0",
	"fe80::1%eth0/64",
	"198.51.100.0/33",
	"198.51.100.0/",
	"/24",
	"127.1",
	"127.1:5000",
	"2130706433",
	"mirror.example.",
	"bad_host.example",
	"-mirror.example",
	"mirror.example/path",
	"mirror.example/v2",
	"user@mirror.example",
	"mirror.example?x=1",
	"mirror example",
	"${REGISTRY}",
	"$(hostname):5000",
	"{{ registry }}:5000",
	"ftp://mirror.example",
	"unix:///var/run/registry.sock",
}

// TestExactDockerInsecureRegistryWriteKeepsLoopbackAndBenignAllowed pins the
// other side: Docker already trusts loopback, so loopback entries in any
// spelling, a daemon.json without insecure registries, and entries the closed
// grammar cannot prove all stay allowed.
func TestExactDockerInsecureRegistryWriteKeepsLoopbackAndBenignAllowed(t *testing.T) {
	t.Parallel()
	for _, entry := range dockerAllowedRegistrySpellings {
		content := `{"insecure-registries":[` + jsonString(t, entry) + `]}`
		input := dockerRegistryInput(t, "Write", "file_path", dockerDaemonConfigPath, content)
		facts := Analyze(input)
		if ExactDockerInsecureRegistryWrite(input, facts) {
			t.Errorf("entry %q produced a proof", entry)
		}
	}
	for _, content := range []string{
		`{"log-driver":"json-file"}`,
		`{"log-driver":"json-file","log-opts":{"max-size":"10m"}}`,
		`{"insecure-registries":[]}`,
		`{"registry-mirrors":["https://mirror.example"]}`,
		`{}`,
	} {
		input := dockerRegistryInput(t, "Write", "file_path", dockerDaemonConfigPath, content)
		if facts := Analyze(input); ExactDockerInsecureRegistryWrite(input, facts) {
			t.Errorf("benign document %q produced a proof", content)
		}
	}
}

// TestExactDockerInsecureRegistryWriteJudgesEveryEntry pins that one remote
// registry decides the document even when other entries are loopback, and
// that one entry the grammar cannot prove still leaves the document unproven.
// A registry listed twice is one registry, as Docker reads it.
func TestExactDockerInsecureRegistryWriteJudgesEveryEntry(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name    string
		entries string
		want    bool
	}{
		{"loopback then remote host port", `"127.0.0.1:5000","198.51.100.7:5000"`, true},
		{"remote host port then loopback url", `"198.51.100.7:5000","http://localhost:5000"`, true},
		{"remote cidr and loopback cidr", `"127.0.0.0/8","10.0.0.0/8"`, true},
		{"mixed spellings", `"198.51.100.7:5000","http://mirror.example","10.1.0.0/16"`, true},
		{"loopback only", `"127.0.0.1:5000","localhost","::1"`, false},
		{"remote and unprovable entry", `"198.51.100.7:5000","bad_host.example"`, false},
		{"remote and non-string entry", `"198.51.100.7:5000",7`, false},
		{"duplicate entry", `"198.51.100.7:5000","198.51.100.7:5000"`, true},
		{"duplicate loopback entry", `"127.0.0.1:5000","127.0.0.1:5000"`, false},
	} {
		input := dockerRegistryInput(t, "Write", "file_path", dockerDaemonConfigPath,
			`{"insecure-registries":[`+test.entries+`]}`)
		if got := ExactDockerInsecureRegistryWrite(input, Analyze(input)); got != test.want {
			t.Errorf("%s: proof=%t, want %t", test.name, got, test.want)
		}
	}
}

func jsonString(t *testing.T, value string) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

// TestExactDockerInsecureRegistryWriteJudgesTheWholeDocument pins that the
// other settings of a daemon.json, a registry listed twice and a repeated key
// never decide the verdict: the document is judged by the insecure-registries
// list dockerd reads from it.
func TestExactDockerInsecureRegistryWriteJudgesTheWholeDocument(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name, content string
		want          bool
	}{
		{"setting after the list", `{"insecure-registries":["198.51.100.7:5000"],"debug":true}`, true},
		{"setting before the list", `{"log-driver":"json-file","insecure-registries":["http://198.51.100.7:5000"]}`, true},
		{"pretty printed with settings", "{\n  \"debug\": true,\n  \"log-driver\": \"json-file\",\n  \"insecure-registries\": [\n    \"198.51.100.7:5000\"\n  ]\n}\n", true},
		{"settings with an object value", `{"log-opts":{"max-size":"10m"},"insecure-registries":["10.0.0.0/8"]}`, true},
		{"the same entry twice", `{"insecure-registries":["198.51.100.7:5000","198.51.100.7:5000"]}`, true},
		{"repeated key, the last holds the registry", `{"insecure-registries":[],"insecure-registries":["198.51.100.7:5000"]}`, true},
		{"repeated key, the last is empty", `{"insecure-registries":["198.51.100.7:5000"],"insecure-registries":[]}`, false},
		{"settings and no list", `{"debug":true,"log-driver":"json-file"}`, false},
		{"settings and a loopback list", `{"debug":true,"insecure-registries":["127.0.0.1:5000"]}`, false},
		{"settings and an empty list", `{"debug":true,"insecure-registries":[]}`, false},
		{"list of another type", `{"debug":true,"insecure-registries":"198.51.100.7:5000"}`, false},
		{"list with a number", `{"insecure-registries":["198.51.100.7:5000",7]}`, false},
		{"key in another case", `{"Insecure-Registries":["198.51.100.7:5000"]}`, false},
		{"key one level down", `{"log-opts":{"insecure-registries":["198.51.100.7:5000"]}}`, false},
		{"array document", `[{"insecure-registries":["198.51.100.7:5000"]}]`, false},
	} {
		input := dockerRegistryInput(t, "Write", "file_path", dockerDaemonConfigPath, test.content)
		if got := ExactDockerInsecureRegistryWrite(input, Analyze(input)); got != test.want {
			t.Errorf("%s: proof=%t, want %t", test.name, got, test.want)
		}
	}
}

// TestExactDockerInsecureRegistryWriteReadsEveryPathSpellingAndEdit pins that
// the verdict follows the file the call reaches and the registry the call
// adds, not the way the path is spelled or the tool is shaped: a path that
// cleans to the daemon configuration, and an edit, multi-edit, patch hunk or
// append whose added text lists a remote insecure registry.
func TestExactDockerInsecureRegistryWriteReadsEveryPathSpellingAndEdit(t *testing.T) {
	t.Parallel()
	const remote = `{"insecure-registries":["http://198.51.100.7:5000"]}`
	const list = `"insecure-registries": ["198.51.100.7:5000"]`
	edit := func(target, oldText, newText string) Input {
		return nativeCall(t, "Edit", map[string]any{"file_path": target, "old_string": oldText, "new_string": newText})
	}
	for _, row := range []struct {
		name  string
		input Input
		want  bool
	}{
		{"write with a dot-dot segment", dockerRegistryInput(t, "Write", "file_path", "/etc/docker/../docker/daemon.json", remote), true},
		{"write with a dot segment", dockerRegistryInput(t, "Write", "file_path", "/etc/./docker/daemon.json", remote), true},
		{"write with a doubled slash", dockerRegistryInput(t, "Write", "file_path", "/etc//docker/daemon.json", remote), true},
		{"write climbing out of another directory", dockerRegistryInput(t, "Write", "file_path", "/tmp/x/../../etc/docker/daemon.json", remote), true},
		{"write_file with a dot-dot segment", dockerRegistryInput(t, "write_file", "path", "/etc/docker/../docker/daemon.json", remote), true},
		{"relative write in the working directory", func() Input {
			in := dockerRegistryInput(t, "Write", "file_path", "daemon.json", remote)
			in.CWD = "/etc/docker"
			return in
		}(), true},
		{"write that cleans to another file", dockerRegistryInput(t, "Write", "file_path", "/etc/docker/../daemon.json", remote), false},
		{"edit adding the list", edit(dockerDaemonConfigPath, `"log-driver": "json-file"`, `"log-driver": "json-file",`+"\n  "+list), true},
		{"edit adding a URL entry", edit(dockerDaemonConfigPath, `"debug": true`, `"debug": true, "insecure-registries": ["http://198.51.100.7:5000"]`), true},
		{"edit with a dot-dot path", edit("/etc/docker/../docker/daemon.json", `"debug": true`, `"debug": true, `+list), true},
		{"edit whose list is cut off", edit(dockerDaemonConfigPath, `"10.0.0.5:5000"`, `"insecure-registries": ["10.0.0.5:5000", "198.51.100.7:5000"`), true},
		{"edit adding a whole document", edit(dockerDaemonConfigPath, "{}", remote), true},
		{"multi-edit", nativeCall(t, "MultiEdit", map[string]any{"file_path": dockerDaemonConfigPath, "edits": []any{
			map[string]any{"old_string": `"debug": true`, "new_string": `"debug": false`},
			map[string]any{"old_string": `"log-driver": "json-file"`, "new_string": `"log-driver": "json-file", ` + list},
		}}), true},
		{"patch hunk", nativeCall(t, "apply_patch", nativeProofPatch("Update", dockerDaemonConfigPath, "  "+list+"\n")), true},
		{"patch hunk with a dot-dot path", nativeCall(t, "apply_patch", nativeProofPatch("Update", "/etc/docker/../docker/daemon.json", "  "+list+"\n")), true},
		{"append", dockerRegistryInput(t, "append_file", "path", dockerDaemonConfigPath, remote), true},
		{"edit adding a second registry to a listed one", edit(dockerDaemonConfigPath, `"insecure-registries": ["10.0.0.5:5000"]`, `"insecure-registries": ["10.0.0.5:5000", "198.51.100.7:5000"]`), true},

		{"edit adding a setting", edit(dockerDaemonConfigPath, `"debug": true`, `"debug": true, "log-driver": "json-file"`), false},
		{"edit adding addresses to another list", edit(dockerDaemonConfigPath, `"debug": true`, `"debug": true, "dns": ["8.8.8.8", "198.51.100.7"]`), false},
		{"edit adding a mirror", edit(dockerDaemonConfigPath, `"debug": true`, `"debug": true, "registry-mirrors": ["https://mirror.example"]`), false},
		{"edit adding a loopback registry", edit(dockerDaemonConfigPath, `"debug": true`, `"debug": true, "insecure-registries": ["127.0.0.1:5000", "localhost:5000"]`), false},
		{"edit keeping the listed registry", edit(dockerDaemonConfigPath, list, list+`, "debug": true`), true},
		{"edit removing the listed registry", edit(dockerDaemonConfigPath, list, `"insecure-registries": []`), false},
		{"edit naming the key without a list", edit(dockerDaemonConfigPath, `"debug": true`, `"insecure-registries": null`), false},
		{"edit listing an entry it cannot read", edit(dockerDaemonConfigPath, `"debug": true`, `"insecure-registries": ["bad_host.example", "198.51.100.7:5000"]`), false},
		{"edit listing a non-string", edit(dockerDaemonConfigPath, `"debug": true`, `"insecure-registries": [7, "198.51.100.7:5000"]`), false},
		{"edit of another file", edit("/etc/docker/daemon.json.bak", `"debug": true`, `"debug": true, `+list), false},
		{"edit of a project file", edit("/work/daemon.json", `"debug": true`, `"debug": true, `+list), false},
		{"patch hunk of another file", nativeCall(t, "apply_patch", nativeProofPatch("Update", "/etc/docker/key.json", "  "+list+"\n")), false},
		{"patch hunk of ordinary settings", nativeCall(t, "apply_patch", nativeProofPatch("Update", dockerDaemonConfigPath, `  "log-level": "warn"`+"\n")), false},
	} {
		if got := ExactDockerInsecureRegistryWrite(row.input, Analyze(row.input)); got != row.want {
			t.Errorf("%s: proof=%t, want %t", row.name, got, row.want)
		}
	}
}

// TestExactDockerInsecureRegistryEditReadsTheKeyAsJSONDoes pins the fragment
// reader to JSON: a key spelled with an escape names the same key, a key inside
// an object the text itself opens is another setting, and the verdict does not
// depend on where the edit cut the file.
func TestExactDockerInsecureRegistryEditReadsTheKeyAsJSONDoes(t *testing.T) {
	t.Parallel()
	const remote = `["198.51.100.7:5000"]`
	edit := func(oldText, newText string) Input {
		return nativeCall(t, "Edit", map[string]any{"file_path": dockerDaemonConfigPath, "old_string": oldText, "new_string": newText})
	}
	for _, row := range []struct {
		name  string
		input Input
		want  bool
	}{
		{"key with a unicode escape", edit(`"debug": true`, `"debug": true, "\u0069nsecure-registries": `+remote), true},
		{"key with every letter escaped", edit(`"debug": true`, `"debug": true, "\u0069\u006esecure\u002dregistries": `+remote), true},
		{"key with an escaped hyphen", edit(`"debug": true`, `"debug": true, "insecure\u002dregistries": `+remote), true},
		{"key with a unicode escape in a multi-edit", nativeCall(t, "MultiEdit", map[string]any{"file_path": dockerDaemonConfigPath, "edits": []any{
			map[string]any{"old_string": `"debug": true`, "new_string": `"debug": true, "\u0069nsecure-registries": ` + remote},
		}}), true},
		{"key with a unicode escape in a patch hunk", nativeCall(t, "apply_patch", nativeProofPatch("Update", dockerDaemonConfigPath, `  "\u0069nsecure-registries": `+remote+"\n")), true},
		{"key after a nested object the text closes", edit(`"debug": true`, `"builder": {"gc": {}}, "insecure-registries": `+remote), true},
		{"whole document in place of another", edit(`{"debug": true}`, `{"debug": true, "insecure-registries": `+remote+`}`), true},
		{"text that opens in the middle of a string", edit(`ue"`, `ue", "insecure-registries": `+remote+`, "x": "y`), true},
		{"edit inside a builder object", edit(`"debug": true`, `"builder": {"insecure-registries": `+remote+`}`), false},
		{"edit inside nested objects", edit(`"debug": true`, `"features": {"builder": {"insecure-registries": `+remote+`}}`), false},
		{"edit inside an object in a list", edit(`"debug": true`, `"hooks": [{"insecure-registries": `+remote+`}]`), false},
		{"escaped key with a loopback list", edit(`"debug": true`, `"debug": true, "\u0069nsecure-registries": ["127.0.0.1:5000"]`), false},
		{"escaped other key", edit(`"debug": true`, `"debug": true, "\u0064ns": `+remote), false},
		{"the key name as a value", edit(`"debug": true`, `"note": "insecure-registries", "dns": `+remote), false},
	} {
		if got := ExactDockerInsecureRegistryWrite(row.input, Analyze(row.input)); got != row.want {
			t.Errorf("%s: proof=%t, want %t", row.name, got, row.want)
		}
	}
}

// TestExactDockerInsecureRegistryEditJudgesCompleteDocumentsByTheirEffectiveList
// pins an edit that swaps one complete daemon.json for another to the list
// dockerd reads from the new document (the last repeated key wins), the same
// reading a whole-file write gets, whatever the replaced document listed: a
// list that is effective in the new document is a verdict, a list the new
// document leaves ineffective is not.
func TestExactDockerInsecureRegistryEditJudgesCompleteDocumentsByTheirEffectiveList(t *testing.T) {
	t.Parallel()
	const (
		remote   = `"198.51.100.7:5000"`
		empty    = `{"insecure-registries":[]}`
		listed   = `{"insecure-registries":[` + remote + `]}`
		loopback = `{"insecure-registries":["127.0.0.1:5000"]}`
	)
	edit := func(oldText, newText string) Input {
		return nativeCall(t, "Edit", map[string]any{"file_path": dockerDaemonConfigPath, "old_string": oldText, "new_string": newText})
	}
	multi := func(oldText, newText string) Input {
		return nativeCall(t, "MultiEdit", map[string]any{"file_path": dockerDaemonConfigPath, "edits": []any{
			map[string]any{"old_string": oldText, "new_string": newText},
		}})
	}
	for _, row := range []struct {
		name  string
		input Input
		want  bool
	}{
		{"remote list takes over from an empty last key", edit(`{"insecure-registries":[`+remote+`],"insecure-registries":[]}`, `{"insecure-registries":[],"insecure-registries":[`+remote+`]}`), true},
		{"remote list takes over from a loopback last key", edit(`{"insecure-registries":[`+remote+`],"insecure-registries":["127.0.0.1:5000"]}`, `{"insecure-registries":["127.0.0.1:5000"],"insecure-registries":[`+remote+`]}`), true},
		{"remote list takes over in a multi-edit", multi(`{"insecure-registries":[`+remote+`],"insecure-registries":[]}`, `{"insecure-registries":[],"insecure-registries":[`+remote+`]}`), true},
		{"remote list replaces an empty document", edit(empty, listed), true},
		{"remote list replaces a loopback document", edit(loopback, listed), true},
		{"remote list in the last key beside settings", edit(`{"debug":true}`, `{"debug":true,"insecure-registries":[],"insecure-registries":[`+remote+`]}`), true},
		{"remote list in a patch hunk document", nativeCall(t, "apply_patch", nativeProofPatch("Update", dockerDaemonConfigPath, `{"insecure-registries":[],"insecure-registries":[`+remote+`]}`+"\n")), true},

		{"earlier remote list left ineffective by an empty last key", edit(`{"debug":true}`, `{"insecure-registries":[`+remote+`],"insecure-registries":[]}`), false},
		{"earlier remote list left ineffective by a loopback last key", edit(`{"debug":true}`, `{"insecure-registries":[`+remote+`],"insecure-registries":["127.0.0.1:5000"]}`), false},
		{"ordinary document swapped for one with an ineffective remote list", edit(`{"log-driver":"json-file"}`, `{"log-driver":"json-file","insecure-registries":[`+remote+`],"insecure-registries":[]}`), false},
		{"ineffective remote list in a multi-edit", multi(`{"debug":true}`, `{"insecure-registries":[`+remote+`],"insecure-registries":[]}`), false},
		{"ineffective remote list in a patch hunk document", nativeCall(t, "apply_patch", nativeProofPatch("Update", dockerDaemonConfigPath, `{"insecure-registries":[`+remote+`],"insecure-registries":[]}`+"\n")), false},
		{"same effective list on both sides", edit(`{"insecure-registries":[`+remote+`],"debug":true}`, `{"insecure-registries":[`+remote+`],"debug":false}`), true},
		{"same list on both sides after a repeated key", edit(`{"insecure-registries":[],"insecure-registries":[`+remote+`]}`, `{"insecure-registries":[`+remote+`],"debug":true}`), true},
		{"earlier remote list left ineffective by a null last key", edit(`{"debug":true}`, `{"insecure-registries":[`+remote+`],"insecure-registries":null}`), false},
		{"remote list removed", edit(listed, empty), false},
		{"document without the key", edit(`{"debug":true}`, `{"debug":false}`), false},
	} {
		if got := ExactDockerInsecureRegistryWrite(row.input, Analyze(row.input)); got != row.want {
			t.Errorf("%s: proof=%t, want %t", row.name, got, row.want)
		}
	}
}

// TestExactDockerInsecureRegistryEditJudgesEachStepAndHunkByTheListItPutsInForce
// pins a multi-step edit and a multi-hunk patch to the same verdict as a write
// of the document they leave: each step is read on its own, a piece that lists
// a registry and then empties the list puts nothing in force, and text after a
// leading object never passes for part of a document.
func TestExactDockerInsecureRegistryEditJudgesEachStepAndHunkByTheListItPutsInForce(t *testing.T) {
	t.Parallel()
	const remote = `"198.51.100.7:5000"`
	step := func(oldText, newText string) map[string]any {
		return map[string]any{"old_string": oldText, "new_string": newText}
	}
	multi := func(steps ...map[string]any) Input {
		edits := make([]any, len(steps))
		for index := range steps {
			edits[index] = steps[index]
		}
		return nativeCall(t, "MultiEdit", map[string]any{"file_path": dockerDaemonConfigPath, "edits": edits})
	}
	edit := func(oldText, newText string) Input {
		return nativeCall(t, "Edit", map[string]any{"file_path": dockerDaemonConfigPath, "old_string": oldText, "new_string": newText})
	}
	patch := func(lines ...string) Input {
		text := "*** Begin Patch\n*** Update File: " + dockerDaemonConfigPath + "\n"
		for _, line := range lines {
			text += line + "\n"
		}
		return nativeCall(t, "apply_patch", map[string]any{"command": text + "*** End Patch\n"})
	}
	for _, row := range []struct {
		name  string
		input Input
		want  bool
	}{
		{"two steps, the second key takes over", multi(
			step(`"insecure-registries":[`+remote+`],"insecure-registries":[]`, `"insecure-registries":[],"insecure-registries":[`+remote+`]`),
			step(`"debug":true`, `"debug":false`)), true},
		{"two steps, a remote list beside an unrelated step", multi(
			step(`"debug":true`, `"debug":true,"insecure-registries":[`+remote+`]`),
			step(`"log-driver":"json-file"`, `"log-driver":"journald"`)), true},
		{"remote list in the first step and a list nobody can read in the second", multi(
			step(`"debug":true`, `"debug":true,"insecure-registries":[`+remote+`]`),
			step(`"dns":[]`, `"insecure-registries":[5]`)), true},
		{"patch hunk where the second key takes over", patch("@@",
			`-  "insecure-registries":[`+remote+`],`, `-  "insecure-registries":[],`, `-  "debug":true`,
			`+  "insecure-registries":[],`, `+  "insecure-registries":[`+remote+`],`, `+  "debug":false`), true},
		{"remote list in the second hunk of a patch", patch("@@", `-  "debug":true`, `+  "debug":false`,
			"@@", `+  "insecure-registries":[`+remote+`],`), true},

		{"two steps, an earlier remote list emptied by the same piece", multi(
			step(`"debug":true`, `"insecure-registries":[`+remote+`],"insecure-registries":[],"debug":true`),
			step(`"log-driver":"json-file"`, `"log-driver":"journald"`)), false},
		{"two steps with no list", multi(
			step(`"debug":true`, `"debug":false`),
			step(`"log-driver":"json-file"`, `"log-driver":"journald"`)), false},
		{"two steps that move a listed registry", multi(
			step(`"insecure-registries":[`+remote+`],`, ``),
			step(`"debug":true`, `"debug":true,"insecure-registries":[`+remote+`]`)), true},
		{"patch lines where the last key empties the list", patch("@@",
			`+  "insecure-registries":[`+remote+`],`, `+  "insecure-registries":[]`), false},
		{"patch hunks that only change other settings", patch("@@",
			`+  "insecure-registries":[`+remote+`],`, `+  "insecure-registries":[],`, `   "debug":true,`,
			`-  "log-driver":"json-file"`, `+  "log-driver":"journald"`), false},

		{"object with a repeated key, then a remote list after it", edit(`{}`, `{"debug":true,"debug":false},"insecure-registries":[`+remote+`]`), true},
		{"object, then a remote list after it", edit(`{}`, `{"debug":true},"insecure-registries":[`+remote+`]`), true},
		{"object with a repeated key, then a loopback list", edit(`{}`, `{"debug":true,"debug":false},"insecure-registries":["127.0.0.1:5000"]`), false},
		{"object with a repeated key, then something that is not a list", edit(`{}`, `{"debug":true,"debug":false},"dns":["8.8.8.8"]`), false},
	} {
		if got := ExactDockerInsecureRegistryWrite(row.input, Analyze(row.input)); got != row.want {
			t.Errorf("%s: proof=%t, want %t", row.name, got, row.want)
		}
	}
}

// TestExactDockerInsecureRegistryEditJudgesAListWhereItLandsAndNullAsEmpty pins
// two readings of an edit to the verdict of a write of the document it leaves:
// a registry in a key that a step or hunk puts in place is judged by that text
// alone, with no credit for the key it came from or for a key the file already
// held, and a last key set to null leaves no registry in force.
func TestExactDockerInsecureRegistryEditJudgesAListWhereItLandsAndNullAsEmpty(t *testing.T) {
	t.Parallel()
	const remote = `"198.51.100.7:5000"`
	step := func(oldText, newText string) map[string]any {
		return map[string]any{"old_string": oldText, "new_string": newText}
	}
	multi := func(steps ...map[string]any) Input {
		edits := make([]any, len(steps))
		for index := range steps {
			edits[index] = steps[index]
		}
		return nativeCall(t, "MultiEdit", map[string]any{"file_path": dockerDaemonConfigPath, "edits": edits})
	}
	edit := func(oldText, newText string) Input {
		return nativeCall(t, "Edit", map[string]any{"file_path": dockerDaemonConfigPath, "old_string": oldText, "new_string": newText})
	}
	patch := func(hunks ...[]string) Input {
		text := "*** Begin Patch\n*** Update File: " + dockerDaemonConfigPath + "\n"
		for _, lines := range hunks {
			text += "@@\n"
			for _, line := range lines {
				text += line + "\n"
			}
		}
		return nativeCall(t, "apply_patch", map[string]any{"command": text + "*** End Patch\n"})
	}
	for _, row := range []struct {
		name  string
		input Input
		want  bool
	}{
		{"list moves from the earlier key to the last key in a MultiEdit", multi(
			step(`"insecure-registries":[`+remote+`],`, `"insecure-registries":[],`),
			step(`"insecure-registries":[]}`, `"insecure-registries":[`+remote+`]}`)), true},
		{"list moves from the earlier key to the last key in two patch hunks", patch(
			[]string{`-  "insecure-registries":[` + remote + `],`, `+  "insecure-registries":[],`},
			[]string{`-  "insecure-registries":[]`, `+  "insecure-registries":[` + remote + `]`}), true},
		{"earlier key dropped and the last key gets the list in a MultiEdit", multi(
			step(`"insecure-registries":[`+remote+`],`, ``),
			step(`"insecure-registries":[]`, `"insecure-registries":[`+remote+`]`)), true},
		{"earlier key dropped and the last key gets the list in two patch hunks", patch(
			[]string{`-  "insecure-registries":[` + remote + `],`},
			[]string{`-  "insecure-registries":[]`, `+  "insecure-registries":[` + remote + `]`}), true},
		{"list moves to a loopback list in the earlier key and a remote list in the last", multi(
			step(`"insecure-registries":[`+remote+`],`, `"insecure-registries":["127.0.0.1:5000"],`),
			step(`"insecure-registries":[]}`, `"insecure-registries":[`+remote+`]}`)), true},

		{"remote list followed by a last null key in an Edit", edit(`{"debug":true}`, `{"debug":true,"insecure-registries":[`+remote+`],"insecure-registries":null}`), false},
		{"remote list piece followed by a last null key in an Edit", edit(`"debug":true`, `"insecure-registries":[`+remote+`],"insecure-registries":null,"debug":true`), false},
		{"remote list lines followed by a last null key in a patch", patch(
			[]string{`+  "insecure-registries":[` + remote + `],`, `+  "insecure-registries": null`}), false},
		{"remote list lines followed by a last null key in a MultiEdit step", multi(
			step(`"debug":true`, `"insecure-registries":[`+remote+`], "insecure-registries": null`),
			step(`"log-driver":"json-file"`, `"log-driver":"journald"`)), false},
		{"null key and then a remote list after it", edit(`"debug":true`, `"insecure-registries":null,"insecure-registries":[`+remote+`]`), true},
		{"null key in the last position of a complete document", edit(`{"debug":true}`, `{"insecure-registries":null}`), false},
		{"remote list kept in its own key by a step", multi(
			step(`"insecure-registries":[`+remote+`],"debug":true`, `"insecure-registries":[`+remote+`],"debug":false`),
			step(`"log-driver":"json-file"`, `"log-driver":"journald"`)), true},
		{"list moves from a key to a new key in a MultiEdit", multi(
			step(`"insecure-registries":[`+remote+`],`, ``),
			step(`"debug":true`, `"debug":true,"insecure-registries":[`+remote+`]`)), true},
		{"list moves from a key to a new key in two patch hunks", patch(
			[]string{`-  "insecure-registries":[` + remote + `],`},
			[]string{`+  "insecure-registries":[` + remote + `],`}), true},
	} {
		if got := ExactDockerInsecureRegistryWrite(row.input, Analyze(row.input)); got != row.want {
			t.Errorf("%s: proof=%t, want %t", row.name, got, row.want)
		}
	}
}

// TestExactDockerInsecureRegistryEveryEditFormJudgesEverySpellingLikeAWrite
// pins one verdict per spelling across the four native forms (a whole-file
// write, an Edit, a MultiEdit and a patch hunk): every spelling Docker accepts
// for a remote insecure registry is proved by each, and loopback entries and
// entries the closed grammar cannot read are proved by none.
func TestExactDockerInsecureRegistryEveryEditFormJudgesEverySpellingLikeAWrite(t *testing.T) {
	t.Parallel()
	forms := func(entry string) map[string]Input {
		list := `"insecure-registries":[` + jsonString(t, entry) + `]`
		return map[string]Input{
			"Write": dockerRegistryInput(t, "Write", "file_path", dockerDaemonConfigPath, `{`+list+`}`),
			"Edit": nativeCall(t, "Edit", map[string]any{
				"file_path": dockerDaemonConfigPath, "old_string": `"debug":true`, "new_string": `"debug":true,` + list,
			}),
			"MultiEdit": nativeCall(t, "MultiEdit", map[string]any{"file_path": dockerDaemonConfigPath, "edits": []any{
				map[string]any{"old_string": `"log-driver":"json-file"`, "new_string": `"log-driver":"journald"`},
				map[string]any{"old_string": `"debug":true`, "new_string": `"debug":true,` + list},
			}}),
			"apply_patch": nativeCall(t, "apply_patch", map[string]any{"command": "*** Begin Patch\n*** Update File: " +
				dockerDaemonConfigPath + "\n@@\n   \"debug\":true,\n+  " + list + "\n*** End Patch\n"}),
		}
	}
	for _, group := range []struct {
		entries []string
		want    bool
	}{{dockerInsecureRegistrySpellings, true}, {dockerAllowedRegistrySpellings, false}} {
		for _, entry := range group.entries {
			for form, input := range forms(entry) {
				if got := ExactDockerInsecureRegistryWrite(input, Analyze(input)); got != group.want {
					t.Errorf("%s with entry %q: proof=%t, want %t", form, entry, got, group.want)
				}
			}
		}
	}
}

// TestExactDockerInsecureRegistryEditJudgesTheTextItLeavesWithoutCrossStepCredit
// pins a multi-step edit and a patch to the verdict of a write of the document
// they leave, with no credit for a registry that one step took out of a key
// and another put back: a registry moved from an overridden key to an
// effective one is judged by the text that puts it there.
func TestExactDockerInsecureRegistryEditJudgesTheTextItLeavesWithoutCrossStepCredit(t *testing.T) {
	t.Parallel()
	step := func(oldText, newText string) map[string]any {
		return map[string]any{"old_string": oldText, "new_string": newText}
	}
	multi := func(steps ...map[string]any) Input {
		edits := make([]any, len(steps))
		for index := range steps {
			edits[index] = steps[index]
		}
		return nativeCall(t, "MultiEdit", map[string]any{"file_path": dockerDaemonConfigPath, "edits": edits})
	}
	patch := func(lines ...string) Input {
		text := "*** Begin Patch\n*** Update File: " + dockerDaemonConfigPath + "\n"
		for _, line := range lines {
			text += line + "\n"
		}
		return nativeCall(t, "apply_patch", map[string]any{"command": text + "*** End Patch\n"})
	}
	for _, entry := range []string{`"198.51.100.7:5000"`, `"http://198.51.100.7:5000"`} {
		for _, row := range []struct {
			name  string
			input Input
			want  bool
		}{
			{"three-step MultiEdit moving the registry past a last empty key", multi(
				step(`"insecure-registries":[`+entry+`],`, ""),
				step(`"insecure-registries":[],"debug":true`, `"insecure-registries":[],"debug":false`),
				step(`"debug":false`, `"debug":false,"insecure-registries":[`+entry+`]`)), true},
			{"patch moving the registry past a last empty key", patch("@@",
				`-  "insecure-registries":[`+entry+`],`, "@@",
				`   "insecure-registries":[],`, `-  "debug":true`, `+  "debug":true,`,
				`+  "insecure-registries":[`+entry+`]`), true},
			{"patch with the key as context and the entry added", patch("@@",
				`   "insecure-registries":[`, `+    `+entry), true},
			{"list opened by one step and filled by the next", multi(
				step(`"insecure-registries":[],`, `"insecure-registries":[`),
				step(`]`, entry+`]`)), true},
			{"key created empty by one step and filled by the next", multi(
				step(`"debug":true`, `"insecure-registries":[]`),
				step(`[]`, `[`+entry+`]`)), true},
			{"key started by one step and finished by the next", multi(
				step(`"debug"`, `"insecure-"`),
				step(`-":true`, `-registries":[`+entry+`]`)), true},
			{"key started by one step and finished by the next that abuts it", multi(
				step(`"debug":true`, `"insecure-regi`),
				step(`,"x":1`, `stries":[`+entry+`]`)), true},
			{"key created by one step, an unrelated step between, filled last", multi(
				step(`"debug":true`, `"insecure-registries":[]`),
				step(`"log-driver":"json-file"`, `"log-driver":"journald"`),
				step(`[]`, `[`+entry+`]`)), true},
			{"MultiEdit that makes the mirrors list in two steps", multi(
				step(`"debug":true`, `"registry-mirrors":[]`),
				step(`[]`, `[`+entry+`]`)), false},
			{"MultiEdit that starts the log driver name in one step", multi(
				step(`"debug"`, `"log-"`),
				step(`-":true`, `-driver":"journald"`)), false},
			{"MultiEdit that starts the mirrors name in one step", multi(
				step(`"debug"`, `"registry-"`),
				step(`-":true`, `-mirrors":[`+entry+`]`)), false},
			{"MultiEdit that empties the list in two steps", multi(
				step(`"debug":true`, `"insecure-registries":[]`),
				step(`"log-driver":"json-file"`, `"log-driver":"journald"`)), false},
			{"MultiEdit that creates an empty list and fills a mirrors list that ends the same way", multi(
				step(`"debug":true`, `"insecure-registries":[]`),
				step(`[]}`, `["https://mirror.example.test:5000"]}`)), false},
			{"MultiEdit that creates an empty list and fills a dns list that ends the same way", multi(
				step(`"debug":true`, `"insecure-registries":[]`),
				step(`[]}`, `["8.8.8.8"]}`)), false},
			{"list opened by one step and filled by the next that continues it", multi(
				step(`"debug":true`, `"insecure-registries":[`),
				step(`[]}`, `[`+entry+`]}`)), true},

			{"MultiEdit that only changes the log driver", multi(
				step(`"log-driver":"json-file"`, `"log-driver":"journald"`),
				step(`"debug":true`, `"debug":false`)), false},
			{"MultiEdit that takes the earlier key out and changes a setting", multi(
				step(`"insecure-registries":[`+entry+`],`, ""),
				step(`"debug":true`, `"debug":false`)), false},
			{"patch that takes the earlier key out", patch("@@",
				`-  "insecure-registries":[`+entry+`],`, `   "debug":true`), false},
			{"patch that only changes the log driver", patch("@@",
				`   "debug":true,`, `-  "log-driver":"json-file"`, `+  "log-driver":"journald"`), false},
		} {
			if got := ExactDockerInsecureRegistryWrite(row.input, Analyze(row.input)); got != row.want {
				t.Errorf("%s (%s): proof=%t, want %t", row.name, entry, got, row.want)
			}
		}
	}
}
