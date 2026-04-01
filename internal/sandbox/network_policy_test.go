package sandbox

import (
	"testing"
)

const samplePolicy = `
version: "1.0"
filesystem_policy:
  allowed_paths:
    - /usr
    - /home
network_policies:
  github:
    endpoints:
      - host: github.com
        ports: [443]
      - host: api.github.com
        ports: [443]
    binaries:
      - path: /usr/bin/git
      - path: /usr/bin/curl
  openrouter:
    endpoints:
      - host: openrouter.ai
        ports: [443]
    binaries:
      - path: /usr/bin/node
  telegram:
    endpoints:
      - host: api.telegram.org
        ports: [443]
    binaries:
      - path: /usr/bin/node
process:
  max_processes: 100
`

func TestParseOpenShellPolicy(t *testing.T) {
	p, err := ParseOpenShellPolicy([]byte(samplePolicy))
	if err != nil {
		t.Fatalf("ParseOpenShellPolicy: %v", err)
	}

	names := p.NetworkPolicyNames()
	if len(names) != 3 {
		t.Fatalf("expected 3 network policy entries, got %d: %v", len(names), names)
	}

	want := map[string]bool{"github": true, "openrouter": true, "telegram": true}
	for _, n := range names {
		if !want[n] {
			t.Errorf("unexpected policy name %q", n)
		}
	}
}

func TestRemoveEndpointsByHost(t *testing.T) {
	p, err := ParseOpenShellPolicy([]byte(samplePolicy))
	if err != nil {
		t.Fatalf("ParseOpenShellPolicy: %v", err)
	}

	removed := p.RemoveEndpointsByHost("openrouter.ai")
	if len(removed) != 1 {
		t.Fatalf("expected 1 removed entry, got %d", len(removed))
	}

	names := p.NetworkPolicyNames()
	if len(names) != 2 {
		t.Fatalf("expected 2 remaining entries, got %d: %v", len(names), names)
	}
	for _, n := range names {
		if n == "openrouter" {
			t.Fatal("openrouter entry should have been removed")
		}
	}
}

func TestRemoveEndpointsByHost_NoMatch(t *testing.T) {
	p, err := ParseOpenShellPolicy([]byte(samplePolicy))
	if err != nil {
		t.Fatalf("ParseOpenShellPolicy: %v", err)
	}

	removed := p.RemoveEndpointsByHost("unknown.example.com")
	if len(removed) != 0 {
		t.Fatalf("expected 0 removed entries, got %d", len(removed))
	}

	names := p.NetworkPolicyNames()
	if len(names) != 3 {
		t.Fatalf("expected 3 entries unchanged, got %d", len(names))
	}
}

func TestRemoveEndpointsByHost_MultipleEndpoints(t *testing.T) {
	p, err := ParseOpenShellPolicy([]byte(samplePolicy))
	if err != nil {
		t.Fatalf("ParseOpenShellPolicy: %v", err)
	}

	// github entry has both github.com and api.github.com
	removed := p.RemoveEndpointsByHost("github.com")
	if len(removed) != 1 {
		t.Fatalf("expected 1 removed entry, got %d", len(removed))
	}

	names := p.NetworkPolicyNames()
	if len(names) != 2 {
		t.Fatalf("expected 2 remaining entries, got %d: %v", len(names), names)
	}
	for _, n := range names {
		if n == "github" {
			t.Fatal("github entry should have been removed")
		}
	}
}

func TestHasEndpointForHost(t *testing.T) {
	p, err := ParseOpenShellPolicy([]byte(samplePolicy))
	if err != nil {
		t.Fatalf("ParseOpenShellPolicy: %v", err)
	}

	if !p.HasEndpointForHost("openrouter.ai") {
		t.Error("expected to find openrouter.ai")
	}
	if !p.HasEndpointForHost("api.telegram.org") {
		t.Error("expected to find api.telegram.org")
	}
	if p.HasEndpointForHost("evil.example.com") {
		t.Error("did not expect to find evil.example.com")
	}
}

func TestMarshalPreservesOtherSections(t *testing.T) {
	p, err := ParseOpenShellPolicy([]byte(samplePolicy))
	if err != nil {
		t.Fatalf("ParseOpenShellPolicy: %v", err)
	}

	p.RemoveEndpointsByHost("openrouter.ai")

	data, err := p.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	p2, err := ParseOpenShellPolicy(data)
	if err != nil {
		t.Fatalf("re-parse: %v", err)
	}

	if p2.raw["version"] != "1.0" {
		t.Errorf("version not preserved: %v", p2.raw["version"])
	}
	if p2.raw["filesystem_policy"] == nil {
		t.Error("filesystem_policy not preserved")
	}
	if p2.raw["process"] == nil {
		t.Error("process not preserved")
	}
}

func TestStripPolicyHeader(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "with metadata and separator",
			input: "Version: 3\nHash: abc123\nStatus: active\n---\nversion: \"1.0\"\n",
			want:  "version: \"1.0\"\n",
		},
		{
			name:  "no metadata",
			input: "version: \"1.0\"\nnetwork_policies:\n",
			want:  "version: \"1.0\"\nnetwork_policies:\n",
		},
		{
			name:  "separator only",
			input: "---\nversion: \"1.0\"\n",
			want:  "version: \"1.0\"\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := string(StripPolicyHeader([]byte(tt.input)))
			if got != tt.want {
				t.Errorf("StripPolicyHeader:\n got:  %q\n want: %q", got, tt.want)
			}
		})
	}
}

func TestParseMCPEndpoint(t *testing.T) {
	tests := []struct {
		endpoint string
		wantHost string
		wantPort int
		wantSkip bool
	}{
		{"https://mcp.evil.com/sse", "mcp.evil.com", 443, false},
		{"https://mcp.internal.com:8443/api", "mcp.internal.com", 8443, false},
		{"http://remote.example.com/mcp", "remote.example.com", 80, false},
		{"http://localhost:3000/mcp", "", 0, true},
		{"http://127.0.0.1:8080/api", "", 0, true},
		{"my-local-mcp", "", 0, true},
		{"/usr/local/bin/mcp-server", "", 0, true},
		{"", "", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.endpoint, func(t *testing.T) {
			host, port, skip := ParseMCPEndpoint(tt.endpoint)
			if host != tt.wantHost {
				t.Errorf("host: got %q, want %q", host, tt.wantHost)
			}
			if port != tt.wantPort {
				t.Errorf("port: got %d, want %d", port, tt.wantPort)
			}
			if skip != tt.wantSkip {
				t.Errorf("skip: got %v, want %v", skip, tt.wantSkip)
			}
		})
	}
}

func TestParseEmptyPolicy(t *testing.T) {
	p, err := ParseOpenShellPolicy([]byte("{}"))
	if err != nil {
		t.Fatalf("ParseOpenShellPolicy: %v", err)
	}

	names := p.NetworkPolicyNames()
	if len(names) != 0 {
		t.Fatalf("expected 0 entries, got %d", len(names))
	}

	removed := p.RemoveEndpointsByHost("anything.com")
	if len(removed) != 0 {
		t.Fatalf("expected 0 removed, got %d", len(removed))
	}
}
