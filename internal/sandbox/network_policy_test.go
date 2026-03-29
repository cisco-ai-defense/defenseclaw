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

func TestAddNetworkPolicy_NewEntry(t *testing.T) {
	p, err := ParseOpenShellPolicy([]byte(samplePolicy))
	if err != nil {
		t.Fatalf("ParseOpenShellPolicy: %v", err)
	}

	p.AddNetworkPolicy("slack", []string{"slack.com", "hooks.slack.com"}, []int{443}, []string{"/usr/bin/curl"})

	if !p.HasEndpointForHost("slack.com") {
		t.Error("expected to find slack.com after add")
	}
	if !p.HasEndpointForHost("hooks.slack.com") {
		t.Error("expected to find hooks.slack.com after add")
	}

	names := p.NetworkPolicyNames()
	if len(names) != 4 {
		t.Fatalf("expected 4 entries, got %d: %v", len(names), names)
	}
}

func TestAddNetworkPolicy_UpsertMergesHosts(t *testing.T) {
	p, err := ParseOpenShellPolicy([]byte(samplePolicy))
	if err != nil {
		t.Fatalf("ParseOpenShellPolicy: %v", err)
	}

	p.AddNetworkPolicy("github", []string{"raw.githubusercontent.com"}, []int{443}, nil)

	if !p.HasEndpointForHost("github.com") {
		t.Error("original host github.com should still exist")
	}
	if !p.HasEndpointForHost("api.github.com") {
		t.Error("original host api.github.com should still exist")
	}
	if !p.HasEndpointForHost("raw.githubusercontent.com") {
		t.Error("new host raw.githubusercontent.com should exist after upsert")
	}

	names := p.NetworkPolicyNames()
	if len(names) != 3 {
		t.Fatalf("upsert should not add a new entry, expected 3, got %d", len(names))
	}
}

func TestAddNetworkPolicy_UpsertMergesBinaries(t *testing.T) {
	p, err := ParseOpenShellPolicy([]byte(samplePolicy))
	if err != nil {
		t.Fatalf("ParseOpenShellPolicy: %v", err)
	}

	p.AddNetworkPolicy("github", nil, nil, []string{"/usr/bin/wget"})

	entries := p.NetworkPolicyEntries()
	var githubEntry *NetworkPolicyEntry
	for i := range entries {
		if entries[i].Name == "github" {
			githubEntry = &entries[i]
			break
		}
	}
	if githubEntry == nil {
		t.Fatal("github entry not found")
	}

	found := false
	for _, b := range githubEntry.Binaries {
		if b == "/usr/bin/wget" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected /usr/bin/wget in binaries, got %v", githubEntry.Binaries)
	}

	origFound := false
	for _, b := range githubEntry.Binaries {
		if b == "/usr/bin/git" {
			origFound = true
		}
	}
	if !origFound {
		t.Errorf("original binary /usr/bin/git should still exist, got %v", githubEntry.Binaries)
	}
}

func TestAddNetworkPolicy_UpsertUpdatesPortsForExistingHost(t *testing.T) {
	p, err := ParseOpenShellPolicy([]byte(samplePolicy))
	if err != nil {
		t.Fatalf("ParseOpenShellPolicy: %v", err)
	}

	p.AddNetworkPolicy("github", []string{"github.com"}, []int{8080}, nil)

	entries := p.NetworkPolicyEntries()
	var githubEntry *NetworkPolicyEntry
	for i := range entries {
		if entries[i].Name == "github" {
			githubEntry = &entries[i]
			break
		}
	}
	if githubEntry == nil {
		t.Fatal("github entry not found")
	}

	for _, ep := range githubEntry.Endpoints {
		if ep.Host == "github.com" {
			if ep.Port != 8080 {
				t.Errorf("expected port 8080 after upsert, got %d", ep.Port)
			}
			return
		}
	}
	t.Error("github.com endpoint not found after upsert")
}

func TestAddNetworkPolicy_UpsertDeduplicates(t *testing.T) {
	p, err := ParseOpenShellPolicy([]byte(samplePolicy))
	if err != nil {
		t.Fatalf("ParseOpenShellPolicy: %v", err)
	}

	p.AddNetworkPolicy("github", []string{"github.com"}, []int{443}, []string{"/usr/bin/git"})

	entries := p.NetworkPolicyEntries()
	var githubEntry *NetworkPolicyEntry
	for i := range entries {
		if entries[i].Name == "github" {
			githubEntry = &entries[i]
			break
		}
	}
	if githubEntry == nil {
		t.Fatal("github entry not found")
	}

	hostCount := 0
	for _, ep := range githubEntry.Endpoints {
		if ep.Host == "github.com" {
			hostCount++
		}
	}
	if hostCount != 1 {
		t.Errorf("expected github.com once, found %d times", hostCount)
	}

	binCount := 0
	for _, b := range githubEntry.Binaries {
		if b == "/usr/bin/git" {
			binCount++
		}
	}
	if binCount != 1 {
		t.Errorf("expected /usr/bin/git once, found %d times", binCount)
	}
}

func TestAddNetworkPolicy_DefaultPort(t *testing.T) {
	p, err := ParseOpenShellPolicy([]byte("{}"))
	if err != nil {
		t.Fatalf("ParseOpenShellPolicy: %v", err)
	}

	p.AddNetworkPolicy("test", []string{"example.com"}, nil, nil)

	entries := p.NetworkPolicyEntries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if len(entries[0].Endpoints) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(entries[0].Endpoints))
	}
	if entries[0].Endpoints[0].Port != 443 {
		t.Errorf("expected default port 443, got %d", entries[0].Endpoints[0].Port)
	}
}

func TestAddNetworkPolicy_NoBinaries(t *testing.T) {
	p, err := ParseOpenShellPolicy([]byte("{}"))
	if err != nil {
		t.Fatalf("ParseOpenShellPolicy: %v", err)
	}

	p.AddNetworkPolicy("test", []string{"example.com"}, []int{443}, nil)

	entries := p.NetworkPolicyEntries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if len(entries[0].Binaries) != 0 {
		t.Errorf("expected no binaries, got %v", entries[0].Binaries)
	}
}

func TestAddNetworkPolicy_PreservesOtherSections(t *testing.T) {
	p, err := ParseOpenShellPolicy([]byte(samplePolicy))
	if err != nil {
		t.Fatalf("ParseOpenShellPolicy: %v", err)
	}

	p.AddNetworkPolicy("slack", []string{"slack.com"}, []int{443}, nil)

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

func TestRemoveNetworkPolicyByName(t *testing.T) {
	p, err := ParseOpenShellPolicy([]byte(samplePolicy))
	if err != nil {
		t.Fatalf("ParseOpenShellPolicy: %v", err)
	}

	if !p.RemoveNetworkPolicyByName("telegram") {
		t.Fatal("expected RemoveNetworkPolicyByName to return true")
	}

	names := p.NetworkPolicyNames()
	if len(names) != 2 {
		t.Fatalf("expected 2 remaining entries, got %d: %v", len(names), names)
	}
	for _, n := range names {
		if n == "telegram" {
			t.Fatal("telegram should have been removed")
		}
	}
}

func TestRemoveNetworkPolicyByName_NotFound(t *testing.T) {
	p, err := ParseOpenShellPolicy([]byte(samplePolicy))
	if err != nil {
		t.Fatalf("ParseOpenShellPolicy: %v", err)
	}

	if p.RemoveNetworkPolicyByName("nonexistent") {
		t.Fatal("expected RemoveNetworkPolicyByName to return false for missing entry")
	}

	names := p.NetworkPolicyNames()
	if len(names) != 3 {
		t.Fatalf("expected 3 entries unchanged, got %d", len(names))
	}
}

func TestRemoveNetworkPolicyByName_EmptyPolicy(t *testing.T) {
	p, err := ParseOpenShellPolicy([]byte("{}"))
	if err != nil {
		t.Fatalf("ParseOpenShellPolicy: %v", err)
	}

	if p.RemoveNetworkPolicyByName("anything") {
		t.Fatal("expected RemoveNetworkPolicyByName to return false on empty policy")
	}
}

func TestHasNetworkPolicyName(t *testing.T) {
	p, err := ParseOpenShellPolicy([]byte(samplePolicy))
	if err != nil {
		t.Fatalf("ParseOpenShellPolicy: %v", err)
	}

	if !p.HasNetworkPolicyName("github") {
		t.Error("expected to find github")
	}
	if !p.HasNetworkPolicyName("openrouter") {
		t.Error("expected to find openrouter")
	}
	if p.HasNetworkPolicyName("nonexistent") {
		t.Error("did not expect to find nonexistent")
	}
}

func TestNetworkPolicyEntries(t *testing.T) {
	p, err := ParseOpenShellPolicy([]byte(samplePolicy))
	if err != nil {
		t.Fatalf("ParseOpenShellPolicy: %v", err)
	}

	entries := p.NetworkPolicyEntries()
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}

	byName := make(map[string]NetworkPolicyEntry)
	for _, e := range entries {
		byName[e.Name] = e
	}

	gh, ok := byName["github"]
	if !ok {
		t.Fatal("github entry not found")
	}
	if len(gh.Endpoints) != 2 {
		t.Errorf("github: expected 2 endpoints, got %d", len(gh.Endpoints))
	}
	if len(gh.Binaries) != 2 {
		t.Errorf("github: expected 2 binaries, got %d", len(gh.Binaries))
	}

	tg, ok := byName["telegram"]
	if !ok {
		t.Fatal("telegram entry not found")
	}
	if len(tg.Endpoints) != 1 {
		t.Errorf("telegram: expected 1 endpoint, got %d", len(tg.Endpoints))
	}
	if tg.Endpoints[0].Host != "api.telegram.org" {
		t.Errorf("telegram: expected host api.telegram.org, got %s", tg.Endpoints[0].Host)
	}
}
