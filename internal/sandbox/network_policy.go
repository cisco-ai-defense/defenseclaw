package sandbox

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// OpenShellPolicy wraps a full OpenShell sandbox policy YAML.
// Only network_policies is manipulated; all other sections pass through unchanged.
type OpenShellPolicy struct {
	raw map[string]interface{}
}

// RemovedEntry captures a network policy entry removed by DefenseClaw.
type RemovedEntry struct {
	Host          string                 `yaml:"host"`
	Port          int                    `yaml:"port,omitempty"`
	RemovedAt     time.Time              `yaml:"removed_at"`
	Reason        string                 `yaml:"reason"`
	Sandbox       string                 `yaml:"sandbox"`
	OriginalEntry map[string]interface{} `yaml:"original_entry"`
}

// ParseOpenShellPolicy parses a full OpenShell policy YAML into a
// structure that allows surgical edits to network_policies while
// preserving all other sections.
func ParseOpenShellPolicy(data []byte) (*OpenShellPolicy, error) {
	var raw map[string]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("sandbox: parse openshell policy: %w", err)
	}
	if raw == nil {
		raw = make(map[string]interface{})
	}
	return &OpenShellPolicy{raw: raw}, nil
}

func (p *OpenShellPolicy) Marshal() ([]byte, error) {
	return yaml.Marshal(p.raw)
}

// NetworkPolicyNames returns the names of all entries in network_policies.
// The YAML uses a map keyed by policy name (e.g. network_policies.allow_sidecar).
func (p *OpenShellPolicy) NetworkPolicyNames() []string {
	npMap := p.networkPolicyMap()
	var names []string
	for name := range npMap {
		names = append(names, name)
	}
	return names
}

// RemoveEndpointsByHost removes all network_policies entries that contain
// an endpoint matching the given host. Returns the removed entries for
// preservation and audit.
func (p *OpenShellPolicy) RemoveEndpointsByHost(host string) []RemovedEntry {
	npRaw, ok := p.raw["network_policies"]
	if !ok {
		return nil
	}
	npMap, ok := npRaw.(map[string]interface{})
	if !ok {
		return nil
	}

	var removed []RemovedEntry

	for name, entryRaw := range npMap {
		entry, ok := entryRaw.(map[string]interface{})
		if !ok {
			continue
		}
		if policyMatchesHost(entry, host) {
			removed = append(removed, RemovedEntry{
				Host:          host,
				OriginalEntry: entry,
				Reason:        fmt.Sprintf("network policy entry %q removed: contains endpoint for %s", name, host),
			})
			delete(npMap, name)
		}
	}

	return removed
}

// HasEndpointForHost returns true if any network policy entry contains
// an endpoint matching the given host.
func (p *OpenShellPolicy) HasEndpointForHost(host string) bool {
	for _, entry := range p.networkPolicyMap() {
		if policyMatchesHost(entry, host) {
			return true
		}
	}
	return false
}

// networkPolicyMap returns the network_policies section as a map of
// policy-name -> policy-object. The YAML structure is:
//
//	network_policies:
//	  allow_sidecar:
//	    binaries: [...]
//	    endpoints: [...]
func (p *OpenShellPolicy) networkPolicyMap() map[string]map[string]interface{} {
	npRaw, ok := p.raw["network_policies"]
	if !ok {
		return nil
	}
	npMap, ok := npRaw.(map[string]interface{})
	if !ok {
		return nil
	}
	result := make(map[string]map[string]interface{}, len(npMap))
	for name, entryRaw := range npMap {
		if entry, ok := entryRaw.(map[string]interface{}); ok {
			result[name] = entry
		}
	}
	return result
}

func policyMatchesHost(policy map[string]interface{}, host string) bool {
	endpointsRaw, ok := policy["endpoints"]
	if !ok {
		return false
	}
	endpoints, ok := endpointsRaw.([]interface{})
	if !ok {
		return false
	}
	for _, epRaw := range endpoints {
		ep, ok := epRaw.(map[string]interface{})
		if !ok {
			continue
		}
		if epHost, ok := ep["host"].(string); ok && epHost == host {
			return true
		}
	}
	return false
}

// StripPolicyHeader removes metadata lines (Version, Hash, Status) and
// the YAML document separator from `openshell policy get --full` output.
func StripPolicyHeader(data []byte) []byte {
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "---" {
			rest := strings.Join(lines[i+1:], "\n")
			return []byte(rest)
		}
		if !isMetadataLine(trimmed) && trimmed != "" {
			rest := strings.Join(lines[i:], "\n")
			return []byte(rest)
		}
	}
	return data
}

func isMetadataLine(line string) bool {
	for _, prefix := range []string{"Version:", "Hash:", "Status:", "Policy:"} {
		if strings.HasPrefix(line, prefix) {
			return true
		}
	}
	return false
}

// ParseMCPEndpoint extracts host and port from an MCP endpoint URL.
// Returns empty host for non-URL targets (stdio MCPs, localhost).
func ParseMCPEndpoint(endpoint string) (host string, port int, skip bool) {
	if !strings.Contains(endpoint, "://") {
		return "", 0, true
	}

	u, err := url.Parse(endpoint)
	if err != nil {
		return "", 0, true
	}

	host = u.Hostname()
	if host == "" {
		return "", 0, true
	}

	if isLocalhost(host) {
		return "", 0, true
	}

	port = 443
	if u.Scheme == "http" {
		port = 80
	}
	if u.Port() != "" {
		fmt.Sscanf(u.Port(), "%d", &port)
	}

	return host, port, false
}

func isLocalhost(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1" ||
		host == "[::1]" || host == "0.0.0.0"
}
