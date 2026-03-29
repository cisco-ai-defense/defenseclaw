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

// NetworkPolicyEntry holds the parsed representation of a single
// network_policies entry for display purposes.
type NetworkPolicyEntry struct {
	Name      string     `json:"name"`
	Endpoints []Endpoint `json:"endpoints"`
	Binaries  []string   `json:"binaries"`
}

// NetworkPolicyEntries returns all network_policies entries as structured objects.
func (p *OpenShellPolicy) NetworkPolicyEntries() []NetworkPolicyEntry {
	npMap := p.networkPolicyMap()
	entries := make([]NetworkPolicyEntry, 0, len(npMap))
	for name, raw := range npMap {
		entry := NetworkPolicyEntry{Name: name}

		if epsRaw, ok := raw["endpoints"].([]interface{}); ok {
			for _, epRaw := range epsRaw {
				ep, ok := epRaw.(map[string]interface{})
				if !ok {
					continue
				}
				host, _ := ep["host"].(string)
				var port int
				if portsRaw, ok := ep["ports"].([]interface{}); ok && len(portsRaw) > 0 {
					port, _ = portsRaw[0].(int)
				}
				if host != "" {
					entry.Endpoints = append(entry.Endpoints, Endpoint{Host: host, Port: port})
				}
			}
		}

		if binsRaw, ok := raw["binaries"].([]interface{}); ok {
			for _, binRaw := range binsRaw {
				bin, ok := binRaw.(map[string]interface{})
				if !ok {
					continue
				}
				if path, ok := bin["path"].(string); ok {
					entry.Binaries = append(entry.Binaries, path)
				}
			}
		}

		entries = append(entries, entry)
	}
	return entries
}

// AddNetworkPolicy adds or merges a named network policy entry.
// If an entry with the given name already exists, new hosts and binaries
// are merged into it (upsert). Ports apply to all hosts in this call.
func (p *OpenShellPolicy) AddNetworkPolicy(name string, hosts []string, ports []int, binaries []string) {
	if p.raw["network_policies"] == nil {
		p.raw["network_policies"] = make(map[string]interface{})
	}
	npMap, ok := p.raw["network_policies"].(map[string]interface{})
	if !ok {
		npMap = make(map[string]interface{})
		p.raw["network_policies"] = npMap
	}

	if len(ports) == 0 {
		ports = []int{443}
	}

	portsList := make([]interface{}, len(ports))
	for i, port := range ports {
		portsList[i] = port
	}

	existing, hasExisting := npMap[name]
	if hasExisting {
		entry, ok := existing.(map[string]interface{})
		if !ok {
			entry = make(map[string]interface{})
		}
		mergeEndpoints(entry, hosts, portsList)
		mergeBinaries(entry, binaries)
		npMap[name] = entry
		return
	}

	var endpoints []interface{}
	for _, host := range hosts {
		endpoints = append(endpoints, map[string]interface{}{
			"host":  host,
			"ports": portsList,
		})
	}

	entry := map[string]interface{}{
		"endpoints": endpoints,
	}
	if len(binaries) > 0 {
		var bins []interface{}
		for _, b := range binaries {
			bins = append(bins, map[string]interface{}{"path": b})
		}
		entry["binaries"] = bins
	}

	npMap[name] = entry
}

// HasNetworkPolicyName returns true if a network_policies entry with the
// given name exists.
func (p *OpenShellPolicy) HasNetworkPolicyName(name string) bool {
	npRaw, ok := p.raw["network_policies"]
	if !ok {
		return false
	}
	npMap, ok := npRaw.(map[string]interface{})
	if !ok {
		return false
	}
	_, exists := npMap[name]
	return exists
}

// RemoveNetworkPolicyByName removes a network_policies entry by its name.
// Returns true if an entry was removed.
func (p *OpenShellPolicy) RemoveNetworkPolicyByName(name string) bool {
	npRaw, ok := p.raw["network_policies"]
	if !ok {
		return false
	}
	npMap, ok := npRaw.(map[string]interface{})
	if !ok {
		return false
	}
	if _, exists := npMap[name]; !exists {
		return false
	}
	delete(npMap, name)
	return true
}

func mergeEndpoints(entry map[string]interface{}, hosts []string, portsList []interface{}) {
	var endpoints []interface{}
	if existing, ok := entry["endpoints"].([]interface{}); ok {
		endpoints = existing
	}

	hostIndex := make(map[string]int)
	for i, epRaw := range endpoints {
		if ep, ok := epRaw.(map[string]interface{}); ok {
			if h, ok := ep["host"].(string); ok {
				hostIndex[h] = i
			}
		}
	}

	for _, host := range hosts {
		if idx, exists := hostIndex[host]; exists {
			if ep, ok := endpoints[idx].(map[string]interface{}); ok {
				ep["ports"] = portsList
			}
			continue
		}
		endpoints = append(endpoints, map[string]interface{}{
			"host":  host,
			"ports": portsList,
		})
	}
	entry["endpoints"] = endpoints
}

func mergeBinaries(entry map[string]interface{}, binaries []string) {
	if len(binaries) == 0 {
		return
	}

	var bins []interface{}
	if existing, ok := entry["binaries"].([]interface{}); ok {
		bins = existing
	}

	existingPaths := make(map[string]bool)
	for _, binRaw := range bins {
		if bin, ok := binRaw.(map[string]interface{}); ok {
			if p, ok := bin["path"].(string); ok {
				existingPaths[p] = true
			}
		}
	}

	for _, b := range binaries {
		if existingPaths[b] {
			continue
		}
		bins = append(bins, map[string]interface{}{"path": b})
	}
	entry["binaries"] = bins
}
