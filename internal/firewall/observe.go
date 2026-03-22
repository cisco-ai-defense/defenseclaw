package firewall

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// ObservedConnection is a single active outbound TCP connection.
type ObservedConnection struct {
	RemoteIP   string
	RemotePort string
	Domain     string // reverse-DNS result, empty if unresolved
	Command    string // process name from lsof
}

// ObservationResult holds what was found during observation.
type ObservationResult struct {
	Connections    []ObservedConnection
	SkillDomains   []string // domains found in skill source files
	ProposedConfig *FirewallConfig
	WouldBlock     []ObservedConnection // connections not covered by proposed config
}

// Observe watches active outbound connections and scans skill directories to
// build a proposed firewall allowlist. No root required — lsof is read-only.
func Observe(ctx context.Context, skillDirs []string) (*ObservationResult, error) {
	conns, _ := observeConnections(ctx) // lsof failure is non-fatal
	skillDomains := scanSkillsForDomains(skillDirs)
	proposed := buildProposedConfig(conns, skillDomains)
	wouldBlock := findWouldBlock(conns, proposed)

	return &ObservationResult{
		Connections:    conns,
		SkillDomains:   skillDomains,
		ProposedConfig: proposed,
		WouldBlock:     wouldBlock,
	}, nil
}

// observeConnections runs lsof to list established outbound TCP connections.
func observeConnections(ctx context.Context) ([]ObservedConnection, error) {
	tctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(tctx, "lsof", "-i", "4", "-n", "-P", "-sTCP:ESTABLISHED")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("firewall: observe: lsof: %w", err)
	}
	return parseLSOF(out), nil
}

// connPattern matches "localIP:port->remoteIP:port" in lsof NAME field.
var connPattern = regexp.MustCompile(`\d+\.\d+\.\d+\.\d+:\d+->(\d+\.\d+\.\d+\.\d+):(\d+)`)

func parseLSOF(data []byte) []ObservedConnection {
	seen := make(map[string]bool)
	var conns []ObservedConnection

	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 9 {
			continue
		}
		command := fields[0]
		m := connPattern.FindStringSubmatch(fields[8])
		if m == nil {
			continue
		}
		remoteIP, remotePort := m[1], m[2]
		if isPrivateIP(remoteIP) {
			continue
		}
		key := remoteIP + ":" + remotePort
		if seen[key] {
			continue
		}
		seen[key] = true
		conns = append(conns, ObservedConnection{
			RemoteIP:   remoteIP,
			RemotePort: remotePort,
			Domain:     reverseLookup(remoteIP),
			Command:    command,
		})
	}
	return conns
}

func reverseLookup(ip string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	names, err := (&net.Resolver{}).LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}

// urlPattern extracts hostnames from http(s):// URLs in source files.
var urlPattern = regexp.MustCompile(`https?://([a-zA-Z0-9][a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})`)

var textExtensions = map[string]bool{
	".py": true, ".js": true, ".ts": true, ".go": true,
	".yaml": true, ".yml": true, ".json": true, ".toml": true,
	".env": true, ".md": true, ".txt": true, ".sh": true,
}

func scanSkillsForDomains(dirs []string) []string {
	seen := make(map[string]bool)
	for _, dir := range dirs {
		_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			if !textExtensions[filepath.Ext(path)] {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			for _, m := range urlPattern.FindAllSubmatch(data, -1) {
				domain := string(m[1])
				if domain == "localhost" || strings.HasSuffix(domain, ".local") {
					continue
				}
				seen[domain] = true
			}
			return nil
		})
	}
	var result []string
	for d := range seen {
		result = append(result, d)
	}
	sort.Strings(result)
	return result
}

func buildProposedConfig(conns []ObservedConnection, skillDomains []string) *FirewallConfig {
	cfg := DefaultFirewallConfig()

	domainSet := make(map[string]bool)
	for _, d := range cfg.Allowlist.Domains {
		domainSet[d] = true
	}

	var extraIPs []string
	for _, c := range conns {
		if c.Domain != "" {
			domainSet[apexDomain(c.Domain)] = true
		} else {
			extraIPs = append(extraIPs, c.RemoteIP)
		}
	}
	for _, d := range skillDomains {
		domainSet[d] = true
	}

	var domains []string
	for d := range domainSet {
		domains = append(domains, d)
	}
	sort.Strings(domains)
	cfg.Allowlist.Domains = domains
	cfg.Allowlist.IPs = dedupeStrings(extraIPs)
	return cfg
}

func findWouldBlock(conns []ObservedConnection, cfg *FirewallConfig) []ObservedConnection {
	if cfg.DefaultAction != "deny" {
		return nil
	}
	allowedDomains := make(map[string]bool)
	for _, d := range cfg.Allowlist.Domains {
		allowedDomains[d] = true
	}
	allowedIPs := make(map[string]bool)
	for _, ip := range cfg.Allowlist.IPs {
		allowedIPs[ip] = true
	}

	var blocked []ObservedConnection
	for _, c := range conns {
		if allowedIPs[c.RemoteIP] {
			continue
		}
		if c.Domain != "" {
			apex := apexDomain(c.Domain)
			if allowedDomains[apex] || allowedDomains[c.Domain] {
				continue
			}
		}
		blocked = append(blocked, c)
	}
	return blocked
}

func apexDomain(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) <= 2 {
		return domain
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

func isPrivateIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, cidr := range []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"127.0.0.0/8", "169.254.0.0/16",
	} {
		_, network, _ := net.ParseCIDR(cidr)
		if network != nil && network.Contains(parsed) {
			return true
		}
	}
	return false
}

func dedupeStrings(ss []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}
