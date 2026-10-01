package platform

import (
	"fmt"
	"net"
	"os/exec"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/shield/providers"
)

// ResolveLLMIPs resolves all LLM provider domains to IP addresses.
func ResolveLLMIPs(registry *providers.Registry) ([]string, error) {
	var allIPs []string
	seen := make(map[string]bool)

	for _, p := range registry.Providers() {
		for _, domain := range p.Domains {
			if strings.HasPrefix(domain, ".") || strings.Contains(domain, "localhost") || strings.Contains(domain, "127.0.0.1") {
				continue
			}
			host := domain
			if h, _, err := net.SplitHostPort(domain); err == nil {
				host = h
			}
			ips, err := net.LookupHost(host)
			if err != nil {
				continue
			}
			for _, ip := range ips {
				if !seen[ip] {
					seen[ip] = true
					allIPs = append(allIPs, ip)
				}
			}
		}
	}
	return allIPs, nil
}

// BuildPFConf generates pf.conf rules that redirect outbound port-443 traffic
// to LLM provider IPs through the local shield proxy.
//
// Uses "rdr pass" on the default route interface. On macOS, transparent proxy
// needs the packet diverted before it leaves — this requires pf on the physical
// interface + enabling IP forwarding + the proxy using SO_ORIGINAL_DST equivalent.
//
// For the POC, we use a simpler approach: block outbound to LLM IPs on port 443,
// which forces applications to fail. Combined with https_proxy, apps that support
// it go through the proxy; apps that don't get blocked. This demonstrates the concept.
//
// Production would use a macOS Network Extension (NETransparentProxyProvider).
func BuildPFConf(ips []string) string {
	var sb strings.Builder
	sb.WriteString("# DefenseClaw Shield — block direct LLM access\n")
	sb.WriteString("# Forces traffic through the shield proxy\n")
	for _, ip := range ips {
		sb.WriteString(fmt.Sprintf("block drop out quick proto tcp from any to %s port 443\n", ip))
	}
	return sb.String()
}

// InstallPFRules installs pf rules that block direct access to LLM providers.
func InstallPFRules(ips []string) (undo func(), err error) {
	anchor := "com.defenseclaw.shield"
	rules := BuildPFConf(ips)

	cmd := exec.Command("sudo", "pfctl", "-a", anchor, "-f", "-")
	cmd.Stdin = strings.NewReader(rules)
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("pfctl: %s: %w", strings.TrimSpace(string(out)), err)
	}

	exec.Command("sudo", "pfctl", "-e").CombinedOutput()

	return func() {
		exec.Command("sudo", "pfctl", "-a", anchor, "-F", "all").CombinedOutput()
	}, nil
}

// PrintSetupInstructions prints manual setup steps.
func PrintSetupInstructions(proxyPort string, ips []string) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf(`
DefenseClaw Shield — Network Setup

The shield proxy is running on 127.0.0.1:%s.
To route Claude Code (or any agent) through it:

  export HTTPS_PROXY=http://127.0.0.1:%s
  export NODE_TLS_REJECT_UNAUTHORIZED=0
  claude "your prompt"

For agents that ignore HTTPS_PROXY (like Bun), block direct LLM access:

  echo '`, proxyPort, proxyPort))

	for _, ip := range ips {
		sb.WriteString(fmt.Sprintf("  block drop out quick proto tcp from any to %s port 443\n", ip))
	}

	sb.WriteString(fmt.Sprintf(`  ' | sudo pfctl -a com.defenseclaw.shield -f -
  sudo pfctl -e

This blocks direct connections to LLM APIs, forcing traffic through the proxy.
To undo: sudo pfctl -a com.defenseclaw.shield -F all
`))
	return sb.String()
}
