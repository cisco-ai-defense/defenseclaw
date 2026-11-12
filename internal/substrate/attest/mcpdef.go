// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"

	toml "github.com/pelletier/go-toml/v2"

	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// MCPServer is one MCP server definition found in an image.
type MCPServer struct {
	Name      string
	Transport string // stdio, http or sse
	Command   string
	Args      []string
	// EnvKeys are the names of the server's env entries; SecretEnv are the
	// names whose value looks like an inline credential (values are never
	// kept).
	EnvKeys   []string
	SecretEnv []string
	URL       string
	// Source is the config file that defines the server.
	Source string
	// Scope names where inside the file (a project path) when it is not the
	// top level.
	Scope string
}

type rawServer struct {
	Type    string            `json:"type" toml:"type"`
	Command string            `json:"command" toml:"command"`
	Args    []string          `json:"args" toml:"args"`
	Env     map[string]string `json:"env" toml:"env"`
	URL     string            `json:"url" toml:"url"`
}

func (r rawServer) server(name, source, scope string) MCPServer {
	s := MCPServer{Name: name, Command: r.Command, Args: r.Args, URL: r.URL, Source: source, Scope: scope}
	switch {
	case r.URL != "" && (r.Type == "sse"):
		s.Transport = "sse"
	case r.URL != "":
		s.Transport = "http"
	default:
		s.Transport = "stdio"
	}
	for k, v := range r.Env {
		s.EnvKeys = append(s.EnvKeys, k)
		if looksLikeCredential(v) {
			s.SecretEnv = append(s.SecretEnv, k)
		}
	}
	sort.Strings(s.EnvKeys)
	sort.Strings(s.SecretEnv)
	return s
}

var credentialShape = regexp.MustCompile(`^(sk-[A-Za-z0-9_\-]{16,}|sk-ant-[A-Za-z0-9_\-]{16,}|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|xox[abprs]-[A-Za-z0-9\-]{10,}|AIza[0-9A-Za-z_\-]{30,}|eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,})$`)

func looksLikeCredential(v string) bool {
	v = strings.TrimSpace(v)
	if strings.HasPrefix(v, "${") || strings.HasPrefix(v, "$") || strings.HasPrefix(v, "placeholder") {
		return false
	}
	return credentialShape.MatchString(v)
}

// mcpConfigNames are the file names (and parents) that carry MCP servers.
func isMCPConfig(p string) bool {
	base := path.Base(p)
	switch base {
	case ".mcp.json", "mcp.json", ".claude.json", "managed-mcp.json":
		return true
	case "settings.json", "settings.local.json":
		return strings.HasSuffix(path.Dir(p), "/.claude")
	case "config.toml":
		return strings.HasSuffix(path.Dir(p), "/.codex") || strings.HasSuffix(path.Dir(p), "/codex")
	}
	return false
}

// ParseMCPConfig reads the servers one config file defines. A file that
// parses but names no servers returns none; a file that does not parse is an
// error, so a malformed config is never read as "no servers".
func ParseMCPConfig(p string, data []byte) ([]MCPServer, error) {
	var out []MCPServer
	if strings.HasSuffix(p, ".toml") {
		var doc struct {
			Servers map[string]rawServer `toml:"mcp_servers"`
		}
		if err := toml.Unmarshal(data, &doc); err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		for n, s := range doc.Servers {
			out = append(out, s.server(n, p, ""))
		}
	} else {
		var doc struct {
			Servers  map[string]rawServer `json:"mcpServers"`
			Projects map[string]struct {
				Servers map[string]rawServer `json:"mcpServers"`
			} `json:"projects"`
		}
		if err := json.Unmarshal(data, &doc); err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		for n, s := range doc.Servers {
			out = append(out, s.server(n, p, ""))
		}
		for proj, pv := range doc.Projects {
			for n, s := range pv.Servers {
				out = append(out, s.server(n, p, proj))
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Source != out[j].Source {
			return out[i].Source < out[j].Source
		}
		if out[i].Scope != out[j].Scope {
			return out[i].Scope < out[j].Scope
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

// ToolDef is a tool an MCP server declares, read from its source.
type ToolDef struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	InputSchema any    `json:"inputSchema"`
}

var (
	pyToolDecorator = regexp.MustCompile(`(?m)^[ \t]*@\w+\.tool\s*(\([^)]*\))?[ \t]*\n(?:[ \t]*@[^\n]*\n)*[ \t]*(?:async[ \t]+)?def[ \t]+(\w+)[ \t]*\(`)
	pyDecoDesc      = regexp.MustCompile(`description\s*=\s*(?:"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)')`)
	pyDecoName      = regexp.MustCompile(`name\s*=\s*(?:"([^"]+)"|'([^']+)')`)
	pyDocstring     = regexp.MustCompile(`(?s)"""(.*?)"""|'''(.*?)'''`)
	pyToolCtor      = regexp.MustCompile(`(?s)\bTool\(\s*name\s*=\s*"([^"]+)"\s*,\s*description\s*=\s*"((?:[^"\\]|\\.)*)"`)
	jsToolCall      = regexp.MustCompile("(?s)\\.(?:tool|registerTool)\\(\\s*[\"'`]([\\w\\-.]+)[\"'`]\\s*,\\s*(?:\\{[^}]*?description\\s*:\\s*)?[\"'`]((?:[^\"'`\\\\]|\\\\.)*)[\"'`]")
	jsToolObject    = regexp.MustCompile("(?s)name\\s*:\\s*[\"']([\\w\\-.]+)[\"']\\s*,\\s*description\\s*:\\s*[\"'`]((?:[^\"'`\\\\]|\\\\.)*)[\"'`]")
)

// ExtractToolDefs reads tool names and descriptions out of server source
// text (Python decorators and Tool(...), JavaScript tool calls and objects).
// It is static: a server that builds its tools at run time yields none.
func ExtractToolDefs(src string) []ToolDef {
	var out []ToolDef
	seen := map[string]bool{}
	add := func(name, desc string) {
		name = strings.TrimSpace(name)
		if name == "" || seen[name] {
			return
		}
		seen[name] = true
		out = append(out, ToolDef{Name: name, Description: strings.TrimSpace(desc),
			InputSchema: map[string]any{"type": "object", "properties": map[string]any{}}})
	}
	for _, m := range pyToolDecorator.FindAllStringSubmatchIndex(src, -1) {
		deco := ""
		if m[2] >= 0 {
			deco = src[m[2]:m[3]]
		}
		name := src[m[4]:m[5]]
		if nm := pyDecoName.FindStringSubmatch(deco); nm != nil {
			name = nm[1] + nm[2]
		}
		desc := ""
		if dm := pyDecoDesc.FindStringSubmatch(deco); dm != nil {
			desc = dm[1] + dm[2]
		} else {
			// The docstring: the first triple-quoted string after the
			// signature, before the next top-level statement.
			rest := src[m[1]:]
			if end := strings.Index(rest, "\ndef "); end > 0 {
				rest = rest[:end]
			}
			if len(rest) > 6000 {
				rest = rest[:6000]
			}
			if dm := pyDocstring.FindStringSubmatch(rest); dm != nil {
				desc = dm[1] + dm[2]
			}
		}
		add(name, desc)
	}
	for _, m := range pyToolCtor.FindAllStringSubmatch(src, -1) {
		add(m[1], m[2])
	}
	for _, m := range jsToolCall.FindAllStringSubmatch(src, -1) {
		add(m[1], m[2])
	}
	for _, m := range jsToolObject.FindAllStringSubmatch(src, -1) {
		add(m[1], m[2])
	}
	return out
}

// sourceExt are the server source files the extractor reads.
var sourceExt = map[string]bool{".py": true, ".js": true, ".mjs": true, ".cjs": true, ".ts": true}

// runtimeFetchers launch a package from a registry at run time.
var runtimeFetchers = map[string]bool{"npx": true, "uvx": true, "pipx": true, "bunx": true, "pnpx": true}

var pinnedPkg = regexp.MustCompile(`(@\d+\.\d+\.\d+|==\d+\.\d+|@sha256:[0-9a-f]{64})`)
var fetchAndExec = regexp.MustCompile(`(?i)(curl|wget)[^|;&]*\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:/(?:usr/)?bin/(?:env\s+)?)?(ba|z|da)?sh\b|\b(ba|z|da)?sh\s+(?:-\S+\s+)*<\(\s*(curl|wget)|\b(ba|z)?sh\s+-c\s+["']?(?:\$\(|\x60)\s*(curl|wget)|base64\s+(-d|--decode)[^|;]*\|\s*(?:/\S*/)?(ba|z)?sh|\beval\s+["']?(?:\$\(|\x60)\s*(curl|wget)`)
var shells = map[string]bool{"sh": true, "bash": true, "zsh": true, "dash": true, "ash": true, "cmd": true, "cmd.exe": true, "powershell": true, "pwsh": true}

// ConfigRules returns the findings of the config-level checks on a server:
// what launching it would do, whatever its tools say. allowedHosts, when not
// empty, lists the remote MCP hosts an admin allows.
func ConfigRules(s MCPServer, allowedHosts []string) []scanner.Finding {
	var out []scanner.Finding
	add := func(rule string, sev scanner.Severity, title, desc, fix string) {
		out = append(out, scanner.Finding{ID: rule, RuleID: rule, Severity: sev, Title: title,
			Description: desc, Location: s.Source, Remediation: fix, Scanner: ConfigScannerName,
			Category: "mcp-config", Tags: []string{"substrate", "template"}})
	}
	joined := s.Command + " " + strings.Join(s.Args, " ")
	base := path.Base(s.Command)
	if fetchAndExec.MatchString(joined) {
		add("mcp-fetch-and-exec", scanner.SeverityHigh, "MCP server downloads and runs code",
			fmt.Sprintf("server %q launches a command that pipes a download into a shell", s.Name),
			"Install the server into the image at build time and pin it")
	} else if shells[base] || (base == "env" && firstShellArg(s.Args)) {
		add("mcp-shell-wrapper", scanner.SeverityMedium, "MCP server starts through a shell",
			fmt.Sprintf("server %q runs %s, so its real command line is hidden from review", s.Name, base),
			"Start the server binary directly")
	}
	if runtimeFetchers[base] {
		pinned := false
		for _, a := range s.Args {
			if pinnedPkg.MatchString(a) {
				pinned = true
			}
		}
		if pinned {
			add("mcp-runtime-package-pinned", scanner.SeverityInfo, "MCP server package is fetched at run time (pinned)",
				fmt.Sprintf("server %q fetches a pinned package with %s each start", s.Name, base),
				"Install the package into the image so the build scans the code that runs")
		} else {
			add("mcp-runtime-package-unpinned", scanner.SeverityMedium, "MCP server package is fetched at run time and not pinned",
				fmt.Sprintf("server %q fetches a package with %s each start, with no version pin; the build cannot scan what it will run", s.Name, base),
				"Install the package into the image at a pinned version")
		}
	}
	if s.URL != "" {
		u, err := url.Parse(s.URL)
		host := ""
		if err == nil {
			host = strings.ToLower(u.Hostname())
		}
		switch {
		case err != nil || host == "":
			add("mcp-bad-url", scanner.SeverityMedium, "MCP server URL does not parse", fmt.Sprintf("server %q has an unusable URL", s.Name), "Fix the URL")
		default:
			if u.Scheme == "http" && !isLoopbackHost(host) {
				add("mcp-plain-http", scanner.SeverityMedium, "MCP server is reached over plain HTTP",
					fmt.Sprintf("server %q uses http:// to %s", s.Name, host), "Use https")
			}
			if a, err := netip.ParseAddr(host); err == nil && (a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsUnspecified()) {
				add("mcp-private-address", scanner.SeverityHigh, "MCP server points at a private or metadata address",
					fmt.Sprintf("server %q targets %s", s.Name, host), "Point it at a public MCP endpoint, or remove it")
			}
			if len(allowedHosts) > 0 && !hostAllowed(host, allowedHosts) {
				add("mcp-host-not-allowed", scanner.SeverityMedium, "MCP server host is not on the allow list",
					fmt.Sprintf("server %q uses %s, which the admin has not allowed", s.Name, host), "Ask the admin to allow the host, or remove the server")
			}
		}
	}
	for _, k := range s.SecretEnv {
		add("mcp-inline-secret", scanner.SeverityMedium, "MCP server config holds a credential",
			fmt.Sprintf("server %q sets %s to a value that looks like a credential; an image must hold no secret value", s.Name, k),
			"Use a Substrate secret with a placeholder")
	}
	return out
}

// ConfigScannerName names the findings of the config rules.
const ConfigScannerName = "dc-template-config"

func isLoopbackHost(h string) bool {
	if h == "localhost" {
		return true
	}
	a, err := netip.ParseAddr(h)
	return err == nil && a.IsLoopback()
}

func hostAllowed(host string, allowed []string) bool {
	for _, a := range allowed {
		a = strings.ToLower(strings.TrimSpace(a))
		if a == host || (strings.HasPrefix(a, "*.") && strings.HasSuffix(host, a[1:])) {
			return true
		}
	}
	return false
}

// firstShellArg reports whether "env [-flags] [VAR=x] <shell>" starts a shell.
func firstShellArg(args []string) bool {
	for _, a := range args {
		if strings.HasPrefix(a, "-") || strings.Contains(a, "=") {
			continue
		}
		return shells[path.Base(a)]
	}
	return false
}
