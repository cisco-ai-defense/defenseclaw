package unit

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/firewall"
	"github.com/defenseclaw/defenseclaw/internal/firewall/iptables"
	"github.com/defenseclaw/defenseclaw/internal/firewall/pfctl"
	"github.com/defenseclaw/defenseclaw/internal/firewall/platform"
)

// ── Config validation ─────────────────────────────────────────────────────────

func TestFirewallConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     firewall.FirewallConfig
		wantErr bool
	}{
		{
			name: "valid deny config",
			cfg: firewall.FirewallConfig{
				DefaultAction: "deny",
				Rules: []firewall.Rule{
					{Name: "allow-https", Protocol: "tcp", Port: 443, Action: "allow"},
				},
			},
		},
		{
			name: "valid allow config",
			cfg:  firewall.FirewallConfig{DefaultAction: "allow"},
		},
		{
			name:    "invalid default_action",
			cfg:     firewall.FirewallConfig{DefaultAction: "reject"},
			wantErr: true,
		},
		{
			name: "rule missing name",
			cfg: firewall.FirewallConfig{
				DefaultAction: "deny",
				Rules:         []firewall.Rule{{Action: "allow"}},
			},
			wantErr: true,
		},
		{
			name: "rule invalid action",
			cfg: firewall.FirewallConfig{
				DefaultAction: "deny",
				Rules:         []firewall.Rule{{Name: "bad", Action: "pass"}},
			},
			wantErr: true,
		},
		{
			name: "rule invalid direction",
			cfg: firewall.FirewallConfig{
				DefaultAction: "deny",
				Rules:         []firewall.Rule{{Name: "bad", Action: "allow", Direction: "inbound"}},
			},
			wantErr: true,
		},
		{
			name: "allowlist valid IP",
			cfg: firewall.FirewallConfig{
				DefaultAction: "deny",
				Allowlist:     firewall.AllowlistConfig{IPs: []string{"1.2.3.4"}},
			},
		},
		{
			name: "allowlist valid CIDR",
			cfg: firewall.FirewallConfig{
				DefaultAction: "deny",
				Allowlist:     firewall.AllowlistConfig{IPs: []string{"10.0.0.0/8"}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if tt.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// ── DefaultFirewallConfig ─────────────────────────────────────────────────────

func TestDefaultFirewallConfig(t *testing.T) {
	cfg := firewall.DefaultFirewallConfig()

	if cfg.DefaultAction != "deny" {
		t.Errorf("expected deny, got %q", cfg.DefaultAction)
	}
	if len(cfg.Allowlist.Domains) == 0 {
		t.Error("expected pre-populated domains")
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("default config invalid: %v", err)
	}
}

// ── Save / Load roundtrip ─────────────────────────────────────────────────────

func TestFirewallConfig_SaveLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "firewall.yaml")

	original := firewall.DefaultFirewallConfig()
	original.Allowlist.Domains = append(original.Allowlist.Domains, "example.com")

	if err := firewall.Save(original, path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := firewall.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if loaded.DefaultAction != original.DefaultAction {
		t.Errorf("DefaultAction: got %q, want %q", loaded.DefaultAction, original.DefaultAction)
	}

	found := false
	for _, d := range loaded.Allowlist.Domains {
		if d == "example.com" {
			found = true
		}
	}
	if !found {
		t.Error("loaded config missing added domain")
	}
}

func TestFirewallConfig_LoadMissingFile(t *testing.T) {
	_, err := firewall.Load("/nonexistent/firewall.yaml")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

// ── pfctl compiler ────────────────────────────────────────────────────────────

func TestPfctlCompiler_Platform(t *testing.T) {
	c := pfctl.New()
	if c.Platform() != "pfctl" {
		t.Errorf("expected pfctl, got %q", c.Platform())
	}
}

func TestPfctlCompiler_Compile_DenyDefault(t *testing.T) {
	c := pfctl.New()
	cfg := &firewall.FirewallConfig{
		DefaultAction: "deny",
		Allowlist: firewall.AllowlistConfig{
			IPs:  []string{"1.2.3.4"},
			Ports: []int{443},
		},
	}

	rules, err := c.Compile(cfg)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	joined := strings.Join(rules, "\n")
	if !strings.Contains(joined, "block out") {
		t.Error("expected 'block out' in deny rules")
	}
	if !strings.Contains(joined, "1.2.3.4") {
		t.Error("expected allowlist IP in rules")
	}
}

func TestPfctlCompiler_Compile_AllowDefault(t *testing.T) {
	c := pfctl.New()
	cfg := &firewall.FirewallConfig{DefaultAction: "allow"}

	rules, err := c.Compile(cfg)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	joined := strings.Join(rules, "\n")
	if !strings.Contains(joined, "pass out all") {
		t.Error("expected 'pass out all' in allow config")
	}
}

func TestPfctlCompiler_ApplyCommand(t *testing.T) {
	c := pfctl.New()
	cmd := c.ApplyCommand("/path/to/rules.conf")
	if !strings.Contains(cmd, "sudo pfctl") {
		t.Errorf("expected sudo pfctl, got %q", cmd)
	}
	if !strings.Contains(cmd, "/path/to/rules.conf") {
		t.Errorf("expected path in command, got %q", cmd)
	}
}

func TestPfctlCompiler_RemoveCommand(t *testing.T) {
	c := pfctl.New()
	cmd := c.RemoveCommand()
	if !strings.Contains(cmd, "pfctl") {
		t.Errorf("expected pfctl in remove command, got %q", cmd)
	}
}

func TestPfctlCompiler_ValidateArg(t *testing.T) {
	c := pfctl.New()

	if err := c.ValidateArg("1.2.3.4"); err != nil {
		t.Errorf("valid IP rejected: %v", err)
	}
	if err := c.ValidateArg("api.anthropic.com"); err != nil {
		t.Errorf("valid domain rejected: %v", err)
	}
	if err := c.ValidateArg("evil; rm -rf /"); err == nil {
		t.Error("shell injection not rejected")
	}
	if err := c.ValidateArg("$(whoami)"); err == nil {
		t.Error("command substitution not rejected")
	}
}

// ── iptables compiler ─────────────────────────────────────────────────────────

func TestIPTablesCompiler_Platform(t *testing.T) {
	c := iptables.New()
	if c.Platform() != "iptables" {
		t.Errorf("expected iptables, got %q", c.Platform())
	}
}

func TestIPTablesCompiler_Compile_DenyDefault(t *testing.T) {
	c := iptables.New()
	cfg := &firewall.FirewallConfig{
		DefaultAction: "deny",
		Allowlist: firewall.AllowlistConfig{
			IPs:  []string{"1.2.3.4"},
			Ports: []int{443},
		},
	}

	rules, err := c.Compile(cfg)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	joined := strings.Join(rules, "\n")
	if !strings.Contains(joined, "-A OUTPUT -j DROP") {
		t.Error("expected DROP rule for deny default")
	}
	if !strings.Contains(joined, "1.2.3.4") {
		t.Error("expected allowlist IP in rules")
	}
	if !strings.Contains(joined, "COMMIT") {
		t.Error("expected COMMIT at end of iptables rules")
	}
}

func TestIPTablesCompiler_Compile_AllowDefault(t *testing.T) {
	c := iptables.New()
	cfg := &firewall.FirewallConfig{DefaultAction: "allow"}

	rules, err := c.Compile(cfg)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	joined := strings.Join(rules, "\n")
	if strings.Contains(joined, "-A OUTPUT -j DROP") {
		t.Error("unexpected DROP rule in allow config")
	}
}

func TestIPTablesCompiler_ValidateArg(t *testing.T) {
	c := iptables.New()

	if err := c.ValidateArg("ACCEPT"); err != nil {
		t.Errorf("known flag ACCEPT rejected: %v", err)
	}
	if err := c.ValidateArg("1.2.3.4"); err != nil {
		t.Errorf("valid IP rejected: %v", err)
	}
	if err := c.ValidateArg("evil; rm -rf /"); err == nil {
		t.Error("shell injection not rejected")
	}
}

// ── RulesHash ─────────────────────────────────────────────────────────────────

func TestRulesHash_Deterministic(t *testing.T) {
	rules := []string{"pass out all", "block in all", "# This is a comment"}
	h1 := firewall.RulesHash(rules)
	h2 := firewall.RulesHash(rules)
	if h1 != h2 {
		t.Error("hash is not deterministic")
	}
}

func TestRulesHash_IgnoresComments(t *testing.T) {
	rules := []string{"pass out all"}
	rulesWithComment := []string{"# Generated by defenseclaw", "pass out all"}
	h1 := firewall.RulesHash(rules)
	h2 := firewall.RulesHash(rulesWithComment)
	if h1 != h2 {
		t.Error("comment changed hash — comments should be ignored")
	}
}

func TestRulesHash_DifferentRules(t *testing.T) {
	h1 := firewall.RulesHash([]string{"pass out all"})
	h2 := firewall.RulesHash([]string{"block out all"})
	if h1 == h2 {
		t.Error("different rules produced same hash")
	}
}

func TestRulesHash_Length(t *testing.T) {
	h := firewall.RulesHash([]string{"pass out all"})
	if len(h) != 12 {
		t.Errorf("expected 12-char hash, got %d chars: %q", len(h), h)
	}
}

// ── Platform compiler selection ───────────────────────────────────────────────

func TestNewCompiler_ReturnsCorrectPlatform(t *testing.T) {
	c := platform.NewCompiler()
	if runtime.GOOS == "darwin" {
		if c.Platform() != "pfctl" {
			t.Errorf("on darwin, expected pfctl, got %q", c.Platform())
		}
	} else {
		if c.Platform() != "iptables" {
			t.Errorf("on linux, expected iptables, got %q", c.Platform())
		}
	}
}

// ── Named rules compilation ───────────────────────────────────────────────────

func TestPfctlCompiler_NamedRule_Deny(t *testing.T) {
	c := pfctl.New()
	cfg := &firewall.FirewallConfig{
		DefaultAction: "allow",
		Rules: []firewall.Rule{
			{
				Name:        "block-metadata",
				Protocol:    "tcp",
				Destination: "169.254.169.254",
				Action:      "deny",
			},
		},
	}

	rules, err := c.Compile(cfg)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	joined := strings.Join(rules, "\n")
	if !strings.Contains(joined, "block") {
		t.Error("expected 'block' rule for deny action")
	}
	if !strings.Contains(joined, "169.254.169.254") {
		t.Error("expected metadata IP in rules")
	}
}

func TestIPTablesCompiler_NamedRule_Deny(t *testing.T) {
	c := iptables.New()
	cfg := &firewall.FirewallConfig{
		DefaultAction: "allow",
		Rules: []firewall.Rule{
			{
				Name:        "block-metadata",
				Protocol:    "tcp",
				Destination: "169.254.169.254",
				Action:      "deny",
			},
		},
	}

	rules, err := c.Compile(cfg)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	joined := strings.Join(rules, "\n")
	if !strings.Contains(joined, "-j DROP") {
		t.Error("expected DROP for deny rule")
	}
	if !strings.Contains(joined, "169.254.169.254") {
		t.Error("expected metadata IP in rules")
	}
}

// ── Logging rules ─────────────────────────────────────────────────────────────

func TestPfctlCompiler_Compile_WithLogging(t *testing.T) {
	c := pfctl.New()
	cfg := &firewall.FirewallConfig{
		DefaultAction: "deny",
		Logging:       firewall.LoggingConfig{Enabled: true, Prefix: "[BLOCKED]", RateLimit: "5/min"},
	}

	rules, err := c.Compile(cfg)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	joined := strings.Join(rules, "\n")
	if !strings.Contains(joined, "block out log") {
		t.Error("expected 'block out log' when logging enabled")
	}
}

// ── Shell injection guard in arg validation ───────────────────────────────────

func TestPfctlCompiler_ValidateArg_Injection(t *testing.T) {
	c := pfctl.New()
	dangerous := []string{
		"x; rm -rf /",
		"$(cat /etc/passwd)",
		"`whoami`",
		"x && curl evil.com",
		"x | nc -e /bin/sh",
		"x { malicious }",
	}
	for _, arg := range dangerous {
		t.Run(arg, func(t *testing.T) {
			if err := c.ValidateArg(arg); err == nil {
				t.Errorf("expected rejection of %q", arg)
			}
		})
	}
}

// ── compile produces stable rule file format ──────────────────────────────────

func TestPfctlCompiler_RulesWritten(t *testing.T) {
	c := pfctl.New()
	cfg := firewall.DefaultFirewallConfig()

	rules, err := c.Compile(cfg)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "firewall.pf.conf")
	content := strings.Join(rules, "\n") + "\n"
	if err := os.WriteFile(rulesPath, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	data, err := os.ReadFile(rulesPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !strings.Contains(string(data), "DefenseClaw") {
		t.Error("expected DefenseClaw header in compiled rules")
	}
}
