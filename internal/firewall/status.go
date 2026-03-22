package firewall

import (
	"crypto/sha256"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Status represents the current state of the firewall anchor.
type Status struct {
	Active      bool
	RuleCount   int
	AnchorName  string
	LastChecked time.Time
	Error       string // non-empty if pfctl/iptables check failed
}

// GetStatus checks whether the DefenseClaw anchor is currently loaded.
// Read-only: runs `pfctl -a <anchor> -sr` or `iptables -L OUTPUT -n`.
// Degrades gracefully if the command isn't available or requires root.
func GetStatus(compiler Compiler, anchorName string) Status {
	s := Status{
		AnchorName:  anchorName,
		LastChecked: time.Now(),
	}

	switch compiler.Platform() {
	case "pfctl":
		s.Active, s.RuleCount, s.Error = pfctlStatus(anchorName)
	case "iptables":
		s.Active, s.RuleCount, s.Error = iptablesStatus()
	default:
		s.Error = "unknown platform"
	}

	return s
}

func pfctlStatus(anchorName string) (active bool, ruleCount int, errMsg string) {
	cmd := exec.Command("pfctl", "-a", anchorName, "-sr")
	out, err := cmd.Output()
	if err != nil {
		// pfctl returns exit 1 when anchor is empty — that's ok.
		if len(out) == 0 {
			return false, 0, ""
		}
		return false, 0, fmt.Sprintf("pfctl: %v", err)
	}
	lines := nonEmptyLines(string(out))
	return len(lines) > 0, len(lines), ""
}

func iptablesStatus() (active bool, ruleCount int, errMsg string) {
	cmd := exec.Command("iptables", "-L", "OUTPUT", "-n")
	out, err := cmd.Output()
	if err != nil {
		return false, 0, fmt.Sprintf("iptables: %v", err)
	}
	// Count non-header lines.
	lines := nonEmptyLines(string(out))
	count := 0
	for _, l := range lines {
		if strings.HasPrefix(l, "Chain") || strings.HasPrefix(l, "target") {
			continue
		}
		count++
	}
	return count > 0, count, ""
}

// RulesHash returns a SHA-256 fingerprint of compiled rules so drift can be detected.
func RulesHash(rules []string) string {
	h := sha256.New()
	for _, r := range rules {
		if strings.HasPrefix(r, "#") {
			continue // Ignore comments — they don't affect enforcement.
		}
		fmt.Fprintln(h, r)
	}
	return fmt.Sprintf("%x", h.Sum(nil))[:12]
}

func nonEmptyLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(l); t != "" {
			out = append(out, t)
		}
	}
	return out
}
