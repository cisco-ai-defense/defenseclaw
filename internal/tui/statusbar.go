package tui

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/defenseclaw/defenseclaw/internal/firewall"
	"github.com/defenseclaw/defenseclaw/internal/firewall/platform"
)

type StatusBar struct {
	width          int
	alertCount     int
	skillCount     int
	blockedSkills  int
	mcpCount       int
	blockedMCPs    int
	sandboxStatus  string
	firewallStatus string // "active", "inactive", "unknown"
	message        string
}

func NewStatusBar() StatusBar {
	return StatusBar{sandboxStatus: "unknown", firewallStatus: "unknown"}
}

func (s *StatusBar) SetSize(w int) {
	s.width = w
}

func (s *StatusBar) Update(alertCount, skillCount, blockedSkills, mcpCount, blockedMCPs int) {
	s.alertCount = alertCount
	s.skillCount = skillCount
	s.blockedSkills = blockedSkills
	s.mcpCount = mcpCount
	s.blockedMCPs = blockedMCPs
}

func (s *StatusBar) DetectSandbox(openshellBinary string) {
	if _, err := exec.LookPath(openshellBinary); err == nil {
		s.sandboxStatus = "active"
	} else {
		s.sandboxStatus = "inactive"
	}
}

// DetectFirewall checks whether the DefenseClaw firewall anchor is loaded.
func (s *StatusBar) DetectFirewall(anchorName string) {
	compiler := platform.NewCompiler()
	status := firewall.GetStatus(compiler, anchorName)
	if status.Error != "" {
		s.firewallStatus = "unknown"
	} else if status.Active {
		s.firewallStatus = "active"
	} else {
		s.firewallStatus = "inactive"
	}
}

func (s *StatusBar) SetMessage(msg string) {
	s.message = msg
}

func (s *StatusBar) View() string {
	left := StatusLabelStyle.Render(" DEFENSECLAW ")

	alertSeg := fmt.Sprintf(" Alerts: %d ", s.alertCount)
	if s.alertCount > 0 {
		alertSeg = StyleHigh.Render(alertSeg)
	}

	skillSeg := fmt.Sprintf(" Skills: %d (%d blocked) ", s.skillCount, s.blockedSkills)
	mcpSeg := fmt.Sprintf(" MCPs: %d (%d blocked) ", s.mcpCount, s.blockedMCPs)

	sandboxSeg := " Sandbox: " + s.sandboxStatus + " "
	if s.sandboxStatus == "active" {
		sandboxSeg = StyleAllowed.Render(sandboxSeg)
	} else {
		sandboxSeg = StyleInfo.Render(sandboxSeg)
	}

	fwSeg := " Firewall: " + s.firewallStatus + " "
	switch s.firewallStatus {
	case "active":
		fwSeg = StyleAllowed.Render(fwSeg)
	case "inactive":
		fwSeg = StyleHigh.Render(fwSeg)
	default:
		fwSeg = StyleInfo.Render(fwSeg)
	}

	sections := left + alertSeg + skillSeg + mcpSeg + sandboxSeg + fwSeg

	if s.message != "" {
		sections += "  " + lipgloss.NewStyle().Italic(true).Foreground(lipgloss.Color("228")).Render(s.message)
	}

	gap := s.width - lipgloss.Width(sections)
	if gap < 0 {
		gap = 0
	}

	return StatusBarStyle.Width(s.width).Render(sections + strings.Repeat(" ", gap))
}
