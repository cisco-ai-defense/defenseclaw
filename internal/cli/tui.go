package cli

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/tui"
)

var tuiCmd = &cobra.Command{
	Use:   "tui",
	Short: "Open the interactive terminal dashboard",
	Long:  "Launches the DefenseClaw TUI with live alerts, skills, and MCP server management.",
	RunE:  runTUI,
}

func init() {
	rootCmd.AddCommand(tuiCmd)
}

func runTUI(_ *cobra.Command, _ []string) error {
	model := tui.New(auditStore, cfg.OpenShell.Binary, cfg.Firewall.AnchorName)

	p := tea.NewProgram(model, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		return fmt.Errorf("tui: %w", err)
	}
	return nil
}
