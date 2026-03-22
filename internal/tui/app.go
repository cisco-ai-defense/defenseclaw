package tui

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

const (
	tabAlerts = iota
	tabSkills
	tabMCPs
	tabCount
)

const refreshInterval = 5 * time.Second

var tabNames = [tabCount]string{"Alerts", "Skills", "MCP Servers"}

type refreshMsg struct{}

type Model struct {
	activeTab int
	width     int
	height    int

	alerts    AlertsPanel
	skills    SkillsPanel
	mcps      MCPsPanel
	detail    DetailModal
	statusBar StatusBar

	store           *audit.Store
	openshellBinary string
	anchorName      string
}

func New(store *audit.Store, openshellBinary, anchorName string) Model {
	m := Model{
		alerts:          NewAlertsPanel(store),
		skills:          NewSkillsPanel(store),
		mcps:            NewMCPsPanel(store),
		detail:          NewDetailModal(),
		statusBar:       NewStatusBar(),
		store:           store,
		openshellBinary: openshellBinary,
		anchorName:      anchorName,
	}
	return m
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(
		tickRefresh(),
		func() tea.Msg {
			return refreshMsg{}
		},
	)
}

func tickRefresh() tea.Cmd {
	return tea.Tick(refreshInterval, func(_ time.Time) tea.Msg {
		return refreshMsg{}
	})
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		panelH := m.height - 5
		m.alerts.SetSize(m.width, panelH)
		m.skills.SetSize(m.width, panelH)
		m.mcps.SetSize(m.width, panelH)
		m.detail.SetSize(m.width, m.height)
		m.statusBar.SetSize(m.width)
		return m, nil

	case refreshMsg:
		m.refresh()
		return m, tickRefresh()

	case tea.KeyMsg:
		if m.detail.IsVisible() {
			switch msg.String() {
			case "esc", "enter", "q":
				m.detail.Hide()
			}
			return m, nil
		}

		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit

		case "tab":
			m.activeTab = (m.activeTab + 1) % tabCount
			return m, nil

		case "shift+tab":
			m.activeTab = (m.activeTab - 1 + tabCount) % tabCount
			return m, nil

		case "k", "up":
			m.cursorUp()
			return m, nil

		case "j", "down":
			m.cursorDown()
			return m, nil

		case "enter":
			m.showDetail()
			return m, nil

		case "b":
			msg := m.toggleBlock()
			m.statusBar.SetMessage(msg)
			return m, nil

		case "a":
			msg := m.toggleAllow()
			m.statusBar.SetMessage(msg)
			return m, nil

		case "d":
			if m.activeTab == tabAlerts {
				msg := m.alerts.Dismiss()
				m.statusBar.SetMessage(msg)
			}
			return m, nil

		case "r":
			m.refresh()
			m.statusBar.SetMessage("Refreshed")
			return m, nil
		}
	}

	return m, nil
}

func (m Model) View() string {
	if m.detail.IsVisible() {
		return m.detail.View()
	}

	var b strings.Builder

	b.WriteString(m.renderTabBar())
	b.WriteString("\n")

	switch m.activeTab {
	case tabAlerts:
		b.WriteString(m.alerts.View())
	case tabSkills:
		b.WriteString(m.skills.View())
	case tabMCPs:
		b.WriteString(m.mcps.View())
	}

	content := b.String()
	contentHeight := lipgloss.Height(content)
	panelHeight := m.height - 3
	if contentHeight < panelHeight {
		content += strings.Repeat("\n", panelHeight-contentHeight)
	}

	help := m.renderHelp()
	statusBar := m.statusBar.View()

	return content + "\n" + help + "\n" + statusBar
}

func (m *Model) refresh() {
	m.alerts.Refresh()
	m.skills.Refresh()
	m.mcps.Refresh()
	m.statusBar.Update(
		m.alerts.Count(),
		m.skills.Count(),
		m.skills.BlockedCount(),
		m.mcps.Count(),
		m.mcps.BlockedCount(),
	)
	m.statusBar.DetectSandbox(m.openshellBinary)
	m.statusBar.DetectFirewall(m.anchorName)
}

func (m *Model) cursorUp() {
	switch m.activeTab {
	case tabAlerts:
		m.alerts.CursorUp()
	case tabSkills:
		m.skills.CursorUp()
	case tabMCPs:
		m.mcps.CursorUp()
	}
}

func (m *Model) cursorDown() {
	switch m.activeTab {
	case tabAlerts:
		m.alerts.CursorDown()
	case tabSkills:
		m.skills.CursorDown()
	case tabMCPs:
		m.mcps.CursorDown()
	}
}

func (m *Model) showDetail() {
	switch m.activeTab {
	case tabAlerts:
		if sel := m.alerts.Selected(); sel != nil {
			m.detail.ShowAlert(sel.Severity, sel.Action, sel.Target, sel.Details, sel.Timestamp.Format("2006-01-02 15:04:05"))
		}
	case tabSkills:
		if sel := m.skills.Selected(); sel != nil {
			m.detail.ShowSkill(sel.Name, sel.Status, sel.Reason, sel.Time)
		}
	case tabMCPs:
		if sel := m.mcps.Selected(); sel != nil {
			m.detail.ShowMCP(sel.URL, sel.Status, sel.Reason, sel.Time)
		}
	}
}

func (m *Model) toggleBlock() string {
	switch m.activeTab {
	case tabSkills:
		return m.skills.ToggleBlock()
	case tabMCPs:
		return m.mcps.ToggleBlock()
	}
	return ""
}

func (m *Model) toggleAllow() string {
	switch m.activeTab {
	case tabSkills:
		sel := m.skills.Selected()
		if sel != nil && sel.Status == "blocked" {
			return m.skills.ToggleBlock()
		}
	case tabMCPs:
		sel := m.mcps.Selected()
		if sel != nil && sel.Status == "blocked" {
			return m.mcps.ToggleBlock()
		}
	}
	return ""
}

func (m Model) renderTabBar() string {
	var tabs []string
	for i, name := range tabNames {
		count := ""
		switch i {
		case tabAlerts:
			count = fmt.Sprintf(" (%d)", m.alerts.Count())
		case tabSkills:
			count = fmt.Sprintf(" (%d)", m.skills.Count())
		case tabMCPs:
			count = fmt.Sprintf(" (%d)", m.mcps.Count())
		}
		label := name + count
		if i == m.activeTab {
			tabs = append(tabs, ActiveTabStyle.Render(label))
		} else {
			tabs = append(tabs, TabStyle.Render(label))
		}
	}

	title := TitleStyle.Render("DefenseClaw")
	tabBar := lipgloss.JoinHorizontal(lipgloss.Top, tabs...)
	gap := m.width - lipgloss.Width(title) - lipgloss.Width(tabBar) - 4
	if gap < 1 {
		gap = 1
	}

	return title + strings.Repeat(" ", gap) + tabBar
}

func (m Model) renderHelp() string {
	base := "tab/shift-tab: switch  j/k/↑/↓: navigate  enter: detail  r: refresh  q: quit"
	switch m.activeTab {
	case tabAlerts:
		base = "tab/shift-tab: switch  j/k/↑/↓: navigate  enter: detail  d: dismiss  r: refresh  q: quit"
	case tabSkills, tabMCPs:
		base = "tab/shift-tab: switch  j/k/↑/↓: navigate  enter: detail  b: block  a: allow  r: refresh  q: quit"
	}
	return HelpStyle.Render("  " + base)
}
