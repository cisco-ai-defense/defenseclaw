// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package tui

import (
	"fmt"
	"strings"
	"time"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

const (
	PanelOverview = iota
	PanelAlerts
	PanelSkills
	PanelMCPs
	PanelPlugins
	PanelInventory
	PanelLogs
	PanelAudit
	PanelActivity
	PanelSetup
	panelCount
)

var panelNames = [panelCount]string{
	"Overview", "Alerts", "Skills", "MCPs", "Plugins",
	"Inventory", "Logs", "Audit", "Activity", "Setup",
}

const refreshInterval = 5 * time.Second
const slowRefreshInterval = 30 * time.Second

var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

type refreshMsg struct{}
type slowRefreshMsg struct{}
type spinTickMsg struct{}

// HealthSnapshot mirrors the gateway /health JSON structure.
type HealthSnapshot struct {
	StartedAt string           `json:"started_at"`
	UptimeMS  int64            `json:"uptime_ms"`
	Gateway   SubsystemHealth  `json:"gateway"`
	Watcher   SubsystemHealth  `json:"watcher"`
	API       SubsystemHealth  `json:"api"`
	Guardrail SubsystemHealth  `json:"guardrail"`
	Telemetry SubsystemHealth  `json:"telemetry"`
	Splunk    SubsystemHealth  `json:"splunk"`
	Sandbox   *SubsystemHealth `json:"sandbox,omitempty"`
}

// SubsystemHealth mirrors a single subsystem from /health.
type SubsystemHealth struct {
	State     string                 `json:"state"`
	Since     string                 `json:"since,omitempty"`
	LastError string                 `json:"last_error,omitempty"`
	Details   map[string]interface{} `json:"details,omitempty"`
}

type healthUpdateMsg struct {
	Health *HealthSnapshot
	Err    error
}

// Model is the root Bubbletea model for the unified TUI.
type Model struct {
	activePanel int
	width       int
	height      int

	// Panels (stubs that will be filled in later phases)
	overview  OverviewPanel
	alerts    AlertsPanel
	skills    SkillsPanel
	mcps      MCPsPanel
	plugins   PluginsPanel
	inventory InventoryPanel
	logs      LogsPanel
	auditHist AuditPanel
	activity  ActivityPanel
	setup     SetupPanel

	// Overlays
	detail     DetailModal
	palette    PaletteModel
	actionMenu ActionMenu
	helpOpen   bool

	// Persistent command input
	cmdInput      textinput.Model
	cmdInputFocus bool

	// Infrastructure
	store    *audit.Store
	cfg      *config.Config
	theme    *Theme
	hints    *HintEngine
	executor *CommandExecutor
	registry []CmdEntry

	// Notifications
	toasts ToastManager

	// State
	health      *HealthSnapshot
	commandsRun int
	version     string
	spinFrame   int
	lastRefresh time.Time

	// v2 terminal state
	isDark  bool
	focused bool
}

// Deps holds all external dependencies needed to construct the TUI Model.
type Deps struct {
	Store           *audit.Store
	Config          *config.Config
	OpenshellBinary string
	AnchorName      string
	Version         string
}

// SetProgram sets the tea.Program reference on the executor for sending messages.
func (m *Model) SetProgram(p *tea.Program) {
	m.executor.SetProgram(p)
}

// New creates the root TUI model with all panels initialized.
func New(deps Deps) Model {
	theme := DefaultTheme()
	executor := NewCommandExecutor()
	registry := BuildRegistry()

	ti := textinput.New()
	ti.Placeholder = "Type a command… (no \"defenseclaw\" prefix needed)"
	ti.Prompt = "> "
	ti.CharLimit = 256
	ti.SetWidth(60)
	s := textinput.DefaultStyles(true)
	inputBg := lipgloss.Color("235")
	s.Focused.Prompt = lipgloss.NewStyle().Foreground(lipgloss.Color("62")).Bold(true).Background(inputBg)
	s.Focused.Text = lipgloss.NewStyle().Foreground(lipgloss.Color("252")).Background(inputBg)
	s.Focused.Placeholder = lipgloss.NewStyle().Foreground(lipgloss.Color("243")).Background(inputBg)
	ti.SetStyles(s)

	m := Model{
		overview:   NewOverviewPanel(theme, deps.Config, deps.Version),
		alerts:     NewAlertsPanel(deps.Store),
		skills:     NewSkillsPanel(deps.Store),
		mcps:       NewMCPsPanel(deps.Store),
		plugins:    NewPluginsPanel(theme, deps.Store),
		inventory:  NewInventoryPanel(theme, executor, deps.Store),
		logs:       NewLogsPanel(theme, deps.Config),
		auditHist:  NewAuditPanel(theme, deps.Store),
		activity:   NewActivityPanel(theme),
		setup:      NewSetupPanel(theme, deps.Config, executor),
		detail:     NewDetailModal(),
		palette:    NewPaletteModel(theme, registry, executor),
		actionMenu: NewActionMenu(theme),

		cmdInput: ti,

		store:    deps.Store,
		cfg:      deps.Config,
		theme:    theme,
		hints:    NewHintEngine(),
		executor: executor,
		registry: registry,
		version:  deps.Version,

		isDark:  true,
		focused: true,
	}
	return m
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(
		tickRefresh(),
		tickSlowRefresh(),
		func() tea.Msg { return refreshMsg{} },
		m.logs.Init(),
		tickSpin(),
		func() tea.Msg { return tea.RequestBackgroundColor() },
	)
}

func tickSpin() tea.Cmd {
	return tea.Tick(100*time.Millisecond, func(_ time.Time) tea.Msg {
		return spinTickMsg{}
	})
}

func tickRefresh() tea.Cmd {
	return tea.Tick(refreshInterval, func(_ time.Time) tea.Msg {
		return refreshMsg{}
	})
}

func tickSlowRefresh() tea.Cmd {
	return tea.Tick(slowRefreshInterval, func(_ time.Time) tea.Msg {
		return slowRefreshMsg{}
	})
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.resizePanels()
		return m, nil

	case refreshMsg:
		m.refresh()
		m.toasts.Tick()
		cmds = append(cmds, tickRefresh())
		cmds = append(cmds, m.pollHealth())
		return m, tea.Batch(cmds...)

	case slowRefreshMsg:
		cmds = append(cmds, tickSlowRefresh())
		if m.inventory.loaded && !m.inventory.loading {
			cmds = append(cmds, m.inventory.LoadCmd())
		}
		if m.plugins.loaded && !m.plugins.loading {
			cmds = append(cmds, m.plugins.LoadCmd())
		}
		return m, tea.Batch(cmds...)

	case healthUpdateMsg:
		if msg.Err != nil {
			m.health = nil
		} else {
			m.health = msg.Health
		}
		m.overview.SetHealth(m.health)
		return m, nil

	case CommandStartMsg:
		m.commandsRun++
		m.activity.AddEntry(msg.Command)
		return m, nil

	case CommandOutputMsg:
		m.activity.AppendOutput(msg.Line)
		if m.setup.IsWizardRunning() {
			m.setup.WizardAppendOutput(msg.Line)
		}
		return m, nil

	case CommandDoneMsg:
		m.activity.FinishEntry(msg.ExitCode, msg.Duration)
		m.refresh()
		if m.setup.IsWizardRunning() {
			m.setup.WizardFinished(msg.ExitCode)
		}
		if msg.ExitCode != 0 {
			m.toasts.Push(ToastError, fmt.Sprintf("'%s' failed (exit %d)", msg.Command, msg.ExitCode))
		} else {
			m.toasts.Push(ToastSuccess, fmt.Sprintf("'%s' completed", msg.Command))
		}
		var postCmds []tea.Cmd
		if m.inventory.loaded && !m.inventory.loading {
			postCmds = append(postCmds, m.inventory.LoadCmd())
		}
		if m.plugins.loaded && !m.plugins.loading {
			postCmds = append(postCmds, m.plugins.LoadCmd())
		}
		if len(postCmds) > 0 {
			return m, tea.Batch(postCmds...)
		}
		return m, nil

	case InventoryLoadedMsg:
		m.inventory.ApplyLoaded(msg)
		return m, nil

	case PluginsLoadedMsg:
		m.plugins.ApplyLoaded(msg)
		return m, nil

	case tea.BackgroundColorMsg:
		m.isDark = msg.IsDark()
		return m, nil

	case tea.FocusMsg:
		m.focused = true
		return m, nil

	case tea.BlurMsg:
		m.focused = false
		return m, nil

	case spinTickMsg:
		m.spinFrame = (m.spinFrame + 1) % len(spinnerFrames)
		return m, tickSpin()

	case logPollMsg:
		var cmd tea.Cmd
		m.logs, cmd = m.logs.Update(msg)
		if cmd != nil {
			cmds = append(cmds, cmd)
		}
		return m, tea.Batch(cmds...)

	case tea.KeyPressMsg:
		return m.handleKey(msg)

	case tea.MouseMsg:
		mouse := msg.Mouse()
		switch msg.(type) {
		case tea.MouseClickMsg:
			return m.handleMouseClick(mouse)
		case tea.MouseWheelMsg:
			return m.handleMouseWheel(mouse)
		case tea.MouseMotionMsg:
			return m.handleMouseMotion(mouse)
		}
		return m, nil
	}

	// Forward cursor blink and other messages to the text input when focused
	if m.cmdInputFocus {
		var cmd tea.Cmd
		m.cmdInput, cmd = m.cmdInput.Update(msg)
		if cmd != nil {
			cmds = append(cmds, cmd)
		}
	}

	// Forward to active panel
	switch m.activePanel {
	case PanelLogs:
		var cmd tea.Cmd
		m.logs, cmd = m.logs.Update(msg)
		if cmd != nil {
			cmds = append(cmds, cmd)
		}
	case PanelActivity:
		m.activity.Update(msg)
	}

	return m, tea.Batch(cmds...)
}

func (m Model) handleMouseClick(mouse tea.Mouse) (tea.Model, tea.Cmd) {
	y := mouse.Y
	x := mouse.X

	if mouse.Button != tea.MouseLeft {
		return m, nil
	}

	// Block clicks when a full-screen overlay is active
	if m.helpOpen {
		m.helpOpen = false
		return m, nil
	}
	if m.actionMenu.IsVisible() {
		m.actionMenu.Hide()
		return m, nil
	}
	if m.detail.IsVisible() {
		m.detail.Hide()
		return m, nil
	}

	// Click on header row => tab switch
	if y == 0 {
		if panel := m.tabHitTest(x); panel >= 0 {
			if cmd := m.switchPanel(panel); cmd != nil {
				return m, cmd
			}
		}
		return m, nil
	}
	// Click on input bar row
	if y == m.height-3 {
		if !m.cmdInputFocus {
			m.cmdInputFocus = true
			cmd := m.cmdInput.Focus()
			m.palette.Open()
			return m, cmd
		}
		return m, nil
	}
	// Click on status strip row
	if y == m.height-1 {
		return m, nil
	}
	// Click in panel area => unfocus input if focused
	if m.cmdInputFocus {
		m.cmdInputFocus = false
		m.cmdInput.Blur()
		return m, nil
	}
	// Forward clicks to list panels for cursor positioning
	return m.handlePanelClick(x, y)
}

func (m Model) handleMouseWheel(mouse tea.Mouse) (tea.Model, tea.Cmd) {
	switch mouse.Button {
	case tea.MouseWheelUp:
		return m.handlePanelScroll(-3)
	case tea.MouseWheelDown:
		return m.handlePanelScroll(3)
	}
	return m, nil
}

func (m Model) handleMouseMotion(mouse tea.Mouse) (tea.Model, tea.Cmd) {
	if m.activePanel == PanelSetup {
		panelStartY := 1
		relY := mouse.Y - panelStartY
		m.setup.HandleMouseMotion(mouse.X, relY)
	}
	return m, nil
}

func (m Model) tabHitTest(x int) int {
	titleWidth := lipgloss.Width(
		lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("230")).
			Background(lipgloss.Color("62")).
			Padding(0, 1).
			Render("DC " + m.version),
	)
	totalTabW := m.totalTabBarWidth()
	tabBarStart := m.width - totalTabW
	if tabBarStart < titleWidth+1 {
		tabBarStart = titleWidth + 1
	}
	return m.tabHitTestFromStart(x, tabBarStart)
}

func (m Model) tabLabelWidth(i int) int {
	labels := m.buildTabLabels()
	if i < 0 || i >= len(labels) {
		return 0
	}
	return lipgloss.Width(labels[i]) + 2 // +2 for Padding(0,1)
}

func (m Model) totalTabBarWidth() int {
	total := 0
	for i := range panelNames {
		total += m.tabLabelWidth(i)
		if i > 0 {
			total++ // space separator
		}
	}
	return total
}

func (m Model) tabHitTestFromStart(x, start int) int {
	cursor := start
	for i := range panelNames {
		if i > 0 {
			cursor++ // space separator
		}
		w := m.tabLabelWidth(i)
		if x >= cursor && x < cursor+w {
			return i
		}
		cursor += w
	}
	return -1
}

func (m Model) handlePanelClick(x, y int) (tea.Model, tea.Cmd) {
	panelStartY := 1 // header is 1 line, panel content starts at row 1
	relY := y - panelStartY
	if relY < 0 {
		return m, nil
	}

	switch m.activePanel {
	case PanelAlerts:
		if relY == 0 {
			positions := m.alerts.SevButtonPositions()
			for i, pos := range positions {
				if x >= pos[0] && x < pos[1] {
					m.alerts.SetSevFilter(sevFilterOrder[i])
					return m, nil
				}
			}
			return m, nil
		}
		// buttons(1) + separator(1) + header(1) = 3
		headerLines := 3
		if m.alerts.FilterText() != "" {
			headerLines++
		}
		if m.alerts.IsFiltering() {
			headerLines++
		}
		idx := relY - headerLines + m.alerts.ScrollOffset()
		if idx >= 0 && idx < m.alerts.FilteredCount() {
			if m.alerts.CursorAt() == idx {
				m.alerts.ToggleDetail()
			} else {
				m.alerts.SetCursor(idx)
			}
		}
	case PanelSkills:
		// summary(1) + separator(1) + [filter] + [filtering] + header(1)
		headerLines := 3
		if m.skills.FilterText() != "" {
			headerLines++
		}
		if m.skills.IsFiltering() {
			headerLines++
		}
		idx := relY - headerLines + m.skills.ScrollOffset()
		if idx >= 0 && idx < m.skills.FilteredCount() {
			if m.skills.CursorAt() == idx {
				return m.openSkillDetail()
			}
			m.skills.SetCursor(idx)
		}
	case PanelMCPs:
		headerLines := 3
		if m.mcps.FilterText() != "" {
			headerLines++
		}
		if m.mcps.IsFiltering() {
			headerLines++
		}
		idx := relY - headerLines + m.mcps.ScrollOffset()
		if idx >= 0 && idx < m.mcps.FilteredCount() {
			if m.mcps.CursorAt() == idx {
				return m.openMCPDetail()
			}
			m.mcps.SetCursor(idx)
		}
	case PanelPlugins:
		// header(1) only
		headerLines := 1
		idx := relY - headerLines + m.plugins.ScrollOffset()
		if idx >= 0 && idx < m.plugins.FilteredCount() {
			if m.plugins.CursorAt() == idx {
				return m.openPluginDetail()
			}
			m.plugins.SetCursor(idx)
		}
	case PanelInventory:
		// Row 0: sub-tab bar
		if relY == 0 {
			if tab := m.inventory.SubTabHitTest(x); tab >= 0 {
				m.inventory.activeSub = tab
				m.inventory.cursor = 0
				m.inventory.detailOpen = false
				m.inventory.detailCache = nil
				m.inventory.filter = ""
			}
			return m, nil
		}
		// subtab(1) + separator(1) = 2 lines before content
		contentRelY := relY - 2
		if contentRelY < 0 {
			return m, nil
		}
		switch m.inventory.activeSub {
		case invSubSummary:
			return m, nil
		case invSubSkills:
			// Row 0 of content = summary stats bar (clickable filters)
			if contentRelY == 0 {
				positions := m.inventory.SkillFilterPositions()
				filterKeys := []string{"", "eligible", "warning", "blocked"}
				for i, pos := range positions {
					if x >= pos[0] && x < pos[1] {
						m.inventory.SetFilter(filterKeys[i])
						return m, nil
					}
				}
				return m, nil
			}
			// filter indicator(0-1) + blank(1) + column header(1) + list items
			headerLines := 2 // blank + column header
			if m.inventory.filter != "" {
				headerLines++ // filter indicator line
			}
			idx := contentRelY - 1 - headerLines // -1 for stats bar
			if idx >= 0 {
				prev := m.inventory.CursorAt()
				m.inventory.SetCursor(idx)
				if prev == idx {
					return m.openInventoryDetail()
				}
			}
		case invSubPlugins:
			if contentRelY == 0 {
				positions := m.inventory.PluginFilterPositions()
				filterKeys := []string{"", "loaded", "disabled", "blocked"}
				for i, pos := range positions {
					if x >= pos[0] && x < pos[1] {
						m.inventory.SetFilter(filterKeys[i])
						return m, nil
					}
				}
				return m, nil
			}
			headerLines := 2
			if m.inventory.filter != "" {
				headerLines++
			}
			idx := contentRelY - 1 - headerLines
			if idx >= 0 {
				prev := m.inventory.CursorAt()
				m.inventory.SetCursor(idx)
				if prev == idx {
					return m.openInventoryDetail()
				}
			}
		case invSubMCPs:
			headerLines := 1
			idx := contentRelY - headerLines
			if idx >= 0 {
				prev := m.inventory.CursorAt()
				m.inventory.SetCursor(idx)
				if prev == idx {
					return m.openInventoryDetail()
				}
			}
		default:
			idx := contentRelY
			if idx >= 0 {
				prev := m.inventory.CursorAt()
				m.inventory.SetCursor(idx)
				if prev == idx {
					return m.openInventoryDetail()
				}
			}
		}
	case PanelAudit:
		headerLines := 0
		if m.auditHist.FilterText() != "" {
			headerLines++
		}
		if m.auditHist.IsFiltering() {
			headerLines++
		}
		// summary(1) + separator(1) + header(1)
		headerLines += 3
		idx := relY - headerLines + m.auditHist.ScrollOffset()
		if idx >= 0 && idx < m.auditHist.FilteredCount() {
			if m.auditHist.CursorAt() == idx {
				return m.openAuditDetail()
			}
			m.auditHist.SetCursor(idx)
		}
	case PanelActivity:
		entryIdx := relY / 2
		if entryIdx >= 0 && entryIdx < m.activity.Count() {
			m.activity.SetCursor(entryIdx)
		}
	case PanelSetup:
		m.setup.HandleMouseClick(x, relY)
	case PanelLogs:
		if relY == 0 {
			tabX := 2
			for i, name := range logSourceNames {
				label := fmt.Sprintf("  %s  ", name)
				w := lipgloss.Width(m.theme.ActiveTab.Render(label))
				if x >= tabX && x < tabX+w {
					m.logs.source = i
					m.logs.scroll = 0
					return m, nil
				}
				tabX += w + 2
			}
			if x >= tabX+3 {
				m.logs.TogglePause()
			}
		}
		if relY == 1 {
			btnX := 2
			for _, preset := range filterPresets {
				label := filterLabels[preset]
				num := fmt.Sprintf("%d", filterPresetIndex(preset)+1)
				text := fmt.Sprintf(" %s %s ", num, label)
				w := lipgloss.Width(text)
				if x >= btnX && x < btnX+w {
					m.logs.SetFilter(preset)
					return m, nil
				}
				btnX += w + 2
			}
		}
	}
	return m, nil
}

func (m Model) handlePanelScroll(delta int) (tea.Model, tea.Cmd) {
	switch m.activePanel {
	case PanelOverview:
		m.overview.ScrollBy(delta)
	case PanelAlerts:
		m.alerts.ScrollBy(delta)
	case PanelSkills:
		m.skills.ScrollBy(delta)
	case PanelMCPs:
		m.mcps.ScrollBy(delta)
	case PanelPlugins:
		m.plugins.ScrollBy(delta)
	case PanelInventory:
		m.inventory.ScrollBy(delta)
	case PanelLogs:
		m.logs.ScrollBy(delta)
	case PanelAudit:
		m.auditHist.ScrollBy(delta)
	case PanelActivity:
		m.activity.ScrollBy(delta)
	case PanelSetup:
		m.setup.ScrollBy(delta)
	}
	return m, nil
}

func (m Model) handleKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	// Help overlay takes priority
	if m.helpOpen {
		m.helpOpen = false
		return m, nil
	}

	// Action menu takes priority
	if m.actionMenu.IsVisible() {
		return m.handleActionMenuKey(msg)
	}

	// Detail modal takes priority
	if m.detail.IsVisible() {
		switch msg.String() {
		case "esc", "enter", "q":
			m.detail.Hide()
		}
		return m, nil
	}

	// Persistent command input takes priority when focused
	if m.cmdInputFocus {
		return m.handleCmdInputKey(msg)
	}

	// Command palette overlay (legacy, still usable)
	if m.palette.Active {
		return m.handlePaletteKey(msg)
	}

	// Filter input mode takes priority
	if m.isFilterActive() {
		return m.handleFilterKey(msg)
	}

	// If Activity terminal mode is active, let it consume q/esc instead of quitting
	if m.activePanel == PanelActivity && m.activity.termMode {
		if msg.String() == "ctrl+c" {
			m.executor.Cancel()
			return m, nil
		}
		m.activity.Update(msg)
		return m, nil
	}

	// If Setup has a form, wizard running, output visible, or field editing, let it consume keys
	if m.activePanel == PanelSetup && (m.setup.editing || m.setup.wizFormEditing || m.setup.IsFormActive() || m.setup.IsWizardRunning() || len(m.setup.wizOutput) > 0) {
		return m.handleSetupKey(msg)
	}

	if m.panelOwnsDigitShortcut(msg.String()) {
		return m.handlePanelKey(msg)
	}

	switch msg.String() {
	case "ctrl+c":
		return m, tea.Quit
	case "q":
		if m.activePanel == PanelSetup {
			return m.handlePanelKey(msg)
		}
		return m, tea.Quit

	case "?":
		m.helpOpen = true
		return m, nil

	case ":", "ctrl+k":
		m.cmdInputFocus = true
		cmd := m.cmdInput.Focus()
		m.palette.Open()
		return m, cmd

	case "/":
		return m.startFilter()

	// Number keys switch panels
	case "1":
		m.activePanel = PanelOverview
	case "2":
		m.activePanel = PanelAlerts
	case "3":
		m.activePanel = PanelSkills
	case "4":
		m.activePanel = PanelMCPs
	case "5":
		if cmd := m.switchPanel(PanelPlugins); cmd != nil {
			return m, cmd
		}
	case "6":
		if cmd := m.switchPanel(PanelInventory); cmd != nil {
			return m, cmd
		}
	case "7":
		m.activePanel = PanelLogs
	case "8":
		m.activePanel = PanelAudit
	case "9":
		m.activePanel = PanelActivity
	case "0":
		m.activePanel = PanelSetup

	case "tab":
		m.activePanel = (m.activePanel + 1) % panelCount
	case "shift+tab":
		m.activePanel = (m.activePanel - 1 + panelCount) % panelCount

	default:
		return m.handlePanelKey(msg)
	}

	return m, nil
}

func (m Model) panelOwnsDigitShortcut(key string) bool {
	switch m.activePanel {
	case PanelAlerts:
		return key >= "1" && key <= "5"
	case PanelInventory:
		return key >= "1" && key <= "4"
	default:
		return false
	}
}

func (m Model) isFilterActive() bool {
	switch m.activePanel {
	case PanelAlerts:
		return m.alerts.IsFiltering()
	case PanelSkills:
		return m.skills.IsFiltering()
	case PanelMCPs:
		return m.mcps.IsFiltering()
	case PanelAudit:
		return m.auditHist.IsFiltering()
	}
	return false
}

func (m Model) startFilter() (tea.Model, tea.Cmd) {
	switch m.activePanel {
	case PanelAlerts:
		m.alerts.StartFilter()
	case PanelSkills:
		m.skills.StartFilter()
	case PanelMCPs:
		m.mcps.StartFilter()
	case PanelAudit:
		m.auditHist.StartFilter()
	}
	return m, nil
}

func (m Model) handleFilterKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	key := msg.String()
	switch key {
	case "esc":
		switch m.activePanel {
		case PanelAlerts:
			m.alerts.ClearFilter()
		case PanelSkills:
			m.skills.ClearFilter()
		case PanelMCPs:
			m.mcps.ClearFilter()
		case PanelAudit:
			m.auditHist.ClearFilter()
		}
	case "enter":
		switch m.activePanel {
		case PanelAlerts:
			m.alerts.StopFilter()
		case PanelSkills:
			m.skills.StopFilter()
		case PanelMCPs:
			m.mcps.StopFilter()
		case PanelAudit:
			m.auditHist.StopFilter()
		}
	case "backspace":
		switch m.activePanel {
		case PanelAlerts:
			f := m.alerts.FilterText()
			if len(f) > 0 {
				m.alerts.SetFilter(f[:len(f)-1])
			}
		case PanelSkills:
			f := m.skills.FilterText()
			if len(f) > 0 {
				m.skills.SetFilter(f[:len(f)-1])
			}
		case PanelMCPs:
			f := m.mcps.FilterText()
			if len(f) > 0 {
				m.mcps.SetFilter(f[:len(f)-1])
			}
		case PanelAudit:
			f := m.auditHist.FilterText()
			if len(f) > 0 {
				m.auditHist.SetFilter(f[:len(f)-1])
			}
		}
	default:
		if len(key) == 1 {
			switch m.activePanel {
			case PanelAlerts:
				m.alerts.SetFilter(m.alerts.FilterText() + key)
			case PanelSkills:
				m.skills.SetFilter(m.skills.FilterText() + key)
			case PanelMCPs:
				m.mcps.SetFilter(m.mcps.FilterText() + key)
			case PanelAudit:
				m.auditHist.SetFilter(m.auditHist.FilterText() + key)
			}
		}
	}
	return m, nil
}

func (m Model) handleActionMenuKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.actionMenu.Hide()
	case "up", "k":
		m.actionMenu.CursorUp()
	case "down", "j":
		m.actionMenu.CursorDown()
	case "enter":
		sel := m.actionMenu.SelectedAction()
		if sel != nil {
			cmd := m.executeActionMenuItem(sel.Key)
			m.actionMenu.Hide()
			return m, cmd
		}
	default:
		key := msg.String()
		for _, action := range m.actionMenu.actions {
			if action.Key == key {
				cmd := m.executeActionMenuItem(key)
				m.actionMenu.Hide()
				return m, cmd
			}
		}
	}
	return m, nil
}

func (m Model) executeActionMenuItem(key string) tea.Cmd {
	switch m.activePanel {
	case PanelSkills:
		sel := m.skills.Selected()
		if sel == nil {
			return nil
		}
		switch key {
		case "s":
			return m.executor.Execute("defenseclaw", []string{"skill", "scan", sel.Name}, "scan skill "+sel.Name)
		case "i":
			return m.executor.Execute("defenseclaw", []string{"skill", "info", sel.Name}, "info skill "+sel.Name)
		case "b":
			return m.executor.Execute("defenseclaw", []string{"skill", "block", sel.Name}, "block skill "+sel.Name)
		case "a":
			return m.executor.Execute("defenseclaw", []string{"skill", "allow", sel.Name}, "allow skill "+sel.Name)
		case "u":
			return m.executor.Execute("defenseclaw", []string{"skill", "unblock", sel.Name}, "unblock skill "+sel.Name)
		case "d":
			return m.executor.Execute("defenseclaw", []string{"skill", "disable", sel.Name}, "disable skill "+sel.Name)
		case "q":
			return m.executor.Execute("defenseclaw", []string{"skill", "quarantine", sel.Name}, "quarantine skill "+sel.Name)
		case "r":
			return m.executor.Execute("defenseclaw", []string{"skill", "restore", sel.Name}, "restore skill "+sel.Name)
		}
	case PanelMCPs:
		sel := m.mcps.Selected()
		if sel == nil {
			return nil
		}
		switch key {
		case "s":
			return m.executor.Execute("defenseclaw", []string{"mcp", "scan", sel.URL}, "scan mcp "+sel.URL)
		case "b":
			return m.executor.Execute("defenseclaw", []string{"mcp", "block", sel.URL}, "block mcp "+sel.URL)
		case "a":
			return m.executor.Execute("defenseclaw", []string{"mcp", "allow", sel.URL}, "allow mcp "+sel.URL)
		case "u":
			return m.executor.Execute("defenseclaw", []string{"mcp", "unblock", sel.URL}, "unblock mcp "+sel.URL)
		case "x":
			return m.executor.Execute("defenseclaw", []string{"mcp", "unset", sel.URL}, "unset mcp "+sel.URL)
		}
	}
	return nil
}

func (m Model) handleCmdInputKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.cmdInputFocus = false
		m.cmdInput.Blur()
		m.cmdInput.SetValue("")
		m.palette.Close()
		return m, nil
	case "tab":
		if sel := m.palette.SelectedName(); sel != "" {
			m.cmdInput.SetValue(sel + " ")
			m.cmdInput.CursorEnd()
			m.palette.SetInput(sel + " ")
		}
		return m, nil
	case "up":
		m.palette.MoveUp()
		return m, nil
	case "down":
		m.palette.MoveDown()
		return m, nil
	case "enter":
		input := m.cmdInput.Value()
		m.cmdInputFocus = false
		m.cmdInput.Blur()
		m.cmdInput.SetValue("")
		m.palette.Close()
		if input == "" {
			return m, nil
		}
		entry, extra := MatchCommand(input, m.registry)
		if entry == nil {
			m.toasts.Push(ToastWarn, "Unknown command: "+input)
			m.activity.AddEntry("? " + input)
			m.activity.AppendOutput("Unknown command: " + input)
			m.activity.AppendOutput("Tip: type ':' and start typing to see available commands")
			m.activity.FinishEntry(1, 0)
			m.activePanel = PanelActivity
			return m, nil
		}
		args, err := buildCLIArgs(entry, extra)
		if err != nil {
			m.toasts.Push(ToastWarn, "Invalid command arguments: "+err.Error())
			m.activity.AddEntry("? " + input)
			m.activity.AppendOutput("Invalid command arguments: " + err.Error())
			m.activity.FinishEntry(1, 0)
			m.activePanel = PanelActivity
			return m, nil
		}
		displayName := entry.TUIName
		if extra != "" {
			displayName += " " + extra
		}
		m.activePanel = PanelActivity
		return m, m.executor.Execute(entry.CLIBinary, args, displayName)
	}

	// Forward all other keys to the textinput, then sync palette
	var cmd tea.Cmd
	m.cmdInput, cmd = m.cmdInput.Update(msg)
	m.palette.SetInput(m.cmdInput.Value())
	return m, cmd
}

func (m Model) handlePaletteKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.palette.Close()
		return m, nil
	case "enter":
		input := m.palette.input
		cmd, err := m.palette.Execute()
		m.palette.Close()
		if err != nil {
			m.toasts.Push(ToastWarn, "Invalid command arguments: "+err.Error())
			m.activity.AddEntry("? " + strings.TrimSpace(input))
			m.activity.AppendOutput("Invalid command arguments: " + err.Error())
			m.activity.FinishEntry(1, 0)
			m.activePanel = PanelActivity
			return m, nil
		}
		if cmd != nil {
			m.activePanel = PanelActivity
			return m, cmd
		}
		return m, nil
	default:
		m.palette.HandleKey(msg)
		return m, nil
	}
}

func (m Model) handlePanelKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch m.activePanel {
	case PanelOverview:
		return m.handleOverviewKey(msg)
	case PanelAlerts:
		return m.handleAlertsKey(msg)
	case PanelSkills:
		return m.handleSkillsKey(msg)
	case PanelMCPs:
		return m.handleMCPsKey(msg)
	case PanelPlugins:
		return m.handlePluginsKey(msg)
	case PanelLogs:
		return m.handleLogsKey(msg)
	case PanelInventory:
		return m.handleInventoryKey(msg)
	case PanelAudit:
		return m.handleAuditKey(msg)
	case PanelActivity:
		return m.handleActivityKey(msg)
	case PanelSetup:
		return m.handleSetupKey(msg)
	}
	return m, nil
}

func (m Model) handleSetupKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	key := msg.String()

	// Global setup shortcuts (not when editing, form active, or running a wizard)
	if !m.setup.editing && !m.setup.IsFormActive() && !m.setup.IsWizardRunning() && len(m.setup.wizOutput) == 0 {
		switch key {
		case "S":
			if m.setup.HasChanges() {
				if err := m.setup.SaveConfig(); err != nil {
					m.toasts.Push(ToastError, "Config save failed: "+err.Error())
					return m, nil
				}
				m.cfg = m.setup.GetConfig()
				m.toasts.Push(ToastSuccess, "Config saved — restarting gateway to apply changes…")
				return m, m.executor.Execute("defenseclaw-gateway", []string{"restart"}, "restart (config changed)")
			}
			return m, nil
		case "R":
			if err := m.setup.RevertConfig(); err != nil {
				m.toasts.Push(ToastError, "Config revert failed: "+err.Error())
			} else {
				m.cfg = m.setup.GetConfig()
				m.toasts.Push(ToastInfo, "Config reverted from disk")
			}
			return m, nil
		}
	}

	runCmd, binary, args, displayName := m.setup.HandleKey(msg)
	var cmds []tea.Cmd
	if focusCmd := m.setup.DrainFocusCmd(); focusCmd != nil {
		cmds = append(cmds, focusCmd)
	}
	if runCmd {
		if m.executor.IsRunning() {
			m.setup.WizardFinished(-1)
			m.toasts.Push(ToastWarn, "Another command is running — wait or press Ctrl+C first")
		} else {
			cmds = append(cmds, m.executor.Execute(binary, args, displayName))
		}
	}
	if len(cmds) > 0 {
		return m, tea.Batch(cmds...)
	}
	return m, nil
}

func (m Model) handleActivityKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "!":
		last := m.activity.LastCommand()
		if last != "" {
			entry, extra := MatchCommand(last, m.registry)
			if entry != nil {
				args, err := buildCLIArgs(entry, extra)
				if err != nil {
					m.toasts.Push(ToastWarn, "Cannot rerun command: "+err.Error())
					return m, nil
				}
				return m, m.executor.Execute(entry.CLIBinary, args, last)
			}
		}
	default:
		m.activity.Update(msg)
	}
	return m, nil
}

func (m Model) handleAuditKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "j", "down":
		m.auditHist.CursorDown()
	case "k", "up":
		m.auditHist.CursorUp()
	case "esc":
		if m.auditHist.IsDetailOpen() {
			m.auditHist.ToggleDetail()
		}
	case "enter":
		return m.openAuditDetail()
	case "r":
		m.auditHist.Refresh()
	case "e":
		const exportPath = "defenseclaw-audit-export.json"
		m.activity.AddEntry("export audit → " + exportPath)
		if err := m.exportAuditJSON(exportPath); err != nil {
			m.activity.AppendOutput("Export failed: " + err.Error())
			m.activity.FinishEntry(1, 0)
			m.toasts.Push(ToastError, "Audit export failed: "+err.Error())
			return m, nil
		}
		m.activity.AppendOutput("Wrote JSON audit export to " + exportPath)
		m.activity.FinishEntry(0, 0)
		m.toasts.Push(ToastSuccess, "Audit exported to "+exportPath)
	}
	return m, nil
}

func (m Model) handleOverviewKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "s":
		cmd := m.executor.Execute("defenseclaw", []string{"skill", "scan", "--all"}, "scan skill --all")
		m.activePanel = PanelActivity
		return m, cmd
	case "d":
		cmd := m.executor.Execute("defenseclaw", []string{"doctor"}, "doctor")
		m.activePanel = PanelActivity
		return m, cmd
	case "i":
		if cmd := m.switchPanel(PanelInventory); cmd != nil {
			return m, cmd
		}
	case "g":
		cmd := m.executor.Execute("defenseclaw", []string{"setup", "guardrail"}, "setup guardrail")
		m.activePanel = PanelActivity
		return m, cmd
	case "l":
		m.activePanel = PanelLogs
	case "u":
		cmd := m.executor.Execute("defenseclaw", []string{"upgrade", "--yes"}, "upgrade")
		m.activePanel = PanelActivity
		return m, cmd
	}
	return m, nil
}

func (m Model) handleAlertsKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "j", "down":
		m.alerts.CursorDown()
	case "k", "up":
		m.alerts.CursorUp()
	case "enter":
		m.alerts.ToggleDetail()
	case "esc":
		if m.alerts.IsDetailOpen() {
			m.alerts.ToggleDetail()
		}
	case "space":
		m.alerts.ToggleSelect()
		m.alerts.CursorDown()
	case "a":
		m.alerts.SelectAll()
	case "A", "X":
		m.alerts.DeselectAll()
	case "x":
		if m.store != nil && m.alerts.SelectionCount() > 0 {
			ids := m.alerts.SelectedIDs()
			n, err := m.store.AcknowledgeByIDs(ids)
			if err != nil {
				m.toasts.Push(ToastError, "Failed to acknowledge alerts: "+err.Error())
			} else {
				m.activity.AddEntry(fmt.Sprintf("Acknowledged %d selected alerts", n))
				m.activity.FinishEntry(0, 0)
			}
			m.alerts.DeselectAll()
			m.alerts.Refresh()
			m.refresh()
		}
	case "d":
		feedback := m.alerts.Dismiss()
		if feedback != "" {
			m.activity.AddEntry(feedback)
			m.activity.FinishEntry(0, 0)
		}
	case "y":
		if sel := m.alerts.Selected(); sel != nil {
			clip := fmt.Sprintf("[%s] %s — %s\n%s", sel.Severity, sel.Action, sel.Target, sel.Details)
			return m, tea.SetClipboard(clip)
		}
	case "r":
		m.alerts.Refresh()
	// Severity quick-filter keys
	case "1":
		m.alerts.SetSevFilter("")
	case "2":
		m.alerts.SetSevFilter("CRITICAL")
	case "3":
		m.alerts.SetSevFilter("HIGH")
	case "4":
		m.alerts.SetSevFilter("MEDIUM")
	case "5":
		m.alerts.SetSevFilter("LOW")
	case "c":
		if m.store != nil {
			ids := m.alerts.FilteredIDs()
			if len(ids) > 0 {
				n, err := m.store.AcknowledgeByIDs(ids)
				if err != nil {
					m.toasts.Push(ToastError, "Failed to clear alerts: "+err.Error())
				} else {
					label := "all"
					if m.alerts.FilterText() != "" || m.alerts.SevFilter() != "" {
						label = "filtered"
					}
					m.activity.AddEntry(fmt.Sprintf("Cleared %d %s alerts", n, label))
					m.activity.FinishEntry(0, 0)
				}
			}
			m.alerts.DeselectAll()
			m.alerts.Refresh()
			m.refresh()
		}
	case "C":
		if m.store != nil {
			n, err := m.store.AcknowledgeAlerts("all")
			if err == nil {
				m.activity.AddEntry(fmt.Sprintf("Cleared ALL %d alerts", n))
				m.activity.FinishEntry(0, 0)
			}
			m.alerts.DeselectAll()
			m.alerts.Refresh()
			m.refresh()
		}
	}
	return m, nil
}

func (m Model) handleSkillsKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "j", "down":
		m.skills.CursorDown()
	case "k", "up":
		m.skills.CursorUp()
	case "esc":
		if m.skills.IsDetailOpen() {
			m.skills.ToggleDetail()
		}
	case "enter":
		return m.openSkillDetail()
	case "o":
		if sel := m.skills.Selected(); sel != nil {
			info := [][2]string{
				{"Last scan", sel.Time},
				{"Status", sel.Status},
				{"Actions", sel.Actions},
				{"Reason", sel.Reason},
			}
			m.actionMenu.SetSize(m.width, m.height)
			m.actionMenu.Show(sel.Name, sel.Status, info, SkillActions(sel.Status))
		}
	case "b":
		m.skills.ToggleBlock()
	case "a":
		sel := m.skills.Selected()
		if sel != nil && sel.Status == "blocked" {
			m.skills.ToggleBlock()
		}
	case "s":
		if sel := m.skills.Selected(); sel != nil {
			cmd := m.executor.Execute("defenseclaw", []string{"skill", "scan", sel.Name}, "scan skill "+sel.Name)
			m.activePanel = PanelActivity
			return m, cmd
		}
	case "r":
		m.skills.Refresh()
	}
	return m, nil
}

func (m Model) handleMCPsKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "j", "down":
		m.mcps.CursorDown()
	case "k", "up":
		m.mcps.CursorUp()
	case "esc":
		if m.mcps.IsDetailOpen() {
			m.mcps.ToggleDetail()
		}
	case "enter":
		return m.openMCPDetail()
	case "o":
		if sel := m.mcps.Selected(); sel != nil {
			info := [][2]string{
				{"Last scan", sel.Time},
				{"Status", sel.Status},
				{"Actions", sel.Actions},
				{"Reason", sel.Reason},
			}
			m.actionMenu.SetSize(m.width, m.height)
			m.actionMenu.Show(sel.URL, sel.Status, info, MCPActions(sel.Status))
		}
	case "b":
		m.mcps.ToggleBlock()
	case "a":
		sel := m.mcps.Selected()
		if sel != nil && sel.Status == "blocked" {
			m.mcps.ToggleBlock()
		}
	case "s":
		if sel := m.mcps.Selected(); sel != nil {
			cmd := m.executor.Execute("defenseclaw", []string{"mcp", "scan", sel.URL}, "scan mcp "+sel.URL)
			m.activePanel = PanelActivity
			return m, cmd
		}
	case "r":
		m.mcps.Refresh()
	}
	return m, nil
}

func (m Model) handlePluginsKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "j", "down":
		m.plugins.CursorDown()
	case "k", "up":
		m.plugins.CursorUp()
	case "esc":
		if m.plugins.IsDetailOpen() {
			m.plugins.ToggleDetail()
		}
	case "r":
		return m, m.plugins.LoadCmd()
	case "enter":
		return m.openPluginDetail()
	case "s":
		if sel := m.plugins.Selected(); sel != nil {
			cmd := m.executor.Execute("defenseclaw", []string{"plugin", "scan", sel.ID}, "scan plugin "+sel.ID)
			m.activePanel = PanelActivity
			return m, cmd
		}
	}
	return m, nil
}

func (m Model) handleLogsKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	m.logs, cmd = m.logs.Update(msg)
	return m, cmd
}

func (m Model) handleInventoryKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "left", "h":
		if m.inventory.activeSub > 0 {
			m.inventory.activeSub--
			m.inventory.cursor = 0
			m.inventory.detailOpen = false
			m.inventory.detailCache = nil
			m.inventory.filter = ""
		}
	case "right", "l":
		if m.inventory.activeSub < invSubCount-1 {
			m.inventory.activeSub++
			m.inventory.cursor = 0
			m.inventory.detailOpen = false
			m.inventory.detailCache = nil
			m.inventory.filter = ""
		}
	case "j", "down":
		m.inventory.cursor++
		max := m.inventory.currentListLen() - 1
		if max >= 0 && m.inventory.cursor > max {
			m.inventory.cursor = max
		}
	case "k", "up":
		if m.inventory.cursor > 0 {
			m.inventory.cursor--
		}
	case "esc":
		if m.inventory.filter != "" {
			m.inventory.ClearFilter()
		} else if m.inventory.IsDetailOpen() {
			m.inventory.ToggleDetail()
		}
	case "1":
		m.inventory.SetFilter("")
	case "2":
		switch m.inventory.activeSub {
		case invSubSkills:
			m.inventory.SetFilter("eligible")
		case invSubPlugins:
			m.inventory.SetFilter("loaded")
		}
	case "3":
		switch m.inventory.activeSub {
		case invSubSkills:
			m.inventory.SetFilter("warning")
		case invSubPlugins:
			m.inventory.SetFilter("disabled")
		}
	case "4":
		switch m.inventory.activeSub {
		case invSubSkills, invSubPlugins:
			m.inventory.SetFilter("blocked")
		}
	case "enter":
		return m.openInventoryDetail()
	case "r":
		return m, m.inventory.LoadCmd()
	}
	return m, nil
}

// ---------- Detail openers (shared by Enter key and click-on-selected) ----------

func (m Model) openSkillDetail() (tea.Model, tea.Cmd) {
	if m.skills.Selected() == nil {
		return m, nil
	}
	m.skills.ToggleDetail()
	return m, nil
}

func (m Model) openMCPDetail() (tea.Model, tea.Cmd) {
	if m.mcps.Selected() == nil {
		return m, nil
	}
	m.mcps.ToggleDetail()
	return m, nil
}

func (m Model) openPluginDetail() (tea.Model, tea.Cmd) {
	if m.plugins.Selected() == nil {
		return m, nil
	}
	m.plugins.ToggleDetail()
	return m, nil
}

func (m Model) openAuditDetail() (tea.Model, tea.Cmd) {
	if m.auditHist.Selected() == nil {
		return m, nil
	}
	m.auditHist.ToggleDetail()
	return m, nil
}

func (m Model) openInventoryDetail() (tea.Model, tea.Cmd) {
	if m.inventory.inv == nil || m.inventory.activeSub == invSubSummary {
		return m, nil
	}
	m.inventory.ToggleDetail()
	return m, nil
}

func (m Model) tuiShellView(content string) tea.View {
	v := tea.NewView(content)
	v.AltScreen = true
	v.MouseMode = tea.MouseModeCellMotion
	v.ReportFocus = true

	title := fmt.Sprintf("DefenseClaw — %s", panelNames[m.activePanel])
	if m.alerts.Count() > 0 {
		title = fmt.Sprintf("(%d) %s", m.alerts.Count(), title)
	}
	v.WindowTitle = title

	return v
}

func (m Model) View() tea.View {
	if m.width == 0 || m.height == 0 {
		return m.tuiShellView("Loading DefenseClaw TUI...")
	}

	// Help overlay
	if m.helpOpen {
		return m.tuiShellView(m.renderHelp())
	}

	// Action menu overlay
	if m.actionMenu.IsVisible() {
		return m.tuiShellView(m.actionMenu.View())
	}

	// Detail modal
	if m.detail.IsVisible() {
		return m.tuiShellView(m.detail.View())
	}

	var b strings.Builder

	// Header bar
	b.WriteString(m.renderHeader())
	b.WriteString("\n")

	// Main panel content
	panelContent := m.renderActivePanel()
	b.WriteString(panelContent)

	// Pad to fill available space
	toastLines := 0
	if m.toasts.HasToasts() {
		toastLines = len(m.toasts.items) + 1
	}
	paletteLines := 0
	if m.cmdInputFocus && m.palette.Active && m.palette.MatchCount() > 0 {
		paletteLines = m.palette.MatchCount()
		if paletteLines > 8 {
			paletteLines = 8
		}
	}
	usedLines := 5 + toastLines + paletteLines
	contentLines := lipgloss.Height(panelContent)
	availableLines := m.height - usedLines
	if contentLines < availableLines {
		b.WriteString(strings.Repeat("\n", availableLines-contentLines))
	}

	// Persistent command input bar
	b.WriteString("\n")
	inputBar := m.renderInputBar()
	b.WriteString(inputBar)

	// Inline autocomplete dropdown (when command input is focused)
	if m.cmdInputFocus && m.palette.Active && m.palette.MatchCount() > 0 {
		b.WriteString(m.palette.InlineView(m.width))
	}

	// Hint bar
	b.WriteString("\n")
	hint := m.hints.HintForPanel(m.activePanel, m.buildSystemState())
	b.WriteString(m.theme.HintText.Render("  " + hint))

	// Toast notifications (above status strip)
	if m.toasts.HasToasts() {
		b.WriteString("\n")
		m.toasts.SetWidth(m.width)
		b.WriteString(m.toasts.View())
	}

	// Status strip
	b.WriteString("\n")
	b.WriteString(m.renderStatusStrip())

	return m.tuiShellView(b.String())
}

func (m *Model) refresh() {
	m.alerts.Refresh()
	m.skills.Refresh()
	m.mcps.Refresh()
	m.auditHist.Refresh()
	if m.store != nil {
		if err := m.overview.SetEnforcementCounts(m.store); err != nil {
			m.toasts.Push(ToastWarn, "Failed to refresh counts: "+err.Error())
		}
	}
	m.lastRefresh = time.Now()
}

func (m Model) exportAuditJSON(path string) error {
	if m.store == nil {
		return fmt.Errorf("audit store not available")
	}
	return m.store.ExportJSON(path, 500)
}

// switchPanel sets the active panel and triggers auto-load for panels that need it.
func (m *Model) switchPanel(panel int) tea.Cmd {
	m.activePanel = panel
	switch panel {
	case PanelInventory:
		if !m.inventory.loaded && !m.inventory.loading {
			return m.inventory.LoadCmd()
		}
	case PanelPlugins:
		if !m.plugins.loaded && !m.plugins.loading {
			return m.plugins.LoadCmd()
		}
	}
	return nil
}

func (m *Model) resizePanels() {
	panelH := m.height - 5 // header(1) + newline(1) + input bar(1) + hint(1) + status(1)
	if panelH < 10 {
		panelH = 10
	}
	m.alerts.SetSize(m.width, panelH)
	m.skills.SetSize(m.width, panelH)
	m.mcps.SetSize(m.width, panelH)
	m.detail.SetSize(m.width, m.height)
	m.actionMenu.SetSize(m.width, m.height)
	m.logs.SetSize(m.width, panelH)
	m.activity.SetSize(m.width, panelH)
}

func (m Model) pollHealth() tea.Cmd {
	return func() tea.Msg {
		apiPort := 9090
		if m.cfg != nil && m.cfg.Gateway.APIPort > 0 {
			apiPort = m.cfg.Gateway.APIPort
		}
		health, err := fetchHealth(apiPort)
		return healthUpdateMsg{Health: health, Err: err}
	}
}

func (m Model) buildSystemState() SystemState {
	state := SystemState{
		CommandsRun:    m.commandsRun,
		CommandRunning: m.activity.IsRunning(),
		AuditCount:     m.auditHist.Count(),
	}
	if m.health != nil {
		state.GatewayRunning = m.health.Gateway.State == "running"
	}
	if m.cfg != nil {
		state.GuardrailEnabled = m.cfg.Guardrail.Enabled
		state.GuardrailMode = m.cfg.Guardrail.Mode
	}
	state.TotalAlerts = m.overview.activeAlerts
	state.CriticalAlerts = m.countCriticalAlerts()
	state.LogsPaused = m.logs.paused
	state.NewLinesSince = len(m.logs.filteredLines()) - m.logs.scroll - m.logs.visibleLines()
	if state.NewLinesSince < 0 {
		state.NewLinesSince = 0
	}

	switch m.activePanel {
	case PanelAlerts:
		if m.alerts.IsFiltering() {
			state.FilterActive = m.alerts.FilterText()
		}
	case PanelSkills:
		if m.skills.IsFiltering() {
			state.FilterActive = m.skills.FilterText()
		}
	case PanelMCPs:
		if m.mcps.IsFiltering() {
			state.FilterActive = m.mcps.FilterText()
		}
	case PanelAudit:
		if m.auditHist.IsFiltering() {
			state.FilterActive = m.auditHist.FilterText()
		}
	}
	return state
}

func (m Model) countCriticalAlerts() int {
	return m.alerts.CriticalCount()
}

func (m Model) renderHeader() string {
	titleStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("230")).
		Background(lipgloss.Color("62")).
		Padding(0, 1)
	title := titleStyle.Render("DC " + m.version)

	activeStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("230")).
		Background(lipgloss.Color("62")).
		Padding(0, 1)
	inactiveStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("250")).
		Padding(0, 1)

	tabs := m.buildTabLabels()

	var rendered []string
	for i, label := range tabs {
		if i == m.activePanel {
			rendered = append(rendered, activeStyle.Render(label))
		} else {
			rendered = append(rendered, inactiveStyle.Render(label))
		}
	}

	tabBar := strings.Join(rendered, " ")

	gap := m.width - lipgloss.Width(title) - lipgloss.Width(tabBar) - 1
	if gap < 1 {
		gap = 1
	}

	return title + strings.Repeat(" ", gap) + tabBar
}

// buildTabLabels returns tab label strings that fit within the terminal width.
func (m Model) buildTabLabels() []string {
	titleWidth := lipgloss.Width(
		lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("230")).
			Background(lipgloss.Color("62")).
			Padding(0, 1).
			Render("DC " + m.version),
	)
	available := m.width - titleWidth - 2 // 2 for gap

	// Try progressively shorter label formats until one fits
	formats := []func(int, string) string{
		func(n int, name string) string { return fmt.Sprintf("%d:%s", n, name) },
		func(n int, name string) string {
			s := name
			if len(s) > 4 {
				s = s[:4]
			}
			return fmt.Sprintf("%d:%s", n, s)
		},
		func(n int, _ string) string { return fmt.Sprintf("%d", n) },
	}

	for _, fmtFn := range formats {
		var labels []string
		totalW := 0
		for i, name := range panelNames {
			numKey := (i + 1) % 10
			label := fmtFn(numKey, name)
			labels = append(labels, label)
			totalW += lipgloss.Width(label) + 2 // padding(0,1) = +2
			if i > 0 {
				totalW++ // space separator
			}
		}
		if totalW <= available {
			return labels
		}
	}

	// Absolute minimum: just numbers
	var labels []string
	for i := range panelNames {
		numKey := (i + 1) % 10
		labels = append(labels, fmt.Sprintf("%d", numKey))
	}
	return labels
}

func (m Model) renderActivePanel() string {
	switch m.activePanel {
	case PanelOverview:
		return m.overview.View(m.width, m.height-5)
	case PanelAlerts:
		return m.alerts.View()
	case PanelSkills:
		return m.skills.View()
	case PanelMCPs:
		return m.mcps.View()
	case PanelPlugins:
		return m.plugins.View(m.width, m.height-5)
	case PanelInventory:
		return m.inventory.View(m.width, m.height-5)
	case PanelLogs:
		return m.logs.View()
	case PanelAudit:
		return m.auditHist.View(m.width, m.height-5)
	case PanelActivity:
		return m.activity.View()
	case PanelSetup:
		return m.setup.View(m.width, m.height-5)
	default:
		return ""
	}
}

func (m Model) renderInputBar() string {
	barBg := lipgloss.Color("235")

	if m.cmdInputFocus {
		m.cmdInput.SetWidth(m.width - 2)
		return m.cmdInput.View()
	}

	inputStyle := lipgloss.NewStyle().
		Background(barBg).
		Foreground(lipgloss.Color("252")).
		Width(m.width).
		Padding(0, 1)

	hint := m.theme.Dimmed.Render("Press ")
	key := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("62")).Render(":")
	hint2 := m.theme.Dimmed.Render(" or ")
	key2 := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("62")).Render("Ctrl+K")
	hint3 := m.theme.Dimmed.Render(" to type a command")
	return inputStyle.Render(hint + key + hint2 + key2 + hint3)
}

func (m Model) renderStatusStrip() string {
	sep := lipgloss.NewStyle().Foreground(lipgloss.Color("238")).Render("  │  ")

	gwState := "offline"
	gwExtra := ""
	if m.health != nil {
		gwState = m.health.Gateway.State
		if gwState != "running" && m.health.Gateway.LastError != "" {
			gwExtra = " (" + truncate(m.health.Gateway.LastError, 30) + ")"
		}
	}
	gwSeg := m.theme.StateDot(gwState) + " " + m.theme.StateColor(gwState).Render("Gateway"+gwExtra)

	wdState := "unknown"
	wdExtra := ""
	if m.health != nil {
		wdState = m.health.Watcher.State
		if wdState != "running" && m.health.Watcher.LastError != "" {
			wdExtra = " (" + truncate(m.health.Watcher.LastError, 30) + ")"
		}
	}
	wdSeg := m.theme.StateDot(wdState) + " " + m.theme.StateColor(wdState).Render("Watchdog"+wdExtra)

	guardSeg := m.theme.DotOff + " " + m.theme.Disabled.Render("Guardrail")
	if m.cfg != nil && m.cfg.Guardrail.Enabled {
		mode := m.cfg.Guardrail.Mode
		if mode == "" {
			mode = "observe"
		}
		guardSeg = m.theme.DotRunning + " " + m.theme.Clean.Render("Guardrail·"+mode)
	}

	alertCount := m.overview.activeAlerts
	var alertSeg string
	if alertCount > 0 {
		alertSeg = m.theme.DotError + " " + m.theme.High.Render(fmt.Sprintf("%d alerts", alertCount))
	} else {
		alertSeg = m.theme.DotRunning + " " + m.theme.Clean.Render("0 alerts")
	}

	cmdSeg := ""
	if m.activity.IsRunning() {
		frame := spinnerFrames[m.spinFrame]
		cmdSeg = m.theme.Spinner.Render(frame + " running")
	}

	verSeg := m.theme.Dimmed.Render("v" + m.version)

	staleSeg := ""
	if !m.lastRefresh.IsZero() && time.Since(m.lastRefresh) > 3*refreshInterval {
		staleSeg = lipgloss.NewStyle().Foreground(lipgloss.Color("208")).Render("(stale)")
	}

	segments := []string{gwSeg, wdSeg, guardSeg, alertSeg}
	if cmdSeg != "" {
		segments = append(segments, cmdSeg)
	}
	if staleSeg != "" {
		segments = append(segments, staleSeg)
	}
	if !m.focused {
		segments = append(segments, m.theme.Dimmed.Render("[unfocused]"))
	}
	segments = append(segments, verSeg)

	content := " " + strings.Join(segments, sep)
	gap := m.width - lipgloss.Width(content)
	if gap < 0 {
		gap = 0
	}

	return m.theme.StatusBar.Width(m.width).Render(content + strings.Repeat(" ", gap))
}

func (m Model) renderHelp() string {
	var b strings.Builder
	helpLogo := lipgloss.NewStyle().Foreground(lipgloss.Color("62")).Bold(true).Render("  DefenseClaw  Keybindings")
	b.WriteString(helpLogo)
	b.WriteString("\n")
	b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("238")).Render("  " + strings.Repeat("━", 40)))
	b.WriteString("\n\n")

	sections := []struct {
		title string
		keys  [][2]string
	}{
		{"Navigation", [][2]string{
			{"1-9", "Switch to panel by number"},
			{"Tab / Shift+Tab", "Next / previous panel"},
			{": or Ctrl+K", "Open command palette"},
			{"?", "Toggle this help"},
			{"q / Ctrl+C", "Quit"},
		}},
		{"Lists (Alerts, Skills, MCPs, Plugins, Inventory, Audit)", [][2]string{
			{"j/k or Up/Down", "Navigate items"},
			{"Enter or click", "Open detail view for selected item"},
			{"/", "Filter / search"},
			{"r", "Refresh / reload"},
		}},
		{"Skills / MCPs", [][2]string{
			{"s", "Scan selected item"},
			{"b", "Block selected item"},
			{"a", "Allow selected item"},
			{"o", "Open action menu"},
		}},
		{"Alerts", [][2]string{
			{"Enter", "Toggle detail pane for selected alert"},
			{"1-5", "Filter by severity (1=All 2=Crit 3=High 4=Med 5=Low)"},
			{"Space", "Toggle select current alert"},
			{"a", "Select all filtered alerts"},
			{"A / X", "Deselect all"},
			{"x", "Acknowledge selected alerts"},
			{"c", "Clear filtered alerts"},
			{"C", "Clear ALL alerts"},
			{"y", "Copy alert details to clipboard"},
		}},
		{"Logs", [][2]string{
			{"Space", "Pause / resume auto-scroll"},
			{"/", "Search"},
			{"e", "Errors only"},
			{"w", "Warnings+"},
			{"G / g", "Jump to end / start"},
		}},
		{"Overview Quick Actions", [][2]string{
			{"s", "Scan all skills"},
			{"d", "Run doctor"},
			{"g", "Setup guardrail"},
			{"i", "Go to Inventory"},
			{"l", "Go to Logs"},
			{"u", "Upgrade"},
		}},
	}

	for _, sec := range sections {
		b.WriteString(m.theme.SectionHeader.Render("  " + sec.title))
		b.WriteString("\n")
		for _, k := range sec.keys {
			fmt.Fprintf(&b, "  %s  %s\n",
				m.theme.KeyHint.Render(fmt.Sprintf("%-20s", k[0])),
				k[1])
		}
		b.WriteString("\n")
	}

	b.WriteString(m.theme.HintText.Render("  Press any key to close"))
	return b.String()
}
