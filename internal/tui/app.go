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
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

const (
	PanelOverview = iota
	PanelAlerts
	PanelSkills
	PanelMCPs
	PanelPlugins
	PanelInventory
	PanelPolicy
	PanelLogs
	PanelAudit
	PanelActivity
	// PanelTools is inserted immediately before PanelSetup so the
	// existing numeric key bindings (1–9 for the first nine
	// panels, 0 for Setup) all remain stable. Tools is reached
	// via the dedicated 'T' keybinding, the command palette, or
	// tab navigation. Re-ordering would silently change muscle
	// memory for every operator — don't do it without a migration.
	PanelTools
	PanelSetup
	panelCount
)

var panelNames = [panelCount]string{
	"Overview", "Alerts", "Skills", "MCPs", "Plugins",
	"Inventory", "Policy", "Logs", "Audit", "Activity", "Tools", "Setup",
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
	Sinks     SubsystemHealth  `json:"sinks"`
	Sandbox   *SubsystemHealth `json:"sandbox,omitempty"`
	// Connector mirrors gateway.ConnectorHealth: which agent
	// framework (openclaw / zeptoclaw / claudecode / codex) is
	// currently active in the sidecar, plus the live counters.
	// Nil when no connector has been initialised yet — the TUI
	// falls back to cfg.Claw.Mode in that case.
	Connector *ConnectorHealth `json:"connector,omitempty"`
}

// SubsystemHealth mirrors a single subsystem from /health.
type SubsystemHealth struct {
	State     string                 `json:"state"`
	Since     string                 `json:"since,omitempty"`
	LastError string                 `json:"last_error,omitempty"`
	Details   map[string]interface{} `json:"details,omitempty"`
}

// ConnectorHealth mirrors gateway.ConnectorHealth. Field names and
// JSON tags must stay in sync with internal/gateway/health.go::ConnectorHealth
// or the TUI will silently drop the block on parse.
type ConnectorHealth struct {
	Name               string `json:"name"`
	State              string `json:"state"`
	Since              string `json:"since,omitempty"`
	ToolInspectionMode string `json:"tool_inspection_mode,omitempty"`
	SubprocessPolicy   string `json:"subprocess_policy,omitempty"`
	Requests           int64  `json:"requests"`
	Errors             int64  `json:"errors"`
	ToolInspections    int64  `json:"tool_inspections"`
	ToolBlocks         int64  `json:"tool_blocks"`
	SubprocessBlocks   int64  `json:"subprocess_blocks"`
}

type healthUpdateMsg struct {
	Health *HealthSnapshot
	Err    error
}

// refreshTickMsg is an alias for the periodic refresh tick used by tests
// and SLO instrumentation (same handler as refreshMsg).
type refreshTickMsg = refreshMsg

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
	policy    PolicyPanel
	logs      LogsPanel
	auditHist AuditPanel
	activity  ActivityPanel
	tools     ToolsPanel
	setup     SetupPanel

	// Overlays
	detail     DetailModal
	palette    PaletteModel
	actionMenu ActionMenu
	mcpSetForm MCPSetForm
	modePicker ModePickerModal
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
	otelProv *telemetry.Provider

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
	OTel            *telemetry.Provider
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
	dataDir := ""
	if deps.Config != nil {
		dataDir = deps.Config.DataDir
	}

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
		alerts:     NewAlertsPanel(deps.Store, dataDir),
		skills:     NewSkillsPanel(deps.Store),
		mcps:       NewMCPsPanel(deps.Store),
		plugins:    NewPluginsPanel(theme, deps.Store),
		inventory:  NewInventoryPanel(theme, executor, deps.Store),
		policy:     NewPolicyPanel(theme, deps.Config),
		logs:       NewLogsPanel(theme, deps.Config),
		auditHist:  NewAuditPanel(theme, deps.Store),
		activity:   NewActivityPanel(theme, dataDir),
		tools:      NewToolsPanel(deps.Store),
		setup:      NewSetupPanel(theme, deps.Config, executor),
		detail:     NewDetailModal(),
		palette:    NewPaletteModel(theme, registry, executor),
		actionMenu: NewActionMenu(theme),
		mcpSetForm: NewMCPSetForm(),
		modePicker: NewModePickerModal(theme),

		cmdInput: ti,

		store:    deps.Store,
		cfg:      deps.Config,
		theme:    theme,
		hints:    NewHintEngine(),
		executor: executor,
		registry: registry,
		version:  deps.Version,
		otelProv: deps.OTel,

		isDark:  true,
		focused: true,
	}
	// Push the configured connector immediately so the first paint
	// of any data panel shows the right "Source: …" banner before
	// /health has had time to round-trip.
	m.propagateConnector()
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
		// P3-#21: load the cached doctor snapshot from disk so
		// the Overview panel can render status immediately
		// without waiting for the user to manually re-run doctor.
		m.loadDoctorCacheCmd(),
	)
}

// propagateConnector pushes the active connector name (preferring the
// live /health connector block, falling back to cfg.Claw.Mode) to
// every data-listing panel so their "Source: …" banners stay in sync
// with what the gateway is actually routing for.
func (m *Model) propagateConnector() {
	mode := ""
	if m.cfg != nil {
		mode = string(m.cfg.Claw.Mode)
	}
	name := ActiveConnectorName(m.health, mode)
	m.skills.SetConnector(name)
	m.mcps.SetConnector(name)
	m.plugins.SetConnector(name)
	m.inventory.SetConnector(name)
}

// isDoctorCommand reports whether the display-name passed to
// CommandExecutor.Execute corresponds to a `defenseclaw doctor`
// invocation. We match on the prefix rather than exact string so
// future variants ("doctor --json-output", "doctor --verbose")
// keep triggering a cache reload without a code change here.
func isDoctorCommand(cmd string) bool {
	cmd = strings.TrimSpace(cmd)
	return cmd == "doctor" || strings.HasPrefix(cmd, "doctor ")
}

// doctorCacheLoadedMsg carries either a successfully-loaded
// DoctorCache or a soft load error. We always include both so the
// Update handler can decide whether to toast the error — a
// NotExist error on first launch is perfectly normal and should
// stay quiet.
type doctorCacheLoadedMsg struct {
	Cache *DoctorCache
	Err   error
}

// loadDoctorCacheCmd produces a tea.Cmd that reads the on-disk
// doctor cache (if any) off the hot path and emits a
// doctorCacheLoadedMsg. Safe to invoke at any time; it's a
// single-file read with no network calls.
func (m *Model) loadDoctorCacheCmd() tea.Cmd {
	dataDir := ""
	if m.cfg != nil {
		dataDir = m.cfg.DataDir
	}
	return func() tea.Msg {
		c, err := LoadDoctorCache(dataDir)
		return doctorCacheLoadedMsg{Cache: c, Err: err}
	}
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
		t0 := time.Now()
		m.refresh()
		if m.otelProv != nil && m.otelProv.Enabled() {
			ms := float64(time.Since(t0).Milliseconds())
			m.otelProv.RecordTUIRefreshSLO(context.Background(), "all", ms)
		}
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
		// Also refresh skills/MCPs via the CLI so the TUI stays in
		// sync with out-of-process `defenseclaw skill …`/`mcp …`
		// mutations. Only reload if we already have a cached copy
		// — first-time load is still driven by switchPanel.
		if m.skills.IsLoaded() && !m.skills.IsLoading() {
			cmds = append(cmds, m.skills.LoadCmd())
		}
		if m.mcps.IsLoaded() && !m.mcps.IsLoading() {
			cmds = append(cmds, m.mcps.LoadCmd())
		}
		return m, tea.Batch(cmds...)

	case healthUpdateMsg:
		if msg.Err != nil {
			m.health = nil
		} else {
			m.health = msg.Health
		}
		m.overview.SetHealth(m.health)
		m.propagateConnector()
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
		// A `defenseclaw skill …` / `mcp …` invocation likely
		// mutated the merged catalog — rebuild the TUI view so the
		// operator sees the effect without pressing 'r'.
		if m.skills.IsLoaded() && !m.skills.IsLoading() {
			postCmds = append(postCmds, m.skills.LoadCmd())
		}
		if m.mcps.IsLoaded() && !m.mcps.IsLoading() {
			postCmds = append(postCmds, m.mcps.LoadCmd())
		}
		// P3-#21: any successful `defenseclaw doctor` run writes
		// the cache file from the CLI side — re-read it so the
		// Overview DOCTOR box reflects the new numbers without
		// forcing the user to restart the TUI. A failing run
		// (ExitCode != 0) still updates the cache — doctor
		// intentionally writes before exit — so we refresh
		// regardless of the exit code.
		if isDoctorCommand(msg.Command) {
			postCmds = append(postCmds, m.loadDoctorCacheCmd())
		}
		if len(postCmds) > 0 {
			return m, tea.Batch(postCmds...)
		}
		return m, nil

	case doctorCacheLoadedMsg:
		// Soft-fail: a NotExist is normal on first launch, and a
		// parse error means the cache is corrupt — either way
		// we just leave the Overview panel showing "not yet
		// run" rather than crashing the TUI. For parse errors
		// we surface a single toast so the operator knows to
		// run doctor again.
		if msg.Err != nil {
			m.toasts.Push(ToastError, fmt.Sprintf("doctor cache: %v", msg.Err))
			return m, nil
		}
		m.overview.SetDoctorCache(msg.Cache)
		return m, nil

	case InventoryLoadedMsg:
		m.inventory.ApplyLoaded(msg)
		return m, nil

	case PluginsLoadedMsg:
		m.plugins.ApplyLoaded(msg)
		return m, nil

	case FilterChangeMsg:
		m.noteTUIFilterChange(msg.Panel, msg.FilterType, msg.Old, msg.New)
		return m, nil

	case SkillsLoadedMsg:
		// Skills now loads via `defenseclaw skill list --json` in a
		// subprocess so the TUI sees the same merged catalog the CLI
		// prints. ApplyLoaded rewrites p.items + p.filtered; no
		// further refresh needed.
		m.skills.ApplyLoaded(msg)
		return m, nil

	case MCPsLoadedMsg:
		// Same treatment for MCPs: the source of truth is
		// `defenseclaw mcp list --json`, not the audit store.
		m.mcps.ApplyLoaded(msg)
		return m, nil

	case RegoTestResultMsg:
		// B3d: surface `defenseclaw policy test` output in the OPA
		// side panel. Keeping this in Update (not in the executor
		// callback) avoids a round trip through the Activity panel
		// and preserves the operator's place in the Policies tab.
		m.policy.ApplyRegoTestResult(msg.Output, msg.Err)
		return m, nil

	case EditorClosedMsg:
		// After an external $EDITOR session, reload the policy
		// panel from disk so the operator sees their edits
		// immediately. The reload is cheap (a handful of YAML
		// unmarshals) so we don't bother branching on the edited
		// file's type. Errors are surfaced via a toast rather
		// than a modal because the operator can just reopen the
		// editor.
		m.policy.ReloadFromDisk()
		m.policy.ReloadRegoSource()
		if msg.Err != nil {
			m.toasts.Push(ToastError, "editor: "+msg.Err.Error())
		}
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
	// If a panel has an in-panel overlay/form/editor open, don't let
	// a click on the tab strip above silently flip panels out from
	// underneath it — the user is clearly focused on the overlay
	// and a stray click on the header row (common when aiming at
	// the overlay's border) should be a no-op. Mirror the key-router
	// guard above so keyboard and mouse behaviour stay consistent.
	if m.panelExclusive() {
		return m.handlePanelClick(x, y)
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
	// Don't scroll the panel underneath a modal or in-panel overlay —
	// it's jarring to scroll (and invalidate cursor positions)
	// invisibly while a YAML viewer or form is covering the list.
	if m.helpOpen || m.actionMenu.IsVisible() || m.detail.IsVisible() || m.panelExclusive() {
		return m, nil
	}
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
	case PanelOverview:
		// Quick actions bar: the rendered line is at p.quickActionY (pre-scroll),
		// but after scrolling the visible line shifts. The quick actions box is 3
		// lines tall (border-top, content, border-bottom).
		qaVisY := m.overview.quickActionY - m.overview.scroll
		if relY >= qaVisY && relY <= qaVisY+2 {
			if key := m.overview.QuickActionHitTest(x); key != "" {
				switch key {
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
				case "m":
					// Mirror the keyboard handler: open the picker
					// pre-focused on the active connector.
					m.modePicker.Show(m.activeConnectorForPicker())
					return m, nil
				case "p":
					m.activePanel = PanelPolicy
				case "l":
					m.activePanel = PanelLogs
				case "u":
					cmd := m.executor.Execute("defenseclaw", []string{"upgrade", "--yes"}, "upgrade")
					m.activePanel = PanelActivity
					return m, cmd
				case "?":
					m.helpOpen = true
				}
				return m, nil
			}
		}
	case PanelAlerts:
		if relY == 0 {
			positions := m.alerts.SevButtonPositions()
			for i, pos := range positions {
				if x >= pos[0] && x < pos[1] {
					old := m.alerts.SevFilter()
					m.alerts.SetSevFilter(sevFilterOrder[i])
					m.noteTUIFilterChange(PanelNameAlerts, FilterTypeSeverity, old, m.alerts.SevFilter())
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
				m.alerts.ToggleExpandOrDetail()
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
	case PanelPolicy:
		if relY == 0 {
			if tab := m.policy.SubTabHitTest(x); tab >= 0 {
				m.policy.SetSubTab(tab)
			}
			return m, nil
		}
		bin, args, name := m.policy.HandleMouseClick(x, relY)
		if bin != "" {
			m.activePanel = PanelActivity
			return m, m.executor.Execute(bin, args, name)
		}
	case PanelSetup:
		run, bin, args, name := m.setup.HandleMouseClick(x, relY)
		if run && bin != "" {
			m.activePanel = PanelActivity
			return m, m.executor.Execute(bin, args, name)
		}
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
			return m, nil
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
			return m, nil
		}
		// B4a: chip-row hit test for Verdicts source. The panel
		// owns the geometry (labels + prefix widths) via the
		// VerdictChipHitTest helper so this handler stays small
		// and we don't re-derive the row layout in two places.
		if kind, value, ok := m.logs.VerdictChipHitTest(x, relY); ok {
			switch kind {
			case "action":
				m.logs.SetVerdictAction(value)
			case "type":
				m.logs.SetVerdictEventType(value)
			case "severity":
				m.logs.SetVerdictSeverity(value)
			}
			return m, nil
		}
		// B4b: clicking on a log row moves the cursor there and,
		// for the Verdicts source, opens the detail modal — mouse
		// parity with Enter. For Gateway/Watchdog a single click
		// just parks the cursor; Enter still opens the raw-line
		// modal so operators don't get a modal for every scroll
		// click.
		if idx, ok := m.logs.LogRowHitTest(relY); ok {
			m.logs.SetCursor(idx)
			if m.logs.source == logSourceVerdicts {
				if row := m.logs.SelectedVerdict(); row != nil {
					pairs := verdictDetailPairs(*row)
					m.detail.SetSize(m.width, m.height)
					m.detail.Show(fmt.Sprintf("Gateway event — %s", strings.ToUpper(row.eventType)), pairs)
				}
			}
			return m, nil
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
	case PanelPolicy:
		m.policy.ScrollBy(delta)
	case PanelLogs:
		m.logs.ScrollBy(delta)
	case PanelAudit:
		m.auditHist.ScrollBy(delta)
	case PanelActivity:
		m.activity.ScrollBy(delta)
	case PanelTools:
		m.tools.ScrollBy(delta)
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

	// If any panel has an overlay/form/editor/detail modal active,
	// route keys directly to the panel. This runs BEFORE the global
	// shortcut table so `q` inside a YAML viewer closes the overlay
	// (see policy.HandleKey's overlay branch) instead of falling
	// through to a global "q = quit" binding, and digit keys inside
	// a form don't hop panels. Ctrl+C is still honoured below as
	// the single canonical quit key.
	if m.panelExclusive() {
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}
		return m.handlePanelKey(msg)
	}

	if m.panelOwnsDigitShortcut(msg.String()) {
		return m.handlePanelKey(msg)
	}

	switch msg.String() {
	case "ctrl+c":
		// Ctrl+C is the only global quit key now. "q" used to also
		// quit, but that turned closing an in-panel overlay (typing
		// q to dismiss a policy YAML viewer) into an accidental
		// TUI-exit — so q is no longer wired here and is free for
		// panels to use as a local close / quarantine / etc. key.
		return m, tea.Quit
	case "q":
		// Delegate to the active panel; if the panel doesn't bind
		// "q" for something specific (e.g., Setup's back, action
		// menu's quarantine), this is an intentional no-op.
		return m.handlePanelKey(msg)

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
		m.activePanel = PanelPolicy
	case "8":
		m.activePanel = PanelLogs
	case "9":
		m.activePanel = PanelAudit
	case "0":
		m.activePanel = PanelSetup
	case "T":
		// Tools panel has no numeric shortcut (see PanelTools
		// comment in the enum). 'T' is uppercase to avoid clashing
		// with the lowercase 't' most panels use for in-panel
		// actions; it's mnemonic for the panel name.
		if cmd := m.switchPanel(PanelTools); cmd != nil {
			return m, cmd
		}

	case "tab":
		if m.activePanel == PanelPolicy {
			return m.handlePolicyKey(msg)
		}
		m.activePanel = (m.activePanel + 1) % panelCount
	case "shift+tab":
		if m.activePanel == PanelPolicy {
			return m.handlePolicyKey(msg)
		}
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
	case PanelActivity:
		return key == "1" || key == "2"
	default:
		return false
	}
}

// panelExclusive returns true when the active panel has an overlay,
// form, editor, or detail modal visible and must swallow keys before
// the global router gets a chance. Without this, a user typing "q"
// inside the policy YAML viewer (or any future panel overlay) would
// fall through to the global "q = quit" binding and kill the whole
// TUI — the exact bug the user hit when trying to close a rule
// pack overlay. Same story for number keys flipping panels while a
// form is open.
func (m Model) panelExclusive() bool {
	switch m.activePanel {
	case PanelPolicy:
		return m.policy.IsOverlayActive()
	case PanelSkills:
		return m.skills.IsDetailOpen()
	case PanelMCPs:
		return m.mcps.IsDetailOpen() || m.mcpSetForm.IsActive()
	case PanelPlugins:
		return m.plugins.IsDetailOpen()
	case PanelTools:
		return m.tools.IsDetailOpen()
	case PanelAlerts:
		return m.alerts.IsDetailOpen()
	case PanelAudit:
		return m.auditHist.IsDetailOpen()
	case PanelInventory:
		return m.inventory.IsDetailOpen()
	case PanelSetup:
		return m.setup.editing || m.setup.wizFormEditing ||
			m.setup.IsFormActive() || m.setup.IsWizardRunning() ||
			len(m.setup.wizOutput) > 0 || m.setup.IsEditorActive()
	}
	return false
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
		// All skill mutations route through `defenseclaw skill <verb>
		// <name>` — the Python CLI owns admission, audit emission,
		// and gateway RPC. Duplicating any of that in Go would give
		// us a second source of truth that silently drifts (see the
		// pre-P0-#4 ToggleBlock path that bypassed the CLI entirely).
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
		case "e":
			return m.executor.Execute("defenseclaw", []string{"skill", "enable", sel.Name}, "enable skill "+sel.Name)
		case "q":
			return m.executor.Execute("defenseclaw", []string{"skill", "quarantine", sel.Name}, "quarantine skill "+sel.Name)
		case "r":
			return m.executor.Execute("defenseclaw", []string{"skill", "restore", sel.Name}, "restore skill "+sel.Name)
		case "n":
			// `skill install` fetches from ClawHub (or local path if
			// the CLI resolves it there). The TUI side doesn't need
			// to care — we just pass the name and let cmd_skill.py
			// decide.
			return m.executor.Execute("defenseclaw", []string{"skill", "install", sel.Name}, "install skill "+sel.Name)
		}
	case PanelMCPs:
		sel := m.mcps.Selected()
		if sel == nil {
			return nil
		}
		// Every key surfaced by MCPActions() must map to a CLI
		// verb or the action menu will render "Info" as a button
		// and then silently do nothing. Info is read-only so we
		// route through the shell list rather than `mcp info` —
		// the CLI doesn't have a per-server inspect command yet.
		switch key {
		case "s":
			return m.executor.Execute("defenseclaw", []string{"mcp", "scan", sel.URL}, "scan mcp "+sel.URL)
		case "i":
			return m.executor.Execute("defenseclaw", []string{"mcp", "list"}, "list mcp")
		case "b":
			return m.executor.Execute("defenseclaw", []string{"mcp", "block", sel.URL}, "block mcp "+sel.URL)
		case "a":
			return m.executor.Execute("defenseclaw", []string{"mcp", "allow", sel.URL}, "allow mcp "+sel.URL)
		case "u":
			return m.executor.Execute("defenseclaw", []string{"mcp", "unblock", sel.URL}, "unblock mcp "+sel.URL)
		case "x":
			return m.executor.Execute("defenseclaw", []string{"mcp", "unset", sel.URL}, "unset mcp "+sel.URL)
		}
	case PanelPlugins:
		// All plugin mutations route through the defenseclaw
		// Python CLI so admission, runtime, and quarantine state
		// stay coherent (see cli/defenseclaw/commands/cmd_plugin.py
		// PolicyEngine.* calls). Never fork this state in Go — the
		// CLI is the single source of truth.
		sel := m.plugins.Selected()
		if sel == nil {
			return nil
		}
		// Prefer plugin name for user-facing commands since the
		// CLI's block/allow/disable/enable/quarantine/restore
		// resolve via _resolve_openclaw_plugin_id(name). Fall
		// back to the ID when Name is blank (rare, e.g. manifests
		// missing display fields).
		name := sel.Name
		if name == "" {
			name = sel.ID
		}
		switch key {
		case "s":
			return m.executor.Execute("defenseclaw", []string{"plugin", "scan", name}, "scan plugin "+name)
		case "i":
			return m.executor.Execute("defenseclaw", []string{"plugin", "info", name}, "info plugin "+name)
		case "b":
			return m.executor.Execute("defenseclaw", []string{"plugin", "block", name}, "block plugin "+name)
		case "a":
			return m.executor.Execute("defenseclaw", []string{"plugin", "allow", name}, "allow plugin "+name)
		case "u":
			// "Unblock" in the action menu maps to `plugin allow`
			// because that is the CLI verb that clears the block
			// list and (if needed) re-enables the runtime (see
			// cmd_plugin.allow → pe.allow + _enable_plugin_via_gateway).
			return m.executor.Execute("defenseclaw", []string{"plugin", "allow", name}, "unblock plugin "+name)
		case "d":
			return m.executor.Execute("defenseclaw", []string{"plugin", "disable", name}, "disable plugin "+name)
		case "e":
			return m.executor.Execute("defenseclaw", []string{"plugin", "enable", name}, "enable plugin "+name)
		case "q":
			return m.executor.Execute("defenseclaw", []string{"plugin", "quarantine", name}, "quarantine plugin "+name)
		case "r":
			return m.executor.Execute("defenseclaw", []string{"plugin", "restore", name}, "restore plugin "+name)
		case "x":
			return m.executor.Execute("defenseclaw", []string{"plugin", "remove", name}, "remove plugin "+name)
		}
	case PanelTools:
		// Tools mutations route through `defenseclaw tool` so the
		// admission gate, scoped-policy resolution, and audit
		// emission are handled by a single authoritative code
		// path. Scope-qualified targets (e.g. `write_file@filesystem`)
		// are preserved by passing `TargetName` verbatim — do not
		// strip the scope or we'll end up editing the global row.
		sel := m.tools.Selected()
		if sel == nil {
			return nil
		}
		target := sel.TargetName
		if target == "" {
			target = sel.Name
		}
		display := target
		switch key {
		case "i":
			return m.executor.Execute("defenseclaw", []string{"tool", "status", target}, "info tool "+display)
		case "b":
			return m.executor.Execute("defenseclaw", []string{"tool", "block", target}, "block tool "+display)
		case "a":
			return m.executor.Execute("defenseclaw", []string{"tool", "allow", target}, "allow tool "+display)
		case "u":
			return m.executor.Execute("defenseclaw", []string{"tool", "unblock", target}, "unblock tool "+display)
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
	case PanelPolicy:
		return m.handlePolicyKey(msg)
	case PanelAudit:
		return m.handleAuditKey(msg)
	case PanelActivity:
		return m.handleActivityKey(msg)
	case PanelTools:
		return m.handleToolsKey(msg)
	case PanelSetup:
		return m.handleSetupKey(msg)
	}
	return m, nil
}

func (m Model) handlePolicyKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	bin, args, name := m.policy.HandleKey(msg.String())
	// B3d: if the policy panel queued a pending tea.Cmd (e.g., the
	// in-panel `policy test` runner or an editor launch), run it
	// directly instead of going through the executor. We drain the
	// pending cmd before dispatching CLI verbs so a single key
	// press can't both queue a local cmd and a CLI spawn.
	if pending := m.policy.TakeCmd(); pending != nil {
		return m, pending
	}
	if bin != "" {
		m.activePanel = PanelActivity
		return m, m.executor.Execute(bin, args, name)
	}
	return m, nil
}

func (m Model) handleSetupKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	key := msg.String()

	// Global setup shortcuts (not when editing, form active, running a
	// wizard, or inside the Audit Sinks editor — the editor owns 'R'/'E'
	// and 'S' would unexpectedly save pending config changes).
	if !m.setup.editing && !m.setup.IsFormActive() && !m.setup.IsWizardRunning() && len(m.setup.wizOutput) == 0 && !m.setup.IsEditorActive() {
		switch key {
		case "S":
			if m.setup.HasChanges() {
				actPath, _, err := m.setup.AuditActivityTempFile()
				if err != nil {
					m.toasts.Push(ToastError, err.Error())
					return m, nil
				}
				if err := m.setup.SaveConfig(); err != nil {
					if actPath != "" {
						_ = os.Remove(actPath)
					}
					m.toasts.Push(ToastError, "Config save failed: "+err.Error())
					return m, nil
				}
				m.cfg = m.setup.GetConfig()
				m.toasts.Push(ToastSuccess, "Config saved — restarting gateway to apply changes…")
				if actPath != "" {
					c := exec.Command("defenseclaw", "audit", "log-activity", "--payload-file", actPath)
					out, err := c.CombinedOutput()
					if err != nil {
						m.toasts.Push(ToastWarn, fmt.Sprintf("audit log-activity: %v %s", err, strings.TrimSpace(string(out))))
					}
					_ = os.Remove(actPath)
				}
				m.activePanel = PanelActivity
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
	// The mode-picker overlay consumes its own keys when visible. We
	// route here BEFORE any other Overview shortcut so e.g. typing 'o'
	// inside the modal selects OpenClaw instead of being interpreted as
	// a panel-level shortcut. Esc/enter close-or-confirm semantics
	// live with the picker; everything else is forwarded as cursor
	// motion or hotkey jump.
	if m.modePicker.IsVisible() {
		return m.handleModePickerKey(msg)
	}

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
	case "m":
		// Open the connector switcher pre-focused on the currently
		// active mode. ActiveConnectorName is the same resolver used
		// for the SERVICES "Agent" row, so the picker and the
		// dashboard agree on which entry is "active".
		m.modePicker.Show(m.activeConnectorForPicker())
		return m, nil
	case "p":
		m.activePanel = PanelPolicy
	case "l":
		m.activePanel = PanelLogs
	case "u":
		cmd := m.executor.Execute("defenseclaw", []string{"upgrade", "--yes"}, "upgrade")
		m.activePanel = PanelActivity
		return m, cmd
	}
	return m, nil
}

// handleModePickerKey runs while the connector picker overlay is
// open. The contract:
//
//   - esc / q: close without changing anything
//   - enter:   dispatch `defenseclaw setup mode <wire> --yes` and
//              switch to the Activity panel so the user can watch the
//              restart progress (mirrors how [s] / [d] / [u] behave)
//   - up / k:  cursor up
//   - down / j cursor down
//   - o/z/c/k: hotkey jump to the matching row, then confirm — one
//              keystroke is enough because muscle memory is the
//              whole point of the picker
func (m Model) handleModePickerKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "q":
		m.modePicker.Hide()
		return m, nil
	case "up", "k":
		m.modePicker.CursorUp()
		return m, nil
	case "down", "j":
		m.modePicker.CursorDown()
		return m, nil
	case "enter":
		return m.confirmModePicker()
	}
	// Hotkey jump + auto-confirm. We deliberately accept *only* the
	// four documented hotkeys here; other letters fall through to a
	// no-op so a stray keystroke can't surprise-switch the connector.
	if r := []rune(msg.String()); len(r) == 1 {
		if m.modePicker.SelectByHotkey(r[0]) {
			return m.confirmModePicker()
		}
	}
	return m, nil
}

// confirmModePicker dispatches the chosen mode through the Python
// CLI and switches to the Activity panel so the user sees the
// restart output. We always pass --yes because the modal IS the
// confirmation step — there's no point asking again.
func (m Model) confirmModePicker() (tea.Model, tea.Cmd) {
	wire := m.modePicker.Selected()
	m.modePicker.Hide()
	if wire == "" {
		return m, nil
	}
	cmd := m.executor.Execute(
		"defenseclaw",
		[]string{"setup", "mode", wire, "--yes"},
		"setup mode "+wire,
	)
	m.activePanel = PanelActivity
	return m, cmd
}

// activeConnectorForPicker resolves the connector name we want to
// pre-highlight in the picker. Mirrors ActiveConnectorName's
// resolution order so the SERVICES "Agent" row and the picker's
// "(active)" badge always agree on which connector is live.
func (m Model) activeConnectorForPicker() string {
	mode := ""
	if m.cfg != nil {
		mode = string(m.cfg.Claw.Mode)
	}
	return ActiveConnectorName(m.health, mode)
}

func (m Model) handleAlertsKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "j", "down":
		m.alerts.CursorDown()
	case "k", "up":
		m.alerts.CursorUp()
	case "enter":
		m.alerts.ToggleExpandOrDetail()
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
		old := m.alerts.SevFilter()
		m.alerts.SetSevFilter("")
		m.noteTUIFilterChange(PanelNameAlerts, FilterTypeSeverity, old, m.alerts.SevFilter())
	case "2":
		old := m.alerts.SevFilter()
		m.alerts.SetSevFilter("CRITICAL")
		m.noteTUIFilterChange(PanelNameAlerts, FilterTypeSeverity, old, m.alerts.SevFilter())
	case "3":
		old := m.alerts.SevFilter()
		m.alerts.SetSevFilter("HIGH")
		m.noteTUIFilterChange(PanelNameAlerts, FilterTypeSeverity, old, m.alerts.SevFilter())
	case "4":
		old := m.alerts.SevFilter()
		m.alerts.SetSevFilter("MEDIUM")
		m.noteTUIFilterChange(PanelNameAlerts, FilterTypeSeverity, old, m.alerts.SevFilter())
	case "5":
		old := m.alerts.SevFilter()
		m.alerts.SetSevFilter("LOW")
		m.noteTUIFilterChange(PanelNameAlerts, FilterTypeSeverity, old, m.alerts.SevFilter())
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
		// Route through the CLI so block emits an audit event, runs
		// the admission gate, and updates policy the same way a
		// shell user would. Prior to P0-#4 this called
		// m.skills.ToggleBlock() which bypassed all three.
		if sel := m.skills.Selected(); sel != nil {
			cmd := m.executor.Execute("defenseclaw", []string{"skill", "block", sel.Name}, "block skill "+sel.Name)
			m.activePanel = PanelActivity
			return m, cmd
		}
	case "a":
		// 'a' is always "allow" (block-list → allow-list → active is
		// a one-way transition handled by `skill allow`). If the
		// operator wants to unblock without allow-listing they can
		// use 'u' from the action menu.
		if sel := m.skills.Selected(); sel != nil {
			cmd := m.executor.Execute("defenseclaw", []string{"skill", "allow", sel.Name}, "allow skill "+sel.Name)
			m.activePanel = PanelActivity
			return m, cmd
		}
	case "s":
		if sel := m.skills.Selected(); sel != nil {
			cmd := m.executor.Execute("defenseclaw", []string{"skill", "scan", sel.Name}, "scan skill "+sel.Name)
			m.activePanel = PanelActivity
			return m, cmd
		}
	case "r":
		// 'r' now re-runs `defenseclaw skill list --json` rather
		// than re-filtering the stale audit-store view. The old
		// `m.skills.Refresh()` just replayed whatever was already
		// in memory, which is why operators kept seeing stale
		// data after an out-of-process `defenseclaw skill …`.
		return m, m.skills.LoadCmd()
	}
	return m, nil
}

func (m Model) handleMCPsKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	// The Set form owns the keyboard while it's open — route
	// everything through it. On submit it emits (binary, args) and
	// the caller dispatches through CommandExecutor so the MCP
	// `set` verb runs out-of-process (matching every other
	// mutation in this panel).
	if m.mcpSetForm.IsActive() {
		submit, bin, args, display := m.mcpSetForm.HandleKey(msg.String())
		if submit {
			m.mcpSetForm.Close()
			m.activePanel = PanelActivity
			return m, m.executor.Execute(bin, args, display)
		}
		return m, nil
	}
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
			m.actionMenu.Show(sel.URL, sel.Status, info, MCPActions(sel.Status, m.mcps.ActiveConnector()))
		}
	case "b":
		// Pre-P0-#5 this called ToggleBlock() which mutated the
		// local audit store only. That bypasses the admission gate,
		// the gateway RPC, and the formal audit event — so a block
		// from the TUI looked different in the log than a block from
		// the shell. Now every mutation routes through the Python
		// CLI, which is the single source of truth for policy.
		if sel := m.mcps.Selected(); sel != nil {
			cmd := m.executor.Execute("defenseclaw", []string{"mcp", "block", sel.URL}, "block mcp "+sel.URL)
			m.activePanel = PanelActivity
			return m, cmd
		}
	case "a":
		// 'a' always means "allow". The old "only if blocked"
		// short-circuit was a footgun — operators watching a row go
		// from blocked→allowed wanted the full allow-list entry,
		// not an unblock-and-stop. Unblock is still reachable via
		// 'u' in the action menu.
		if sel := m.mcps.Selected(); sel != nil {
			cmd := m.executor.Execute("defenseclaw", []string{"mcp", "allow", sel.URL}, "allow mcp "+sel.URL)
			m.activePanel = PanelActivity
			return m, cmd
		}
	case "s":
		if sel := m.mcps.Selected(); sel != nil {
			cmd := m.executor.Execute("defenseclaw", []string{"mcp", "scan", sel.URL}, "scan mcp "+sel.URL)
			m.activePanel = PanelActivity
			return m, cmd
		}
	case "n", "+":
		// Open the MCP Set form. The form owns its own state and
		// on submit dispatches `defenseclaw mcp set <name> ...`.
		// 'n' mirrors "new" (parity with skill install), '+' is a
		// convenience alias for keyboards that preserve shift.
		m.mcpSetForm.Open("")
	case "r":
		// Same rationale as the skills 'r' key — pull the merged
		// catalog from the CLI instead of re-filtering the
		// already-loaded rows.
		return m, m.mcps.LoadCmd()
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
	case "o":
		// Open the contextual action menu. Parity with Skills/MCPs
		// (both use 'o'). The action menu dispatches via
		// executeActionMenuItem → `defenseclaw plugin <verb> <name>`,
		// routing mutations through the CLI so PolicyEngine,
		// admission audit, and gateway RPC stay in one place.
		if sel := m.plugins.Selected(); sel != nil {
			name := sel.Name
			if name == "" {
				name = sel.ID
			}
			info := [][2]string{
				{"ID", sel.ID},
				{"Version", sel.Version},
				{"Origin", sel.Origin},
				{"Status", sel.Status},
				{"Verdict", sel.Verdict},
			}
			if sel.Scan != nil {
				info = append(info,
					[2]string{"Max severity", sel.Scan.MaxSeverity},
					[2]string{"Findings", fmt.Sprintf("%d", sel.Scan.TotalFindings)},
				)
			}
			m.actionMenu.SetSize(m.width, m.height)
			m.actionMenu.Show(name, sel.Status, info, PluginActions(sel.Verdict, sel.Status, sel.Enabled))
		}
	}
	return m, nil
}

// handleToolsKey handles key input while the Tools panel is active.
// Keybindings mirror Skills/MCPs (j/k nav, enter for detail, o for
// the action menu, r to refresh) so operators get the same ergonomics
// across block-list panels. No filter support yet — the tool list is
// typically short (rules, not inventory), so a dedicated filter UI
// doesn't earn its keep until operator feedback tells us otherwise.
func (m Model) handleToolsKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "j", "down":
		m.tools.CursorDown()
	case "k", "up":
		m.tools.CursorUp()
	case "esc":
		if m.tools.IsDetailOpen() {
			m.tools.ToggleDetail()
		}
	case "enter":
		m.tools.ToggleDetail()
	case "r":
		m.tools.Refresh()
	case "o":
		if sel := m.tools.Selected(); sel != nil {
			scope := sel.Scope
			if scope == "" {
				scope = "(global)"
			}
			info := [][2]string{
				{"Scope", scope},
				{"Status", sel.Status},
				{"Since", sel.Time},
			}
			if sel.Reason != "" {
				info = append(info, [2]string{"Reason", sel.Reason})
			}
			m.actionMenu.SetSize(m.width, m.height)
			m.actionMenu.Show(sel.Name, sel.Status, info, ToolActions(sel.Status))
		}
	}
	return m, nil
}

func (m Model) handleLogsKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	key := msg.String()
	// On the Verdicts source, Enter opens a detail modal for the
	// most-recent visible event. We intercept before handing the
	// key to the panel so the panel's own "search entry" path
	// doesn't swallow Enter while searching is inactive.
	if key == "enter" && !m.logs.searching && m.logs.source == logSourceVerdicts {
		if row := m.logs.SelectedVerdict(); row != nil {
			pairs := verdictDetailPairs(*row)
			m.detail.SetSize(m.width, m.height)
			m.detail.Show(fmt.Sprintf("Gateway event — %s", strings.ToUpper(row.eventType)), pairs)
			return m, nil
		}
	}
	// B4b: Enter on Gateway / Watchdog opens a one-field modal
	// with the raw log line so operators can copy-paste without
	// truncation. The Verdicts branch above already handles its
	// source because its modal is richer (structured kv pairs).
	if key == "enter" && !m.logs.searching && m.logs.source != logSourceVerdicts {
		if line := m.logs.SelectedRawLine(); line != "" {
			m.detail.SetSize(m.width, m.height)
			m.detail.Show(fmt.Sprintf("%s log line", logSourceNames[m.logs.source]), [][2]string{{"Line", line}})
			return m, nil
		}
	}
	// 'J' (capital — lowercase is used for "down" in the panel)
	// opens the SQLite-backed Judge Response viewer. The panel
	// gateway.jsonl tail shows only the last 2 KB of body; the
	// SQLite copy preserves the full redacted response, the input
	// hash, and the correlation IDs for forensic review. We pull
	// the 20 most-recent rows because the detail modal is a simple
	// kv renderer — pagination can come later once operators tell
	// us the cap is too tight.
	if key == "J" && !m.logs.searching && m.logs.source == logSourceVerdicts && m.store != nil {
		rows, err := m.store.ListJudgeResponses(20)
		m.detail.SetSize(m.width, m.height)
		if err != nil {
			m.detail.Show("Judge Responses — error", [][2]string{{"Error", err.Error()}})
			return m, nil
		}
		if len(rows) == 0 {
			m.detail.Show("Judge Responses", [][2]string{{"Info", "No judge responses persisted yet. Ensure guardrail.retain_judge_bodies is on (default) and traffic has been inspected."}})
			return m, nil
		}
		m.detail.Show(fmt.Sprintf("Judge Responses — last %d", len(rows)), judgeResponsesDetailPairs(rows))
		return m, nil
	}
	var cmd tea.Cmd
	m.logs, cmd = m.logs.Update(msg)
	return m, cmd
}

// judgeResponsesDetailPairs formats a slice of audit.JudgeResponse
// rows into the label/value list the shared DetailModal expects.
// The rows are laid out newest-first with a blank separator between
// entries so long redacted bodies don't blur into each other. Each
// row surfaces:
//   - correlation keys (request_id, trace_id, run_id)
//   - verdict shape (kind, action, severity, confidence, fail_closed)
//   - performance (latency_ms)
//   - inspected model vs judge model
//   - the redacted raw body (truncated to 2 KB by the persistor)
//
// Anything that could contain PII is expected to already be
// redacted before we reach this code path; we render the fields
// verbatim.
func judgeResponsesDetailPairs(rows []audit.JudgeResponse) [][2]string {
	pairs := make([][2]string, 0, len(rows)*12)
	for i, r := range rows {
		if i > 0 {
			pairs = append(pairs, [2]string{"", ""})
		}
		prefix := fmt.Sprintf("[%d] ", i+1)
		pairs = append(pairs,
			[2]string{prefix + "Timestamp", r.Timestamp.Format(time.RFC3339Nano)},
			[2]string{prefix + "Kind", r.Kind},
			[2]string{prefix + "Direction", r.Direction},
			[2]string{prefix + "Action", r.Action},
			[2]string{prefix + "Severity", r.Severity},
			[2]string{prefix + "Latency (ms)", fmt.Sprintf("%d", r.LatencyMs)},
		)
		if r.InspectedModel != "" {
			pairs = append(pairs, [2]string{prefix + "Inspected model", r.InspectedModel})
		}
		if r.Model != "" {
			pairs = append(pairs, [2]string{prefix + "Judge model", r.Model})
		}
		if r.RequestID != "" {
			pairs = append(pairs, [2]string{prefix + "Request ID", r.RequestID})
		}
		if r.TraceID != "" {
			pairs = append(pairs, [2]string{prefix + "Trace ID", r.TraceID})
		}
		if r.RunID != "" {
			pairs = append(pairs, [2]string{prefix + "Run ID", r.RunID})
		}
		if r.InputHash != "" {
			pairs = append(pairs, [2]string{prefix + "Input hash", r.InputHash})
		}
		if r.Confidence != 0 {
			pairs = append(pairs, [2]string{prefix + "Confidence", fmt.Sprintf("%.3f", r.Confidence)})
		}
		if r.FailClosedApplied {
			pairs = append(pairs, [2]string{prefix + "Fail-closed", "yes"})
		}
		if r.PromptTemplateID != "" {
			pairs = append(pairs, [2]string{prefix + "Prompt template", r.PromptTemplateID})
		}
		if r.ParseError != "" {
			pairs = append(pairs, [2]string{prefix + "Parse error", r.ParseError})
		}
		pairs = append(pairs, [2]string{prefix + "Raw (redacted)", r.Raw})
	}
	return pairs
}

// verdictDetailPairs formats a structured event into the ordered
// label/value pairs the shared DetailModal expects. Larger bodies
// (judge raw response, error cause) come last so the modal can
// scroll without hiding the identification block.
//
// Fields are grouped by intent so operators can read the modal like
// an incident report: identification → correlation → verdict →
// judge details → lifecycle/error/diagnostic → raw JSON escape
// hatch.
func verdictDetailPairs(r verdictRow) [][2]string {
	pairs := [][2]string{
		{"Timestamp", r.timestamp.Format(time.RFC3339Nano)},
		{"Event type", r.eventType},
		{"Severity", r.severity},
		{"Action", r.action},
		{"Stage", r.stage},
		{"Direction", r.direction},
		{"Model", r.model},
	}

	// Correlation IDs — the whole point of request_id/run_id is to
	// let an operator pivot from the TUI into SQLite, Splunk, or an
	// OTel trace view. Surface them right after identification so
	// they're never more than a skim away.
	if r.provider != "" {
		pairs = append(pairs, [2]string{"Provider", r.provider})
	}
	if r.requestID != "" {
		pairs = append(pairs, [2]string{"Request ID", r.requestID})
	}
	if r.runID != "" {
		pairs = append(pairs, [2]string{"Run ID", r.runID})
	}
	if r.sessionID != "" {
		pairs = append(pairs, [2]string{"Session ID", r.sessionID})
	}

	// Verdict-specific extras — only surface when non-empty so a
	// lifecycle/error modal doesn't show "Categories: " with an
	// empty right-hand side.
	if len(r.categories) > 0 {
		pairs = append(pairs, [2]string{"Categories", strings.Join(r.categories, ", ")})
	}
	if r.latencyMs > 0 {
		pairs = append(pairs, [2]string{"Latency (ms)", fmt.Sprintf("%d", r.latencyMs)})
	}
	if r.kind != "" {
		pairs = append(pairs, [2]string{"Judge kind", r.kind})
	}
	if r.reason != "" {
		pairs = append(pairs, [2]string{"Reason", r.reason})
	}

	// Judge-specific fields — the envelope severity already shows
	// up above as "Severity"; show the judge's own severity only
	// when it disagrees, to avoid visual duplication.
	if r.judgeSeverity != "" && !strings.EqualFold(r.judgeSeverity, r.severity) {
		pairs = append(pairs, [2]string{"Judge severity", r.judgeSeverity})
	}
	if r.judgeInputBytes > 0 {
		pairs = append(pairs, [2]string{"Judge input bytes", fmt.Sprintf("%d", r.judgeInputBytes)})
	}
	if r.judgeParseError != "" {
		pairs = append(pairs, [2]string{"Judge parse error", r.judgeParseError})
	}
	for i, f := range r.judgeFindings {
		label := fmt.Sprintf("Finding %d", i+1)
		val := fmt.Sprintf("category=%s severity=%s", f.Category, f.Severity)
		if f.Rule != "" {
			val += " rule=" + f.Rule
		}
		if f.Source != "" {
			val += " source=" + f.Source
		}
		if f.Conf > 0 {
			val += fmt.Sprintf(" conf=%.2f", f.Conf)
		}
		pairs = append(pairs, [2]string{label, val})
	}

	// Lifecycle, error, diagnostic payload details. Operators open
	// lifecycle events to see "what subsystem transitioned and
	// why"; error events to see code+message+cause; diagnostic to
	// see component+message.
	if r.lifecycleSubsystem != "" {
		pairs = append(pairs, [2]string{"Subsystem", r.lifecycleSubsystem})
	}
	if r.lifecycleTransition != "" {
		pairs = append(pairs, [2]string{"Transition", r.lifecycleTransition})
	}
	if len(r.lifecycleDetails) > 0 {
		// Stable alphabetical ordering — same contract as the
		// inline renderer — so the modal doesn't shuffle between
		// opens.
		keys := make([]string, 0, len(r.lifecycleDetails))
		for k := range r.lifecycleDetails {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			pairs = append(pairs, [2]string{"Detail: " + k, r.lifecycleDetails[k]})
		}
	}
	if r.errorSubsystem != "" {
		pairs = append(pairs, [2]string{"Error subsystem", r.errorSubsystem})
	}
	if r.errorCode != "" {
		pairs = append(pairs, [2]string{"Error code", r.errorCode})
	}
	if r.errorMessage != "" {
		pairs = append(pairs, [2]string{"Error message", r.errorMessage})
	}
	if r.errorCause != "" {
		pairs = append(pairs, [2]string{"Error cause", r.errorCause})
	}
	if r.diagnosticComponent != "" {
		pairs = append(pairs, [2]string{"Diagnostic component", r.diagnosticComponent})
	}
	if r.diagnosticMessage != "" {
		pairs = append(pairs, [2]string{"Diagnostic message", r.diagnosticMessage})
	}

	// Judge raw response is intentionally one of the last fields
	// because it's usually the largest string in the modal and
	// pushes higher-signal correlation IDs off-screen otherwise.
	if r.judgeRaw != "" {
		pairs = append(pairs, [2]string{"Judge raw response", r.judgeRaw})
	}

	pairs = append(pairs, [2]string{"Raw JSON", r.raw})
	return pairs
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
	case "o":
		// P3-#19: 'o' toggles the fast-scan preset (skills+
		// plugins+mcp) that maps to `defenseclaw aibom scan
		// --only skills,plugins,mcp`. Not auto-reloading — the
		// operator presses 'r' next to trigger the scan so
		// they can see the new scope before paying the 15-30s
		// cost.
		m.inventory.ToggleFastScan()
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

	// Mode picker overlay (Overview [m]). Drawn here so it occupies
	// the same screen real estate as the help / action overlays
	// instead of competing with the underlying Overview panel for
	// clicks and re-paints.
	if m.modePicker.IsVisible() {
		m.modePicker.SetSize(m.width, m.height)
		return m.tuiShellView(m.modePicker.View())
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
	if refreshTestHook != nil {
		refreshTestHook()
	}
	m.alerts.Refresh()
	m.skills.Refresh()
	m.mcps.Refresh()
	m.tools.Refresh()
	m.auditHist.Refresh()
	m.activity.LoadMutations()
	if m.store != nil {
		if err := m.overview.SetEnforcementCounts(m.store); err != nil {
			m.toasts.Push(ToastWarn, "Failed to refresh counts: "+err.Error())
		}
	}
	// Silent-bypass tile on the Overview panel. Loading here (rather
	// than in a dedicated command) keeps it on the same refresh cadence
	// as the other Overview counts; LoadGatewayEgress is a bounded
	// tail read (512 KiB) so it's cheap relative to the audit-store
	// queries that already run on this path. A missing gateway.jsonl
	// degrades silently — CountRecentSilentBypass returns 0 for a nil
	// slice, which is the correct "we haven't seen any egress yet"
	// display.
	if m.cfg != nil && m.cfg.DataDir != "" {
		if events, err := LoadGatewayEgress(filepath.Join(m.cfg.DataDir, "gateway.jsonl")); err == nil {
			m.overview.SetSilentBypassCount(CountRecentSilentBypass(events, 5*time.Minute))
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
	case PanelSkills:
		// First visit kicks off `defenseclaw skill list --json`.
		// Subsequent visits reuse the cached rows — slowRefreshMsg
		// is responsible for keeping them fresh.
		if !m.skills.IsLoaded() && !m.skills.IsLoading() {
			return m.skills.LoadCmd()
		}
	case PanelMCPs:
		if !m.mcps.IsLoaded() && !m.mcps.IsLoading() {
			return m.mcps.LoadCmd()
		}
	case PanelTools:
		// Tools loads synchronously off the audit store — no
		// async load command needed. Refresh here so an operator
		// jumping in via 'T' sees fresh rows even if the periodic
		// refresh hasn't fired yet.
		m.tools.Refresh()
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
	m.tools.SetSize(m.width, panelH)
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

// tabNumKey returns the keyboard shortcut number for panel index i, or -1 if
// the panel has no dedicated number key (e.g. Activity when there are >10 panels).
func tabNumKey(i int) int {
	// Panels 0-8 map to keys 1-9; panel panelCount-1 (Setup) always maps to 0.
	// If there are more than 10 panels, the second-to-last (Activity) has no key.
	if i == panelCount-1 {
		return 0
	}
	key := i + 1
	if key <= 9 {
		return key
	}
	return -1
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
			numKey := tabNumKey(i)
			var label string
			if numKey < 0 {
				label = name
			} else {
				label = fmtFn(numKey, name)
			}
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

	// Absolute minimum: just numbers (or name for keyless panels)
	var labels []string
	for i := range panelNames {
		numKey := tabNumKey(i)
		if numKey < 0 {
			labels = append(labels, panelNames[i][:1])
		} else {
			labels = append(labels, fmt.Sprintf("%d", numKey))
		}
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
		// The Set form is an overlay on the MCP panel — when it's
		// open the operator is explicitly in "add / edit" mode and
		// the list underneath would just be visual noise. We swap
		// the whole panel render here (rather than post-composing
		// in renderFrame) so the form gets the full height and the
		// status bar continues to pick up MCP-panel hints.
		if m.mcpSetForm.IsActive() {
			return m.mcpSetForm.View()
		}
		return m.mcps.View()
	case PanelPlugins:
		return m.plugins.View(m.width, m.height-5)
	case PanelInventory:
		return m.inventory.View(m.width, m.height-5)
	case PanelPolicy:
		return m.policy.View(m.width, m.height-5)
	case PanelLogs:
		return m.logs.View()
	case PanelAudit:
		return m.auditHist.View(m.width, m.height-5)
	case PanelActivity:
		return m.activity.View()
	case PanelTools:
		return m.tools.View()
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
			{"Ctrl+C", "Quit"},
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
		{"Policy Panel (7)", [][2]string{
			{"Tab / Shift+Tab", "Switch sub-tab"},
			{"j/k or Up/Down", "Navigate items"},
			{"Enter", "Activate pack / drill into rules"},
			{"Esc", "Back from rule detail"},
			{"d", "Delete suppression (Suppressions tab)"},
			{"v / T / r", "Validate / test / reload (OPA tab)"},
			{"t", "Toggle test files (OPA tab)"},
		}},
		{"Overview Quick Actions", [][2]string{
			{"s", "Scan all skills"},
			{"d", "Run doctor"},
			{"g", "Setup guardrail"},
			{"p", "Go to Policy"},
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
