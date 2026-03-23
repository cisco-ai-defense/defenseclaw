package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	runewidth "github.com/mattn/go-runewidth"
	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enforce"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
	"github.com/defenseclaw/defenseclaw/internal/sandbox"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

var skillCmd = &cobra.Command{
	Use:   "skill",
	Short: "Manage OpenClaw skills — install, scan, disable, enable",
}

var skillDisableCmd = &cobra.Command{
	Use:   "disable <skill-key>",
	Short: "Disable a skill via the OpenClaw gateway and add to block list",
	Long: `Disable a skill by sending a skills.update RPC to the OpenClaw gateway and
adding the skill to the local block list. This immediately prevents the agent
from using the skill.

Requires the gateway to be running. Configure gateway connection in
~/.defenseclaw/config.yaml under the "gateway" section.`,
	Args: cobra.ExactArgs(1),
	RunE: runSkillDisable,
}

var skillEnableCmd = &cobra.Command{
	Use:   "enable <skill-key>",
	Short: "Enable a previously disabled skill via the OpenClaw gateway",
	Long: `Re-enable a skill by sending a skills.update RPC to the OpenClaw gateway and
removing the skill from the local block list.`,
	Args: cobra.ExactArgs(1),
	RunE: runSkillEnable,
}

var skillScanCmd = &cobra.Command{
	Use:   "scan <path|all>",
	Short: "Scan a skill directory or all configured skills",
	Long: `Run skill-scanner against a skill directory and report a pass/fail verdict.

Use 'all' to scan all skills in the configured skill directories.`,
	Args: cobra.ExactArgs(1),
	RunE: runSkillScan,
}

var skillListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all OpenClaw skills with their latest scan severity",
	Long: `List all skills from 'openclaw skills list' merged with the latest
scan results from the DefenseClaw audit database.

Shows skill name, status, description, source, and the severity from
the most recent skill-scanner run (if any).`,
	RunE: runSkillList,
}

var skillInstallCmd = &cobra.Command{
	Use:   "install <skill>",
	Short: "Install and scan an OpenClaw skill via clawhub",
	Long: `Install a skill from ClawHub using 'npx @clawhub install', then scan it.
Post-install actions (block, quarantine, or allow) are determined by the
severity of scan findings and the skill_actions config in config.yaml.

Use --force to pass the --force flag to clawhub (overwrites existing).`,
	Args: cobra.ExactArgs(1),
	RunE: runSkillInstall,
}

var (
	skillDisableReason string
	skillScanJSON      bool
	skillInstallForce  bool
	skillInstallJSON   bool
	skillListJSON      bool
)

func init() {
	skillDisableCmd.Flags().StringVar(&skillDisableReason, "reason", "", "Reason for disabling")
	skillScanCmd.Flags().BoolVar(&skillScanJSON, "json", false, "Output scan results as JSON")
	skillInstallCmd.Flags().BoolVar(&skillInstallForce, "force", false, "Install despite MEDIUM/LOW findings")
	skillInstallCmd.Flags().BoolVar(&skillInstallJSON, "json", false, "Output results as JSON")
	skillListCmd.Flags().BoolVar(&skillListJSON, "json", false, "Output merged skill list as JSON")

	skillCmd.AddCommand(skillDisableCmd)
	skillCmd.AddCommand(skillEnableCmd)
	skillCmd.AddCommand(skillScanCmd)
	skillCmd.AddCommand(skillInstallCmd)
	skillCmd.AddCommand(skillListCmd)
	rootCmd.AddCommand(skillCmd)
}

func runSkillDisable(_ *cobra.Command, args []string) error {
	skillKey := args[0]

	pe := enforce.NewPolicyEngine(auditStore)

	reason := skillDisableReason
	if reason == "" {
		reason = "manual disable via CLI"
	}

	// Add to local block list
	if err := pe.Block("skill", skillKey, reason); err != nil {
		return fmt.Errorf("skill disable: block: %w", err)
	}
	fmt.Printf("[skill] %q added to block list\n", skillKey)

	// Also quarantine and update sandbox if available
	shell := sandbox.NewWithFallback(cfg.OpenShell.Binary, cfg.OpenShell.PolicyDir, cfg.PolicyDir)
	se := enforce.NewSkillEnforcer(cfg.QuarantineDir, shell)
	_ = se.UpdateSandboxPolicy(skillKey, true)

	// Disable via gateway RPC
	if err := disableViaGateway(skillKey); err != nil {
		fmt.Fprintf(os.Stderr, "[skill] gateway RPC failed: %v (skill is still blocked locally)\n", err)
	} else {
		fmt.Printf("[skill] %q disabled via gateway RPC\n", skillKey)
	}

	_ = auditLog.LogAction("skill-disable", skillKey, fmt.Sprintf("reason=%s", reason))
	return nil
}

func runSkillEnable(_ *cobra.Command, args []string) error {
	skillKey := args[0]

	pe := enforce.NewPolicyEngine(auditStore)

	if err := pe.Unblock("skill", skillKey); err != nil {
		return fmt.Errorf("skill enable: unblock: %w", err)
	}
	fmt.Printf("[skill] %q removed from block list\n", skillKey)

	shell := sandbox.NewWithFallback(cfg.OpenShell.Binary, cfg.OpenShell.PolicyDir, cfg.PolicyDir)
	se := enforce.NewSkillEnforcer(cfg.QuarantineDir, shell)
	_ = se.UpdateSandboxPolicy(skillKey, false)

	if err := enableViaGateway(skillKey); err != nil {
		fmt.Fprintf(os.Stderr, "[skill] gateway RPC failed: %v (skill is still unblocked locally)\n", err)
	} else {
		fmt.Printf("[skill] %q enabled via gateway RPC\n", skillKey)
	}

	_ = auditLog.LogAction("skill-enable", skillKey, "re-enabled via CLI")
	return nil
}

// skillVerdict holds the result of scanning a skill directory.
type skillVerdict struct {
	Target        string                `json:"target"`
	Clean         bool                  `json:"clean"`
	MaxSeverity   scanner.Severity      `json:"max_severity"`
	TotalFindings int                   `json:"total_findings"`
	Results       []*scanner.ScanResult `json:"results,omitempty"`
}

// scanSkillPath runs the skill scanner against the given path and returns a verdict.
// If verbose is true, it prints progress to stdout.
func scanSkillPath(ctx context.Context, path string, verbose bool) (*skillVerdict, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	s := scanner.NewSkillScanner(cfg.Scanners.SkillScanner)
	v := &skillVerdict{Target: path, Clean: true, MaxSeverity: scanner.SeverityInfo}

	if verbose {
		fmt.Printf("[scan] %s -> %s\n", s.Name(), path)
	}

	result, err := s.Scan(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("skill scan: %w", err)
	}

	if auditLog != nil {
		_ = auditLog.LogScan(result)
	}

	if !result.IsClean() {
		v.Clean = false
		v.TotalFindings = len(result.Findings)
		v.MaxSeverity = result.MaxSeverity()
	}
	v.Results = append(v.Results, result)

	return v, nil
}

func runSkillScan(cmd *cobra.Command, args []string) error {
	target := args[0]

	if target == "all" {
		return runSkillScanAll(cmd)
	}

	verdict, err := scanSkillPath(cmd.Context(), target, !skillScanJSON)
	if err != nil {
		return err
	}

	printSkillVerdict(verdict)
	return nil
}

// openclawSkillInfo represents the output of 'openclaw skills info <skill> --json'
type openclawSkillInfo struct {
	Name    string `json:"name"`
	BaseDir string `json:"baseDir"`
	Bundled bool   `json:"bundled"`
	Source  string `json:"source"`
}

// openclawSkill represents a single skill entry from 'openclaw skills list --json'.
type openclawSkill struct {
	Name               string `json:"name"`
	Description        string `json:"description"`
	Emoji              string `json:"emoji"`
	Eligible           bool   `json:"eligible"`
	Disabled           bool   `json:"disabled"`
	BlockedByAllowlist bool   `json:"blockedByAllowlist"`
	Source             string `json:"source"`
	Bundled            bool   `json:"bundled"`
	Homepage           string `json:"homepage"`
}

// openclawSkillsList represents the full output of 'openclaw skills list --json'.
type openclawSkillsList struct {
	WorkspaceDir     string          `json:"workspaceDir"`
	ManagedSkillsDir string          `json:"managedSkillsDir"`
	Skills           []openclawSkill `json:"skills"`
}

// skillListItem is the merged representation of an openclaw skill + latest scan data.
type skillListItem struct {
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Source      string           `json:"source"`
	Status      string           `json:"status"`
	Eligible    bool             `json:"eligible"`
	Disabled    bool             `json:"disabled"`
	Bundled     bool             `json:"bundled"`
	Homepage    string           `json:"homepage,omitempty"`
	Scan        *skillScanEntry  `json:"scan,omitempty"`
}

// skillScanEntry holds the latest scan result for a skill, shaped like skill scan --json output.
type skillScanEntry struct {
	Target        string                `json:"target"`
	Clean         bool                  `json:"clean"`
	MaxSeverity   scanner.Severity      `json:"max_severity"`
	TotalFindings int                   `json:"total_findings"`
	Results       []*scanner.ScanResult `json:"results,omitempty"`
}

func runSkillScanAll(cmd *cobra.Command) error {
	// Get all skills from openclaw (includes workspace, global, and bundled)
	skillNames, err := listOpenclawSkills()
	if err != nil {
		return fmt.Errorf("failed to list skills: %w", err)
	}

	if len(skillNames) == 0 {
		fmt.Println("[scan] no skills found")
		return nil
	}

	fmt.Printf("[scan] found %d skills to scan\n\n", len(skillNames))

	var allVerdicts []*skillVerdict

	for _, name := range skillNames {
		// Get skill info to find the baseDir
		info, err := getOpenclawSkillInfo(name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[scan] warning: cannot get info for %s: %v\n", name, err)
			continue
		}

		if info.BaseDir == "" {
			fmt.Fprintf(os.Stderr, "[scan] warning: no baseDir for %s\n", name)
			continue
		}

		verdict, err := scanSkillPath(cmd.Context(), info.BaseDir, !skillScanJSON)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[scan] error scanning %s: %v\n", name, err)
			continue
		}
		allVerdicts = append(allVerdicts, verdict)

		if !skillScanJSON {
			printSkillVerdict(verdict)
			fmt.Println()
		}
	}

	if skillScanJSON {
		data, _ := json.MarshalIndent(allVerdicts, "", "  ")
		fmt.Println(string(data))
	} else {
		// Print summary
		clean, warnings, rejects := 0, 0, 0
		for _, v := range allVerdicts {
			if v.Clean {
				clean++
			} else if cfg.SkillActions.ShouldBlock(string(v.MaxSeverity)) || cfg.SkillActions.ShouldQuarantine(string(v.MaxSeverity)) {
				rejects++
			} else {
				warnings++
			}
		}
		fmt.Printf("Summary: %d clean, %d warnings, %d rejected\n", clean, warnings, rejects)
	}

	return nil
}

// listOpenclawSkillsFull returns the full parsed output of 'openclaw skills list --json'.
func listOpenclawSkillsFull() (*openclawSkillsList, error) {
	out, err := exec.Command("openclaw", "skills", "list", "--json").Output()
	if err != nil {
		return nil, fmt.Errorf("openclaw skills list: %w", err)
	}

	var list openclawSkillsList
	if err := json.Unmarshal(out, &list); err != nil {
		return nil, fmt.Errorf("parse skills list: %w", err)
	}
	return &list, nil
}

// listOpenclawSkills returns all skill names from 'openclaw skills list --json'.
func listOpenclawSkills() ([]string, error) {
	list, err := listOpenclawSkillsFull()
	if err != nil {
		return nil, err
	}

	names := make([]string, len(list.Skills))
	for i, s := range list.Skills {
		names[i] = s.Name
	}
	return names, nil
}

// getOpenclawSkillInfo returns skill info from 'openclaw skills info <name> --json'
func getOpenclawSkillInfo(name string) (*openclawSkillInfo, error) {
	out, err := exec.Command("openclaw", "skills", "info", name, "--json").Output()
	if err != nil {
		return nil, fmt.Errorf("openclaw skills info %s: %w", name, err)
	}

	var info openclawSkillInfo
	if err := json.Unmarshal(out, &info); err != nil {
		return nil, fmt.Errorf("parse skill info: %w", err)
	}
	return &info, nil
}

func printSkillVerdict(verdict *skillVerdict) {
	if skillScanJSON {
		data, _ := json.MarshalIndent(verdict, "", "  ")
		fmt.Println(string(data))
		return
	}

	for _, r := range verdict.Results {
		printScanResult(r)
	}
	if verdict.Clean {
		fmt.Println("  Verdict: CLEAN")
	} else if cfg.SkillActions.ShouldBlock(string(verdict.MaxSeverity)) || cfg.SkillActions.ShouldQuarantine(string(verdict.MaxSeverity)) {
		fmt.Printf("  Verdict: REJECT (%d %s findings)\n", verdict.TotalFindings, verdict.MaxSeverity)
	} else {
		fmt.Printf("  Verdict: WARNING (%d %s findings)\n", verdict.TotalFindings, verdict.MaxSeverity)
	}
}

func skillStatus(s openclawSkill) string {
	if s.Disabled {
		return "disabled"
	}
	if s.BlockedByAllowlist {
		return "blocked"
	}
	if s.Eligible {
		return "active"
	}
	return "inactive"
}

func skillStatusDisplay(s openclawSkill) string {
	if s.Disabled {
		return "✗ disabled"
	}
	if s.BlockedByAllowlist {
		return "✗ blocked"
	}
	if s.Eligible {
		return "✓ ready"
	}
	return "✗ missing"
}

func runSkillList(_ *cobra.Command, _ []string) error {
	list, err := listOpenclawSkillsFull()
	if err != nil {
		return err
	}

	if len(list.Skills) == 0 {
		fmt.Println("No skills found.")
		return nil
	}

	scanMap := buildSkillScanMap()

	if skillListJSON {
		return printSkillListJSON(list.Skills, scanMap)
	}
	return printSkillListTable(list.Skills, scanMap)
}

func buildSkillScanMap() map[string]*skillScanEntry {
	scanMap := make(map[string]*skillScanEntry)
	if auditStore == nil {
		return scanMap
	}
	latestScans, err := auditStore.LatestScansByScanner("skill-scanner")
	if err != nil {
		return scanMap
	}
	for _, ls := range latestScans {
		name := filepath.Base(ls.Target)
		severity := scanner.Severity(ls.MaxSeverity)
		if severity == "" {
			severity = scanner.SeverityInfo
		}
		entry := &skillScanEntry{
			Target:        ls.Target,
			Clean:         ls.FindingCount == 0,
			MaxSeverity:   severity,
			TotalFindings: ls.FindingCount,
		}
		if skillListJSON && ls.RawJSON != "" {
			var sr scanner.ScanResult
			if json.Unmarshal([]byte(ls.RawJSON), &sr) == nil {
				entry.Results = []*scanner.ScanResult{&sr}
			}
		}
		scanMap[name] = entry
	}
	return scanMap
}

// --- bordered table helpers ---

func strDisplayWidth(s string) int { return runewidth.StringWidth(s) }

func strPadRight(s string, width int) string {
	gap := width - strDisplayWidth(s)
	if gap <= 0 {
		return s
	}
	return s + strings.Repeat(" ", gap)
}

func wrapText(s string, width int) []string {
	if width <= 0 || strDisplayWidth(s) <= width {
		return []string{s}
	}
	words := strings.Fields(s)
	if len(words) == 0 {
		return []string{""}
	}
	var lines []string
	cur := words[0]
	for _, w := range words[1:] {
		test := cur + " " + w
		if strDisplayWidth(test) <= width {
			cur = test
		} else {
			lines = append(lines, cur)
			cur = w
		}
	}
	lines = append(lines, cur)
	return lines
}

func tableHLine(widths []int, left, mid, right, fill string) string {
	parts := make([]string, len(widths))
	for i, w := range widths {
		parts[i] = strings.Repeat(fill, w+2) // +2 for cell padding
	}
	return left + strings.Join(parts, mid) + right
}

func tableCell(s string, width int) string {
	return " " + strPadRight(s, width) + " "
}

func printSkillListTable(skills []openclawSkill, scanMap map[string]*skillScanEntry) error {
	readyCount := 0
	for _, s := range skills {
		if s.Eligible && !s.Disabled {
			readyCount++
		}
	}

	type rowData struct {
		status, skill, desc, source, severity string
	}

	rows := make([]rowData, len(skills))
	headers := [5]string{"Status", "Skill", "Description", "Source", "Severity"}
	colW := [5]int{
		strDisplayWidth(headers[0]),
		strDisplayWidth(headers[1]),
		0,
		strDisplayWidth(headers[3]),
		strDisplayWidth(headers[4]),
	}

	for i, s := range skills {
		rows[i] = rowData{
			status:   skillStatusDisplay(s),
			skill:    s.Emoji + " " + s.Name,
			desc:     s.Description,
			source:   s.Source,
			severity: "-",
		}
		if scan, ok := scanMap[s.Name]; ok {
			rows[i].severity = string(scan.MaxSeverity)
		}
		if w := strDisplayWidth(rows[i].status); w > colW[0] {
			colW[0] = w
		}
		if w := strDisplayWidth(rows[i].skill); w > colW[1] {
			colW[1] = w
		}
		if w := strDisplayWidth(rows[i].source); w > colW[3] {
			colW[3] = w
		}
		if w := strDisplayWidth(rows[i].severity); w > colW[4] {
			colW[4] = w
		}
	}

	fixedUsed := colW[0] + colW[1] + colW[3] + colW[4]
	// 5 columns → 6 borders, each cell has 2-char padding (space on each side)
	chrome := 6 + 5*2
	descW := 120 - fixedUsed - chrome
	if descW < 40 {
		descW = 40
	}
	colW[2] = descW

	widths := colW[:]

	fmt.Printf("\nSkills (%d/%d ready)\n", readyCount, len(skills))
	fmt.Println(tableHLine(widths, "┌", "┬", "┐", "─"))
	fmt.Printf("│%s│%s│%s│%s│%s│\n",
		tableCell(headers[0], colW[0]),
		tableCell(headers[1], colW[1]),
		tableCell(headers[2], colW[2]),
		tableCell(headers[3], colW[3]),
		tableCell(headers[4], colW[4]),
	)
	fmt.Println(tableHLine(widths, "├", "┼", "┤", "─"))

	for _, r := range rows {
		descLines := wrapText(r.desc, colW[2])
		if len(descLines) == 0 {
			descLines = []string{""}
		}
		fmt.Printf("│%s│%s│%s│%s│%s│\n",
			tableCell(r.status, colW[0]),
			tableCell(r.skill, colW[1]),
			tableCell(descLines[0], colW[2]),
			tableCell(r.source, colW[3]),
			tableCell(r.severity, colW[4]),
		)
		for _, line := range descLines[1:] {
			fmt.Printf("│%s│%s│%s│%s│%s│\n",
				tableCell("", colW[0]),
				tableCell("", colW[1]),
				tableCell(line, colW[2]),
				tableCell("", colW[3]),
				tableCell("", colW[4]),
			)
		}
	}

	fmt.Println(tableHLine(widths, "└", "┴", "┘", "─"))
	return nil
}

func printSkillListJSON(skills []openclawSkill, scanMap map[string]*skillScanEntry) error {
	items := make([]skillListItem, 0, len(skills))
	for _, s := range skills {
		item := skillListItem{
			Name:        s.Name,
			Description: s.Description,
			Source:      s.Source,
			Status:      skillStatus(s),
			Eligible:    s.Eligible,
			Disabled:    s.Disabled,
			Bundled:     s.Bundled,
			Homepage:    s.Homepage,
		}
		if scan, ok := scanMap[s.Name]; ok {
			item.Scan = scan
		}
		items = append(items, item)
	}
	data, err := json.MarshalIndent(items, "", "  ")
	if err != nil {
		return fmt.Errorf("skill list: json marshal: %w", err)
	}
	fmt.Println(string(data))
	return nil
}

func runSkillInstall(cmd *cobra.Command, args []string) error {
	skillName := args[0]

	pe := enforce.NewPolicyEngine(auditStore)

	// 1. Block list check
	blocked, err := pe.IsBlocked("skill", skillName)
	if err == nil && blocked {
		_ = auditLog.LogAction("install-rejected", skillName, "reason=blocked")
		return fmt.Errorf("skill %q is on the block list — run 'defenseclaw skill enable %s' to unblock", skillName, skillName)
	}

	// 2. Allow list check — skip scan
	allowed, err := pe.IsAllowed("skill", skillName)
	if err == nil && allowed {
		fmt.Printf("[install] %q is on the allow list — skipping scan\n", skillName)
		_ = auditLog.LogAction("install-allowed", skillName, "reason=allow-listed")
		return runClawHubInstall(skillName, skillInstallForce)
	}

	// 3. Install via clawhub
	fmt.Printf("[install] installing %q via clawhub...\n", skillName)
	if err := runClawHubInstall(skillName, skillInstallForce); err != nil {
		return err
	}

	// 4. Locate and scan the installed skill
	skillPath := resolveInstalledSkillPath(skillName)
	if skillPath == "" {
		fmt.Fprintf(os.Stderr, "[install] warning: could not locate installed skill for scan\n")
		return nil
	}

	fmt.Printf("[install] scanning %s...\n", skillPath)
	verdict, err := scanSkillPath(cmd.Context(), skillPath, !skillInstallJSON)
	if err != nil {
		return fmt.Errorf("install: scan error: %w", err)
	}

	if !skillInstallJSON && len(verdict.Results) > 0 {
		for _, r := range verdict.Results {
			printScanResult(r)
		}
	}

	// 5. Handle scan results via config-driven severity actions
	if verdict.Clean {
		fmt.Printf("[install] %q installed and clean\n", skillName)
		_ = auditLog.LogAction("install-clean", skillName, "verdict=clean")
		return nil
	}

	action := cfg.SkillActions.ForSeverity(string(verdict.MaxSeverity))
	detail := fmt.Sprintf("severity=%s findings=%d", verdict.MaxSeverity, verdict.TotalFindings)
	shouldQuarantine := action.File == config.FileActionQuarantine
	shouldBlock := action.Runtime == config.RuntimeBlock

	shell := sandbox.NewWithFallback(cfg.OpenShell.Binary, cfg.OpenShell.PolicyDir, cfg.PolicyDir)
	se := enforce.NewSkillEnforcer(cfg.QuarantineDir, shell)

	if shouldQuarantine {
		_, _ = se.Quarantine(skillPath)
	}
	if shouldBlock {
		_ = pe.Block("skill", skillName,
			fmt.Sprintf("post-install scan: %d findings, max=%s", verdict.TotalFindings, verdict.MaxSeverity))
		_ = se.UpdateSandboxPolicy(skillName, true)
	}

	switch {
	case shouldQuarantine && shouldBlock:
		_ = auditLog.LogAction("install-quarantined", skillName, detail)
		return fmt.Errorf("skill %q quarantined and blocked after scan (%s findings)", skillName, verdict.MaxSeverity)
	case shouldQuarantine:
		_ = auditLog.LogAction("install-quarantined", skillName, detail)
		return fmt.Errorf("skill %q quarantined after scan (%s findings)", skillName, verdict.MaxSeverity)
	case shouldBlock:
		_ = auditLog.LogAction("install-blocked", skillName, detail)
		return fmt.Errorf("skill %q blocked after scan (%s findings)", skillName, verdict.MaxSeverity)
	default:
		fmt.Printf("[install] warning: %d %s findings in %q\n", verdict.TotalFindings, verdict.MaxSeverity, skillName)
		_ = auditLog.LogAction("install-warning", skillName, detail)
		return nil
	}
}

func runClawHubInstall(skillName string, force bool) error {
	args := []string{"clawhub", "install", skillName}
	if force {
		args = append(args, "--force")
	}
	cmd := exec.Command("npx", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("clawhub install: %w", err)
	}
	return nil
}

func resolveInstalledSkillPath(skillName string) string {
	for _, c := range cfg.InstalledSkillCandidates(skillName) {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}

func disableViaGateway(skillKey string) error {
	gwClient, err := gateway.NewClient(&cfg.Gateway)
	if err != nil {
		return err
	}
	defer gwClient.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := gwClient.Connect(ctx); err != nil {
		return err
	}

	return gwClient.DisableSkill(ctx, skillKey)
}

func enableViaGateway(skillKey string) error {
	gwClient, err := gateway.NewClient(&cfg.Gateway)
	if err != nil {
		return err
	}
	defer gwClient.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := gwClient.Connect(ctx); err != nil {
		return err
	}

	return gwClient.EnableSkill(ctx, skillKey)
}
