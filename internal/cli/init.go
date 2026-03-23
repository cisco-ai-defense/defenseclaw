package cli

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

var skipInstall bool

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize DefenseClaw environment",
	Long:  "Creates ~/.defenseclaw/, default config, SQLite database, and installs scanner dependencies.",
	RunE:  runInit,
}

func init() {
	initCmd.Flags().BoolVar(&skipInstall, "skip-install", false, "Skip automatic scanner dependency installation")
	rootCmd.AddCommand(initCmd)
}

func runInit(_ *cobra.Command, _ []string) error {
	env := config.DetectEnvironment()
	fmt.Printf("  Environment: %s\n", env)

	defaults := config.DefaultConfig()
	fmt.Printf("  Claw mode:   %s\n", defaults.Claw.Mode)
	fmt.Printf("  Claw home:   %s\n", defaults.ClawHomeDir())

	dirs := []string{defaults.DataDir, defaults.QuarantineDir, defaults.PluginDir, defaults.PolicyDir}
	// Ensure claw-mode skill directories exist
	for _, d := range defaults.SkillDirs() {
		dirs = append(dirs, d)
	}
	for _, d := range defaults.MCPDirs() {
		dirs = append(dirs, d)
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("init: create %s: %w", dir, err)
		}
	}
	fmt.Println("  Directories: created")

	if err := defaults.Save(); err != nil {
		return fmt.Errorf("init: write config: %w", err)
	}
	fmt.Printf("  Config: %s\n", config.ConfigPath())

	store, err := audit.NewStore(defaults.AuditDB)
	if err != nil {
		return fmt.Errorf("init: create audit db: %w", err)
	}
	defer store.Close()

	if err := store.Init(); err != nil {
		return fmt.Errorf("init: initialize schema: %w", err)
	}
	fmt.Printf("  Audit DB: %s\n", defaults.AuditDB)

	logger := audit.NewLogger(store)
	_ = logger.LogAction("init", defaults.DataDir, fmt.Sprintf("environment=%s", env))

	fmt.Println()
	installScanners(defaults, logger)

	fmt.Println()
	if _, err := exec.LookPath(defaults.OpenShell.Binary); err != nil {
		switch env {
		case config.EnvMacOS:
			fmt.Println("  OpenShell: not available on macOS (sandbox enforcement will be skipped)")
		default:
			fmt.Println("  OpenShell: not found (sandbox enforcement will not be active)")
		}
	} else {
		fmt.Println("  OpenShell: found")
	}

	fmt.Println("\nDefenseClaw initialized. Run 'defenseclaw scan' to start scanning.")

	fmt.Println()
	fmt.Println("  Egress firewall (optional):")
	fmt.Printf("    defenseclaw firewall init          # generate deny-by-default config\n")
	fmt.Printf("    defenseclaw firewall init --observe # auto-detect active connections first\n")
	return nil
}

func installScanners(defaults *config.Config, logger *audit.Logger) {
	if skipInstall {
		fmt.Println("  Scanners: skipped (--skip-install)")
		return
	}

	ensureUV()

	type dep struct {
		name string
		bin  string
		pkg  string
	}

	deps := []dep{
		{"skill-scanner", defaults.Scanners.SkillScanner.Binary, "cisco-ai-skill-scanner"},
		{"mcp-scanner", defaults.Scanners.MCPScanner, "cisco-ai-mcp-scanner"},
		{"cisco-aibom", defaults.Scanners.AIBOM, "cisco-aibom"},
	}

	for _, d := range deps {
		if _, err := exec.LookPath(d.bin); err == nil {
			fmt.Printf("  %s: already installed\n", d.name)
			continue
		}

		fmt.Printf("  %s: installing...", d.name)

		if installWithUV(d.pkg) {
			if _, err := exec.LookPath(d.bin); err == nil {
				fmt.Printf(" done\n")
			} else {
				fmt.Printf(" installed (run 'hash -r' or open a new shell if binary not found)\n")
			}
			_ = logger.LogAction("install-scanner", d.name, fmt.Sprintf("package=%s", d.pkg))
		} else {
			fmt.Printf(" failed\n")
			fmt.Printf("    install manually: uv tool install %s\n", d.pkg)
		}
	}
}

func ensureUV() {
	if _, err := exec.LookPath("uv"); err == nil {
		return
	}

	fmt.Printf("  uv: not found, installing...")

	cmd := exec.Command("sh", "-c", "curl -LsSf https://astral.sh/uv/install.sh | sh")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		fmt.Printf(" failed\n")
		fmt.Printf("    install uv manually: curl -LsSf https://astral.sh/uv/install.sh | sh\n")
		fmt.Printf("    then re-run: defenseclaw init\n")
		return
	}

	addUVToPath()
	fmt.Printf(" done\n")
}

func addUVToPath() {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	uvPaths := []string{
		home + "/.local/bin",
		home + "/.cargo/bin",
	}
	currentPath := os.Getenv("PATH")
	for _, p := range uvPaths {
		if !strings.Contains(currentPath, p) {
			os.Setenv("PATH", p+":"+currentPath)
			currentPath = p + ":" + currentPath
		}
	}
}

func installWithUV(pkg string) bool {
	uvBin, err := exec.LookPath("uv")
	if err != nil {
		return false
	}

	cmd := exec.Command(uvBin, "tool", "install", "--python", "3.13", pkg)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		trimmed := strings.TrimSpace(stderr.String())
		if strings.Contains(trimmed, "already installed") {
			return true
		}
		if trimmed != "" {
			fmt.Printf("\n    %s", firstLine(trimmed))
		}
		return false
	}
	return true
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
