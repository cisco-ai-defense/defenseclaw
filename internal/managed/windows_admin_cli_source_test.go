// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// managedWindowsBareCommandAllowed lists the bare `defenseclaw` commands that
// Windows text may name, by file (below the module root) and the exact
// words. Each is said to a per-user install, whose launcher is on that user's
// PATH; a managed computer has no such command. A new entry needs that
// reason, and an entry no literal uses fails the test.
var managedWindowsBareCommandAllowed = map[string][]string{
	// A user's own sandbox view, on Linux and macOS; Windows runs no
	// sandboxes.
	"internal/cli/enterprise_sandbox_views.go": {"defenseclaw sandbox policy explain"},
	// The other account's per-user gateway holds the managed port: that
	// user removes the per-user install.
	"internal/cli/windows_enterprise_port_holder.go": {"`defenseclaw uninstall --all --binaries --yes`"},
	// Per-user Codex setup refuses a linked CODEX_HOME.
	"internal/gateway/connector/codex_config_dir_windows.go": {"run: defenseclaw setup codex"},
	// The per-user stable hook launcher (LocalAppData\DefenseClaw\HookRuntime);
	// managed hooks run from the machine hook runtime instead.
	"internal/hookruntime/unavailable_windows.go": {"Run `defenseclaw doctor`"},
	// The per-user Setup wizard's last page.
	"cmd/defenseclaw-setup/wizard_windows.go": {"Run defenseclaw to open the TUI", "run defenseclaw init"},
}

var (
	// managedWindowsBareAnywhere is a bare executable with a subcommand, or
	// a bare Windows-only subcommand: neither is on PATH on any computer.
	managedWindowsBareAnywhere = regexp.MustCompile(`(^|[^\\/\w.-])defenseclaw(-gateway)?(\.exe)? enterprise windows|(^|[^\\/\w.-])defenseclaw(-gateway)?\.exe [a-z-]`)
	// managedWindowsBareCommand is any bare DefenseClaw command.
	managedWindowsBareCommand = regexp.MustCompile(`(^|[^\\/\w.-])defenseclaw(-gateway)?(\.exe)? [a-z-]`)
	// managedWindowsContext is a sentence for the administrator of a
	// Windows computer, in a file that builds for every OS: the words
	// managed Windows answers use for where a command runs. "Windows" alone
	// is not one: per-user help names Windows paths beside the per-user
	// commands, which are on PATH.
	managedWindowsContext = regexp.MustCompile(`(?i)elevated|powershell|administrator prompt`)
)

// cowork-1-0-8 GAP-0076, as a source check: the behavioural tables list
// their producers by hand, so a new answer, or one in another package, named
// a managed Windows command that does not run as typed. Every string literal
// of the module's code under internal/ and cmd/ is checked, whatever its
// build tags:
//   - a `& ...` PowerShell call is built only here (WindowsCommandLine);
//   - a hard-coded install path names C:\Program Files instead of
//     %ProgramFiles%, so it is built only here too;
//   - a bare defenseclaw.exe or defenseclaw-gateway.exe with a subcommand,
//     and a bare `defenseclaw enterprise windows ...`, are not on PATH;
//   - a windows-only file, or a sentence that names an elevated prompt,
//     PowerShell or an Administrator prompt, names no bare `defenseclaw ...`
//     command, except to a per-user install
//     (managedWindowsBareCommandAllowed).
func TestManagedWindowsCommandsComeFromTheRenderer(t *testing.T) {
	root := moduleRoot(t)
	fset := token.NewFileSet()
	files := 0
	used := map[string]bool{}
	for _, dir := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				if entry.Name() == "testdata" || strings.HasPrefix(entry.Name(), ".") {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			rel = filepath.ToSlash(rel)
			file, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				return err
			}
			files++
			windowsOnly := windowsOnlySource(t, path)
			ast.Inspect(file, func(node ast.Node) bool {
				lit, ok := node.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				value, err := strconv.Unquote(lit.Value)
				if err != nil {
					t.Errorf("%s: %v", fset.Position(lit.Pos()), err)
					return true
				}
				for _, problem := range managedWindowsLiteralProblems(rel, value, windowsOnly, used) {
					t.Errorf("%s: %s: %q", fset.Position(lit.Pos()), problem, value)
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if files < 500 {
		t.Fatalf("checked %d files under %s; the walk missed the sources", files, root)
	}
	for rel, allowed := range managedWindowsBareCommandAllowed {
		for _, words := range allowed {
			if !used[rel+"\x00"+words] {
				t.Errorf("managedWindowsBareCommandAllowed[%q] lists %q, which no literal of that file names", rel, words)
			}
		}
	}
}

// managedWindowsLiteralProblems lists what is wrong with one string literal
// of file rel (see TestManagedWindowsCommandsComeFromTheRenderer), and marks
// in used the allowed words it names.
func managedWindowsLiteralProblems(rel, value string, windowsOnly bool, used map[string]bool) []string {
	var problems []string
	renderer := strings.HasPrefix(rel, "internal/managed/")
	if !renderer && strings.Contains(value, "`& ") {
		problems = append(problems, "a PowerShell call built by hand: use managed.WindowsAdminCommand or WindowsGatewayCommand")
	}
	if !renderer && strings.Contains(value, `Cisco\DefenseClaw\bin\defenseclaw`) {
		problems = append(problems, "a hard-coded install path: use managed.WindowsAdminCommand or WindowsStandaloneAdminCLI")
	}
	if managedWindowsBareAnywhere.MatchString(value) {
		problems = append(problems, "names a bare DefenseClaw executable or Windows-only command, which is not on PATH")
		return problems
	}
	if !windowsOnly && !managedWindowsContext.MatchString(value) {
		return problems
	}
	rest := value
	for _, words := range managedWindowsBareCommandAllowed[rel] {
		if strings.Contains(rest, words) {
			used[rel+"\x00"+words] = true
			rest = strings.ReplaceAll(rest, words, "")
		}
	}
	if managedWindowsBareCommand.MatchString(rest) {
		problems = append(problems, "names a bare `defenseclaw` command in Windows text, which is not on PATH on a managed computer")
	}
	return problems
}

// windowsOnlySource reports whether path builds for windows and for neither
// linux nor darwin, by its file name and its build constraints.
func windowsOnlySource(t *testing.T, path string) bool {
	t.Helper()
	builds := map[string]bool{}
	for _, goos := range []string{"windows", "linux", "darwin"} {
		ctx := build.Default
		ctx.GOOS, ctx.GOARCH, ctx.CgoEnabled = goos, "amd64", true
		match, err := ctx.MatchFile(filepath.Dir(path), filepath.Base(path))
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		builds[goos] = match
	}
	return builds["windows"] && !builds["linux"] && !builds["darwin"]
}

// moduleRoot is the directory of the go.mod above the test's directory.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the test directory")
		}
		dir = parent
	}
}

// The source check itself: each rule fires, and the renderer, a per-user
// command of an allowed file and plain prose do not.
func TestManagedWindowsLiteralProblems(t *testing.T) {
	for _, row := range []struct {
		name, rel, value string
		windowsOnly      bool
		want             int
	}{
		{"hand-built call", "internal/cli/x.go", "run `& '", false, 1},
		{"hand-built call, quoted path", "internal/gateway/api.go", "then `& ", false, 1},
		{"the renderer", "internal/managed/windows_admin_cli.go", "`& '", false, 0},
		{"hard-coded path", "internal/gateway/x.go", `& 'C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw.exe' status`, false, 1},
		{"bare exe", "internal/cli/x.go", "with `defenseclaw.exe enterprise secret set`", false, 1},
		{"bare exe, unquoted", "internal/cli/x.go", "run defenseclaw.exe enterprise windows ensure", false, 1},
		{"bare gateway exe", "cmd/x/main.go", "with `defenseclaw-gateway.exe status`", false, 1},
		{"bare windows subcommand", "internal/enterprisebundle/driver.go", "run `defenseclaw enterprise windows ensure`", false, 1},
		{"bare windows subcommand, single quotes", "internal/enterprisepolicy/x.go", "run 'defenseclaw enterprise windows repair'", false, 1},
		{"bare gateway windows subcommand", "internal/cli/x.go", "defenseclaw-gateway enterprise windows status", false, 1},
		{"full path is not bare", "internal/cli/x.go", `C:\x\defenseclaw.exe enterprise windows status`, false, 0},
		{"bare command in a windows-only file", "internal/cli/x_windows.go", "run `defenseclaw doctor`", true, 1},
		{"bare command, unquoted, windows-only file", "internal/cli/x_windows.go", "run defenseclaw-gateway provenance show", true, 1},
		{"bare command in Windows text of a portable file", "internal/enterprisepolicy/live.go", "from an elevated Administrator prompt with `defenseclaw audit export`", false, 1},
		{"bare command in a portable file", "internal/cli/x.go", "run `defenseclaw doctor`", false, 0},
		{"per-user help naming a Windows path", "internal/cli/x.go", "after defenseclaw rollback, previous\\data\\audit.db on Windows", false, 0},
		{"bare command beside PowerShell", "internal/cli/x.go", "in PowerShell run defenseclaw status", false, 1},
		{"per-user uninstall, allowed file", "internal/cli/windows_enterprise_port_holder.go", "have that user run `defenseclaw uninstall --all --binaries --yes`, which stops it", true, 0},
		{"allowed file, a second bare command", "internal/cli/windows_enterprise_port_holder.go", "run `defenseclaw uninstall --all --binaries --yes`, then `defenseclaw doctor`", true, 1},
		{"per-user uninstall, other file", "internal/cli/x_windows.go", "run `defenseclaw uninstall --all --binaries --yes`", true, 1},
		{"prose", "internal/cli/x_windows.go", "DefenseClaw is managed by your organization", true, 0},
	} {
		if got := len(managedWindowsLiteralProblems(row.rel, row.value, row.windowsOnly, map[string]bool{})); got != row.want {
			t.Errorf("%s: %d problems, want %d", row.name, got, row.want)
		}
	}
}
