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

// managedWindowsCallAllowed lists, by path prefix below the module root,
// the sources that build a PowerShell call operator (`& `) themselves, with
// the reason. Each writes or reads an agent's hook command, which is not text
// for a person, and has its own golden tests; an entry no literal uses fails
// the test.
var managedWindowsCallAllowed = map[string]string{
	"internal/gateway/connector/":                   "the connector hook-command builders and their ownership parsers write and read agent configs",
	"internal/legacyconnector/":                     "the retired desktop connector's hook-command builder and teardown matcher",
	"internal/cli/windows_managed_hook_settings.go": "reads registered hook commands: strips the call operator before the ownership check",
	"internal/gateway/agent_not_installed.go":       "reads a cmd.exe shim prefix, where & is cmd's command separator",
}

// managedWindowsQuoteAllowed lists the files that double or read a
// PowerShell single quote by hand, with the reason. Each re-renders or reads
// a command line for the gateway's own matching, and is not a command that
// runs; every literal that runs comes from managed.PowerShellLiteral. An
// entry no call uses fails the test.
var managedWindowsQuoteAllowed = map[string]string{
	"internal/gateway/windows_command.go":         "quoteWindowsArg re-renders a parsed argv for policy matching",
	"internal/actionfacts/simple_commands.go":     "re-renders a command with its resolved variables for policy matching",
	"internal/gateway/trusted_action_dispatch.go": "the gateway's command-line reader for trusted actions",
	"internal/gateway/powershell_state_write.go":  "re-renders a ${provider:path} variable as a literal for the state-write matcher",
}

var (
	// managedWindowsCall is PowerShell's call operator before a quoted path,
	// or at the end of a literal that a path is appended to: a command built
	// by hand. && and >& are POSIX shell syntax.
	managedWindowsCall = regexp.MustCompile(`(^|[^&>])& (['"]|$)`)
	// managedWindowsVerbOnly is an instruction to run a DefenseClaw
	// subcommand that names no executable ("run `enterprise windows ensure
	// ...`", "with enterprise secret set"): a managed Windows computer has no
	// DefenseClaw command on PATH, so it does not run as typed. A reference
	// to the command ("`enterprise windows status` reports ...") is not an
	// instruction and stays allowed.
	// "with", "by" and "or" count only before a backticked command: "--purge
	// is valid only with enterprise windows uninstall" describes a flag.
	managedWindowsVerbOnly = regexp.MustCompile("(?i)(\\b(?:re)?run:?\\s+[`'\"]?|\\b(?:with|by|or)\\s+`)enterprise\\s+[a-z]+\\s+[a-z]")
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
	// Setup's /switches are Windows-only too.
	managedWindowsContext = regexp.MustCompile(`(?i)elevated|powershell|administrator prompt|\bSetup /[a-z]|DefenseClawSetup`)
)

// cowork-1-0-8 GAP-0076, as a source check: the behavioural tables list
// their producers by hand, so a new answer, or one in another package, named
// a managed Windows command that does not run as typed. Every string literal
// of the module's code under internal/ and cmd/ is checked, whatever its
// build tags:
//   - a `& ...` PowerShell call is built only here (WindowsCommandLine),
//     except by the hook-command builders (managedWindowsCallAllowed);
//   - a hard-coded install path names C:\Program Files instead of
//     %ProgramFiles%, so it is built only here too;
//   - a bare defenseclaw.exe or defenseclaw-gateway.exe with a subcommand,
//     and a bare `defenseclaw enterprise windows ...`, are not on PATH;
//   - a windows-only file, or a sentence that names an elevated prompt,
//     PowerShell or an Administrator prompt, names no bare `defenseclaw ...`
//     command, except to a per-user install
//     (managedWindowsBareCommandAllowed), and no instruction to run a
//     subcommand without its executable (managedWindowsVerbOnly);
//   - a PowerShell single quote is doubled, or a doubled one read, only by
//     managed.PowerShellLiteral and PowerShellLiteralValue, which handle the
//     typographic quotes too (g072 review 2 S3; managedWindowsQuoteAllowed).
//
// A sentence built with + is checked whole as well, with %s for each part
// that is not a literal: the Windows words and the command were often in
// different literals of one sentence.
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
			chained := map[*ast.BinaryExpr]bool{}
			ast.Inspect(file, func(node ast.Node) bool {
				if call, ok := node.(*ast.CallExpr); ok {
					if problem := powerShellQuoteByHand(call); problem != "" {
						if _, allowed := managedWindowsQuoteAllowed[rel]; allowed {
							used["quote\x00"+rel] = true
						} else {
							t.Errorf("%s: %s", fset.Position(call.Pos()), problem)
						}
					}
					return true
				}
				if sum, ok := node.(*ast.BinaryExpr); ok && sum.Op == token.ADD && !chained[sum] {
					joined, parts := managedWindowsSentence(sum, chained)
					for _, problem := range managedWindowsSentenceProblems(rel, joined, parts, windowsOnly) {
						t.Errorf("%s: %s: %q", fset.Position(sum.Pos()), problem, joined)
					}
					return true
				}
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
	for prefix := range managedWindowsCallAllowed {
		if !used["call\x00"+prefix] {
			t.Errorf("managedWindowsCallAllowed lists %q, where no literal builds a PowerShell call", prefix)
		}
	}
	for rel := range managedWindowsQuoteAllowed {
		if !used["quote\x00"+rel] {
			t.Errorf("managedWindowsQuoteAllowed lists %q, which quotes nothing by hand", rel)
		}
	}
}

// powerShellQuoteByHand is a problem when call is strings.ReplaceAll or
// strings.Replace turning ' into ” (a PowerShell literal quoted by hand) or
// ” into ' (one read by hand): either misses the typographic quotes
// PowerShell reads as single quotes.
func powerShellQuoteByHand(call *ast.CallExpr) string {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || len(call.Args) < 3 || sel.Sel.Name != "ReplaceAll" && sel.Sel.Name != "Replace" {
		return ""
	}
	if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "strings" {
		return ""
	}
	literal := func(expr ast.Expr) string {
		lit, ok := expr.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return "\x00"
		}
		value, err := strconv.Unquote(lit.Value)
		if err != nil {
			return "\x00"
		}
		return value
	}
	switch old, replacement := literal(call.Args[1]), literal(call.Args[2]); {
	case old == "'" && replacement == "''":
		return "a PowerShell literal quoted by hand: use managed.PowerShellLiteral or PowerShellLiteralBody (typographic quotes too)"
	case old == "''" && replacement == "'":
		return "a PowerShell literal read by hand: use managed.PowerShellLiteralValue (typographic quotes too)"
	}
	return ""
}

func TestPowerShellQuoteByHand(t *testing.T) {
	for source, want := range map[string]bool{
		`strings.ReplaceAll(p, "'", "''")`:             true,
		"strings.ReplaceAll(p, `'`, `''`)":             true,
		`strings.Replace(p, "'", "''", -1)`:            true,
		`strings.ReplaceAll(p[1:len(p)-1], "''", "'")`: true,
		"strings.ReplaceAll(p, \"'\", `'\\''`)":        false,
		`strings.ReplaceAll(p, "/", "\\")`:             false,
		`bytes.ReplaceAll(p, "'", "''")`:               false,
		`strings.ReplaceAll(p, quote, "''")`:           false,
		`managed.PowerShellLiteral(p)`:                 false,
	} {
		expr, err := parser.ParseExpr(source)
		if err != nil {
			t.Fatalf("%s: %v", source, err)
		}
		call, ok := expr.(*ast.CallExpr)
		if !ok {
			t.Fatalf("%s: not a call", source)
		}
		if got := powerShellQuoteByHand(call) != ""; got != want {
			t.Errorf("powerShellQuoteByHand(%s) = %t, want %t", source, got, want)
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
	} else if !renderer && managedWindowsCall.MatchString(value) {
		if prefix, ok := managedWindowsCallPrefix(rel); ok {
			used["call\x00"+prefix] = true
		} else {
			problems = append(problems, "a PowerShell call built by hand: use managed.WindowsCommandLine, and say PowerShell")
		}
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
	if managedWindowsVerbOnly.MatchString(value) {
		problems = append(problems, "an instruction to run a subcommand without its executable: use managed.WindowsAdminCommand (windowsEnterpriseAdminCommand in internal/cli)")
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

// managedWindowsSentence is the + chain sum as one string, with %s for each
// operand that is not a string literal, and the literals it joined. It marks
// the chain's inner sums in chained, so a chain is joined once.
func managedWindowsSentence(sum *ast.BinaryExpr, chained map[*ast.BinaryExpr]bool) (string, []string) {
	var joined strings.Builder
	var parts []string
	var walk func(ast.Expr)
	walk = func(expr ast.Expr) {
		switch e := expr.(type) {
		case *ast.BinaryExpr:
			if e.Op == token.ADD {
				chained[e] = true
				walk(e.X)
				walk(e.Y)
				return
			}
		case *ast.BasicLit:
			if e.Kind == token.STRING {
				if value, err := strconv.Unquote(e.Value); err == nil {
					joined.WriteString(value)
					parts = append(parts, value)
					return
				}
			}
		}
		joined.WriteString("%s")
	}
	walk(sum)
	return joined.String(), parts
}

// managedWindowsSentenceProblems lists the problems of a joined sentence
// (managedWindowsSentence) that none of its literals has alone.
func managedWindowsSentenceProblems(rel, joined string, parts []string, windowsOnly bool) []string {
	if len(parts) < 2 {
		return nil
	}
	alone := map[string]bool{}
	for _, part := range parts {
		for _, problem := range managedWindowsLiteralProblems(rel, part, windowsOnly, map[string]bool{}) {
			alone[problem] = true
		}
	}
	var problems []string
	for _, problem := range managedWindowsLiteralProblems(rel, joined, windowsOnly, map[string]bool{}) {
		if !alone[problem] {
			problems = append(problems, "in the joined sentence, "+problem)
		}
	}
	return problems
}

// managedWindowsCallPrefix is the managedWindowsCallAllowed entry that
// covers file rel.
func managedWindowsCallPrefix(rel string) (string, bool) {
	for prefix := range managedWindowsCallAllowed {
		if rel == prefix || strings.HasSuffix(prefix, "/") && strings.HasPrefix(rel, prefix) {
			return prefix, true
		}
	}
	return "", false
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

// The joined-sentence check (g072 review 2 M3): a + chain is checked whole,
// with %s for each part that is not a literal, and reports only what no
// literal of it has alone.
func TestManagedWindowsSentenceProblems(t *testing.T) {
	for _, row := range []struct {
		name, expr  string
		windowsOnly bool
		want        int
	}{
		{"instruction split from its command", "\"run \" + \"`enterprise windows ensure`\"", true, 1},
		{"Windows words in another literal", "\"run Setup /repair X=1, \" + \"or `enterprise windows repair --profile standalone`)\"", false, 1},
		{"the renderer's command", "\"run \" + windowsEnterpriseAdminCommand(\"ensure\") + \" from an elevated PowerShell prompt\"", true, 0},
		{"found in one literal already", "\"run `enterprise windows ensure`\" + \" now\"", true, 0},
		{"bare command after Windows words", "\"from an elevated PowerShell prompt, \" + \"run `defenseclaw doctor`\"", false, 1},
		{"one literal", "\"run \" + x", true, 0},
		{"portable prose", "\"run \" + \"`enterprise secret set`\"", false, 0},
	} {
		expr, err := parser.ParseExpr(row.expr)
		if err != nil {
			t.Fatalf("%s: %v", row.name, err)
		}
		sum, ok := expr.(*ast.BinaryExpr)
		if !ok {
			t.Fatalf("%s: not a sum", row.name)
		}
		joined, parts := managedWindowsSentence(sum, map[*ast.BinaryExpr]bool{})
		if got := len(managedWindowsSentenceProblems("internal/cli/x.go", joined, parts, row.windowsOnly)); got != row.want {
			t.Errorf("%s: %d problems in %q, want %d", row.name, got, joined, row.want)
		}
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
		{"hard-coded path", "internal/gateway/x.go", `& 'C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw.exe' status`, false, 2},
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
		// g072 review 2 M3: a run instruction without the executable.
		{"verb-only run, backticked", "internal/cli/x_windows.go", "run `enterprise windows ensure --profile standalone` first", true, 1},
		{"verb-only run, unquoted", "internal/cli/x_windows.go", "; run enterprise windows repair, or DefenseClawSetup-Enterprise-Standalone-x64.exe /repair", true, 1},
		{"verb-only run, capitalised", "internal/cli/x_windows.go", "Run enterprise windows repair to unpack it", true, 1},
		{"verb-only rerun", "internal/cli/x_windows.go", "rerun 'enterprise windows ensure'", true, 1},
		{"verb-only Run:", "internal/cli/x_windows.go", "Run: enterprise acp setup --client zed", true, 1},
		{"verb-only with", "internal/cli/x_windows.go", "store its key with `enterprise secret set`", true, 1},
		{"verb-only by", "internal/cli/x_windows.go", "its key stored by `enterprise secret set`", true, 1},
		{"verb-only or", "internal/cli/x.go", "run Setup /repair ATTESTCLAUDEEFFECTIVEPOLICY=1, or `enterprise windows repair --profile standalone`", false, 1},
		{"a flag's rule is not an instruction", "internal/cli/x_windows.go", "--purge is valid only with enterprise windows uninstall", true, 0},
		{"verb-only, two spaces", "internal/cli/x_windows.go", "run  enterprise  windows  ensure", true, 1},
		{"verb-only run in elevated text of a portable file", "internal/cli/x.go",
			"run `enterprise windows repair --profile standalone --json` from an elevated administrator or SYSTEM session", false, 1},
		{"verb-only in a portable file without Windows words", "internal/config/x.go", "store the key with `enterprise secret set --name <name>`", false, 0},
		{"a reference to the command", "internal/cli/x_windows.go", "`enterprise windows status` reports the deployment", true, 0},
		{"the renderer's command", "internal/cli/x_windows.go", "run %s from an elevated PowerShell prompt", true, 0},
		// g072 review 2 M4: a call operator built outside the renderer.
		{"call operator before a single-quoted path", "internal/cli/enterprise_acp.go", "& '", false, 1},
		{"call operator alone", "internal/cli/enterprise_acp_setup.go", "& ", false, 1},
		{"call operator after a pipe", "internal/cli/x.go", "$payload | & ", false, 1},
		{"call operator before a double-quoted path", "cmd/defenseclaw-acp/main.go", `& "`, false, 1},
		{"call operator in a sentence", "internal/cli/x.go", "as that user, run: & 'C:\\x\\defenseclaw.exe' enterprise acp setup", false, 1},
		{"connector hook-command builder", "internal/gateway/connector/helpers.go", "& ", false, 0},
		{"connector hook-command builder, subpackage", "internal/gateway/connector/hookexec/process_start_windows.go", "$payload | & ", true, 0},
		{"legacy connector hook-command builder", "internal/legacyconnector/legacyconnector.go", "& ", false, 0},
		{"allowed file name is not a prefix", "internal/cli/windows_managed_hook_settings_extra.go", "& ", false, 1},
		{"POSIX and", "internal/firewall/iptables/iptables.go", "sudo iptables -F OUTPUT && ", false, 0},
		{"POSIX redirect", "internal/actionfacts/x.go", " -i >& ", false, 0},
		{"the renderer builds the call", "internal/managed/windows_admin_cli.go", "& ", false, 0},
	} {
		if got := len(managedWindowsLiteralProblems(row.rel, row.value, row.windowsOnly, map[string]bool{})); got != row.want {
			t.Errorf("%s: %d problems, want %d", row.name, got, row.want)
		}
	}
}
