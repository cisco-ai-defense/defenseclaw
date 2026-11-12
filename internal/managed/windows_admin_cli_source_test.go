// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"fmt"
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
}

// managedWindowsSetupAllowance lets one source name a Setup action in plain
// text (managedWindowsBareSetup, managedWindowsSetupPhrase). path is a file
// below the module root, or a folder ending in "/". With words empty it covers
// every literal of that path; with words set it covers a literal that holds
// those words (they are taken out of the literal before it is checked again),
// or, with exact set, only a literal that is those words. The reason says why
// no administrator is sent to a Setup that is not installed.
type managedWindowsSetupAllowance struct {
	path, words, reason string
	exact               bool
}

// managedWindowsBareSetupAllowed lists the sources that may name a Setup
// action ("Setup /ensure", the file name with a switch, "run Setup again") as
// plain text, with the reason. Setup is not installed on a managed computer,
// so a hint that sends an administrator to it runs it with
// managed.WindowsSetupCommand and says where it comes from
// (managed.WindowsSetupSource); the installed CLI's own command
// (managed.WindowsAdminCommand) is named instead where it does the same work;
// a hint that only asks for the failed run again says "the same command"
// (cowork-1-0-8 GAP-0095). An entry no literal uses fails the test.
var managedWindowsBareSetupAllowed = []managedWindowsSetupAllowance{
	{path: "cmd/defenseclaw-enterprise-setup/", reason: "Setup's own usage and refusals: the administrator who reads them is running that Setup"},
	{path: "internal/cli/enterprise_bundle_apply_windows.go", words: "Windows takes bundles from Setup /ensure BUNDLE= or --bundle",
		reason: "names the Setup switch that is the other way to deliver a bundle, beside --bundle; whoever delivers one holds Setup"},
	{path: "internal/cli/windows_enterprise_bundle.go", words: "with Setup /ensure",
		reason: "a refusal of bundle arguments: says which Setup switch takes BUNDLE=, TRUSTANCHORS= and REFUSECAPABILITYLOSS=, and names the installed CLI's ensure beside it; the MDM that delivers a bundle holds Setup"},
	{path: "internal/cli/enterprise_hooks_platform_windows.go", words: "Setup /repair or /ensure prunes them now",
		reason: "states what prunes a deleted account's rows, for the standalone profile and Secure Client alike (an aside, not the instruction); Secure Client text is unchanged"},
	{path: "internal/enterprisehooks/install_windows.go", words: "Setup /repair or /ensure prunes its rows",
		reason: "states what prunes a deleted account's rows, for the standalone profile and Secure Client alike (an aside, not the instruction); Secure Client text is unchanged"},
	{path: "internal/enterprisehooks/managed_policy_drift_windows.go", words: "Setup /ensure", exact: true,
		reason: "the Secure Client branch of the ownership-record hint keeps the text it always had; the standalone branch renders Setup and its source"},
	{path: "internal/cli/windows_managed_hooks_lifecycle.go", words: "Setup /repair", exact: true,
		reason: "windowsManagedHooksRepairStep on Secure Client keeps the text it always had; the standalone profile names the installed CLI"},
	{path: "internal/cli/windows_managed_hooks_lifecycle.go", words: "Setup /ensure", exact: true,
		reason: "windowsManagedHooksEnsureStep on Secure Client keeps the text it always had; the standalone profile names the installed CLI"},
	{path: "internal/cli/windows_enterprise_prereq.go", words: "run Setup from an elevated administrator or LocalSystem context (the deployment system's machine context)", exact: true,
		reason: "the elevation remedy of a Secure Client run keeps its text; a standalone run asks for the same command (input.Standalone)"},
	{path: "internal/cli/windows_enterprise_prereq.go", exact: true,
		words:  "allow the DefenseClaw installer script and module in the antimalware or endpoint protection product (exclusion by signer or path), then run Setup again",
		reason: "the antimalware script-block remedy is classified for a Secure Client run only (windowsEnterpriseRunPowerShell, !standalone) and keeps its text"},
	{path: "internal/cli/windows_enterprise_prereq.go", exact: true,
		words:  "set Turn on Script Execution (Group Policy, machine and user) to Not Configured or to allow the installer, or use the signed payload where AllSigned is enforced, then run Setup again",
		reason: "the execution-policy script-block remedy is classified for a Secure Client run only (windowsEnterpriseRunPowerShell, !standalone) and keeps its text"},
	{path: "internal/cli/windows_enterprise_service.go", words: "run Setup again", exact: true,
		reason: "windowsEnterpriseStagingRetryStep on Secure Client keeps the text it always had; a standalone run asks for the same command"},
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
	"internal/gateway/windows_command.go":           "quoteWindowsArg's set of characters that need quoting (&'\") re-renders a parsed argv for policy matching",
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
	// managedWindowsCall is PowerShell's call operator before a quoted path
	// (an apostrophe, a double quote or a typographic quote, after spaces or
	// a tab, or after none where a word starts), before a fmt verb, or at the
	// end of a literal that a path is appended to: a command built by hand
	// (g072 review 3 M1). && and >& are POSIX shell syntax, &' inside a word
	// is a character set ("!$&'()"), &%s; an XML entity, and a lone "&" (a
	// token a reader compares with) is not a command; joined into one it is
	// (managedWindowsAmpersandWord).
	// A word starts after a blank, | ; { ( and, since g072 review 4 M3, a
	// backtick (the repo's markdown for a command), a double quote, = : and
	// a comma. A no-break space is a blank to PowerShell, and an indexed or
	// starred verb (%[1]s, %*s) is a verb. Documented limits, which no source
	// uses: &%s with no space (an XML entity's twin), a strings.Builder
	// WriteString("&") then WriteByte(' '), string('&'), and
	// strings.ReplaceAll(p, "'", strings.Repeat("'", 2)).
	managedWindowsCall = regexp.MustCompile(`(^|[\s|;{(\x60"=:,])&['"\x{2018}-\x{201B}]|(^|[^&>])&[ \t\x{00A0}]+(?:['"\x{2018}-\x{201B}]|%(?:\[\d+\])?[-+# 0-9.*]*[sqvc]|$)`)
	// managedWindowsVerbOnly is an instruction to run a DefenseClaw
	// subcommand that names no executable ("run `enterprise windows ensure
	// ...`", "with enterprise secret set"): a managed Windows computer has no
	// DefenseClaw command on PATH, so it does not run as typed. A reference
	// to the command ("`enterprise windows status` reports ...") is not an
	// instruction and stays allowed.
	// "with", "by" and "or" count only before a backticked command: "--purge
	// is valid only with enterprise windows uninstall" describes a flag.
	// A fmt verb counts as a word: "run `enterprise windows %s`" (g072
	// review 3 M1).
	managedWindowsVerbOnly = regexp.MustCompile("(?i)(\\b(?:(?:re)?run:?|use)\\s+[`'\"]?|\\b(?:with|by|or)\\s+`)enterprise\\s+(?:[a-z]+|%[sqv])\\s+(?:[a-z]|%[sqv])")
	// managedWindowsBareAnywhere is a bare executable with a subcommand, or
	// a bare Windows-only subcommand: neither is on PATH on any computer.
	// A closing quote or backtick may sit between the name and its first
	// argument ("`defenseclaw.exe` status"), and a fmt verb counts as a word.
	managedWindowsBareAnywhere = regexp.MustCompile("(^|[^\\\\/\\w.-])defenseclaw(-gateway)?(\\.exe)?[`'\"]?\\s+enterprise\\s+windows|(^|[^\\\\/\\w.-])defenseclaw(-gateway)?\\.exe[`'\"]?\\s+(?:[a-z-]|%[sqv])")
	// managedWindowsBareCommand is any bare DefenseClaw command.
	managedWindowsBareCommand = regexp.MustCompile("(^|[^\\\\/\\w.-])defenseclaw(-gateway)?(\\.exe)?[`'\"]?\\s+(?:[a-z-]|%[sqv])")
	// managedWindowsContext is a sentence for the administrator of a
	// Windows computer, in a file that builds for every OS: the words
	// managed Windows answers use for where a command runs. "Windows" alone
	// is not one: per-user help names Windows paths beside the per-user
	// commands, which are on PATH.
	// Setup's /switches are Windows-only too.
	// managedWindowsBareSetup is Setup named as a command in plain text: the
	// file name with a switch, or "Setup /repair". It is not a command that
	// runs on a managed computer, where Setup is not installed
	// (cowork-1-0-8 GAP-0095).
	managedWindowsBareSetup = regexp.MustCompile("(?i)DefenseClawSetup-Enterprise-Standalone-x64\\.exe[`'\"]?\\s+/[a-z]|\\bSetup\\s+/(?:repair|ensure|uninstall|install|upgrade|reconcile|recover|verify)\\b")
	// managedWindowsSetupPhrase is an instruction to run Setup that names no
	// command: "run Setup again", "Setup again", "run Setup." or "run
	// DefenseClaw Setup from ...". On a managed computer there is no Setup to
	// run, and the administrator is told neither the form nor the source. A
	// sentence that goes on to name what Setup is to run ("run DefenseClaw
	// Setup of the installed release as LocalSystem: `& ...`") is not one:
	// its command comes from the renderer.
	managedWindowsSetupPhrase = regexp.MustCompile(`\bSetup\s+again\b|\b(?:[Rr]e-?run|[Rr]un)\s+(?:(?:the|a|this|that|same)\s+)*(?:DefenseClaw\s+)?Setup\s*(?:[.,;:)]|$|(?:and|or|then|first|to|once|from|when|after|before)\b)`)
	managedWindowsContext     = regexp.MustCompile(`(?i)elevated|powershell|administrator prompt|\bSetup /[a-z]|DefenseClawSetup`)
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
			checkManagedWindowsFile(file, rel, windowsOnlySource(t, path), used, func(pos token.Pos, problem string) {
				t.Errorf("%s: %s", fset.Position(pos), problem)
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
	for _, allowance := range managedWindowsBareSetupAllowed {
		if allowance.reason == "" {
			t.Errorf("managedWindowsBareSetupAllowed %q %q has no reason", allowance.path, allowance.words)
		}
		if !used["setup\x00"+allowance.path+"\x00"+allowance.words] {
			t.Errorf("managedWindowsBareSetupAllowed lists %q %q, where no literal names Setup in plain text", allowance.path, allowance.words)
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

// checkManagedWindowsFile runs every rule of
// TestManagedWindowsCommandsComeFromTheRenderer over one parsed file of rel,
// marks in used the allowlist entries it needs, and reports each problem.
// The probe test runs planted variants through it.
func checkManagedWindowsFile(file *ast.File, rel string, windowsOnly bool, used map[string]bool, report func(token.Pos, string)) {
	chained := map[*ast.BinaryExpr]bool{}
	ast.Inspect(file, func(node ast.Node) bool {
		switch n := node.(type) {
		case *ast.CallExpr:
			if problem := powerShellQuoteByHand(n); problem != "" {
				if _, allowed := managedWindowsQuoteAllowed[rel]; allowed {
					used["quote\x00"+rel] = true
				} else {
					report(n.Pos(), problem)
				}
			}
			if joined, parts, ok := managedWindowsFormatted(n); ok {
				for _, problem := range managedWindowsSentenceProblems(rel, joined, parts, windowsOnly) {
					report(n.Pos(), fmt.Sprintf("%s: %q", strings.Replace(problem, "in the joined sentence", "in the formatted text", 1), joined))
				}
			}
			for _, arg := range managedWindowsFmtOrJoinArgs(n) {
				if managedWindowsAmpersandWord(arg) {
					managedWindowsReportWord(rel, arg.Pos(), used, report)
				}
			}
		case *ast.CompositeLit:
			for _, element := range n.Elts {
				if managedWindowsAmpersandWord(element) {
					managedWindowsReportWord(rel, element.Pos(), used, report)
				}
			}
		case *ast.BinaryExpr:
			if n.Op == token.ADD && !chained[n] {
				joined, parts := managedWindowsSentence(n, chained)
				for _, problem := range managedWindowsSentenceProblems(rel, joined, parts, windowsOnly) {
					report(n.Pos(), fmt.Sprintf("%s: %q", problem, joined))
				}
			}
		case *ast.BasicLit:
			if n.Kind != token.STRING {
				return true
			}
			value, err := strconv.Unquote(n.Value)
			if err != nil {
				report(n.Pos(), err.Error())
				return true
			}
			for _, problem := range managedWindowsLiteralProblems(rel, value, windowsOnly, used) {
				report(n.Pos(), fmt.Sprintf("%s: %q", problem, value))
			}
		}
		return true
	})
}

// managedWindowsAmpersandWord reports whether expr is the literal "&" or
// "& ": a call operator that a strings.Join, a fmt.Sprint or a []string
// turns into a command (g072 review 3 M1).
func managedWindowsAmpersandWord(expr ast.Expr) bool {
	lit, ok := expr.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return false
	}
	value, err := strconv.Unquote(lit.Value)
	return err == nil && strings.TrimRight(value, " \t") == "&"
}

func managedWindowsReportWord(rel string, pos token.Pos, used map[string]bool, report func(token.Pos, string)) {
	if strings.HasPrefix(rel, "internal/managed/") {
		return
	}
	if prefix, ok := managedWindowsCallPrefix(rel); ok {
		used["call\x00"+prefix] = true
		return
	}
	report(pos, "a PowerShell call operator joined into a command by hand: use managed.WindowsCommandLine, and say PowerShell")
}

// managedWindowsFmtOrJoinArgs are the arguments of a strings.Join or a
// fmt.Sprint, Sprintln or Sprintf call, whose literals end up in one string.
func managedWindowsFmtOrJoinArgs(call *ast.CallExpr) []ast.Expr {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return nil
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok {
		return nil
	}
	switch {
	case pkg.Name == "strings" && sel.Sel.Name == "Join":
		return call.Args
	case pkg.Name == "fmt" && strings.HasPrefix(sel.Sel.Name, "Sprint"):
		return call.Args
	}
	return nil
}

// managedWindowsFormatted is a fmt.Sprintf, Errorf, Printf or Fprintf call
// whose format is a literal, rendered with each literal argument (a string
// or a rune) in place of its verb, the other verbs kept; parts are the
// format and those arguments. ok is false when no argument is a literal:
// the format is then checked as a literal already. "%c %s" with '&' is
// "& %s", and "run `%s enterprise windows ensure`" with "defenseclaw" is a
// bare command (g072 review 3 M1).
func managedWindowsFormatted(call *ast.CallExpr) (string, []string, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return "", nil, false
	}
	if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "fmt" {
		return "", nil, false
	}
	first := 0
	switch sel.Sel.Name {
	case "Sprintf", "Errorf", "Printf":
	case "Fprintf":
		first = 1
	default:
		return "", nil, false
	}
	if len(call.Args) <= first {
		return "", nil, false
	}
	format, ok := managedWindowsLiteralValue(call.Args[first])
	if !ok {
		return "", nil, false
	}
	args := call.Args[first+1:]
	parts := []string{format}
	var out strings.Builder
	next := 0
	for i := 0; i < len(format); i++ {
		if format[i] != '%' {
			out.WriteByte(format[i])
			continue
		}
		j := i + 1
		for j < len(format) && strings.IndexByte("+-# 0123456789.[]*", format[j]) >= 0 {
			j++
		}
		if j >= len(format) {
			out.WriteString(format[i:])
			break
		}
		verb := format[i : j+1]
		i = j
		if format[j] == '%' {
			out.WriteByte('%')
			continue
		}
		if next < len(args) {
			if value, ok := managedWindowsLiteralValue(args[next]); ok {
				out.WriteString(value)
				parts = append(parts, value)
				next++
				continue
			}
		}
		next++
		out.WriteString(verb)
	}
	return out.String(), parts, len(parts) > 1
}

// managedWindowsLiteralValue is expr's value when it is a string or rune literal.
func managedWindowsLiteralValue(expr ast.Expr) (string, bool) {
	lit, ok := expr.(*ast.BasicLit)
	if !ok {
		return "", false
	}
	switch lit.Kind {
	case token.STRING:
		value, err := strconv.Unquote(lit.Value)
		return value, err == nil
	case token.CHAR:
		value, _, _, err := strconv.UnquoteChar(lit.Value[1:len(lit.Value)-1], '\'')
		return string(value), err == nil
	}
	return "", false
}

// powerShellQuoteByHand is a problem when call is strings.ReplaceAll or
// strings.Replace turning ' into ” (a PowerShell literal quoted by hand) or
// ” into ' (one read by hand): either misses the typographic quotes
// PowerShell reads as single quotes.
func powerShellQuoteByHand(call *ast.CallExpr) string {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
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
	pkg, _ := sel.X.(*ast.Ident)
	switch {
	case pkg != nil && pkg.Name == "strings" && sel.Sel.Name == "NewReplacer":
		// strings.NewReplacer("'", "''") (g072 review 3 M1).
		for i := 0; i+1 < len(call.Args); i += 2 {
			if problem := powerShellQuotePair(literal(call.Args[i]), literal(call.Args[i+1])); problem != "" {
				return problem
			}
		}
		return ""
	case (sel.Sel.Name == "ReplaceAllString" || sel.Sel.Name == "ReplaceAllLiteralString") && len(call.Args) == 2:
		// A regexp replacing a quote with '' (g072 review 3 M1).
		if replacement := literal(call.Args[1]); replacement == "''" || replacement == "$0$0" || replacement == "${0}${0}" {
			return "a PowerShell literal quoted by hand: use managed.PowerShellLiteral or PowerShellLiteralBody (typographic quotes too)"
		}
		return ""
	case pkg == nil || pkg.Name != "strings" || len(call.Args) < 3 || sel.Sel.Name != "ReplaceAll" && sel.Sel.Name != "Replace":
		return ""
	}
	return powerShellQuotePair(literal(call.Args[1]), literal(call.Args[2]))
}

// powerShellQuotePair is a problem when replacing old with replacement
// quotes a PowerShell literal by hand or reads one.
func powerShellQuotePair(old, replacement string) string {
	switch {
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
		// g072 review 3 M1.
		`strings.NewReplacer("'", "''").Replace(p)`:           true,
		`strings.NewReplacer("a", "b", "'", "''").Replace(p)`: true,
		`strings.NewReplacer("''", "'")`:                      true,
		`regexp.MustCompile("'").ReplaceAllString(p, "''")`:   true,
		`quote.ReplaceAllLiteralString(p, "''")`:              true,
		`strings.NewReplacer("\\", "/")`:                      false,
		`quote.ReplaceAllString(p, "_")`:                      false,
		`strings.ReplaceAll(p, "/", "\\")`:                    false,
		`bytes.ReplaceAll(p, "'", "''")`:                      false,
		`strings.ReplaceAll(p, quote, "''")`:                  false,
		`managed.PowerShellLiteral(p)`:                        false,
	} {
		expr, err := parser.ParseExpr(source)
		if err != nil {
			t.Fatalf("%s: %v", source, err)
		}
		call, ok := expr.(*ast.CallExpr)
		if !ok {
			t.Fatalf("%s: not a call", source)
		}
		if outer, ok := call.Fun.(*ast.SelectorExpr); ok && outer.Sel.Name == "Replace" {
			if inner, ok := outer.X.(*ast.CallExpr); ok {
				call = inner // strings.NewReplacer(...).Replace(p)
			}
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
	if !renderer && (managedWindowsBareSetup.MatchString(value) || managedWindowsSetupPhrase.MatchString(value)) {
		if !managedWindowsSetupAllowedLiteral(rel, value, used) {
			problems = append(problems, "names Setup in plain text, which is not installed on a managed computer: use managed.WindowsSetupCommand with managed.WindowsSetupSource, the installed CLI's command (managed.WindowsAdminCommand), or \"the same command\" for a retry of the failed run")
		}
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

// managedWindowsSetupAllowedLiteral reports whether the allowances of file rel
// cover every plain-text Setup mention of value, and marks in used the
// allowances it needed. An allowance with words takes those words out of
// the literal, and what is left must name Setup in no other way.
func managedWindowsSetupAllowedLiteral(rel, value string, used map[string]bool) bool {
	rest := value
	for _, allowance := range managedWindowsBareSetupAllowed {
		if rel != allowance.path && (!strings.HasSuffix(allowance.path, "/") || !strings.HasPrefix(rel, allowance.path)) {
			continue
		}
		key := "setup\x00" + allowance.path + "\x00" + allowance.words
		switch {
		case allowance.words == "":
			used[key] = true
			return true
		case allowance.exact:
			if value == allowance.words {
				used[key] = true
				return true
			}
		case strings.Contains(rest, allowance.words):
			used[key] = true
			rest = strings.ReplaceAll(rest, allowance.words, "")
		}
	}
	return !managedWindowsBareSetup.MatchString(rest) && !managedWindowsSetupPhrase.MatchString(rest)
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
		{"verb-only run, unquoted", "internal/cli/x_windows.go", "; run enterprise windows repair, or DefenseClawSetup-Enterprise-Standalone-x64.exe /repair", true, 2},
		// cowork-1-0-8 GAP-0095: Setup is not installed on a managed computer.
		{"Setup file name with a switch", "internal/cli/x.go", "then run DefenseClawSetup-Enterprise-Standalone-x64.exe /repair JSON=1", false, 1},
		{"Setup file name in backticks", "internal/cli/x_windows.go", "run `DefenseClawSetup-Enterprise-Standalone-x64.exe` /ensure", true, 1},
		{"Setup short form", "internal/cli/x_windows.go", "run Setup /ensure again", true, 1},
		{"Setup short form, uninstall", "internal/enterpriseunix/x.go", "then Setup /uninstall PURGE=1", false, 1},
		{"Setup in Setup's own output", "cmd/defenseclaw-enterprise-setup/host_busy.go", "run Setup /ensure again when the computer is less busy", true, 0},
		{"Setup rendered by the renderer", "internal/cli/x_windows.go", "run %s from an elevated PowerShell prompt", true, 0},
		// cowork-1-0-8 GAP-0095 round 2: "run Setup" with no switch names Setup with no command and no source.
		{"run Setup again", "internal/cli/x_windows.go", "free some space, then run Setup again", true, 1},
		{"Setup again alone", "internal/cli/x.go", "Setup again after the restart", false, 1},
		{"run Setup, sentence end", "internal/cli/x_windows.go", "fix the folder and run Setup.", true, 1},
		{"rerun Setup", "internal/cli/x_windows.go", "rerun Setup when the antivirus lets go", true, 1},
		{"run the Setup, from", "internal/cli/x_windows.go", "run the Setup from an elevated prompt", true, 1},
		{"run DefenseClaw Setup, then", "internal/cli/x_windows.go", "run DefenseClaw Setup then verify", true, 1},
		{"Setup of the installed release, command follows", "internal/cli/x_windows.go", "run DefenseClaw Setup of the installed release as LocalSystem: ", true, 0},
		{"a retry as the same command", "internal/cli/x_windows.go", "then run the same command again", true, 0},
		{"an exact allowance covers its literal", "internal/cli/windows_managed_hooks_lifecycle.go", "Setup /repair", true, 0},
		{"an exact allowance covers only its literal", "internal/cli/windows_managed_hooks_lifecycle.go", "run Setup /repair now", true, 1},
		{"an exact allowance, another file", "internal/cli/x_windows.go", "Setup /repair", true, 1},
		{"a words allowance covers its words", "internal/cli/windows_enterprise_bundle.go", "deliver both with Setup /ensure or, from an elevated PowerShell prompt, with the CLI", true, 0},
		{"a words allowance leaves other mentions", "internal/cli/windows_enterprise_bundle.go", "deliver both with Setup /ensure or run Setup again", true, 1},
		{"a words allowance leaves another switch", "internal/cli/windows_enterprise_bundle.go", "deliver both with Setup /ensure, or Setup /repair", true, 1},
		{"Setup named without a switch", "internal/cli/x_windows.go", "the next Setup run", true, 0},
		{"the renderer's own doc", "internal/managed/windows_admin_cli.go", "Setup /repair", false, 0},
		{"verb-only run, capitalised", "internal/cli/x_windows.go", "Run enterprise windows repair to unpack it", true, 1},
		{"verb-only rerun", "internal/cli/x_windows.go", "rerun 'enterprise windows ensure'", true, 1},
		{"verb-only Run:", "internal/cli/x_windows.go", "Run: enterprise acp setup --client zed", true, 1},
		{"verb-only with", "internal/cli/x_windows.go", "store its key with `enterprise secret set`", true, 1},
		{"verb-only by", "internal/cli/x_windows.go", "its key stored by `enterprise secret set`", true, 1},
		{"verb-only or", "internal/cli/x.go", "run Setup /repair ATTESTCLAUDEEFFECTIVEPOLICY=1, or `enterprise windows repair --profile standalone`", false, 2},
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
		// g072 review 3 M1: near variants of a hand-built call.
		{"call operator before a fmt verb", "internal/cli/x.go", "& %s enterprise windows status", false, 1},
		{"call operator before a quoted fmt verb", "internal/cli/x.go", "& %q status", false, 1},
		{"call operator without a space", "internal/cli/x.go", "&'", false, 1},
		{"call operator, two spaces", "internal/cli/x.go", "&  '", false, 1},
		{"call operator, a tab", "internal/cli/x.go", "&\t'", false, 1},
		{"call operator before a typographic quote", "internal/cli/x.go", "& \u2018", false, 1},
		{"call operator before U+201B", "internal/cli/x.go", "&\u201b", false, 1},
		{"a lone ampersand is a token", "internal/actionfacts/x.go", "&", false, 0},
		{"a cmd.exe chain", "internal/gateway/x.go", "a & b", false, 0},
		{"a character set", "internal/watcher/x.go", "[!$&'()*+,;=%]", false, 0},
		{"an XML entity", "internal/cli/x.go", "unknown reference &%s;", false, 0},
		{"call operator after a pipe, no space", "internal/cli/x.go", "$payload |&'", false, 1},
		{"bare command with a fmt verb", "internal/cli/x_windows.go", "run `defenseclaw %s` from an elevated PowerShell prompt", true, 1},
		{"verb-only with a fmt verb", "internal/cli/x_windows.go", "run `enterprise windows %s --profile standalone`", true, 1},
		{"verb-only family as a fmt verb", "internal/cli/x_windows.go", "run `enterprise %s status`", true, 1},
		{"verb-only use", "internal/cli/x_windows.go", "use `enterprise windows ensure --profile standalone`", true, 1},
		{"bare exe, backtick before the argument", "internal/cli/x.go", "run `defenseclaw.exe` enterprise windows status", false, 1},
		{"bare exe, quote before the argument", "internal/cli/x_windows.go", "run 'defenseclaw.exe' status", true, 1},
		{"bare command, backticked name", "internal/cli/x_windows.go", "run `defenseclaw` doctor", true, 1},
		{"a backticked name in prose", "internal/cli/x_windows.go", "the `defenseclaw` launcher is per-user", true, 1},
		{"a quoted install path", "internal/cli/x_windows.go", "run 'C:\\x\\defenseclaw.exe' status", true, 0},
	} {
		if got := len(managedWindowsLiteralProblems(row.rel, row.value, row.windowsOnly, map[string]bool{})); got != row.want {
			t.Errorf("%s: %d problems, want %d", row.name, got, row.want)
		}
	}
}

// g072 review 3 M1: the review's probes, planted in a windows-only file and
// run through the same file check as the source walk; each must fail.
func TestManagedWindowsProbeVariantsAreCaught(t *testing.T) {
	for name, expr := range map[string]string{
		"raw call operator":                  "`& '` + p",
		"split install path":                 `"C:\\Program Files\\Cisco\\" + "DefenseClaw\\bin\\defenseclaw.exe" + " status"`,
		"Sprintf call operator":              `fmt.Sprintf("& %s enterprise windows status", p)`,
		"Sprintf %c ampersand":               `fmt.Sprintf("%c %s", '&', p)`,
		"joined call operator":               `"&" + " " + p`,
		"strings.Join call operator":         `strings.Join([]string{"&", p, "status"}, " ")`,
		"no space":                           `"&'" + p + "'"`,
		"two spaces":                         `"&  '" + p`,
		"a tab":                              `"&\t'" + p`,
		"typographic quote":                  `"& \u2018" + p`,
		"NewReplacer quoting":                `strings.NewReplacer("'", "''").Replace(p)`,
		"Sprintf bare command":               "fmt.Sprintf(\"run `defenseclaw %s` from an elevated PowerShell prompt\", v)",
		"Sprintf verb-only":                  "fmt.Sprintf(\"run `enterprise windows %s --profile standalone`\", v)",
		"Sprintf name as an argument":        "fmt.Sprintf(\"run `%s enterprise windows ensure`\", \"defenseclaw\")",
		"backtick between name and argument": "\"run \" + \"`defenseclaw.exe` \" + \"enterprise windows status\"",
		// g072 review 4 M3.
		"backtick before a no-space call": "\"run `&'\" + p + \"' status`\"",
		"double quote before &'":          `"\"&'" + p`,
		"equals before &'":                `"-Command=&'" + p`,
		"colon before &'":                 `"Run:&'" + p`,
		"Sprintf indexed verb":            `fmt.Sprintf("& %[1]s status", p)`,
		"Sprintf starred verb":            `fmt.Sprintf("& %*s", 2, p)`,
		"no-break space":                  `"&\u00a0'" + p`,
	} {
		src := "package cli\n\nfunc probe(p, v string) any { return " + expr + " }\n"
		file, err := parser.ParseFile(token.NewFileSet(), "zz_probe_windows.go", src, 0)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var problems []string
		checkManagedWindowsFile(file, "internal/cli/zz_probe_windows.go", true, map[string]bool{}, func(_ token.Pos, problem string) {
			problems = append(problems, problem)
		})
		if len(problems) == 0 {
			t.Errorf("%s: %s passes the source check", name, expr)
		}
	}
	// Benign twins: a token compared with, a renderer's line, a cmd.exe chain.
	for name, expr := range map[string]string{
		"a token compared with": `p == "&"`,
		"the renderer":          `WindowsCommandLine(p, "status")`,
		"a cmd.exe chain":       `p + " & echo " + v`,
		"Sprintf POSIX and":     `fmt.Sprintf("%s && %s", p, v)`,
		"a character set":       `strings.ContainsAny(p, "!$&'()*")`,
		"an XML entity":         `fmt.Errorf("unknown reference &%s;", p)`,
	} {
		src := "package cli\n\nfunc probe(p, v string) any { return " + expr + " }\n"
		file, err := parser.ParseFile(token.NewFileSet(), "zz_probe.go", src, 0)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		checkManagedWindowsFile(file, "internal/cli/zz_probe.go", false, map[string]bool{}, func(_ token.Pos, problem string) {
			t.Errorf("%s: %s: %s", name, expr, problem)
		})
	}
}
