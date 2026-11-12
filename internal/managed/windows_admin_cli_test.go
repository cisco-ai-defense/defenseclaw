// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"runtime"
	"strings"
	"testing"
)

// cowork-1-0-8 GAP-0076: a managed Windows command runs as typed in
// PowerShell. The path is a literal, and so is every argument that is not a
// plain word or a <placeholder>: an account named "John Smith" was two
// arguments, "O'Brien" broke the quoting and "svc$" expanded as a variable.
func TestWindowsAdminCommandQuotesEveryArgument(t *testing.T) {
	cli := "& " + PowerShellLiteral(WindowsStandaloneAdminCLI())
	if runtime.GOOS != "windows" {
		if want := `& 'C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw.exe'`; cli != want {
			t.Fatalf("installed CLI = %s, want %s", cli, want)
		}
	}
	for _, row := range []struct {
		args []string
		want string
	}{
		{[]string{"status"}, cli + " status"},
		{[]string{"enterprise", "windows", "status", "--profile", "standalone"}, cli + " enterprise windows status --profile standalone"},
		{[]string{"enterprise", "policy", "show", "--user", "dcadmin"}, cli + " enterprise policy show --user dcadmin"},
		{[]string{"enterprise", "policy", "show", "--user", "John Smith"}, cli + " enterprise policy show --user 'John Smith'"},
		{[]string{"enterprise", "policy", "show", "--user", "O'Brien"}, cli + " enterprise policy show --user 'O''Brien'"},
		{[]string{"enterprise", "policy", "show", "--user", "O\u2019Brien"}, cli + " enterprise policy show --user 'O\u2019\u2019Brien'"},
		{[]string{"enterprise", "policy", "show", "--user", "svc$"}, cli + " enterprise policy show --user 'svc$'"},
		{[]string{"enterprise", "policy", "show", "--user", `DCLAB\ent-bob`}, cli + ` enterprise policy show --user 'DCLAB\ent-bob'`},
		{[]string{"enterprise", "policy", "show", "--user", "a;b"}, cli + " enterprise policy show --user 'a;b'"},
		{[]string{"enterprise", "policy", "show", "--user", "`x"}, cli + " enterprise policy show --user '`x'"},
		{[]string{"enterprise", "policy", "show", "--user", ""}, cli + " enterprise policy show --user ''"},
		{[]string{"enterprise", "policy", "show", "--user", "<user>"}, cli + " enterprise policy show --user <user>"},
		{[]string{"audit", "export", "--connector", "<connector>", "-o", "<file>"}, cli + " audit export --connector <connector> -o <file>"},
		{[]string{"enterprise", "windows", "ensure", "--bundle", "<bundle file>"}, cli + " enterprise windows ensure --bundle <bundle file>"},
		// A <...> that hides quoting or a variable is no placeholder.
		{[]string{"--user", "<$x>"}, cli + " --user '<$x>'"},
		{[]string{"--user", "<a'b>"}, cli + " --user '<a''b>'"},
		{[]string{"scan", "skill", `C:\DefenseClawReview\bad-skill`}, cli + ` scan skill 'C:\DefenseClawReview\bad-skill'`},
		{[]string{"--json", "-o", "x.json", "--name=ai-key", "a/b:c+d"}, cli + " --json -o x.json --name=ai-key a/b:c+d"},
	} {
		if got := WindowsAdminCommand(row.args...); got != row.want {
			t.Errorf("WindowsAdminCommand(%q) = %s, want %s", row.args, got, row.want)
		}
	}
	gateway := "& " + PowerShellLiteral(WindowsStandaloneGatewayCLI()) + " enterprise windows sandbox list --user 'r103 probe'"
	if got := WindowsGatewayCommand("enterprise", "windows", "sandbox", "list", "--user", "r103 probe"); got != gateway ||
		!strings.HasSuffix(WindowsStandaloneGatewayCLI(), `\Cisco\DefenseClaw\bin\defenseclaw-gateway.exe`) {
		t.Errorf("WindowsGatewayCommand = %s, want %s", got, gateway)
	}
	// The path is quoted the same way.
	if got, want := WindowsCommandLine(`D:\Apps' x\Cisco\DefenseClaw\bin\defenseclaw.exe`, "status"), `& 'D:\Apps'' x\Cisco\DefenseClaw\bin\defenseclaw.exe' status`; got != want {
		t.Errorf("quoted path = %s, want %s", got, want)
	}
	if got, want := WindowsCommandLine(`C:\T\defenseclaw.exe`), `& 'C:\T\defenseclaw.exe'`; got != want {
		t.Errorf("no arguments = %s, want %s", got, want)
	}
}

// g072 review 2 S3: one quoting rule. The body doubles every single quote
// PowerShell reads, the apostrophe and U+2018 to U+201B, and the value of a
// body is the text it quoted.
func TestPowerShellLiteralBodyAndValue(t *testing.T) {
	for _, row := range []struct{ value, body string }{
		{`C:\Users\dc-user\x.exe`, `C:\Users\dc-user\x.exe`},
		{`C:\Users\O'Brien\x.exe`, `C:\Users\O''Brien\x.exe`},
		{"C:\\Users\\O\u2019Brien\\x.exe", "C:\\Users\\O\u2019\u2019Brien\\x.exe"},
		{"\u2018a\u2019 \u201ab\u201b", "\u2018\u2018a\u2019\u2019 \u201a\u201ab\u201b\u201b"},
		{"''", "''''"},
		{"", ""},
	} {
		if got := PowerShellLiteralBody(row.value); got != row.body {
			t.Errorf("PowerShellLiteralBody(%q) = %q, want %q", row.value, got, row.body)
		}
		if got := PowerShellLiteral(row.value); got != "'"+row.body+"'" {
			t.Errorf("PowerShellLiteral(%q) = %q", row.value, got)
		}
		if got := PowerShellLiteralValue(row.body); got != row.value {
			t.Errorf("PowerShellLiteralValue(%q) = %q, want %q", row.body, got, row.value)
		}
	}
	// A lone quote is kept, as the parsers kept a lone apostrophe.
	if got := PowerShellLiteralValue("O\u2019Brien'x"); got != "O\u2019Brien'x" {
		t.Errorf("lone quotes = %q", got)
	}
	old, ok := PowerShellLiteralBeforeTypographicQuotes("& 'C:\\Users\\O\u2019\u2019Brien''s\\x.exe' --hook codex")
	if !ok || old != "& 'C:\\Users\\O\u2019Brien''s\\x.exe' --hook codex" {
		t.Errorf("before 1.0.9 = %q, %t", old, ok)
	}
	if _, ok := PowerShellLiteralBeforeTypographicQuotes("& 'C:\\Users\\O''Brien\\x.exe'"); ok {
		t.Error("a command without typographic quotes has no earlier form")
	}
}

// g072 review 2 S2: the hint names the Program Files of the machine
// registration. A standard user who sets ProgramFiles in a shell does not
// get a hint, for an administrator to paste elevated, that names a folder of
// theirs.
func TestWindowsAdminCommandIgnoresAPoisonedProgramFiles(t *testing.T) {
	want := WindowsAdminCommand("enterprise", "windows", "status", "--profile", "standalone")
	wantGateway := WindowsGatewayCommand("provenance", "show")
	for _, poison := range []string{`C:\Users\dcw-std1\Controlled`, `D:\Apps' x\`, ""} {
		t.Setenv("ProgramFiles", poison)
		got := WindowsAdminCommand("enterprise", "windows", "status", "--profile", "standalone")
		gotGateway := WindowsGatewayCommand("provenance", "show")
		if got != want || gotGateway != wantGateway || poison != "" && (strings.Contains(got, poison) || strings.Contains(gotGateway, poison)) {
			t.Errorf("ProgramFiles=%q changed the hint: %s / %s, want %s / %s", poison, got, gotGateway, want, wantGateway)
		}
	}
	if runtime.GOOS != "windows" && want != `& 'C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw.exe' enterprise windows status --profile standalone` {
		t.Errorf("hint off Windows = %s", want)
	}
}
