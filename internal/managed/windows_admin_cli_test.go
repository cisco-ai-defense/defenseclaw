// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

import "testing"

// cowork-1-0-8 GAP-0076: a managed Windows command runs as typed in
// PowerShell. The path is a literal, and so is every argument that is not a
// plain word or a <placeholder>: an account named "John Smith" was two
// arguments, "O'Brien" broke the quoting and "svc$" expanded as a variable.
func TestWindowsAdminCommandQuotesEveryArgument(t *testing.T) {
	t.Setenv("ProgramFiles", `C:\Program Files`)
	cli := `& 'C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw.exe'`
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
	gateway := `& 'C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-gateway.exe' enterprise windows sandbox list --user 'r103 probe'`
	if got := WindowsGatewayCommand("enterprise", "windows", "sandbox", "list", "--user", "r103 probe"); got != gateway {
		t.Errorf("WindowsGatewayCommand = %s, want %s", got, gateway)
	}
	// The path is quoted the same way, and follows %ProgramFiles%.
	t.Setenv("ProgramFiles", `D:\Apps' x\`)
	if got, want := WindowsAdminCommand("status"), `& 'D:\Apps'' x\Cisco\DefenseClaw\bin\defenseclaw.exe' status`; got != want {
		t.Errorf("quoted path = %s, want %s", got, want)
	}
	if got, want := WindowsCommandLine(`C:\T\defenseclaw.exe`), `& 'C:\T\defenseclaw.exe'`; got != want {
		t.Errorf("no arguments = %s, want %s", got, want)
	}
}
