package effects

import "testing"

func TestDET111R1NewgrpLowersHeredocAsShellBody(t *testing.T) {
	call := Call{Surface: SurfaceShell, Command: "newgrp users <<'EOF'\nprintf k >> ~/.ssh/authorized_keys\nEOF"}
	got := Extract(call, Options{Flavor: FlavorPOSIX, Dialect: DialectPOSIX, Home: "/home/u", CWD: "/home/u/proj"})
	for _, effect := range got.Effects {
		if effect.Kind == KindAppend && effect.Target.Path == "/home/u/.ssh/authorized_keys" &&
			effect.TargetState == TargetStateKnown && effect.RoleState == RoleStateKnown {
			return
		}
	}
	t.Fatalf("newgrp heredoc append was not a known append effect: %+v", got)
}

func TestDET111R1TeeObjectModelsPipedAppend(t *testing.T) {
	if !hasAppendFlag([]Word{{Value: "-Append", Static: true}}, "-append", DialectPowerShell) {
		t.Fatal("PowerShell append flag comparison failed")
	}
	entry, ok := lookupProgram("tee-object", FlavorWindows, DialectPowerShell, false)
	if !ok || entry.AppendFlag != "-append" {
		t.Fatalf("Tee-Object append row = %+v, ok=%v", entry, ok)
	}
	call := Call{Surface: SurfaceShell, Command: `Write-Output key | Tee-Object -Append -FilePath C:\Users\u\.ssh\authorized_keys`}
	got := Extract(call, Options{Flavor: FlavorWindows, Dialect: DialectPowerShell, Home: `C:\Users\u`, CWD: `C:\Users\u\proj`})
	for _, effect := range got.Effects {
		if effect.Kind == KindAppend && effect.Target.Path == `C:\Users\u\.ssh\authorized_keys` &&
			effect.TargetState == TargetStateKnown && effect.RoleState == RoleStateKnown && effect.Data != nil && effect.Data.Text != "" {
			return
		}
	}
	t.Fatalf("Tee-Object piped append was not a known append effect with content: %+v", got)
}
