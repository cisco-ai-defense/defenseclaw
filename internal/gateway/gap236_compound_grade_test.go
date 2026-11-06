package gateway

import (
	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"testing"
)

func TestGAP236CompoundGradePreservesNamedTargets(t *testing.T) {
	const home = `C:\Users\review`
	rows := []struct {
		name, command, cwd, want string
		dialect                  actionfacts.Dialect
	}{
		{"listing_after_pwd", `pwd; bash -c 'ls -d */* | head "-3"'`, home, "allow", actionfacts.DialectPOSIX},
		{"listing_before_pwd", `bash -c 'ls -d */* | head "-3"'; pwd`, home, "allow", actionfacts.DialectPOSIX},
		{"listing_after_cd_dot", `cd .; bash -c 'ls -d */* | head "-3"'`, home, "allow", actionfacts.DialectPOSIX},
		{"listing_after_true", `true; bash -c 'ls -d */* | head "-3"'`, home, "allow", actionfacts.DialectPOSIX},
		{"listing_after_stat", `stat .; bash -c 'ls -d */* | head "-3"'`, home, "allow", actionfacts.DialectPOSIX},
		{"listing_after_pwd_with_escaped_quote", `pwd; bash -c "ls -d */* | head -n \"3\""`, home, "allow", actionfacts.DialectPOSIX},
		{"listing_with_quoted_n_option", `bash -c 'ls -d */* | head "-n" "3"'`, home, "allow", actionfacts.DialectPOSIX},
		{"listing_with_discards_and_quotes", `bash -c 'ls -d */* 2>/dev/null | head "-3"'`, home, "allow", actionfacts.DialectPOSIX},
		{"listing_with_escaped_inner_quote", `bash -c "ls -d */* | head -n \"3\""`, home, "allow", actionfacts.DialectPOSIX},
		{"here_string_then_pwd", "$t = @'\n.ssh/authorized_k*\n'@; Write-Output $t; pwd", home, "allow", actionfacts.DialectPowerShell},
		{"here_string_pwd_before_print", "$t = @'\n.ssh/authorized_k*\n'@; pwd; Write-Output $t", home, "allow", actionfacts.DialectPowerShell},
		{"project_copy_then_pwd", `cp *.txt build/; pwd`, home + `\project`, "allow", actionfacts.DialectPOSIX},
		{"config_copy_then_pwd", `cp ~/.defenseclaw/conf*.yaml project/copy.yaml; pwd`, home, "allow", actionfacts.DialectPOSIX},
		{"copy_switch_then_pwd", `Copy-Item -Recurse -Path .\src -Destination .\build; pwd`, home + `\project`, "allow", actionfacts.DialectPowerShell},
		{"project_copy_then_cd_known_write", `cp *.txt build/; d=../.ssh; cd "$d"; echo k >> authorized_keys`, home + `\project`, "block", actionfacts.DialectPOSIX},
		{"config_copy_then_cd_known_write", `cp ~/.defenseclaw/conf*.yaml project/copy.yaml; d=.ssh; cd "$d"; echo k >> authorized_keys`, home, "block", actionfacts.DialectPOSIX},
		{"here_string_then_ps_known_cd_write", "$t = @'\n.ssh/authorized_k*\n'@; Write-Output $t; $d = '.ssh'; cd $d; echo k >> authorized_keys", home, "block", actionfacts.DialectPowerShell},
		{"copy_switch_then_ps_known_cd_write", `Copy-Item -Recurse -Path .\src -Destination .\build; $d = '.ssh'; cd $d; Set-Content authorized_keys k`, home, "block", actionfacts.DialectPowerShell},
		{"copy_switch_then_nested_cd_write", `Copy-Item -Recurse -Path .\src -Destination .\build; bash -c 'cd .ssh; echo k >> authorized_keys'`, home, "block", actionfacts.DialectPowerShell},
		{"here_string_then_nested_cd_write", "$t = @'\n.ssh/authorized_k*\n'@; Write-Output $t; bash -c 'cd .ssh; echo k >> authorized_keys'", home, "block", actionfacts.DialectPowerShell},
		{"quoted_option_then_nested_cd_write", `t="-t $HOME/.ssh"; cp "$t" a.txt; bash -c 'cd ../.ssh; echo k >> authorized_keys'`, home + `\project`, "block", actionfacts.DialectPOSIX},
		{"listing_then_pushd_write", `ls */*; pushd .ssh; echo k >> authorized_keys`, home, "block", actionfacts.DialectPOSIX},
		{"listing_then_cd_dashdash_write", `ls */*; cd -- .ssh; echo k >> authorized_keys`, home, "block", actionfacts.DialectPOSIX},
		{"listing_then_cd_known_write", `ls */*; d=.ssh; cd "$d"; echo k >> authorized_keys`, home, "block", actionfacts.DialectPOSIX},
		{"listing_then_conditional_known_write", `ls */*; d=.ssh; cd "$d" && echo k >> authorized_keys`, home, "block", actionfacts.DialectPOSIX},
		{"listing_then_subshell_write", `ls */*; (cd .ssh; echo k >> authorized_keys)`, home, "block", actionfacts.DialectPOSIX},
		{"listing_then_nested_known_write", `ls */*; bash -c 'd=.ssh; cd "$d"; echo k >> authorized_keys'`, home, "block", actionfacts.DialectPOSIX},
		{"listing_then_cd_write_dotpath", `ls */*; cd .ssh; echo k >> ./authorized_keys`, home, "block", actionfacts.DialectPOSIX},
		{"listing_then_cd_write_known_value", `ls */*; cd .ssh; t=authorized_keys; cp a "$t"`, home, "block", actionfacts.DialectPOSIX},
		{"copy_then_cd_known_value", `Copy-Item -Recurse -Path .\src -Destination .\build; cd .ssh; $t='authorized_keys'; Set-Content -Path $t -Value k`, home, "block", actionfacts.DialectPowerShell},
		{"listing_then_setlocation_write", `ls */*; Set-Location -Path .ssh; Set-Content -Path authorized_keys -Value k`, home, "block", actionfacts.DialectPowerShell},
		{"listing_then_nested_cd_write", `ls */*; bash -c 'cd .ssh; echo k >> authorized_keys'`, home, "block", actionfacts.DialectPOSIX},
	}
	for _, row := range rows {
		for _, connector := range []string{"codex", "claudecode"} {
			t.Run(row.name+"/"+connector, func(t *testing.T) {
				grade := sshKeyMentionGrade(trustedActionRequest{Input: actionfacts.Input{
					Command: row.command, CWD: row.cwd, ActiveHome: home,
				}})
				got := gap236BalancedAction(t, row.command, row.cwd, home, connector, row.dialect, false)
				t.Logf("grade=%s verdict=%s want=%s", grade, got, row.want)
				if got != row.want {
					t.Errorf("verdict %s, want %s", got, row.want)
				}
			})
		}
	}
}
