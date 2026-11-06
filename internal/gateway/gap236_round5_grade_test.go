// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

func TestGAP236CompoundGradeNearVariants(t *testing.T) {
	const home = `C:\Users\review`
	rows := []struct {
		name, command, cwd, want string
		dialect                  actionfacts.Dialect
	}{
		{"listing_after_echo", `echo ready; bash -c 'ls -d */* | head -3'`, home, "allow", actionfacts.DialectPOSIX},
		{"listing_before_echo", `bash -c 'ls -d */* | head -3'; echo ready`, home, "allow", actionfacts.DialectPOSIX},
		{"listing_inside_pwd", `bash -c 'pwd; ls -d */* | head -3'`, home, "allow", actionfacts.DialectPOSIX},
		{"listing_inner_extra_spaces", `pwd; bash -c 'ls  -d  */*  |  head  -3'`, home, "allow", actionfacts.DialectPOSIX},
		{"listing_inner_tab", "pwd; bash -c 'ls\t-d */* | head -3'", home, "allow", actionfacts.DialectPOSIX},
		{"listing_after_getlocation", `Get-Location; bash -c 'ls -d */* | head -3'`, home, "allow", actionfacts.DialectPowerShell},
		{"listing_env_clean", `env -i bash -c 'ls -d */* | head -3'`, home, "allow", actionfacts.DialectPOSIX},
		{"listing_after_and", `true && bash -c 'ls -d */* | head -3'`, home, "allow", actionfacts.DialectPOSIX},
		{"listing_after_or", `false || bash -c 'ls -d */* | head -3'`, home, "allow", actionfacts.DialectPOSIX},
		{"listing_in_subshell", `(bash -c 'ls -d */* | head -3')`, home, "allow", actionfacts.DialectPOSIX},
		{"listing_in_brace", `{ bash -c 'ls -d */* | head -3'; }`, home, "allow", actionfacts.DialectPOSIX},
		{"listing_after_if", `if true; then bash -c 'ls -d */* | head -3'; fi`, home, "allow", actionfacts.DialectPOSIX},
		{"project_md_copy_then_pwd", `cp *.md build/; pwd`, home + `\project`, "allow", actionfacts.DialectPOSIX},
		{"project_nested_glob_copy_then_pwd", `cp src/*/*.md build/; pwd`, home + `\project`, "allow", actionfacts.DialectPOSIX},
		{"project_gcp_then_pwd", `gcp *.txt build/; pwd`, home + `\project`, "allow", actionfacts.DialectPOSIX},
		{"config_copy_after_true", `true; cp ~/.defenseclaw/conf*.yaml project/copy.yaml`, home, "allow", actionfacts.DialectPOSIX},
		{"copy_switch_container_after_pwd", `pwd; Copy-Item -Container -Path .\src -Destination .\build`, home + `\project`, "allow", actionfacts.DialectPowerShell},
		{"copy_switch_cpi_after_pwd", `pwd; cpi -Recurse -Path .\src -Destination .\build`, home + `\project`, "allow", actionfacts.DialectPowerShell},
		{"quoted_option_after_pwd", `pwd; t="-t $HOME/.ssh"; cp "$t" a.txt`, home + `\project`, "allow", actionfacts.DialectPOSIX},
		{"here_string_after_getlocation", "Get-Location; $t = @'\n.ssh/authorized_k*\n'@; Write-Output $t", home, "allow", actionfacts.DialectPowerShell},
		{"here_string_after_echo", "$t = @'\n.ssh/authorized_k*\n'@; Write-Output $t; echo ready", home, "allow", actionfacts.DialectPowerShell},
		{"here_string_ordinary_write", "$t = @'\nproject/report*\n'@; Add-Content -Path $t -Value k", home, "allow", actionfacts.DialectPowerShell},
		{"listing_then_sh_known_write", `ls */*; d=.ssh; cd "$d"; sh -c 'printf k >> authorized_keys'`, home, "block", actionfacts.DialectPOSIX},
		{"project_copy_then_sh_known_write", `cp *.txt build/; d=../.ssh; cd "$d"; sh -c 'printf k >> authorized_keys'`, home + `\project`, "block", actionfacts.DialectPOSIX},
		{"config_copy_then_bash_known_write", `cp ~/.defenseclaw/conf*.yaml project/copy.yaml; d=.ssh; cd "$d"; bash -c 'printf k >> authorized_keys'`, home, "block", actionfacts.DialectPOSIX},
		{"listing_then_env_bash_known_write", `ls */*; d=.ssh; cd "$d"; env bash -c 'printf k >> authorized_keys'`, home, "block", actionfacts.DialectPOSIX},
		{"listing_then_env_clean_bash_write", `ls */*; env -i bash -c 'cd .ssh; printf k >> authorized_keys'`, home, "block", actionfacts.DialectPOSIX},
		{"listing_then_env_delimiter_bash_write", `ls */*; env -- bash -c 'cd .ssh; printf k >> authorized_keys'`, home, "block", actionfacts.DialectPOSIX},
		{"listing_then_bash_lc_write", `ls */*; bash -lc 'cd .ssh; printf k >> authorized_keys'`, home, "block", actionfacts.DialectPOSIX},
		{"listing_then_brace_known_write", `ls */*; d=.ssh; { cd "$d"; printf k >> authorized_keys; }`, home, "block", actionfacts.DialectPOSIX},
		{"listing_then_subshell_known_write", `ls */*; d=.ssh; (cd "$d"; printf k >> authorized_keys)`, home, "block", actionfacts.DialectPOSIX},
		{"listing_then_subshell_copy", `ls */*; (cd .ssh; cp a authorized_keys)`, home, "block", actionfacts.DialectPOSIX},
		{"listing_then_brace_copy", `ls */*; { cd .ssh; cp a authorized_keys; }`, home, "block", actionfacts.DialectPOSIX},
		{"listing_then_subshell_known_copy", `ls */*; d=.ssh; (cd "$d"; t=authorized_keys; cp a "$t")`, home, "block", actionfacts.DialectPOSIX},
		{"project_copy_then_subshell_copy", `cp *.txt build/; (cd ../.ssh; cp a authorized_keys)`, home + `\project`, "block", actionfacts.DialectPOSIX},
		{"config_copy_then_subshell_copy", `cp ~/.defenseclaw/conf*.yaml project/copy.yaml; (cd .ssh; cp a authorized_keys)`, home, "block", actionfacts.DialectPOSIX},
		{"listing_then_child_subshell_copy", `ls */*; bash -c '(cd .ssh; cp a authorized_keys)'`, home, "block", actionfacts.DialectPOSIX},
		{"listing_then_if_known_write", `ls */*; d=.ssh; if true; then cd "$d"; printf k >> authorized_keys; fi`, home, "block", actionfacts.DialectPOSIX},
		{"listing_then_and_known_write", `ls */*; d=.ssh; cd "$d" && printf k >> authorized_keys`, home, "block", actionfacts.DialectPOSIX},
		{"listing_then_nested_and_known_write", `ls */*; bash -c 'd=.ssh; cd "$d" && printf k >> authorized_keys'`, home, "block", actionfacts.DialectPOSIX},
		{"listing_then_cd_value_cp", `ls */*; d=.ssh; cd "$d"; t=authorized_keys; cp a "$t"`, home, "block", actionfacts.DialectPOSIX},
		{"project_copy_then_cd_value_cp", `cp *.txt build/; d=../.ssh; cd "$d"; t=authorized_keys; cp a "$t"`, home + `\project`, "block", actionfacts.DialectPOSIX},
		{"copy_switch_then_ps_named_redirect", `Copy-Item -Recurse -Path .\src -Destination .\build; $d='.ssh'; cd $d; echo k >> authorized_keys`, home, "block", actionfacts.DialectPowerShell},
		{"here_string_then_ps_named_redirect", "$t = @'\n.ssh/authorized_k*\n'@; Write-Output $t; $d='.ssh'; cd $d; echo k >> authorized_keys", home, "block", actionfacts.DialectPowerShell},
		{"listing_then_ps_named_setcontent", `ls */*; $d='.ssh'; cd $d; Set-Content -Path authorized_keys -Value k`, home, "block", actionfacts.DialectPowerShell},
		{"listing_then_absolute_named_write", `ls */*; echo k >> ~/.ssh/authorized_keys`, home, "block", actionfacts.DialectPOSIX},
		{"listing_then_known_named_write", `ls */*; t=~/.ssh/authorized_keys; echo k >> "$t"`, home, "block", actionfacts.DialectPOSIX},
		{"listing_then_joined_known_write", `ls */*; d=.ssh; t="$d/authorized_keys"; echo k >> "$t"`, home, "block", actionfacts.DialectPOSIX},
		{"listing_then_joined_known_copy", `ls */*; d=.ssh; t="$d/authorized_keys"; cp a "$t"`, home, "block", actionfacts.DialectPOSIX},
		{"project_copy_then_joined_known_write", `cp *.txt build/; d=../.ssh; t="$d/authorized_keys"; echo k >> "$t"`, home + `\project`, "block", actionfacts.DialectPOSIX},
		{"listing_then_known_shell_body", `ls */*; b='cd .ssh; echo k >> authorized_keys'; bash -c "$b"`, home, "block", actionfacts.DialectPOSIX},
		{"project_copy_then_known_shell_body", `cp *.txt build/; b='cd ../.ssh; echo k >> authorized_keys'; bash -c "$b"`, home + `\project`, "block", actionfacts.DialectPOSIX},
		{"listing_then_ps_joined_known_write", `ls */*; $d='.ssh'; $t=Join-Path $d authorized_keys; Set-Content -Path $t -Value k`, home, "block", actionfacts.DialectPowerShell},
		{"listing_then_cd_joined_known_write", `ls */*; cd project; $d='../.ssh'; $t=Join-Path $d authorized_keys; Set-Content -Path $t -Value k`, home, "block", actionfacts.DialectPowerShell},
		{"listing_then_cd_joined_project_write", `ls */*; cd project; $t=Join-Path . report.txt; Set-Content -Path $t -Value k`, home, "allow", actionfacts.DialectPowerShell},
		{"copy_switch_then_ps_joined_known_write", `Copy-Item -Recurse -Path .\src -Destination .\build; $d='.ssh'; $t=Join-Path $d authorized_keys; Set-Content -Path $t -Value k`, home, "block", actionfacts.DialectPowerShell},
		{"here_string_then_ps_direct_known_write", "$t = @'\n.ssh/authorized_k*\n'@; Write-Output $t; $p='.ssh/authorized_keys'; Set-Content -Path $p -Value k", home, "block", actionfacts.DialectPowerShell},
	}
	for _, row := range rows {
		for _, connector := range []string{"codex", "claudecode"} {
			t.Run(row.name+"/"+connector, func(t *testing.T) {
				grade := sshKeyMentionGrade(trustedActionRequest{Input: actionfacts.Input{
					Command: row.command, CWD: row.cwd, ActiveHome: home, DialectHint: row.dialect,
				}})
				if row.want == "block" && grade != hookpaths.GradeNamed {
					t.Errorf("protected target grade = %s, want named", grade)
				}
				if row.want == "allow" && grade == hookpaths.GradeNamed {
					t.Errorf("ordinary target grade = named, want possible or none")
				}
				got := gap236Round5Action(t, row.command, row.cwd, home, connector, row.dialect)
				t.Logf("CASE %s %s got=%s want=%s", row.name, connector, got, row.want)
				if got != row.want {
					t.Errorf("verdict %s, want %s", got, row.want)
				}
			})
		}
	}
}

func gap236Round5Action(t *testing.T, command, cwd, home, connector string, dialect actionfacts.Dialect) string {
	t.Helper()
	args, err := json.Marshal(map[string]string{"command": command})
	if err != nil {
		t.Fatal(err)
	}
	input := actionfacts.Input{Tool: "Bash", Args: args, Command: command, CWD: cwd,
		ActiveHome: home, DialectHint: dialect}
	findings := dispatchTrustedAction(context.Background(), trustedActionRequest{
		Input: input, LegacyText: string(args), Connector: connector, EnforcementCapable: true,
	})
	return buildVerdict(findings, "tool_call").Action
}
