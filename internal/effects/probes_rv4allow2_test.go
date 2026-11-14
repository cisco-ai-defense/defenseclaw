package effects

import "testing"

func TestRv4AllowlistShapes2(t *testing.T) {
	cases := []struct {
		n   string
		o   Options
		cmd string
	}{
		{"cp listed, dir dest", envOpts, `cp a.txt /tmp/d/`},
		{"cp single unlisted, dir dest", envOpts, `cp -Q a.txt /tmp/d/`},
		{"mv single unlisted, dir dest", envOpts, `mv -Q a.txt /tmp/d/`},
		{"tee single unlisted", envOpts, `echo x | tee -Q /tmp/x`},
		{"ps Remove-Item unlisted", winPS, `Remove-Item -Bogus a.txt`},
		{"ps Set-Content unlisted", winPS, `Set-Content -Bogus a.txt -Value x`},
		{"cmd type switch", winCmd, `type /Q a.txt`},
	}
	for _, c := range cases {
		checkRow(t, c.n, c.o, sh(c.cmd), "")
	}
}
