package effects

import "testing"

// rv4: directory-stack and cwd-state semantics, neutral paths only.
// Expected real cwd for the final touch is noted per case.
func TestRv4CwdState(t *testing.T) {
	cases := []struct {
		n, want string
		o       Options
		cmd     string
	}{
		{"posix pushd no-arg swaps", "/tmp/a/f", envOpts, `cd /tmp/a; pushd /tmp/b; pushd; touch f`},
		{"posix pushd +1 rotates", "/tmp/a/f", envOpts, `cd /tmp/a; pushd /tmp/b; pushd +1; touch f`},
		{"posix popd +1 keeps cwd", "/tmp/b/f", envOpts, `pushd /tmp/b; popd +1; touch f`},
		{"posix popd -n keeps cwd", "/tmp/b/f", envOpts, `pushd /tmp/b; popd -n; touch f`},
		{"posix dot-dot lexical", "physical (needs fs)", envOpts, `touch /tmp/l/../f`},
		{"cmd cd no-arg prints only", `c:\a\f`, winCmd, `cd /d C:\a & cd & type nul > f`},
		{"cmd pushd no-arg prints only", `c:\a\f`, winCmd, `cd /d C:\a & pushd & type nul > f`},
		{"cmd cd other drive keeps C", `c:\a\f`, winCmd, `cd /d C:\a & cd D:\b & type nul > f`},
		{"ps Push-Location no-arg", `c:\a\f`, winPS, `Set-Location C:\a; Push-Location; New-Item f`},
	}
	for _, c := range cases {
		checkRow(t, c.n, c.o, sh(c.cmd), "")
	}
}
