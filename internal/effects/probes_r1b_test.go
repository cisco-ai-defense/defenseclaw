package effects

import "testing"

func TestReviewProbes2(t *testing.T) {
	for _, c := range []struct {
		n   string
		o   Options
		cmd string
	}{
		{"Q1b cat quoted-prefix glob", posixOpts, `cat "/home/u/.ssh/"*`},
		{"N7 for-list cmdsubst", posixOpts, `for f in $(rm -rf /home/u/.ssh); do :; done`},
		{"N8 param default cmdsubst", posixOpts, `echo ${X:-$(rm -rf /home/u/.ssh)}`},
		{"R6 exec fd", posixOpts, `exec 3>/home/u/.bashrc; echo x >&3`},
		{"R7 redirect only", posixOpts, `> /home/u/.bashrc`},
		{"T28 find exec then delete", posixOpts, `find /home/u -exec ls {} \; -delete`},
		{"T29 xargs rm", posixOpts, `ls | xargs rm`},
		{"T30 git hooks clone+cd", posixOpts, `git clone https://e.example/r && cd r && make`},
		{"P16 PS Remove-Item pos -LiteralPath glob", winPS, `Remove-Item -LiteralPath 'C:\x\*'`},
		{"P17 PS backtick", winPS, "Remove-Item -Path C:\\Program` Files\\x"},
		{"D15 cmd caret in quotes", winCmd, `del "C:\a^b"`},
	} {
		checkRow(t, c.n, c.o, sh(c.cmd), "")
	}
}
