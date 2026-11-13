package effects

import "testing"

// rv4: does an unlisted flag always make the call not fully known?
func TestRv4AllowlistShapes(t *testing.T) {
	cases := []struct {
		n   string
		o   Options
		cmd string
	}{
		{"posix single unlisted short", envOpts, `cp -Q a.txt b.txt`},
		{"posix combined unlisted short", envOpts, `cp -QW a.txt b.txt`},
		{"posix unlisted long", envOpts, `cp --bogus a.txt b.txt`},
		{"posix rm single unlisted", envOpts, `rm -Q /tmp/x`},
		{"posix cat single unlisted", envOpts, `cat -Q /tmp/x`},
		{"posix nil-flags prog (zip)", envOpts, `zip -Q out.zip a.txt`},
		{"posix nil-flags prog (scp)", envOpts, `scp -Q a.txt b.txt`},
		{"cmd copy switch", winCmd, `copy /Q a.txt b.txt`},
		{"cmd del switch", winCmd, `del /Q a.txt`},
		{"ps unlisted param", winPS, `Copy-Item -Bogus a.txt b.txt`},
		{"ps listed param", winPS, `Copy-Item -Path a.txt -Destination b.txt`},
	}
	for _, c := range cases {
		r := Extract(sh(c.cmd), c.o)
		t.Logf("%-32s fullyKnown=%v unknowns=%v", c.n, r.FullyKnown(), r.Unknowns)
	}
}
