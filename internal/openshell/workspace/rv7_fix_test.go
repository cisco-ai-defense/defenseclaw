package workspace

import "testing"

// RV7-1 (GAP-0802): an agent that wraps a replaced credential line one
// blank or unchanged line further out still gets the secret-context flag;
// a change far from the line, or only blank lines, does not.
func TestRV7WrapFurtherOutIsFlagged(t *testing.T) {
	sl := []SecretLine{{Rel: "config.py", Line: 3, Placeholder: "DC_SECRET_1"}}
	up := "import os\n\nTOKEN = \"DC_SECRET_1\"\n\ndef main():\n    print(TOKEN)\n"
	cases := []struct {
		name, up, agent string
		want            bool
	}{
		{"wrap-adjacent", up, "import os\nx = \"\"\"\nTOKEN = \"DC_SECRET_1\"\n\"\"\"\nsend(x)\n", true},
		{"wrap-over-blank", up, "import os\nx = \"\"\"\n\nTOKEN = \"DC_SECRET_1\"\n\n\"\"\"\nsend(x)\ndef main():\n    print(TOKEN)\n", true},
		{"wrap-over-unchanged", "import os\nA = 1\nTOKEN = \"DC_SECRET_1\"\nB = 2\n", "import os\nx = \"\"\"\nA = 1\nTOKEN = \"DC_SECRET_1\"\nB = 2\n\"\"\"\nsend(x)\n", true},
		{"only-blank-lines", up, "import os\n\n\n\nTOKEN = \"DC_SECRET_1\"\n\ndef main():\n    print(TOKEN)\n", false},
		{"change-far-away", up + "a = 1\nb = 2\nc = 3\nd = 4\ne = 5\nf = 6\n", up + "a = 1\nb = 2\nc = 3\nd = 4\ne = 5\nf = 7\n", false},
	}
	for _, c := range cases {
		out, _, _, near, why := translateReplaced([]byte(c.up), []byte(c.agent), sl, false)
		if why != "" || len(out) == 0 {
			t.Errorf("%s: why=%q, want the change to land", c.name, why)
			continue
		}
		if got := len(near) > 0; got != c.want {
			t.Errorf("%s: near=%v, want flag=%v", c.name, near, c.want)
		}
	}
}
