package actionfacts

import "testing"

// GAP-2378: bash expands ~<user> from the password database at a word start
// and after the first = of an assignment-shaped word; the twin spells the
// active user's prefix as the active home and leaves every other word as is.
func TestActiveUserTildeTwinSpellsTheActiveHome(t *testing.T) {
	const home = "/home/dcku"
	for _, tc := range []struct {
		command, twin string
		ok            bool
	}{
		{"echo x > ~dcku/.defenseclaw/hooks/f", "echo x > /home/dcku/.defenseclaw/hooks/f", true},
		{"cp a.txt ~dcku/.defenseclaw/config.yaml", "cp a.txt /home/dcku/.defenseclaw/config.yaml", true},
		{"dd if=a.txt of=~dcku/.defenseclaw/config.yaml", "dd if=a.txt of=/home/dcku/.defenseclaw/config.yaml", true},
		{"x=~dcku/f; cd ~dcku && ls", "x=/home/dcku/f; cd /home/dcku && ls", true},
		{"HOME=/tmp/h echo x > ~dcku/f", "HOME=/tmp/h echo x > /home/dcku/f", true},
		{`echo "~dcku/f" '~dcku/g' \~dcku/h ~dckux/i ~dcku"x"/j`, "", false},
		{"cat <<EOF > notes.md\n~dcku/.defenseclaw/config.yaml\nEOF\n", "", false},
		{"cat ~other/.defenseclaw/config.yaml", "", false},
		{"echo a:~dcku/f", "", false},
		{"echo ~dcku 'x'", "echo /home/dcku 'x'", true},
		{"dd if=a.txt of=~/.defenseclaw/config.yaml", "dd if=a.txt of=/home/dcku/.defenseclaw/config.yaml", true},
		{"HOME=/tmp/h dd if=a.txt of=~/f", "", false},
		{"echo ~/f", "", false},
	} {
		twin, user, ok := ActiveUserTildeTwin(tc.command, home)
		if ok != tc.ok || twin != tc.twin || ok && user != "dcku" {
			t.Errorf("%q: twin %q user %q ok=%v, want %q ok=%v", tc.command, twin, user, ok, tc.twin, tc.ok)
		}
	}
	if _, _, ok := ActiveUserTildeTwin("echo x > ~dcku/f", "C:/Users/dcku"); ok {
		t.Error("a Windows home has no password-database tilde-prefix twin")
	}
}
