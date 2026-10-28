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
	// Git Bash expands ~<user> to the user's Windows profile as well.
	if twin, _, ok := ActiveUserTildeTwin("echo x > ~dcku/f", "C:/Users/dcku"); !ok || twin != "echo x > C:/Users/dcku/f" {
		t.Errorf("Windows home twin %q ok=%v", twin, ok)
	}
}

// GAP-2375: under a Windows drive home Git Bash maps /c/... and
// /cygdrive/c/... to C:/...; the twin spells word-leading mounts as drive
// paths and leaves double-quoted text, other words and POSIX homes alone.
func TestMSYSDrivePathTwinSpellsTheDrive(t *testing.T) {
	const home = "C:/Users/dcw"
	for _, tc := range []struct {
		command, twin string
		ok            bool
	}{
		{"rmdir /c/Users/dcw/.defenseclaw/hooks", "rmdir C:/Users/dcw/.defenseclaw/hooks", true},
		{"rm -rf /cygdrive/c/Users/dcw/.defenseclaw/hooks", "rm -rf C:/Users/dcw/.defenseclaw/hooks", true},
		{"cp a.txt '/d/x y' > /c/Users/dcw/out.txt", "cp a.txt 'D:/x y' > C:/Users/dcw/out.txt", true},
		{"cd /c && ls", "cd C: && ls", true},
		{`echo "/c/Users/dcw/f" x/c/y /cc/d /tmp/x`, "", false},
		{"cat <<EOF\n/c/Users/dcw/f\nEOF\n", "", false},
	} {
		twin, ok := MSYSDrivePathTwin(tc.command, home)
		if ok != tc.ok || twin != tc.twin {
			t.Errorf("%q: twin %q ok=%v, want %q ok=%v", tc.command, twin, ok, tc.twin, tc.ok)
		}
	}
	if _, ok := MSYSDrivePathTwin("rmdir /c/x", "/home/dcw"); ok {
		t.Error("a POSIX home has no MSYS drive mounts")
	}
	if got := MSYSDrivePath("/cygdrive/e"); got != "E:/" {
		t.Errorf("MSYSDrivePath(/cygdrive/e) = %q", got)
	}
}
