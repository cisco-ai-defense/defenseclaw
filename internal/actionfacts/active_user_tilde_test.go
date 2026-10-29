package actionfacts

import (
	"strings"
	"testing"
)

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
		twin, prefixes, ok := ActiveUserTildeTwin(tc.command, home)
		if ok != tc.ok || twin != tc.twin || ok && strings.Contains(tc.command, "~dcku") && (len(prefixes) != 1 || prefixes[0] != "~dcku") {
			t.Errorf("%q: twin %q prefixes %q ok=%v, want %q ok=%v", tc.command, twin, prefixes, ok, tc.twin, tc.ok)
		}
	}
	// Git Bash expands ~<user> to the user's Windows profile as well.
	if twin, _, ok := ActiveUserTildeTwin("echo x > ~dcku/f", "C:/Users/dcku"); !ok || twin != "echo x > C:/Users/dcku/f" {
		t.Errorf("Windows home twin %q ok=%v", twin, ok)
	}
}

// GAP-2378 (checker p18 RV18-1): a directory login (user@domain) and a
// login that is not the home's base name (sssd /home/%d/%u) are
// tilde-prefixes of the active home too, matched without case; another
// user's login is not, and dd of=~/ is still read as the home.
func TestActiveUserTildeTwinReadsDirectoryLogins(t *testing.T) {
	for _, tc := range []struct {
		home, login, command, twin string
		ok                         bool
	}{
		{"/home/dcad-r103-eng1@dclab.test", "", "echo x > ~dcad-r103-eng1@dclab.test/.defenseclaw/hooks/f",
			"echo x > /home/dcad-r103-eng1@dclab.test/.defenseclaw/hooks/f", true},
		{"/home/dcad-r103-eng1@dclab.test", "", "cp a ~DCAD-R103-ENG1@DCLAB.TEST/.ssh/authorized_keys",
			"cp a /home/dcad-r103-eng1@dclab.test/.ssh/authorized_keys", true},
		{"/home/dcad-r103-eng1@dclab.test", "", "dd if=a.txt of=~/.defenseclaw/config.yaml",
			"dd if=a.txt of=/home/dcad-r103-eng1@dclab.test/.defenseclaw/config.yaml", true},
		{"/home/dcad-r103-eng1@dclab.test", "", "echo x > ~bob@dclab.test/f", "", false},
		{"/home/dclab.test/eng1", "eng1@dclab.test", "echo x > ~eng1@dclab.test/.defenseclaw/config.yaml",
			"echo x > /home/dclab.test/eng1/.defenseclaw/config.yaml", true},
		{"/home/dclab.test/eng1", "eng1@dclab.test", "echo x > ~eng1/f; cat '~eng1@dclab.test/g'",
			"echo x > /home/dclab.test/eng1/f; cat '~eng1@dclab.test/g'", true},
		{"/home/dclab.test/eng1", "", "echo x > ~eng1@dclab.test/f", "", false},
	} {
		var logins []string
		if tc.login != "" {
			logins = []string{tc.login}
		}
		twin, _, ok := ActiveUserTildeTwin(tc.command, tc.home, logins...)
		if ok != tc.ok || twin != tc.twin {
			t.Errorf("%s %q: twin %q ok=%v, want %q ok=%v", tc.home, tc.command, twin, ok, tc.twin, tc.ok)
		}
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
