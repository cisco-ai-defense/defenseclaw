package hookpaths

import (
	"strings"
	"testing"
)

// newItemSpellings are spellings of the -ItemType parameter that PowerShell
// binds to it (checked natively on Windows PowerShell 5.1 by the
// rel-1-0-10:GAP-0849 review, transformations T0 to T9): the name, the Type
// alias, prefixes, every dash form, upper case and -ItemType: with the value
// in the next word.
var newItemSpellings = []struct{ id, spelling string }{
	{"T0-identity", "-ItemType "},
	{"T1-alias-prefix-ty", "-Ty "},
	{"T2-alias-prefix-typ", "-Typ "},
	{"T3-endash-name", "–ItemType "},
	{"T4-colon-space", "-ItemType: "},
	{"T5-upper", "-ITEMTYPE "},
	{"T6-prefix-it", "-it "},
	{"T7-alias-type", "-Type "},
	{"T8-emdash-alias", "—Type "},
	{"T9-prefix-itemt", "-itemt "},
	{"T10-hbar-name", "―ItemType "},
	{"T11-colon-inline", "-ItemType:"},
}

// TestNewItemItemTypeBindsAsPowerShellDoes: the rows of
// TestNewItemMayMakeLinkOnlyForALinkItemType that name an item type, under
// every spelling PowerShell binds to -ItemType. A link item type stays a
// possible link, and a file or a folder stays none, in every spelling
// (rel-1-0-10:GAP-0849: five of them read as no item type, so a link was
// taken for a file).
func TestNewItemItemTypeBindsAsPowerShellDoes(t *testing.T) {
	rows := []struct {
		command string
		want    bool
	}{
		{`New-Item -Path .\e.txt -ItemType File -Force`, false},
		{`New-Item .\logs -ItemType Directory`, false},
		{`New-Item -Path .\e.txt -ItemType 'file' -Value 'hello world'`, false},
		{`New-Item -Path .\l -ItemType SymbolicLink -Target .\a`, true},
		{`New-Item -Path .\l -ItemType Junction -Target .\a`, true},
		{`New-Item -Path .\l -ItemType HardLink -Value .\a`, true},
		{`New-Item -Path .\l -ItemType Thing`, true},
	}
	for _, spelling := range newItemSpellings {
		for _, row := range rows {
			command := strings.Replace(row.command, "-ItemType ", spelling.spelling, 1)
			if got := CommandMayMakeLink(command); got != row.want {
				t.Errorf("%s: CommandMayMakeLink(%q) = %v, want %v", spelling.id, command, got, row.want)
			}
		}
	}
}

// TestNewItemBindingThisReadingCannotFollowMayMakeALink: a parameter word
// that binds to no known New-Item parameter or to more than one (-t is Type
// and Target), an item type PowerShell matches as a pattern or by a prefix
// of a link type, an item type from pipeline input, and a positional word
// past -Path keep the conservative answer; the prefixes PowerShell reads as
// a file or a folder do not.
func TestNewItemBindingThisReadingCannotFollowMayMakeALink(t *testing.T) {
	for _, tc := range []struct {
		name, command string
		want          bool
	}{
		{"ambiguous -t (Type or Target)", `New-Item -Path .\e.txt -t File`, true},
		{"ambiguous -i", `New-Item -Path .\e.txt -i File`, true},
		{"unknown parameter", `New-Item -Path .\e.txt -Kind File`, true},
		{"a number in a parameter place is a second positional", `New-Item .\e.txt -1 -ItemType File`, true},
		{"link type prefix", `New-Item -Path .\l -ItemType s -Target .\a`, true},
		{"wildcard type", `New-Item -Path .\l -ItemType *link -Target .\a`, true},
		{"empty inline value at the end", `New-Item -Path .\l -Target .\a -ItemType:`, true},
		{"second positional word", `New-Item .\e.txt .\f.txt -ItemType File`, true},
		{"pipeline input", `Get-Item .\x | New-Item -Path .\e.txt -ItemType File`, true},
		{"pipeline input, no item type", `Get-Item .\x | New-Item -Path .\e.txt`, true},
		{"file prefix", `New-Item -Path .\e.txt -ItemType f`, false},
		{"directory prefix", `New-Item -Path .\logs -ItemType dir`, false},
		{"container", `New-Item -Path .\logs -ItemType Container`, false},
		{"common parameters", `New-Item -Path .\e.txt -ItemType File -ErrorAction Stop -ev err -WhatIf -Force`, false},
		{"pipeline producer only", `New-Item -Path .\e.txt -ItemType File | Out-Null`, false},
	} {
		if got := CommandMayMakeLink(tc.command); got != tc.want {
			t.Errorf("%s: CommandMayMakeLink(%q) = %v, want %v", tc.name, tc.command, got, tc.want)
		}
	}
}

// TestNewItemSpellingsReadAsThePlainLink: the link reading of a command
// (commandLinks) is the same in every spelling of -ItemType, also when the
// shell parser cannot read the command (rel-1-0-10:GAP-0849, cert L73: a
// first statement that assigns a parenthesized expression left only the
// literal -ItemType text to find the link, so -Ty, an en dash and -ItemType:
// read as no link).
func TestNewItemSpellingsReadAsThePlainLink(t *testing.T) {
	home := t.TempDir()
	const computed = `$t = Join-Path $env:TEMP ("gap0849-" + [guid]::NewGuid()); `
	rows := []string{
		`New-Item -ItemType SymbolicLink -Path ./l -Target $t; Add-Content ./l marker`,
		`New-Item -ItemType SymbolicLink -Path ./l -Target ./a; Add-Content ./l marker`,
		`New-Item -ItemType Junction -Path ./l -Target $t`,
		`New-Item -ItemType Directory -Path ./d; Add-Content ./d/f.txt marker`,
		`New-Item -ItemType File -Path ./f.txt; Add-Content ./f.txt marker`,
	}
	type reading struct{ known, unread, opaque bool }
	read := func(command string) reading {
		links := commandLinks(command, home, home, nil, false, false)
		return reading{links.known, links.unread, links.opaque}
	}
	for _, row := range rows {
		for _, prefix := range []string{"", computed} {
			plain := prefix + row
			want := read(plain)
			if prefix != "" && strings.Contains(row, "SymbolicLink -Path ./l -Target $t") && want.known {
				t.Errorf("%q: the plain link reads as known, want unread", plain)
			}
			for _, spelling := range newItemSpellings {
				command := strings.Replace(plain, "-ItemType ", spelling.spelling, 1)
				if got := read(command); got != want {
					t.Errorf("%s: commandLinks(%q) = %+v, want the plain reading %+v", spelling.id, command, got, want)
				}
			}
		}
	}
}

// TestNewItemInAnotherProgramsTextReadsByItsWords: a New-Item spelling the
// PowerShell reading does not read as a call (a PowerShell script in a
// bash string another program runs) is read from its words for the link
// reading. A folder or a file stays no link, as before; a link stays a
// possible link in every spelling (rel-1-0-10:GAP-0849: the first fix took
// every such New-Item for a possible link, and the owner A/B showed benign
// folder scripts sent to a Windows host blocked; a parenthesized path is one
// word, and a bracket left open keeps the possible link).
func TestNewItemInAnotherProgramsTextReadsByItsWords(t *testing.T) {
	rows := []struct {
		command string
		want    bool
	}{
		{`ssh h "powershell -c 'New-Item -ItemType Directory -Force $o | Out-Null; Get-ChildItem $o'"`, false},
		{`ssh h "pwsh -c \"New-Item -ItemType Directory -Force -Path C:\x\y 2>&1\""`, false},
		{`run h 'New-Item "$root\a.stop" -ItemType File -Force; exit 0'`, false},
		{`run h '$w = (New-Item -ItemType Directory -Path $out -Force); Set-Content $w\f.txt x'`, false},
		{`ssh h "powershell -c 'New-Item -ItemType SymbolicLink -Path .\l -Target $t'"`, true},
		{`ssh h "powershell -c 'New-Item -ItemType Junction -Path .\l -Target .\a'"`, true},
		{`run h 'New-Item -Path .\l -ItemType $kind -Target .\a'`, true},
		{"cat > s.ps1 <<'EOF'\nNew-Item -ItemType Directory -Force (Split-Path $out) | Out-Null\nEOF", false},
		{`run h 'New-Item -ItemType File -Path (Join-Path $d "a b.txt"; $x) -Force'`, false},
		{`run h 'New-Item -ItemType SymbolicLink -Path (Join-Path $d l) -Target $t'`, true},
		{`run h 'New-Item (Join-Path $d l) .\x -ItemType Directory'`, true},
		{`run h 'New-Item -ItemType Directory -Path (Join-Path $d l'`, true},
	}
	for _, spelling := range newItemSpellings {
		for _, row := range rows {
			command := strings.Replace(row.command, "-ItemType ", spelling.spelling, 1)
			if got := commandNewItemLinkSpelled(command); got != row.want {
				t.Errorf("%s: commandNewItemLinkSpelled(%q) = %v, want %v", spelling.id, command, got, row.want)
			}
		}
	}
}
