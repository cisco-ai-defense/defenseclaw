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
