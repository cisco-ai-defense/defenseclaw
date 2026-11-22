package gateway

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// TestACPPowerShellQuotingRoundTrips checks that an ACP argument or env value
// quoted for PowerShell is one literal that reads back as the value exactly,
// whatever the agent put in it: every single quote PowerShell honors (the
// apostrophe and U+2018 to U+201B) is doubled, and the expansion characters
// stay inert inside the literal.
func TestACPPowerShellQuotingRoundTrips(t *testing.T) {
	quotes := []rune{'\'', '\u2018', '\u2019', '\u201a', '\u201b'}
	values := []string{
		"two words",
		"C:\\Program Files\\x",
		"",
		"plain",
		"a" + string('$') + "(b)",
		string('`') + "n" + string('`') + "$",
		"line1\nline2\r\n",
		"; & | > " + string('$') + "env:X",
		"\"double\"",
	}
	for _, q := range quotes {
		values = append(values,
			string(q),
			"a"+string(q)+"b",
			string(q)+"; x "+string(q),
			string(q)+string(q)+string(q),
		)
	}
	for _, value := range values {
		for _, render := range []struct {
			name string
			fn   func(string, string) string
		}{{"word", acpQuoteWord}, {"always", acpQuoteAlways}} {
			got := render.fn(value, "windows")
			if render.name == "word" && acpPlainWord.MatchString(value) {
				if got != value {
					t.Errorf("acpQuoteWord(%q) = %q, want the plain word unchanged", value, got)
				}
				continue
			}
			if got != managed.PowerShellLiteral(value) {
				t.Errorf("%s(%q) = %q, want managed.PowerShellLiteral %q", render.name, value, got, managed.PowerShellLiteral(value))
				continue
			}
			runes := []rune(got)
			if len(runes) < 2 || runes[0] != '\'' || runes[len(runes)-1] != '\'' {
				t.Errorf("%s(%q) = %q, not one single-quoted literal", render.name, value, got)
				continue
			}
			body := string(runes[1 : len(runes)-1])
			// The literal does not end early: in the body every quote
			// character comes in identical pairs.
			inner := []rune(body)
			for i := 0; i < len(inner); i++ {
				if strings.ContainsRune(string(quotes), inner[i]) {
					if i+1 >= len(inner) || inner[i+1] != inner[i] {
						t.Errorf("%s(%q) = %q: quote at %d is not doubled", render.name, value, got, i)
						break
					}
					i++
				}
			}
			if back := managed.PowerShellLiteralValue(body); back != value {
				t.Errorf("%s(%q) = %q reads back as %q", render.name, value, got, back)
			}
		}
	}
	// An ordinary value renders as before the shared rule.
	if got, want := acpQuoteWord("it's", "windows"), "'it''s'"; got != want {
		t.Errorf("acpQuoteWord(it's) = %q, want %q", got, want)
	}
	if got, want := acpQuoteAlways("v", "windows"), "'v'"; got != want {
		t.Errorf("acpQuoteAlways(v) = %q, want %q", got, want)
	}
}
