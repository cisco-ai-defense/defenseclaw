// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

// rel-1-0-6:GAP-0880, GAP-0885 review 7: a call that only Bash reads (select,
// a here-string) is read from its arguments, and a command that is a piece of
// the call as written adds nothing to the judgment it had. A reading with the
// loop variable resolved is new, and stays when the call spells the same text
// somewhere that does not run: a comment, a quoted word, a here-document.
func TestSimpleCommandsOfABashOnlyCallKeepAReadingWhenItsTextIsSpelledElsewhere(t *testing.T) {
	const resolved = "sed -i x '/r/home/.defenseclaw/config.yaml'"
	const loop = "select u in $USER; do sed -i x /r/$u/.defenseclaw/config.yaml; break; done"
	for _, row := range []struct {
		name, command string
		resolved      bool
	}{
		{"as written", loop, true},
		{"text in a comment", loop + " # " + resolved, true},
		{"text in a double quoted word", loop + "; echo \"" + resolved + "\"", true},
		{"text in a single quoted word", loop + "; echo '" + resolved + "'", true},
		{"text in a here-document", loop + "; cat <<'EOF'\n" + resolved + "\nEOF", true},
		{"text in the word list", "select u in $USER '" + resolved + "'; do sed -i x /r/$u/.defenseclaw/config.yaml; break; done", true},
		{"list of other names", "select u in alice bob; do sed -i x /r/$u/notes.txt; break; done # " + resolved, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			raw, err := json.Marshal(map[string]string{"command": row.command})
			if err != nil {
				t.Fatal(err)
			}
			input := Input{Tool: "Bash", Args: raw, ActiveHome: "/r/home", CWD: "/r/home/proj", LoopBindsStraightLine: true}
			facts := Analyze(input)
			if facts.Parse.Status != StatusInvalid {
				t.Fatalf("the POSIX reader accepted %q (%v); the row needs a call it rejects", row.command, facts.Parse.Status)
			}
			var texts []string
			for _, simple := range SimpleCommands(input, facts) {
				if simple.EvaluationFailure != "" {
					t.Fatalf("evaluation failure %q for %s", simple.EvaluationFailure, row.command)
				}
				texts = append(texts, simple.Text)
			}
			if has := slices.Contains(texts, resolved); has != row.resolved {
				t.Errorf("reading of %q = %q: has the resolved reading %v, want %v", row.command, texts, has, row.resolved)
			}
			// The commands the call spells as written add nothing.
			for _, text := range texts {
				if strings.Contains(text, "$u") {
					t.Errorf("reading of %q holds %q, a piece of the call with the variable unresolved", row.command, text)
				}
			}
		})
	}
}
