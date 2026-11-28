package cli

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// GAP-0786: secrets set, rm and test take --mine only as a no-op, for
// scripts that pass it. It stays out of their help, the stub manifest and the
// docs in 1.0.11; secrets list --mine is a real filter and stays shown.
func TestSecretsMineNoOpFlagStaysHidden(t *testing.T) {
	root := newSubstrateSecretsCmd()
	seen := 0
	for _, sub := range root.Commands() {
		f := sub.Flags().Lookup("mine")
		if f == nil {
			continue
		}
		seen++
		if sub.Name() == "list" {
			if f.Hidden {
				t.Errorf("secrets list --mine is a filter and must show in help")
			}
			continue
		}
		if !f.Hidden {
			t.Errorf("secrets %s --mine is a no-op and must be hidden", sub.Name())
		}
		if strings.Contains(sub.UsageString(), "--mine") {
			t.Errorf("secrets %s help shows --mine:\n%s", sub.Name(), sub.UsageString())
		}
	}
	if seen < 4 {
		t.Errorf("only %d secrets subcommands carry --mine, want list, set, rm, test", seen)
	}
	docs, err := os.ReadFile("../../docs-site/content/docs/substrate/secrets.mdx")
	if err != nil {
		t.Fatal(err)
	}
	noop := regexp.MustCompile("secrets (set|rm|test|add)[^\n]*--mine")
	if m := noop.Find(docs); m != nil {
		t.Errorf("the docs show the no-op flag: %s", m)
	}
}
