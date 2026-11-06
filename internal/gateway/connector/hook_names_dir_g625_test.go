// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// TestGAP0625HookCommandNamesHookDir pins the text-only ownership rule: a
// command that names the managed hook directory is DefenseClaw's whatever
// shell form surrounds it; a command that does not is the user's.
func TestGAP0625HookCommandNamesHookDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix hook commands")
	}
	home := testenv.PrivateTempDir(t)
	data := filepath.Join(home, ".defenseclaw")
	hooks := filepath.Join(data, "hooks")
	script := filepath.Join(hooks, "hermes-hook.sh")
	if err := os.MkdirAll(hooks, 0o700); err != nil {
		t.Fatal(err)
	}
	owned := filepath.Join(hooks, "owned-file")
	if err := os.WriteFile(owned, []byte("hook\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	outsideLink := filepath.Join(home, "owned-link")
	if err := os.Symlink(owned, outsideLink); err != nil {
		t.Fatal(err)
	}
	managed := shellWord(filepath.Join(hooks, "hookX"))
	user := shellWord(filepath.Join(home, "user-hooks", "hookX"))
	forms := []struct {
		command string
		want    bool
	}{
		{"MANAGED", true},
		{"MANAGED --event pre_tool_call", true},
		{"env -i bash -lc MANAGED", true},
		{"bash -Ec MANAGED", true},
		{"bash -E -c MANAGED", true},
		{"bash -Bc MANAGED", true},
		{"bash --noediting -c MANAGED", true},
		{"bash -E MANAGED", true},
		{"exec bash -c MANAGED", true},
		{"command -p MANAGED", true},
		{"command bash -c MANAGED", true},
		{"env -i bash -Ec MANAGED", true},
		{"HOOK=MANAGED; source \"$HOOK\"", true},
		{"bash -Ec '/bin/printf %s MANAGED'", true},
		{"HOOK=MANAGED; eval \"$HOOK\"", true},
		{"HOOK=MANAGED; . \"$HOOK\"", true},
		{"f() { \"$HOOK\"; }; HOOK=MANAGED f", true},
		{"HOOK=MANAGED; f() { \"$HOOK\"; }; HOOK=/bin/true f", true},
		{"f() { local HOOK=MANAGED; \"$HOOK\"; }; f", true},
		{"/bin/printf %s MANAGED", true},
		{"bash -c '/bin/printf %s MANAGED'", true},
		{"MANAGED; USER", true},
		{"~/.defenseclaw/hooks/hookX", true},
		{"$HOME/.defenseclaw/hooks/hookX", true},
		{"\"${HOME}\"/.defenseclaw/hooks/hookX", true},
		{"'HOME/.defense'claw/hooks/hookX", true},
		{"HOME/.defenseclaw/sub/../hooks/hookX", true},
		{"HOME//.defenseclaw/./hooks/hookX", true},
		{"HOME/.defenseclaw/hooks", true},
		{"OUTSIDE_LINK", true},
		{"USER", false},
		{"HOOK=USER; \"$HOOK\" && /bin/true", false},
		{"HOME/.defenseclaw/hooks-old/hookX", false},
		{"HOME/.defenseclaw/hooksX", false},
		{"HOME/.defenseclaw-hooks/hookX", false},
		{"/bin/true HOME/.defenseclaw", false},
		{"~/bin/hookX", false},
		{"/usr/local/bin/hooks/hookX", false},
		{"", false},
	}
	for _, form := range forms {
		command := strings.NewReplacer("MANAGED", managed, "USER", user, "OUTSIDE_LINK", shellWord(outsideLink), "HOME/", home+"/").Replace(form.command)
		if got := hookCommandNamesHookDir(command, script); got != form.want {
			t.Errorf("hookCommandNamesHookDir(%q) = %v, want %v", form.command, got, form.want)
		}
	}
}
