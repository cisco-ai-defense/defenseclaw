//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/hookguard"
)

// The per-user Devin command Setup renders, split with Devin's word rules
// (posixHookCommandSplit) and started the way Devin starts it, blocks a
// launcher that is missing or a folder on the events Devin can block
// (exit 2, the sentence on stdout), and passes a working launcher's answer
// through on every event (rel-1-0-6 GAP-0676). The profile path has a space
// and a quote.
func TestWindowsDevinCommandBlocksALauncherThatCannotStart(t *testing.T) {
	old := windows.SetErrorMode(windows.SEM_FAILCRITICALERRORS | windows.SEM_NOGPFAULTERRORBOX)
	t.Cleanup(func() { windows.SetErrorMode(old) })
	image, err := os.ReadFile(guiSubsystemCopyOfTestBinary(t))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	t.Log("ROW| form | launcher | invocation | exit | stdout | stderr | ms |")
	for _, shape := range []string{"working", "missing", "folder"} {
		launcher := makeLauncherShape(t, filepath.Join(root, "dcw std1's", shape, ".local", "bin"), shape, image)
		setHookBinaryOverride(t, launcher)
		hookScript := windowsDevinBashHookCommand(launcher)
		for _, event := range devinHookEvents {
			command := devinHookCommandForEvent("windows", SetupOpts{}, hookScript, event)
			guarded := strings.Contains(command, " "+hookguard.DevinSubcommand+" "+event+" ")
			if guarded != hookguard.DevinBlockEvent(event) || !guarded && command != hookScript {
				t.Fatalf("%s %s: %q; want the guard only on a block event", shape, event, command)
			}
			if !guarded && shape != "working" {
				continue // the direct start of a launcher that cannot start: Devin's own start error
			}
			word, rest, ok := posixHookCommandSplit(command)
			if !ok || !filepath.IsAbs(filepath.FromSlash(word)) {
				t.Fatalf("%s %s: %q does not split into an absolute program (%q)", shape, event, command, word)
			}
			argv := append([]string{filepath.FromSlash(word)}, strings.Fields(rest)...)
			payload := `{"session_id":"g676","hook_event_name":"` + event + `","tool_name":"exec","tool_input":{"command":"echo ok"}}`
			result := runLauncherStartCommand(t, func(ctx context.Context) *exec.Cmd {
				return exec.CommandContext(ctx, argv[0], argv[1:]...)
			}, payload, 30*time.Second)
			t.Log(result.row("devin "+event, shape, "devin words"))
			switch {
			case shape == "working":
				if result.hung || result.exit != 0 || !strings.Contains(result.stdout, launcherStartRan) ||
					!strings.Contains(result.stdout, `"args":"hook --connector devin"`) {
					t.Errorf("devin %s, working launcher: %+v; want the launcher's own answer", event, result)
				}
			case result.hung || result.exit != 2 || !strings.Contains(result.stdout, hookguard.LauncherMessage("Devin", shape == "missing")):
				t.Errorf("devin %s, %s launcher: %+v; want exit 2 with the Devin sentence", event, shape, result)
			}
		}
	}
}
