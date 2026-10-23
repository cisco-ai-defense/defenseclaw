// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"golang.org/x/sys/windows"
)

// The administrator's entries in the shared machine hooks.json come back from
// a guard rebuild byte for byte: the rebuild edits only DefenseClaw's own
// registration, however the file is formatted.
func TestWindowsCursorMachineGuardRebuildKeepsForeignHooksBytes(t *testing.T) {
	const hook = `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe`
	foreignA := `{"command": "C:\\Tools\\audit.cmd 2>&1 && echo \u00e9", "timeout": 5.0, "type":"command"}`
	foreignB := `{ "type" : "command" , "command" : "admin <one> & two" }`
	extra := `"x-admin": {"note": "keep  me", "n": 1e3}`
	for _, damage := range []struct {
		name     string
		document func(installed string) string
		foreign  []string
	}{
		{
			name: "registration removed",
			document: func(string) string {
				return "{\n\t\"hooks\": {\n\t\t\"beforeShellExecution\": [ " + foreignA + " ],\n\t\t\"adminEvent\":[" + foreignB +
					"]\n\t},\n\t\"version\": 1,\n\t" + extra + "\n}\n"
			},
			foreign: []string{foreignA, `"adminEvent":[` + foreignB + `]`, extra},
		},
		{
			name: "registration fails open",
			document: func(installed string) string {
				edited := strings.ReplaceAll(installed, `"failClosed": true`, `"failClosed": false`)
				edited = strings.Replace(edited, `"hooks": {`, `"hooks": {`+"\n    \"adminEvent\":["+foreignB+"],", 1)
				return strings.Replace(edited, "{", "{\n  "+extra+",", 1)
			},
			foreign: []string{`"adminEvent":[` + foreignB + `]`, extra},
		},
	} {
		for _, enrolled := range []bool{false, true} {
			for _, removeAdapter := range []bool{false, true} {
				name := damage.name + map[bool]string{false: "/empty", true: "/Alice"}[enrolled] +
					map[bool]string{false: "/adapter intact", true: "/adapter missing"}[removeAdapter]
				t.Run(name, func(t *testing.T) {
					paths := installWindowsCursorStandaloneGuardForTest(t, hook, enrolled)
					targetsBefore, _, err := ReadWindowsCursorManagedPolicyTargets()
					if err != nil {
						t.Fatal(err)
					}
					installed, err := os.ReadFile(paths.Hooks)
					if err != nil {
						t.Fatal(err)
					}
					document := damage.document(string(installed))
					if document == string(installed) {
						t.Fatal("fixture did not change hooks.json")
					}
					if err := windowsManagedPolicyWriter(paths.Hooks, []byte(document), true); err != nil {
						t.Fatal(err)
					}
					if removeAdapter {
						if err := os.Remove(paths.Adapter); err != nil {
							t.Fatal(err)
						}
					}
					if restored, err := RestoreWindowsCursorManagedAdapter(hook); err != nil || !restored {
						t.Fatalf("rebuild: restored=%t err=%v", restored, err)
					}
					after, err := os.ReadFile(paths.Hooks)
					if err != nil {
						t.Fatal(err)
					}
					for _, foreign := range damage.foreign {
						if !bytes.Contains(after, []byte(foreign)) {
							t.Fatalf("the rebuild changed the administrator's bytes %q:\n%s", foreign, after)
						}
					}
					if err := connector.VerifyWindowsCursorEnterpriseHooks(after, paths.Adapter, "closed"); err != nil {
						t.Fatalf("rebuilt registration is not the closed guard: %v", err)
					}
					targets, active, err := ReadWindowsCursorManagedPolicyTargets()
					if err != nil || !active || !slices.Equal(targets, targetsBefore) {
						t.Fatalf("rebuilt guard: active=%t targets=%v (want %v) err=%v", active, targets, targetsBefore, err)
					}
					if again, err := RestoreWindowsCursorManagedAdapter(hook); err != nil || again {
						t.Fatalf("second repair of a healthy guard: restored=%t err=%v", again, err)
					}
				})
			}
		}
	}
}

// An administrator saves hooks.json from another process, without the
// DefenseClaw lock, at any moment while a guard rebuild runs. No save is ever
// lost: when the rebuild returns, hooks.json holds the save, with the guard
// merged in or (when the save came last) as the administrator wrote it.
func TestWindowsCursorMachineGuardRebuildConcurrentWriterKeepsEverySave(t *testing.T) {
	const hook = `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe`
	paths := installWindowsCursorStandaloneGuardForTest(t, hook, true)
	document := func(name string) []byte {
		return []byte(fmt.Sprintf(`{"version":1,"hooks":{"adminEvent":[{"type":"command","command":%q}]}}`, name))
	}
	busy := func(err error) bool {
		return errors.Is(err, windows.ERROR_SHARING_VIOLATION) || errors.Is(err, windows.ERROR_ACCESS_DENIED) ||
			errors.Is(err, windows.ERROR_LOCK_VIOLATION)
	}
	retry := func(write func() error) error {
		var err error
		for attempt := 0; attempt < 2000; attempt++ {
			if err = write(); err == nil || !busy(err) {
				return err
			}
			time.Sleep(time.Millisecond)
		}
		return err
	}
	// The administrator's editor either rewrites the file in place or saves
	// a temporary file over it.
	save := func(data []byte, inPlace bool) error {
		if inPlace {
			return retry(func() error { return os.WriteFile(paths.Hooks, data, 0o600) })
		}
		temp := paths.Hooks + ".admin-save"
		if err := os.WriteFile(temp, data, 0o600); err != nil {
			return err
		}
		return retry(func() error { return os.Rename(temp, paths.Hooks) })
	}
	damage := func(iteration int) {
		t.Helper()
		if err := save(document(fmt.Sprintf("admin-damage-%d", iteration)), false); err != nil {
			t.Fatal(err)
		}
		if iteration%2 == 1 {
			if err := os.Remove(paths.Adapter); err != nil && !errors.Is(err, os.ErrNotExist) {
				t.Fatal(err)
			}
		}
	}
	// Spread the save over the whole rebuild.
	damage(1)
	started := time.Now()
	if restored, err := RestoreWindowsCursorManagedAdapter(hook); err != nil || !restored {
		t.Fatalf("baseline rebuild: restored=%t err=%v", restored, err)
	}
	window := time.Since(started)*3/2 + time.Millisecond
	const iterations = 150
	for iteration := 0; iteration < iterations; iteration++ {
		damage(iteration)
		saved := fmt.Sprintf(`{"type":"command","command":"admin-save-%d"}`, iteration)
		delay := time.Duration(rand.Int64N(int64(window)))
		done := make(chan error, 1)
		go func() {
			time.Sleep(delay)
			done <- save(document(fmt.Sprintf("admin-save-%d", iteration)), iteration%3 == 0)
		}()
		_, rebuildErr := RestoreWindowsCursorManagedAdapter(hook)
		if err := <-done; err != nil {
			t.Fatalf("iteration %d: administrator save: %v", iteration, err)
		}
		after, err := os.ReadFile(paths.Hooks)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(after, []byte(saved)) {
			t.Fatalf("iteration %d (save %s into a %s rebuild, rebuild error %v): the rebuild discarded the administrator's save:\n%s",
				iteration, delay, window, rebuildErr, after)
		}
	}
	if _, err := RestoreWindowsCursorManagedAdapter(hook); err != nil {
		t.Fatalf("quiet repair after the writer stopped: %v", err)
	}
	after, err := os.ReadFile(paths.Hooks)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(after, []byte(fmt.Sprintf(`"admin-save-%d"`, iterations-1))) {
		t.Fatalf("the quiet repair lost the last save:\n%s", after)
	}
	if _, active, err := ReadWindowsCursorManagedPolicyTargets(); err != nil || !active {
		t.Fatalf("guard after the quiet repair: active=%t err=%v", active, err)
	}
	entries, err := os.ReadDir(filepath.Dir(paths.Hooks))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".defenseclaw-policy-") {
			t.Fatalf("the rebuild left a temporary file behind: %s", entry.Name())
		}
	}
}
