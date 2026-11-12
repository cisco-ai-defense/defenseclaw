// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"context"
	"os"
	"strings"
	"sync"
	"testing"
)

// openClawCombinedSpelling is an openclaw.json written the way OpenClaw's
// JSON5 reader accepts it, with every spelling at once: LF lines, the U+2028
// and U+2029 separators, line and block comments, single quotes, bare keys, a
// hexadecimal port and trailing commas.
const openClawCombinedSpelling = "// my OpenClaw settings\u2028" +
	"/* block\ncomment */\n" +
	"{\n" +
	"  /* gateway */ gateway: { port: 0x4965, }, " +
	"  agents: { defaults: { model: { primary: 'first', }, }, }, " +
	"  plugins: { entries: { 'somebody-else': { enabled: true, }, }, },\n" +
	"}\n"

// Setup runs again on every gateway start, so an uninstall follows several
// setups. Whatever the number, an openclaw.json nobody edited gets its
// pre-setup bytes back.
func TestOpenClawUninstallRestoresPreSetupBytesAfterRepeatedSetups(t *testing.T) {
	for _, setups := range []int{1, 2, 3, 5} {
		for cycle := 0; cycle < 3; cycle++ {
			_, configPath, opts := openClawJSON5Fixture(t, t.TempDir())
			if err := os.WriteFile(configPath, []byte(openClawCombinedSpelling), 0o644); err != nil {
				t.Fatal(err)
			}
			c := NewOpenClawConnector()
			for i := 0; i < setups; i++ {
				if err := c.Setup(context.Background(), opts); err != nil {
					t.Fatalf("setup %d of %d: %v", i+1, setups, err)
				}
			}
			if err := c.Teardown(context.Background(), opts); err != nil {
				t.Fatalf("Teardown after %d setups: %v", setups, err)
			}
			if got := mustReadFileString(t, configPath); got != openClawCombinedSpelling {
				t.Fatalf("after %d setups, uninstall left other bytes.\nwant %q\n got %q", setups, openClawCombinedSpelling, got)
			}
		}
	}
}

// A gateway start runs Setup while the setup command (or another start) may
// still be inside its own registration of the plugin. The record that makes
// uninstall exact has to survive that: overlapping setups end in the same
// exact restore as one.
func TestOpenClawUninstallRestoresPreSetupBytesAfterOverlappingSetups(t *testing.T) {
	for cycle := 0; cycle < 40; cycle++ {
		_, configPath, opts := openClawJSON5Fixture(t, t.TempDir())
		if err := os.WriteFile(configPath, []byte(openClawCombinedSpelling), 0o644); err != nil {
			t.Fatal(err)
		}
		c := NewOpenClawConnector()
		var wg sync.WaitGroup
		errs := make(chan error, 3)
		start := make(chan struct{})
		for i := 0; i < 3; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				errs <- c.registerPlugin(opts)
			}()
		}
		close(start)
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatalf("cycle %d: registering the plugin: %v", cycle, err)
			}
		}
		if err := c.Teardown(context.Background(), opts); err != nil {
			t.Fatalf("cycle %d: Teardown: %v", cycle, err)
		}
		if got := mustReadFileString(t, configPath); got != openClawCombinedSpelling {
			t.Fatalf("cycle %d: overlapping setups, then uninstall left other bytes.\nwant %q\n got %q", cycle, openClawCombinedSpelling, got)
		}
	}
}

// OpenClaw saves openclaw.json itself while it runs. The file is then no
// longer the one DefenseClaw wrote, so uninstall keeps OpenClaw's change and
// takes out only DefenseClaw's settings, and says so; an unedited file
// restores exactly and says nothing.
func TestOpenClawUninstallSaysWhenItKeptAFileOpenClawSaved(t *testing.T) {
	for _, edited := range []bool{false, true} {
		_, configPath, opts := openClawJSON5Fixture(t, t.TempDir())
		if err := os.WriteFile(configPath, []byte(openClawCombinedSpelling), 0o644); err != nil {
			t.Fatal(err)
		}
		var notice bytes.Buffer
		previous := openClawTeardownNoticeOutput
		openClawTeardownNoticeOutput = &notice
		t.Cleanup(func() { openClawTeardownNoticeOutput = previous })

		c := NewOpenClawConnector()
		if err := c.registerPlugin(opts); err != nil {
			t.Fatalf("registering the plugin: %v", err)
		}
		if edited {
			saved := strings.Replace(mustReadFileString(t, configPath), "\"gateway\"", "\"meta\": {\"lastTouchedVersion\": \"x\"},\n  \"gateway\"", 1)
			if err := os.WriteFile(configPath, []byte(saved), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if err := c.Teardown(context.Background(), opts); err != nil {
			t.Fatalf("edited=%v: Teardown: %v", edited, err)
		}
		got := mustReadFileString(t, configPath)
		switch {
		case edited && (!strings.Contains(got, "lastTouchedVersion") || openClawConfigRegistersDefenseClaw(configPath)):
			t.Fatalf("an OpenClaw save was lost or DefenseClaw stayed registered:\n%s", got)
		case edited && !strings.Contains(notice.String(), configPath):
			t.Fatalf("uninstall kept a changed file without saying so: %q", notice.String())
		case !edited && (got != openClawCombinedSpelling || notice.Len() != 0):
			t.Fatalf("an unedited file did not restore quietly: notice %q\n got %q", notice.String(), got)
		}
	}
}
