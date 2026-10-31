// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// A package upgrade renamed the sandbox LaunchAgent (its label carries the
// gateway's tag) while the daemon of the earlier label ran a sandbox. Once
// that sandbox stopped, the daemon waits for a restart; the installed label
// is not loaded in the account's domain, so the restart boots the earlier
// job out and bootstraps the installed one before its kickstart, instead of
// failing with "Could not find service" (GAP-0049).
func TestLauncherRestartLoadsTheRenamedAgentInPlaceOfTheEarlierLabel(t *testing.T) {
	const (
		oldTag = "f7cfc64e0bae"
		newTag = "d6a1a9ccefd7"
	)
	oldLabel := openshell.SandboxAgentBase + "." + oldTag
	newLabel := openshell.SandboxAgentBase + "." + newTag
	oldGateway := openshell.GatewayAgentBase + "." + oldTag
	newGateway := openshell.GatewayAgentBase + "." + newTag
	dir := t.TempDir()
	for _, label := range []string{newLabel, newGateway} {
		if err := os.WriteFile(filepath.Join(dir, label+".plist"), []byte("<plist/>"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	oldDir := launcherAgentsDir
	launcherAgentsDir = dir
	t.Cleanup(func() { launcherAgentsDir = oldDir })

	loaded := map[string]string{
		oldLabel:   "state = running\n",
		oldGateway: "state = running\n",
	}
	var calls []string
	old := launcherRun
	launcherRun = func(_ context.Context, name string, args ...string) (string, error) {
		line := strings.Join(args, " ")
		calls = append(calls, line)
		if name != launcherLaunchctl {
			t.Fatalf("unexpected command %q", name)
		}
		switch {
		case line == "print gui/501":
			var listing []string
			for label := range loaded {
				listing = append(listing, "\t0\t0\t"+label)
			}
			return "gui/501 = {\n\tservices = {\n" + strings.Join(listing, "\n") + "\n\t}\n}", nil
		case line == "print user/501":
			return "", errors.New("exit status 113")
		case strings.HasPrefix(line, "print gui/501/"):
			label := strings.TrimPrefix(line, "print gui/501/")
			if state, ok := loaded[label]; ok {
				return state, nil
			}
			return "Could not find service \"" + label + "\" in domain for user gui: 501", errors.New("exit status 113")
		case strings.HasPrefix(line, "bootout gui/501/"):
			delete(loaded, strings.TrimPrefix(line, "bootout gui/501/"))
			return "", nil
		case strings.HasPrefix(line, "bootstrap gui/501 "):
			plist := strings.TrimPrefix(line, "bootstrap gui/501 ")
			loaded[strings.TrimSuffix(filepath.Base(plist), ".plist")] = "state = not running\n"
			return "", nil
		case strings.HasPrefix(line, "kickstart -k gui/501/"):
			label := strings.TrimPrefix(line, "kickstart -k gui/501/")
			if _, ok := loaded[label]; !ok {
				return "Could not find service \"" + label + "\" in domain for user gui: 501", errors.New("exit status 113")
			}
			loaded[label] = "state = running\n"
			return "", nil
		}
		return "", nil
	}
	t.Cleanup(func() { launcherRun = old })

	if err := launcherRestartDaemon(context.Background(), "darwin", 501); err != nil {
		t.Fatalf("restart after the upgrade renamed the agent: %v\ncalls:\n%s", err, strings.Join(calls, "\n"))
	}
	bootout := slices.Index(calls, "bootout gui/501/"+oldLabel)
	bootstrap := slices.Index(calls, "bootstrap gui/501 "+filepath.Join(dir, newLabel+".plist"))
	kick := slices.Index(calls, "kickstart -k gui/501/"+newLabel)
	if bootout < 0 || bootstrap < 0 || kick < 0 || !(bootout < bootstrap && bootstrap < kick) {
		t.Fatalf("want bootout of %s, bootstrap of %s, then its kickstart; calls:\n%s", oldLabel, newLabel, strings.Join(calls, "\n"))
	}
	// The account's OpenShell gateway of the earlier label keeps running:
	// the root lifecycle replaces it once no sandbox holds it.
	if _, ok := loaded[oldGateway]; !ok || slices.Contains(calls, "bootout gui/501/"+oldGateway) {
		t.Fatalf("the earlier gateway job was touched; calls:\n%s", strings.Join(calls, "\n"))
	}
	if slices.Contains(calls, "bootstrap gui/501 "+filepath.Join(dir, newGateway+".plist")) {
		t.Fatalf("the restart loaded the gateway job; calls:\n%s", strings.Join(calls, "\n"))
	}
}

// A start (no daemon answers) leaves a sandbox job of an earlier label that
// runs to the lifecycle, as before: only a restart replaces it.
func TestLauncherStartLeavesARunningEarlierLabel(t *testing.T) {
	oldLabel := openshell.SandboxAgentBase + ".f7cfc64e0bae"
	newLabel := openshell.SandboxAgentBase + ".d6a1a9ccefd7"
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, newLabel+".plist"), []byte("<plist/>"), 0o644); err != nil {
		t.Fatal(err)
	}
	oldDir := launcherAgentsDir
	launcherAgentsDir = dir
	t.Cleanup(func() { launcherAgentsDir = oldDir })
	var calls []string
	old := launcherRun
	launcherRun = func(_ context.Context, _ string, args ...string) (string, error) {
		line := strings.Join(args, " ")
		calls = append(calls, line)
		switch line {
		case "print gui/501":
			return "gui/501 = {\n\tservices = {\n\t0\t0\t" + oldLabel + "\n\t}\n}", nil
		case "print user/501":
			return "", errors.New("exit status 113")
		case "print gui/501/" + oldLabel:
			return "state = running\n", nil
		}
		if strings.HasPrefix(line, "print gui/501/") {
			return "Could not find service", errors.New("exit status 113")
		}
		return "", nil
	}
	t.Cleanup(func() { launcherRun = old })
	_ = launcherStartDaemon(context.Background(), "darwin", 501)
	if slices.Contains(calls, "bootout gui/501/"+oldLabel) {
		t.Fatalf("a start booted out a running earlier label; calls:\n%s", strings.Join(calls, "\n"))
	}
}
