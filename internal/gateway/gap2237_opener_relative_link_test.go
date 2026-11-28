// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"os"
	"runtime"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

func TestGAP2237KeyWriteBelowOpenerRelativeLinkIsUnknown(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged POSIX gateway")
	}
	kf := "authorized_" + "keys"
	keys := []string{gap2203KeysRule}
	for _, pack := range []string{"default", "strict"} {
		t.Run(pack, func(t *testing.T) {
			api, actor, home, app := gap0545API(t, "claudecode", pack)
			actorRows := []struct {
				command, action string
				rules           []string
			}{
				{"exec 3< /sandbox && echo k >> /dev/fd/3/.ssh/" + kf, "block", keys},
				{"exec 3< /sandbox && echo k >> /proc/self/fd/3/.ssh/" + kf, "block", keys},
				{"echo k >> /proc/thread-self/fd/3/.ssh/" + kf, "block", keys},
				{"echo k >> /proc/self/task/4242/root/sandbox/.ssh/" + kf, "block", keys},
				{"echo k >> /proc/self/task/4242/cwd/.ssh/" + kf, "block", keys},
				{"echo k >> /proc/self/task/4242/fd/3/.ssh/" + kf, "block", keys},
				{"echo m > /dev/fd/1", "allow", nil},
				{"echo m > /proc/self/fd/2", "allow", nil},
				{"echo m > /proc/self/task/4242/fd/3", "allow", nil},
				{"echo m > /proc/self/fd/3/notes.txt", "allow", nil},
			}
			for _, row := range actorRows {
				action, rules := gap2227Hook(t, api, actor, sandboxauth.SandboxHome+"/app", row.command, true)
				if action != row.action || !slices.Equal(rules, row.rules) {
					t.Errorf("actor %q: %s %v, want %s %v", row.command, action, rules, row.action, row.rules)
				}
			}
			laptopRows := []struct {
				command, action string
				rules           []string
			}{
				{"exec 3< " + home + " && echo k >> /dev/fd/3/.ssh/" + kf, "block", keys},
				{"exec 3< " + home + " && echo k >> /proc/self/fd/3/.ssh/" + kf, "block", keys},
				{"echo k >> /proc/self/task/4242/root" + home + "/.ssh/" + kf, "block", keys},
				{"echo m > /dev/fd/1", "allow", nil},
				{"echo m > /proc/self/fd/2", "allow", nil},
			}
			for _, row := range laptopRows {
				if runtime.GOOS != "linux" && row.command != laptopRows[0].command {
					continue
				}
				action, rules := gap2227Hook(t, api, context.Background(), app, row.command, false)
				if action != row.action || !slices.Equal(rules, row.rules) {
					t.Errorf("laptop %q: %s %v, want %s %v", row.command, action, rules, row.action, row.rules)
				}
			}
		})
	}
}
