// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"os"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

func TestFIX2223CReviewHoldsActor(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged POSIX gateway")
	}
	key := "authorized_" + "keys"
	rows := []struct{ name, command string }{
		{"pid-dot-before", "echo k >> /proc/4242/../4242/root/sandbox/.ssh/" + key},
		{"pid-empty-before", "echo k >> //proc/4242/root/../sandbox/.ssh/" + key},
		{"pid-dot-before-root", "echo k >> /proc/4242/./root/../sandbox/.ssh/" + key},
		{"pid-link-text", "ln -s /proc/4242/root/sandbox/.ssh/" + key + " l && echo k >> l"},
		{"ordinary-before-own-root", "echo k >> /tmp/../proc/self/root/../sandbox/.ssh/" + key},
		{"nested-own-root", "echo k >> /proc/self/root/sandbox/../proc/self/root/../sandbox/.ssh/" + key},
		{"cd-root-dot-dot", "cd /proc/self/root/.. && echo k >> sandbox/.ssh/" + key},
		{"cd-root-then-dot-dot", "cd /proc/self/root && cd .. && echo k >> sandbox/.ssh/" + key},
		{"cd-root-dot-dot-sandbox", "cd /proc/self/root/../sandbox && echo k >> .ssh/" + key},
		{"relative-link-text", "ln -s ../../proc/self/root/sandbox/.ssh/" + key + " l && echo k >> l"},
		{"absolute-alias-operand", "ln -s /proc/self/root/sandbox/.ssh/" + key + " l && echo k >> $PWD/l"},
		{"tee-alias-operand", "ln -s /proc/self/root/sandbox/.ssh/" + key + " l && tee -a l < /tmp/k"},
		{"stdin-below-directory", "exec 0< /sandbox && echo k >> /dev/stdin/.ssh/" + key},
		{"descriptor-link-text", "exec 3< /sandbox && ln -s /dev/fd/3/.ssh/" + key + " l && echo k >> l"},
		{"ssh-rc", "echo m > /proc/1/root/sandbox/.ssh/rc"},
		{"ssh-environment", "echo m > /proc/1/root/sandbox/.ssh/environment"},
		{"ssh-config", "echo m > /proc/1/root/sandbox/.ssh/config"},
	}
	for _, pack := range []string{"default", "strict"} {
		t.Run(pack, func(t *testing.T) {
			api, actor, _, _ := gap0545API(t, "claudecode", pack)
			for _, row := range rows {
				t.Run(row.name, func(t *testing.T) {
					action, _ := gap2227Hook(t, api, actor, sandboxauth.SandboxHome+"/app", row.command, true)
					if action != "block" {
						t.Errorf("actor %s: %s, want block", row.name, action)
					}
				})
			}
		})
	}
}

func TestFIX2223DProcessLinkAndGuestRootHolds(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged POSIX gateway")
	}
	key := "authorized_" + "keys"
	rows := []struct{ name, command string }{
		{"thread-cwd-below", "cd /sandbox && echo k >> /proc/thread-self/cwd/.ssh/" + key},
		{"cwd-dot-dot", "echo k >> /proc/self/cwd/../.ssh/" + key},
		{"fd-dot-dot", "mkdir -p /sandbox/app/x /sandbox/root && exec 3< /sandbox/app/x && echo k >> /proc/self/fd/3/../../root/../.ssh/" + key},
		{"self-root-rc", "echo m > /proc/self/root/sandbox/.ssh/rc"},
		{"relative-link-after-cd", "cd /tmp && ln -s ../proc/self/root/sandbox/.ssh/" + key + " l && echo k >> l"},
		{"ordinary-prefix-root", "echo k >> /tmp/x/../../proc/self/root/../sandbox/.ssh/" + key},
	}
	for _, pack := range []string{"default", "strict"} {
		t.Run(pack, func(t *testing.T) {
			api, actor, _, _ := gap0545API(t, "claudecode", pack)
			for _, row := range rows {
				t.Run(row.name, func(t *testing.T) {
					action, _ := gap2227Hook(t, api, actor, sandboxauth.SandboxHome+"/app", row.command, true)
					if action != "block" {
						t.Errorf("actor %s: %s, want block", row.name, action)
					}
				})
			}
		})
	}
}

func TestFIX2223DLaptopProcessLinkGiveback(t *testing.T) {
	if runtime.GOOS != "linux" || os.Geteuid() == 0 {
		t.Skip("Linux unprivileged laptop")
	}
	for _, pack := range []string{"default", "strict"} {
		t.Run(pack, func(t *testing.T) {
			api, _, home, app := gap0545API(t, "claudecode", pack)
			key := "authorized_" + "keys"
			for _, row := range []struct{ name, command string }{
				{"cwd-dot-dot", "echo k >> /proc/self/cwd/../.ssh/" + key},
				{"thread-cwd", "cd " + home + " && echo k >> /proc/thread-self/cwd/.ssh/" + key},
				{"fd-dot-dot", "mkdir -p " + home + "/app/x " + home + "/root && exec 3< " + home + "/app/x && echo k >> /proc/self/fd/3/../../root/../.ssh/" + key},
			} {
				t.Run(row.name, func(t *testing.T) {
					action, _ := gap2227Hook(t, api, context.Background(), app, row.command, false)
					if action != "block" {
						t.Errorf("laptop %s: %s, want block", row.name, action)
					}
				})
			}
		})
	}
}

func TestFIX2223CBenignSelfRootMatchesPlainPath(t *testing.T) {
	if runtime.GOOS != "linux" || os.Geteuid() == 0 {
		t.Skip("Linux unprivileged laptop")
	}
	for _, pack := range []string{"default", "strict"} {
		t.Run(pack, func(t *testing.T) {
			api, _, home, app := gap0545API(t, "claudecode", pack)
			rows := []struct{ name, plain, link string }{
				{"tmp-self", "/tmp/authorized_keys", "/proc/self/root/tmp/authorized_keys"},
				{"tmp-thread-self", "/tmp/authorized_keys", "/proc/thread-self/root/tmp/authorized_keys"},
				{"home-app", home + "/app/authorized_keys", "/proc/self/root" + home + "/app/authorized_keys"},
			}
			for _, row := range rows {
				plain, _ := gap2227Hook(t, api, context.Background(), app, "echo k >> "+row.plain, false)
				link, _ := gap2227Hook(t, api, context.Background(), app, "echo k >> "+row.link, false)
				if plain != link {
					t.Errorf("%s: plain=%s link=%s", row.name, plain, link)
				}
			}
		})
	}
}

func TestFIX2223EReviewHoldsActor(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged POSIX gateway")
	}
	key := "authorized_" + "keys"
	rows := []struct{ name, command string }{
		{"cp-cwd-parent", "cp /tmp/k /proc/self/cwd/../.ssh/" + key},
		{"gcp-cwd-parent", "gcp /tmp/k /proc/self/cwd/../.ssh/" + key},
		{"wrapped-cp-cwd-parent", "env cp /tmp/k /proc/self/cwd/../.ssh/" + key},
		{"relative-dir-link", "cd /tmp && ln -s ../sandbox/.ssh d && echo k >> d/" + key},
		{"relative-dir-link-cp", "cd /tmp && ln -s ../sandbox/.ssh d && cp /tmp/" + key + " d/" + key},
		{"relative-dir-link-tee", "cd /tmp && ln -s ../sandbox/.ssh d && tee -a d/" + key + " < /tmp/k"},
		{"cwd-alias-parent", "ln -s /proc/self/cwd c && echo k >> c/../.ssh/" + key},
		{"cwd-alias-parent-dd", "ln -s /proc/self/cwd c && dd if=/tmp/k of=c/../.ssh/" + key},
	}
	for _, pack := range []string{"default", "strict"} {
		t.Run(pack, func(t *testing.T) {
			api, actor, _, _ := gap0545API(t, "claudecode", pack)
			for _, row := range rows {
				t.Run(row.name, func(t *testing.T) {
					action, _ := gap2227Hook(t, api, actor, sandboxauth.SandboxHome+"/app", row.command, true)
					if action != "block" {
						t.Errorf("actor %s: %s, want block", row.name, action)
					}
				})
			}
		})
	}
}

func TestFIX2223ELaptopProcessAliasParent(t *testing.T) {
	if runtime.GOOS != "linux" || os.Geteuid() == 0 {
		t.Skip("Linux unprivileged laptop")
	}
	for _, pack := range []string{"default", "strict"} {
		t.Run(pack, func(t *testing.T) {
			api, _, _, app := gap0545API(t, "claudecode", pack)
			key := "authorized_" + "keys"
			for _, command := range []string{
				"cp /tmp/k /proc/self/cwd/../.ssh/" + key,
				"ln -s /proc/self/cwd c && echo k >> c/../.ssh/" + key,
			} {
				action, _ := gap2227Hook(t, api, context.Background(), app, command, false)
				if action != "block" {
					t.Errorf("laptop %q: %s, want block", command, action)
				}
			}
		})
	}
}
