// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"runtime"
	"testing"
)

// TestGAP2223GuestOwnRootPathIsTheGuestRoot: a Linux sandbox guest reads its
// /proc/self/root and /proc/thread-self/root as its own /, as a Linux
// gateway reads its own, so a gateway host with no /proc folds them the
// same way, again and again (rel-1-0-10:GAP-2223, RV-2203c P2-1). Another
// process's root, a task/<tid> root and other spellings stay as written.
func TestGAP2223GuestOwnRootPathIsTheGuestRoot(t *testing.T) {
	for _, row := range []struct{ path, want string }{
		{"/proc/self/root", "/"},
		{"/proc/thread-self/root", "/"},
		{"/proc/self/root/sandbox", "/sandbox"},
		{"/proc/thread-self/root/sandbox/app", "/sandbox/app"},
		{"/proc/self/root/proc/1/root", "/proc/1/root"},
		{"/proc/self/root/proc/self/root/tmp", "/tmp"},
		{"/proc/self/root/../sandbox", "/sandbox"},
		{"/tmp/../proc/self/root/../sandbox", "/sandbox"},
		{"/proc/self/root/sandbox/../proc/self/root/../sandbox", "/sandbox"},
		{"/proc/self/root/proc/4242/./root/../sandbox", "/proc/4242/root/../sandbox"},
		{"/proc/./self/root/../../sandbox", "/sandbox"},
		{"/proc/self/../self/root/../sandbox", "/sandbox"},
		{"/proc/self/root/proc/1/root/../sandbox", "/proc/1/root/../sandbox"},
		{"/proc/self/root/../proc/1/root/../sandbox", "/proc/1/root/../sandbox"},
		{"/proc/thread-self/root/proc/self/root", "/"},
		{"/proc/self/root/proc/thread-self/root/proc/1/cwd", "/proc/1/cwd"},
		{"/proc/self/rootx", "/proc/self/rootx"},
		{"/proc/self/cwd", "/proc/self/cwd"},
		{"/proc/self", "/proc/self"},
		{"/proc/self/task/1/root", "/proc/self/task/1/root"},
		{"/proc/1/root", "/proc/1/root"},
		{"/PROC/self/root", "/PROC/self/root"},
		{"/tmp/proc/self/root", "/tmp/proc/self/root"},
		{"/", "/"},
	} {
		if got := GuestOwnRootPath(row.path); got != row.want {
			t.Errorf("GuestOwnRootPath(%q) = %q, want %q", row.path, got, row.want)
		}
	}
	// The walk on a gateway host that is not Linux sees the folded folder:
	// another process's root reached through the guest's own root is
	// unknown, as an unprivileged Linux gateway leaves it.
	if !guestOtherProcessFolder(GuestOwnRootPath("/proc/self/root/proc/1/root")) {
		t.Error("/proc/self/root/proc/1/root is another process's root once folded")
	}
}

func TestGAP2223GuestAliasTargetsFoldLinkText(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("guest POSIX alias parser is not used on Windows")
	}
	for _, source := range []string{
		"/proc/self/root/sandbox/.ssh/authorized_keys",
		"/proc/self/root/../sandbox/.ssh/authorized_keys",
	} {
		command := "ln -s " + source + " l && echo k >> l"
		operands, ok, _ := ShellWriteOperands(command, "/sandbox/app", "/sandbox")
		if !ok || len(operands) != 1 || operands[0] != "/sandbox/app/l" {
			t.Errorf("%q: write operands %q, ok=%v", command, operands, ok)
		}
		links := CommandLinksWithFacts("Bash", command, "/sandbox/app", "/sandbox", nil)
		aliases := links.GuestAliasTargets("/sandbox/app/l", false)
		found := false
		for _, alias := range aliases {
			if GuestOwnRootPath(alias) == "/sandbox/.ssh/authorized_keys" {
				found = true
			}
		}
		if !found {
			t.Errorf("%q: alias targets %q", command, aliases)
		}
		// The sandbox event may not attest a cwd. The link and its later
		// redirect still share one shell directory, and the text is absolute.
		links = CommandLinksWithFacts("Bash", command, "", "/sandbox", nil)
		aliases = links.GuestAliasTargets("l", false)
		found = false
		for _, alias := range aliases {
			if GuestOwnRootPath(alias) == "/sandbox/.ssh/authorized_keys" {
				found = true
			}
		}
		if !found {
			t.Errorf("%q: alias targets without cwd %q", command, aliases)
		}
	}
}

func TestFIX2223DGuestOwnRootKeepsProcessLinkBoundary(t *testing.T) {
	for _, path := range []string{
		"/proc/self/cwd/../.ssh/authorized_keys",
		"/proc/thread-self/cwd/.ssh/authorized_keys",
		"/proc/self/fd/3/../../root/../.ssh/authorized_keys",
	} {
		if got := GuestOwnRootPath(path); got != path {
			t.Errorf("GuestOwnRootPath(%q) = %q; suffix crossed process link", path, got)
		}
	}
}

func TestFIX2223DGuestRelativeAliasAfterDirectoryChange(t *testing.T) {
	command := "cd /tmp && ln -s ../proc/self/root/sandbox/.ssh/authorized_keys l && echo k >> l"
	links := CommandLinksWithFacts("Bash", command, "/sandbox/app", "/sandbox", nil)
	aliases := links.GuestAliasTargets("/tmp/l", false)
	found := false
	for _, alias := range aliases {
		if GuestOwnRootPath(alias) == "/sandbox/.ssh/authorized_keys" {
			found = true
		}
	}
	if !found {
		t.Errorf("relative guest alias targets %q", aliases)
	}
}

func TestFIX2223DGuestRelativeDirectoryAliasAfterChange(t *testing.T) {
	command := "cd /tmp && ln -s ../proc/self/root/sandbox/.ssh l && echo k >> l/authorized_keys"
	links := CommandLinksWithFacts("Bash", command, "/sandbox/app", "/sandbox", nil)
	aliases := links.GuestAliasTargets("/tmp/l/authorized_keys", false)
	for _, alias := range aliases {
		if GuestOwnRootPath(alias) == "/sandbox/.ssh/authorized_keys" {
			return
		}
	}
	t.Errorf("relative directory alias targets %q", aliases)
}

func TestFIX2223DGuestRelativeAliasBelowLink(t *testing.T) {
	command := "ln -s /proc/self/root/sandbox l1 && ln -s l1/.ssh l2 && echo k >> l2/authorized_keys"
	links := CommandLinksWithFacts("Bash", command, "/sandbox/app", "/sandbox", nil)
	aliases := links.GuestAliasTargets("/sandbox/app/l2/authorized_keys", false)
	for _, alias := range aliases {
		if GuestOwnRootPath(alias) == "/sandbox/.ssh/authorized_keys" {
			return
		}
	}
	t.Errorf("relative alias below link targets %q", aliases)
}

func TestGAP2223GuestAliasTargetsUseLinuxCase(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("guest POSIX alias parser is not used on Windows")
	}
	command := "ln -s /proc/self/root/sandbox/.ssh/authorized_keys L && echo k >> l"
	links := CommandLinksWithFacts("Bash", command, "", "/sandbox", nil)
	if aliases := links.GuestAliasTargets("l", false); len(aliases) != 0 {
		t.Errorf("a Linux guest must not follow a differently cased link: %q", aliases)
	}
}

func TestFIX2223CGuestAliasTargetsProcessLinks(t *testing.T) {
	rows := []struct{ command, want string }{
		{"ln -s /proc/4242/root/sandbox/.ssh/authorized_keys l && echo k >> l", "/proc/4242/root/sandbox/.ssh/authorized_keys"},
		{"exec 3< /sandbox && ln -s /dev/fd/3/.ssh/authorized_keys l && echo k >> l", "/dev/fd/3/.ssh/authorized_keys"},
	}
	for _, row := range rows {
		links := CommandLinksWithFacts("Bash", row.command, "/sandbox/app", "/sandbox", nil)
		aliases := links.GuestAliasTargets("/sandbox/app/l", false)
		if len(aliases) == 0 {
			t.Errorf("%q: no aliases", row.command)
			continue
		}
		found := false
		for _, alias := range aliases {
			if alias == row.want {
				found = true
			}
		}
		if !found {
			t.Errorf("%q: aliases %q, want %q", row.command, aliases, row.want)
		}
	}
}

func TestFIX2223CGuestStaticDirectoryPlacesRootBoundWrites(t *testing.T) {
	key := "authorized_" + "keys"
	for _, command := range []string{
		"cd /proc/self/root/.. && echo k >> sandbox/.ssh/" + key,
		"cd /proc/self/root && cd .. && echo k >> sandbox/.ssh/" + key,
		"cd /proc/self/root/../sandbox && echo k >> .ssh/" + key,
	} {
		ops := GuestStaticDirectoryWriteOperands(command, "/sandbox/app", "/sandbox")
		found := false
		for _, op := range ops {
			if GuestOwnRootPath(op.Path) == "/sandbox/.ssh/"+key {
				found = true
			}
		}
		if !found {
			t.Errorf("%q: placed writes %v", command, ops)
		}
	}
}

// TestFIX2223EPhysicalGuestAlias records the host spelling a macOS path
// resolver supplies for a link created under the guest's /tmp.
func TestFIX2223EPhysicalGuestAlias(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS /tmp has a physical /private/tmp spelling")
	}
	key := "authorized_" + "keys"
	command := "cd /tmp && ln -s ../sandbox/.ssh d && echo k >> d/" + key
	links := CommandLinksWithFacts("Bash", command, "/sandbox/app", "/sandbox", nil)
	for _, operand := range []string{"/tmp/d/" + key, "/private/tmp/d/" + key} {
		aliases := links.GuestAliasTargets(operand, false)
		found := false
		for _, alias := range aliases {
			if filepath.Clean(GuestOwnRootPath(alias)) == "/sandbox/.ssh/"+key {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: alias targets %q, want guest protected path", operand, aliases)
		}
	}
}
