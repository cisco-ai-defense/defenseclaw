// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

// linksEtcForTest runs the test as a host where /etc links to /private/etc
// (macOS) or as one where /private/etc is an ordinary directory.
func linksEtcForTest(t *testing.T, linked bool) {
	t.Helper()
	was := HostLinksEtcToPrivate
	HostLinksEtcToPrivate = linked
	t.Cleanup(func() { HostLinksEtcToPrivate = was })
}

// TestContentRuleTargetsAcceptThePhysicalEtcSpelling pins GAP-0819: the
// system files whose writes a content rule judges are the same files under
// /etc and under its macOS physical spelling /private/etc. Look-alike paths
// stay ordinary files.
func TestContentRuleTargetsAcceptThePhysicalEtcSpelling(t *testing.T) {
	linksEtcForTest(t, true)
	for _, c := range []struct{ target, class string }{
		{"/etc/docker/daemon.json", "docker-daemon-config"},
		{"/etc/sudoers.d/ops", "sudoers"},
		{"/etc/passwd", "account-database"},
		{"/etc/ld.so.preload", "global-preload"},
		{"/etc/profile.d/logger.sh", "global-preload"},
		{"/etc/pam.d/sshd", "pam"},
		{"/etc/pam.conf", "pam"},
		{"/etc/docker/other.json", ""},
		{"/etc/profile.d/notes.txt", ""},
		{"/etc/hosts", ""},
	} {
		physical := "/private" + c.target
		if got := contentRuleWriteTarget(c.target); got != c.class {
			t.Errorf("contentRuleWriteTarget(%q) = %q, want %q", c.target, got, c.class)
		}
		if got := contentRuleWriteTarget(physical); got != c.class {
			t.Errorf("contentRuleWriteTarget(%q) = %q, want %q", physical, got, c.class)
		}
	}
	for _, other := range []string{
		"/private/etcetera/passwd", "/private/var/etc/passwd", "/private/etc/../tmp/x",
		"/private/tmp/etc/docker/daemon.json", "/private/private/etc/passwd", "/privateetc/passwd",
	} {
		if got := contentRuleWriteTarget(other); got != "" {
			t.Errorf("contentRuleWriteTarget(%q) = %q, want an ordinary file", other, got)
		}
	}
}

// TestPhysicalEtcSpellingIsOrdinaryWhereEtcIsNotALink pins that a host where
// /etc is not a link reads /private/etc paths as the ordinary files they are.
func TestPhysicalEtcSpellingIsOrdinaryWhereEtcIsNotALink(t *testing.T) {
	linksEtcForTest(t, false)
	for _, target := range []string{
		"/private/etc/docker/daemon.json", "/private/etc/passwd", "/private/etc/pam.conf",
		"/private/etc/pam.d/sshd", "/private/etc/profile.d/logger.sh", "/private/etc/ld.so.preload",
	} {
		if got := EtcSpelling(target); got != target {
			t.Errorf("EtcSpelling(%q) = %q, want it unchanged", target, got)
		}
		if got := contentRuleWriteTarget(target); got != "" {
			t.Errorf("contentRuleWriteTarget(%q) = %q, want an ordinary file", target, got)
		}
	}
	if got := contentRuleWriteTarget("/etc/pam.conf"); got != "pam" {
		t.Errorf("contentRuleWriteTarget(/etc/pam.conf) = %q, want pam", got)
	}
}
