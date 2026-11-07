// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

// TestContentRuleTargetsAcceptThePhysicalEtcSpelling pins GAP-0819: the
// system files whose writes a content rule judges are the same files under
// /etc and under its macOS physical spelling /private/etc. Look-alike paths
// stay ordinary files.
func TestContentRuleTargetsAcceptThePhysicalEtcSpelling(t *testing.T) {
	for _, c := range []struct{ target, class string }{
		{"/etc/docker/daemon.json", "docker-daemon-config"},
		{"/etc/sudoers.d/ops", "sudoers"},
		{"/etc/passwd", "account-database"},
		{"/etc/ld.so.preload", "global-preload"},
		{"/etc/profile.d/logger.sh", "global-preload"},
		{"/etc/pam.d/sshd", "pam"},
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
