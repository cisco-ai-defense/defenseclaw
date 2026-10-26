// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// TestManagedRefusalHintNamesTheManagedExplainCommand is GAP-1692: a
// refusal for an account without a verified ID named `defenseclaw guardrail
// profile list`, which does not run on a managed host.
func TestManagedRefusalHintNamesTheManagedExplainCommand(t *testing.T) {
	managedSet := &guardrailProfileSet{base: &config.Config{DeploymentMode: "managed_enterprise",
		Enterprise: config.EnterpriseConfig{Profile: "standalone"}}}
	want := map[string]string{
		"linux":   "sudo /opt/defenseclaw/bin/defenseclaw-gateway enterprise linux profile-explain --user <user> --connector codex",
		"darwin":  "sudo /opt/cisco/defenseclaw/bin/defenseclaw-gateway enterprise macos profile-explain --user <user> --connector codex",
		"windows": `& 'C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw.exe' enterprise windows profile-explain --user <user> --connector codex`,
	}[runtime.GOOS]
	for _, subject := range []*profileSubject{nil, {UserName: "nosuchuser@dclab.test"}} {
		got := managedSet.profileExplainCommand(subject, "codex", "", false)
		if want != "" && got != want || strings.Contains(got, "guardrail profile") {
			t.Errorf("managed hint for %+v = %q; want %q", subject, got, want)
		}
	}
	verified := &profileSubject{UserID: "1006", IDKind: useridentity.KindPOSIXUID}
	if got := managedSet.profileExplainCommand(verified, "codex", "", false); !strings.Contains(got, "--user 1006 --connector codex") {
		t.Errorf("managed hint for a verified uid = %q", got)
	}
	oss := &guardrailProfileSet{base: &config.Config{}}
	if got := oss.profileExplainCommand(nil, "codex", "", false); got != "defenseclaw guardrail profile list" {
		t.Errorf("per-user hint without an ID = %q", got)
	}
}
