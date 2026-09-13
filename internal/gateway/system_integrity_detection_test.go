// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

const (
	dpkgStatusMutationRuleID      = "integrity.dpkg_status_direct_mutation"
	posixSystemShellReplacementID = "integrity.posix_system_shell_replacement"
	kernelBindTelemetryRuleID     = "integrity.kernel_control_bind_override"
	protectedKernelBindOverrideID = "impact.protected_kernel_control_bind_override"
)

func TestPOSIXSystemShellReplacementProfilePosture(t *testing.T) {
	const command = "cp /bin/bash /bin/dash\n"
	for profile, wantAction := range map[string]string{
		"default": "alert", "permissive": "alert", "strict": "block",
	} {
		connector := "system-shell-replacement-" + profile
		installToolCallCorpusProfileConnector(t, connector, profile)
		result := EvaluateDeterministicAction(
			t.Context(),
			actionfacts.Input{Tool: "bash_command", Command: command, CWD: "/app"},
			command,
			connector,
			profile,
		)
		if result.Action != wantAction {
			t.Fatalf("profile=%s result=%+v want_action=%s", profile, result, wantAction)
		}
		if !slices.Contains(result.RuleIDs, posixSystemShellReplacementID) {
			t.Fatalf("profile=%s result=%+v missing %s", profile, result, posixSystemShellReplacementID)
		}
	}
}

func TestPOSIXSystemShellReplacementHardNegativesStayQuiet(t *testing.T) {
	connector := "system-shell-replacement-negatives"
	installToolCallCorpusProfileConnector(t, connector, "strict")
	for _, command := range []string{
		"cp /bin/dash /bin/dash.real\n",
		"cp /bin/bash /tmp/bash\n",
		"cp -f /bin/bash /bin/dash\n",
		"ln -sf /bin/bash /bin/sh\n",
		"test -f /tmp/flag && cp /bin/bash /bin/dash\n",
		"sudo cp /bin/bash /bin/dash\n",
	} {
		result := EvaluateDeterministicAction(
			t.Context(),
			actionfacts.Input{Tool: "bash_command", Command: command, CWD: "/app"},
			command,
			connector,
			"strict",
		)
		if slices.Contains(result.RuleIDs, posixSystemShellReplacementID) {
			t.Fatalf("command=%q result=%+v", command, result)
		}
	}
}

func TestDPKGStatusMutationIsStrictExactAlertOnly(t *testing.T) {
	for _, profile := range []string{"default", "permissive"} {
		t.Run(profile+" stays quiet", func(t *testing.T) {
			connector := "dpkg-status-" + profile
			installToolCallCorpusProfileConnector(t, connector, profile)
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input: actionfacts.Input{
					Tool:    "shell",
					Command: "printf fixture >> /var/lib/dpkg/status",
				},
				LegacyText:         "printf fixture >> /var/lib/dpkg/status",
				Connector:          connector,
				EnforcementCapable: true,
			})
			if finding := findingWithID(findings, dpkgStatusMutationRuleID); finding != nil {
				t.Fatalf("finding=%#v all=%v, want no universal package-database alert", finding, FindingStrings(findings))
			}
		})
	}

	for _, profile := range []string{"strict"} {
		t.Run(profile, func(t *testing.T) {
			connector := "dpkg-status-" + profile
			installToolCallCorpusProfileConnector(t, connector, profile)
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input: actionfacts.Input{
					Tool:    "shell",
					Command: "printf fixture >> /var/lib/dpkg/status",
				},
				LegacyText:         "printf fixture >> /var/lib/dpkg/status",
				Connector:          connector,
				EnforcementCapable: true,
			})
			finding := findingWithID(findings, dpkgStatusMutationRuleID)
			if finding == nil || !finding.contributesToAlertOnly() ||
				finding.contributesToEnforcement() ||
				!finding.proof.authorizes(finding.RuleID) {
				t.Fatalf("finding=%#v all=%v, want exact alert-only proof", finding, FindingStrings(findings))
			}
		})
	}

	for _, command := range []string{
		"cat /var/lib/dpkg/status",
		"dpkg --update-avail /var/lib/dpkg/status",
		"printf fixture > /tmp/var/lib/dpkg/status",
		"printf fixture > /var/lib/dpkg/status.backup",
		"printf fixture > \"$ROOT/var/lib/dpkg/status\"",
	} {
		connector := "dpkg-status-negatives"
		installToolCallCorpusProfileConnector(t, connector, "strict")
		findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
			Input:              actionfacts.Input{Tool: "shell", Command: command},
			LegacyText:         command,
			Connector:          connector,
			EnforcementCapable: true,
		})
		if findingWithID(findings, dpkgStatusMutationRuleID) != nil {
			t.Fatalf("command=%q findings=%v, want no dpkg mutation finding", command, FindingStrings(findings))
		}
	}
}

func TestDPKGStatusTerminalHeredocIsStrictExactAlertOnly(t *testing.T) {
	const command = "cat << 'EOF' >> /var/lib/dpkg/status\nPackage: fixture\nEOF\n"
	for _, profile := range []string{"default", "permissive"} {
		t.Run(profile+" stays quiet", func(t *testing.T) {
			connector := "dpkg-status-heredoc-" + profile
			installToolCallCorpusProfileConnector(t, connector, profile)
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input: actionfacts.Input{
					Tool: "bash_command",
					Args: []byte(`{"duration":0.1,"keystrokes":"cat << 'EOF' >> /var/lib/dpkg/status\nPackage: fixture\nEOF\n"}`),
				},
				LegacyText:         command,
				Connector:          connector,
				EnforcementCapable: true,
			})
			if finding := findingWithID(findings, dpkgStatusMutationRuleID); finding != nil {
				t.Fatalf("finding=%#v all=%v, want no universal package-database alert", finding, FindingStrings(findings))
			}
		})
	}

	connector := "dpkg-status-heredoc-strict"
	installToolCallCorpusProfileConnector(t, connector, "strict")
	findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
		Input: actionfacts.Input{
			Tool: "bash_command",
			Args: []byte(`{"duration":0.1,"keystrokes":"cat << 'EOF' >> /var/lib/dpkg/status\nPackage: fixture\nEOF\n"}`),
		},
		LegacyText:         command,
		Connector:          connector,
		EnforcementCapable: true,
	})
	finding := findingWithID(findings, dpkgStatusMutationRuleID)
	if finding == nil || !finding.contributesToAlertOnly() ||
		finding.contributesToEnforcement() ||
		!finding.proof.authorizes(finding.RuleID) {
		t.Fatalf("finding=%#v all=%v, want strict exact alert-only heredoc proof", finding, FindingStrings(findings))
	}
}

func TestDPKGStatusTerminalHeredocHardNegatives(t *testing.T) {
	const valid = "cat << 'EOF' >> /var/lib/dpkg/status\nPackage: fixture\nEOF\n"
	for _, input := range []actionfacts.Input{
		{Tool: "bash_command", Args: []byte(`{"keystrokes":"cat /var/lib/dpkg/status\n"}`)},
		{Tool: "bash_command", Args: []byte(`{"keystrokes":"cat << 'EOF' > /tmp/var/lib/dpkg/status\nfixture\nEOF\n"}`)},
		{Tool: "bash_command", Args: []byte(`{"keystrokes":"cat << 'EOF' > $ROOT/var/lib/dpkg/status\nfixture\nEOF\n"}`)},
		{Tool: "bash_command", Args: []byte(`{"keystrokes":"cat << 'EOF' > /var/lib/dpkg/status\nfixture\nEOF\nid\n"}`)},
		{Tool: "bash_command", Args: []byte(`{"keystrokes":"cat << 'ONE' << 'TWO' > /var/lib/dpkg/status\none\nONE\ntwo\nTWO\n"}`)},
		{Tool: "bash_command", Args: []byte(`{"keystrokes":"cat << 'EOF' > /var/lib/dpkg/status\nfixture\n"}`)},
		{Tool: "bash_command", Args: []byte(`{"keystrokes":"cat << 'EOF' > /var/lib/dpkg/status\nfixture\nEOF\n","result":"success"}`)},
		{Tool: "bash_command", Args: []byte(`{"keystrokes":"cat << 'EOF' > /var/lib/dpkg/status\nfixture\nEOF\n"}`), Command: "id\n"},
	} {
		connector := "dpkg-status-heredoc-negatives"
		installToolCallCorpusProfileConnector(t, connector, "strict")
		findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
			Input: input, LegacyText: valid, Connector: connector, EnforcementCapable: true,
		})
		if findingWithID(findings, dpkgStatusMutationRuleID) != nil {
			t.Fatalf("input=%+v findings=%v, want no dpkg mutation finding", input, FindingStrings(findings))
		}
	}
}

func TestKernelControlBindOverridePosture(t *testing.T) {
	const command = "mount --bind /tmp/tcp_wmem /proc/sys/net/ipv4/tcp_wmem"
	for _, profile := range []string{"default", "permissive"} {
		t.Run(profile+" stays quiet", func(t *testing.T) {
			connector := "kernel-bind-" + profile
			installToolCallCorpusProfileConnector(t, connector, profile)
			result := EvaluateDeterministicAction(t.Context(), actionfacts.Input{
				Tool: "shell", Command: command,
			}, command, connector, profile)
			if slices.Contains(result.RuleIDs, kernelBindTelemetryRuleID) || result.Action == "block" {
				t.Fatalf("result=%+v, want no universal block or telemetry", result)
			}
		})
	}

	strictConnector := "kernel-bind-strict"
	installToolCallCorpusProfileConnector(t, strictConnector, "strict")
	strictFindings := dispatchTrustedAction(t.Context(), trustedActionRequest{
		Input:              actionfacts.Input{Tool: "shell", Command: command},
		LegacyText:         command,
		Connector:          strictConnector,
		EnforcementCapable: true,
	})
	strictFinding := findingWithID(strictFindings, kernelBindTelemetryRuleID)
	if strictFinding == nil || !strictFinding.contributesToAlertOnly() ||
		strictFinding.contributesToEnforcement() ||
		!strictFinding.proof.authorizes(strictFinding.RuleID) {
		t.Fatalf("strict finding=%#v all=%v, want exact alert-only proof", strictFinding, FindingStrings(strictFindings))
	}

	packConnector := activateUseCaseProfile(t, "infrastructure-destruction-protection")
	packResult := EvaluateDeterministicAction(t.Context(), actionfacts.Input{
		Tool: "shell", Command: command,
	}, command, packConnector, "default")
	if !slices.Contains(packResult.RuleIDs, protectedKernelBindOverrideID) ||
		packResult.Action != "block" {
		t.Fatalf("pack result=%+v, want protected kernel bind block", packResult)
	}
}

func TestKernelControlBindOverrideHardNegatives(t *testing.T) {
	connector := activateUseCaseProfile(t, "infrastructure-destruction-protection")
	for _, command := range []string{
		"cat /proc/sys/net/ipv4/tcp_wmem",
		"mount --remount /proc/sys/net/ipv4/tcp_wmem",
		"mount --bind /proc/sys/net/ipv4/tcp_wmem /tmp/tcp_wmem",
		"mount --bind /tmp/sys /proc/sys",
		"mount --bind /tmp/kernel /proc/sys/kernel",
		"mount --bind /tmp/value /tmp/proc/sys/net/ipv4/tcp_wmem",
		"mount --bind \"$SOURCE\" /proc/sys/net/ipv4/tcp_wmem",
		"mount --bind /tmp/tcp_wmem \"$TARGET\"",
	} {
		t.Run(command, func(t *testing.T) {
			result := EvaluateDeterministicAction(t.Context(), actionfacts.Input{
				Tool: "shell", Command: command,
			}, command, connector, "default")
			if slices.Contains(result.RuleIDs, protectedKernelBindOverrideID) || result.Action == "block" {
				t.Fatalf("result=%+v, want no protected kernel bind block", result)
			}
		})
	}
}
