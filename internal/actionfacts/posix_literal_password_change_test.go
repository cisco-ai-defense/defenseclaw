// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

func TestExactPOSIXLiteralPasswordChangeCorpusForms(t *testing.T) {
	tests := []struct {
		name    string
		command string
		form    POSIXLiteralPasswordChangeForm
		sink    string
	}{
		{
			// shell-attack-evolution/0004c353cac063f3a000f9cf
			name:    "passwd three-stage trailing bash",
			command: "echo -e \"shutdown\\nprovided by secret store\\nprovided by secret store\"|passwd|bash",
			form:    POSIXLiteralPasswordChangeThreeStageTrailingShell,
			sink:    "passwd",
		},
		{
			// shell-attack-evolution/001d4c495b2c95bbaf94039c
			name:    "passwd two-stage automation",
			command: "echo \"service-user\\nprovided by secret store\\nprovided by secret store\\n\"|passwd",
			form:    POSIXLiteralPasswordChangeTwoStageAutomation,
			sink:    "passwd",
		},
		{
			// shell-attack-evolution/0021dc73fad9f064a7d78b88
			name:    "chpasswd three-stage trailing bash",
			command: "echo \"root:provided by secret store\"|chpasswd|bash",
			form:    POSIXLiteralPasswordChangeThreeStageTrailingShell,
			sink:    "chpasswd",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{
				Tool:        "shell",
				Command:     test.command,
				DialectHint: DialectPOSIX,
			})
			if !facts.Authoritative() || !facts.EnforcementEligible() {
				raw, rawOK := exactPOSIXLiteralPasswordChangePipeline(facts.Commands, facts.DataFlows)
				t.Fatalf("facts not eligible: parse=%+v commands=%+v flows=%+v raw=%+v rawOK=%t",
					facts.Parse, facts.Commands, facts.DataFlows, raw, rawOK)
			}
			fact, ok := ExactPOSIXLiteralPasswordChange(
				facts,
				POSIXLiteralPasswordChangeOutcomeSucceeded,
			)
			if !ok || fact.Form != test.form {
				t.Fatalf("fact=%+v ok=%t, want form %q", fact, ok, test.form)
			}
			if fact.CommandID == 0 || !passwordChangeTestSinkHasOperation(facts, fact.CommandID, test.sink) {
				t.Fatalf("sink fact=%+v commands=%+v", fact, facts.Commands)
			}
		})
	}
}

func TestPOSIXLiteralPasswordChangeHardNegatives(t *testing.T) {
	tests := []struct {
		name    string
		command string
	}{
		{name: "standalone interactive passwd", command: "passwd"},
		{name: "standalone named passwd", command: "passwd service-user"},
		{name: "echo to cat", command: "echo \"root:provided by secret store\"|cat"},
		{name: "dynamic password", command: "echo -e \"service-user\\n$PASSWORD\\n$PASSWORD\"|passwd|bash"},
		{name: "passwd mismatched confirmation", command: "echo -e \"service-user\\nfirst value\\nsecond value\"|passwd|bash"},
		{name: "passwd whitespace account", command: "echo -e \"service user\\nprovided by secret store\\nprovided by secret store\"|passwd|bash"},
		{name: "passwd option-like account", command: "echo -e \"--root\\nprovided by secret store\\nprovided by secret store\"|passwd|bash"},
		{name: "passwd missing trailing newline in automation", command: "echo \"service-user\\nprovided by secret store\\nprovided by secret store\"|passwd"},
		{name: "chpasswd malformed tuple", command: "echo \"root\"|chpasswd|bash"},
		{name: "chpasswd extra tuple", command: "echo \"root:provided by secret store\\nservice-user:provided by secret store\"|chpasswd|bash"},
		{name: "chpasswd root staging", command: "echo \"root:provided by secret store\"|chpasswd -R /staging|bash"},
		{name: "unsupported two-stage chpasswd", command: "echo \"root:provided by secret store\"|chpasswd"},
		{name: "unsupported trailing sh", command: "echo -e \"service-user\\nprovided by secret store\\nprovided by secret store\"|passwd|sh"},
		{name: "sudo wrapper", command: "echo \"root:provided by secret store\"|sudo chpasswd|bash"},
		{name: "env wrapper", command: "echo -e \"service-user\\nprovided by secret store\\nprovided by secret store\"|env passwd|bash"},
		{name: "redirected source", command: "echo -e \"service-user\\nprovided by secret store\\nprovided by secret store\" >/tmp/input|passwd|bash"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{
				Tool:        "shell",
				Command:     test.command,
				DialectHint: DialectPOSIX,
			})
			if fact, ok := ExactPOSIXLiteralPasswordChange(
				facts,
				POSIXLiteralPasswordChangeOutcomeSucceeded,
			); ok {
				t.Fatalf("unexpected proof: %+v facts=%+v", fact, facts)
			}
			for _, command := range facts.Commands {
				if command.Program == "passwd" || command.Program == "chpasswd" {
					if hasFactOperation(command, OperationAccountChange) {
						t.Fatalf("unexpected account-change operation: %+v", command)
					}
				}
			}
		})
	}
}

func TestPOSIXLiteralPasswordChangeHelpAndStatusArePreviewOnly(t *testing.T) {
	for _, command := range []string{
		"passwd --help",
		"passwd --version",
		"passwd -S",
		"passwd --status service-user",
		"chpasswd -h",
		"chpasswd --version",
	} {
		t.Run(command, func(t *testing.T) {
			facts := Analyze(Input{Tool: "shell", Command: command, DialectHint: DialectPOSIX})
			if !facts.Authoritative() || len(facts.Commands) != 1 ||
				facts.Commands[0].Effect != EffectPreview ||
				hasFactOperation(facts.Commands[0], OperationAccountChange) {
				t.Fatalf("unexpected preview facts: %+v", facts)
			}
			if _, ok := ExactPOSIXLiteralPasswordChange(
				facts,
				POSIXLiteralPasswordChangeOutcomeSucceeded,
			); ok {
				t.Fatal("preview produced completed password-change proof")
			}
		})
	}
}

func TestExactPOSIXLiteralPasswordChangeRequiresSuccessfulResult(t *testing.T) {
	facts := Analyze(Input{
		Tool:        "shell",
		Command:     "echo \"service-user\\nprovided by secret store\\nprovided by secret store\\n\"|passwd",
		DialectHint: DialectPOSIX,
	})
	for _, outcome := range []POSIXLiteralPasswordChangeOutcome{
		POSIXLiteralPasswordChangeOutcomeUnknown,
		POSIXLiteralPasswordChangeOutcomeFailed,
		"unexpected",
	} {
		if fact, ok := ExactPOSIXLiteralPasswordChange(facts, outcome); ok {
			t.Fatalf("outcome %q produced proof %+v", outcome, fact)
		}
	}
}

func TestPOSIXLiteralPasswordChangeFactDoesNotRetainSensitiveValues(t *testing.T) {
	facts := Analyze(Input{
		Tool:        "shell",
		Command:     "echo \"root:provided by secret store\"|chpasswd|bash",
		DialectHint: DialectPOSIX,
	})
	fact, ok := ExactPOSIXLiteralPasswordChange(
		facts,
		POSIXLiteralPasswordChangeOutcomeSucceeded,
	)
	if !ok || fact.CommandID == 0 || fact.Form == "" {
		t.Fatalf("fact=%+v ok=%t", fact, ok)
	}
}

func passwordChangeTestSinkHasOperation(
	facts Facts,
	commandID int64,
	program string,
) bool {
	for _, command := range facts.Commands {
		if command.ID == commandID && command.Program == program {
			return hasFactOperation(command, OperationAccountChange)
		}
	}
	return false
}
