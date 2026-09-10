// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

const (
	atomicMacOSSoftwareUpdatePrompt = `osascript -e 'tell app "System Preferences" to activate' -e 'tell app "System Preferences" to activate' -e 'tell app "System Preferences" to display dialog "Software Update requires that you type your password to apply changes." & return & return  default answer "" with icon 1 with hidden answer with title "Software Update"'`
	atomicMacOSSecurityUpdatePrompt = `PWD_SPOOF=$(osascript -e 'display dialog "To perform a security update MacOS needs your passphrase." with title "MacOS Security Update" default answer "" with icon stop with hidden answer')
echo $PWD_SPOOF`
)

func TestExactFakeMacOSUpdateCredentialPrompt(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		command string
		want    bool
	}{
		{name: "atomic system preferences prompt", command: atomicMacOSSoftwareUpdatePrompt, want: true},
		{name: "atomic captured security update prompt", command: atomicMacOSSecurityUpdatePrompt, want: true},
		{name: "generic dialog", command: `osascript -e 'display dialog "Build completed" buttons {"OK"}'`},
		{name: "legitimate credential dialog", command: `osascript -e 'display dialog "Enter the password for the approved VPN" default answer "" with hidden answer'`},
		{name: "real software update", command: `softwareupdate --install --all`},
		{name: "missing hidden answer", command: `osascript -e 'display dialog "To perform a security update MacOS needs your passphrase." with title "MacOS Security Update" default answer "" with icon stop'`},
		{name: "changed security message", command: `osascript -e 'display dialog "To perform a security update macOS needs your password." with title "MacOS Security Update" default answer "" with icon stop with hidden answer'`},
		{name: "changed security title", command: `osascript -e 'display dialog "To perform a security update MacOS needs your passphrase." with title "Security Update" default answer "" with icon stop with hidden answer'`},
		{name: "changed security icon", command: `osascript -e 'display dialog "To perform a security update MacOS needs your passphrase." with title "MacOS Security Update" default answer "" with icon caution with hidden answer'`},
		{name: "extra osascript expression", command: `osascript -e 'display dialog "To perform a security update MacOS needs your passphrase." with title "MacOS Security Update" default answer "" with icon stop with hidden answer' -e 'return 1'`},
		{name: "dynamic script", command: `osascript -e "$PROMPT"`},
		{name: "pipeline", command: `osascript -e 'display dialog "To perform a security update MacOS needs your passphrase." with title "MacOS Security Update" default answer "" with icon stop with hidden answer' | cat`},
		{name: "redirect", command: `osascript -e 'display dialog "To perform a security update MacOS needs your passphrase." with title "MacOS Security Update" default answer "" with icon stop with hidden answer' >/tmp/result`},
		{name: "conditional", command: `test -f /tmp/ready && osascript -e 'display dialog "To perform a security update MacOS needs your passphrase." with title "MacOS Security Update" default answer "" with icon stop with hidden answer'`},
		{name: "sudo wrapper", command: `sudo osascript -e 'display dialog "To perform a security update MacOS needs your passphrase." with title "MacOS Security Update" default answer "" with icon stop with hidden answer'`},
		{name: "absolute executable", command: `/usr/bin/osascript -e 'display dialog "To perform a security update MacOS needs your passphrase." with title "MacOS Security Update" default answer "" with icon stop with hidden answer'`},
		{name: "single activation", command: `osascript -e 'tell app "System Preferences" to activate' -e 'tell app "System Preferences" to display dialog "Software Update requires that you type your password to apply changes." & return & return  default answer "" with icon 1 with hidden answer with title "Software Update"'`},
		{name: "changed preferences app", command: `osascript -e 'tell app "System Settings" to activate' -e 'tell app "System Settings" to activate' -e 'tell app "System Settings" to display dialog "Software Update requires that you type your password to apply changes." & return & return  default answer "" with icon 1 with hidden answer with title "Software Update"'`},
		{name: "changed password message", command: `osascript -e 'tell app "System Preferences" to activate' -e 'tell app "System Preferences" to activate' -e 'tell app "System Preferences" to display dialog "Software Update requires your administrator password." & return & return default answer "" with icon 1 with hidden answer with title "Software Update"'`},
		{name: "inert echo", command: `echo 'osascript -e display dialog Software Update with hidden answer'`},
		{name: "inert printf exact text", command: `printf '%s\n' 'osascript -e '\''display dialog "To perform a security update MacOS needs your passphrase." with title "MacOS Security Update" default answer "" with icon stop with hidden answer'\'''`},
		{name: "wrong dialect", command: atomicMacOSSoftwareUpdatePrompt},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			dialect := DialectPOSIX
			if test.name == "wrong dialect" {
				dialect = DialectPowerShell
			}
			facts := Analyze(Input{Tool: "shell", Command: test.command, DialectHint: dialect})
			if got := ExactFakeMacOSUpdateCredentialPrompt(facts); got != test.want {
				t.Fatalf("ExactFakeMacOSUpdateCredentialPrompt() = %v, want %v; facts=%+v", got, test.want, facts)
			}
		})
	}
}

func TestFakeMacOSUpdateCredentialPromptClassificationIsClosed(t *testing.T) {
	positive := Analyze(Input{Tool: "shell", Command: atomicMacOSSoftwareUpdatePrompt, DialectHint: DialectPOSIX})
	if !positive.Authoritative() || len(positive.Commands) != 1 ||
		!hasFactOperation(positive.Commands[0], OperationCredentialRead) {
		t.Fatalf("exact direct prompt is not authoritative credential capture: %+v", positive)
	}
	generic := Analyze(Input{Tool: "shell", Command: `osascript -e 'display dialog "Password" default answer "" with hidden answer'`, DialectHint: DialectPOSIX})
	if generic.Authoritative() || len(generic.Commands) != 1 ||
		hasFactOperation(generic.Commands[0], OperationCredentialRead) {
		t.Fatalf("generic osascript escaped closed classification: %+v", generic)
	}
}
