// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

func TestExactCompleteFirewallRelaxationSourceForms(t *testing.T) {
	for _, test := range []struct {
		name    string
		command string
	}{
		{
			name:    "flush all then accept input",
			command: "iptables -F\niptables -P INPUT ACCEPT",
		},
		{
			name:    "flush input then accept input",
			command: "sudo iptables -F INPUT\nsudo iptables -P INPUT ACCEPT",
		},
		{
			name: "accept all default policies",
			command: "iptables -P INPUT ACCEPT\n" +
				"iptables -P FORWARD ACCEPT\n" +
				"iptables -P OUTPUT ACCEPT",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{
				Tool: "shell", Command: test.command, CWD: "/repo",
				DialectHint: DialectPOSIX,
			})
			if !facts.Authoritative() || !ExactCompleteFirewallRelaxation(facts) {
				t.Fatalf("proof rejected: parse=%+v commands=%+v", facts.Parse, facts.Commands)
			}
			for _, command := range facts.Commands {
				if command.Program == "iptables" &&
					(!hasFactOperation(command, OperationConfigChange) ||
						!hasFactOperation(command, OperationPolicyBypass)) {
					t.Fatalf("iptables step lacks semantics: %+v", command)
				}
			}
		})
	}
}

func TestExactCompleteFirewallRelaxationHardNegatives(t *testing.T) {
	for _, test := range []struct {
		name    string
		command string
	}{
		{name: "flush only", command: "iptables -F"},
		{name: "accept input only", command: "iptables -P INPUT ACCEPT"},
		{name: "two policies only", command: "iptables -P INPUT ACCEPT\niptables -P FORWARD ACCEPT"},
		{name: "reordered flush pair", command: "iptables -P INPUT ACCEPT\niptables -F"},
		{name: "reordered policies", command: "iptables -P OUTPUT ACCEPT\niptables -P FORWARD ACCEPT\niptables -P INPUT ACCEPT"},
		{name: "dynamic chain", command: "iptables -F $CHAIN\niptables -P INPUT ACCEPT"},
		{name: "dynamic policy", command: "iptables -P INPUT $POLICY\niptables -P FORWARD ACCEPT\niptables -P OUTPUT ACCEPT"},
		{name: "sudo option", command: "sudo -n iptables -F\nsudo iptables -P INPUT ACCEPT"},
		{name: "shell wrapper", command: "sh -c 'iptables -F; iptables -P INPUT ACCEPT'"},
		{name: "redirect", command: "iptables -F > /tmp/result\niptables -P INPUT ACCEPT"},
		{name: "pipeline", command: "iptables -F | tee /tmp/result\niptables -P INPUT ACCEPT"},
		{name: "conditional", command: "iptables -F && iptables -P INPUT ACCEPT"},
		{name: "unrelated command", command: "iptables -F\nwhoami\niptables -P INPUT ACCEPT"},
		{name: "extra iptables option", command: "iptables -w -F\niptables -P INPUT ACCEPT"},
		{name: "delete rule", command: "iptables -D INPUT 1\niptables -P INPUT ACCEPT"},
		{name: "restore form", command: "iptables-restore < /tmp/open.rules"},
		{name: "help form", command: "iptables --help\niptables -P INPUT ACCEPT"},
		{name: "script text write", command: "printf '%s\\n' 'iptables -F' 'iptables -P INPUT ACCEPT' > /tmp/open-firewall.sh"},
		{name: "inert quoted source", command: "echo 'iptables -F; iptables -P INPUT ACCEPT'"},
		{name: "lowercase chain", command: "iptables -F input\niptables -P INPUT ACCEPT"},
		{name: "lowercase verdict", command: "iptables -F\niptables -P INPUT accept"},
		{name: "restoration", command: "iptables -F\niptables -P INPUT ACCEPT\niptables -P INPUT DROP"},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{
				Tool: "shell", Command: test.command, CWD: "/repo",
				DialectHint: DialectPOSIX,
			})
			if ExactCompleteFirewallRelaxation(facts) {
				t.Fatalf("hard negative proved: parse=%+v commands=%+v", facts.Parse, facts.Commands)
			}
		})
	}
}
