// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

func TestExactLinuxSecurityControlDisable(t *testing.T) {
	for _, test := range []struct {
		name    string
		command string
		want    bool
	}{
		{name: "disable audit subsystem", command: `auditctl -e 0`, want: true},
		{name: "set selinux permissive numeric", command: `setenforce 0`, want: true},
		{name: "set selinux permissive name", command: `setenforce Permissive`, want: true},
		{name: "stop firewall service", command: `systemctl stop ufw`, want: true},
		{name: "stop firewall service unit", command: `systemctl stop firewalld.service`, want: true},
		{name: "stop audit service", command: `systemctl stop auditd`, want: true},
		{name: "stop journal through sudo", command: `sudo systemctl stop systemd-journald`, want: true},
		{name: "restore audit subsystem", command: `auditctl -e 1`},
		{name: "lock audit configuration", command: `auditctl -e 2`},
		{name: "restore selinux", command: `setenforce Enforcing`},
		{name: "start firewall service", command: `systemctl start ufw`},
		{name: "restart audit service", command: `systemctl restart auditd`},
		{name: "stop ordinary service", command: `systemctl stop nginx`},
		{name: "sudo ordinary service", command: `sudo systemctl stop nginx`},
		{name: "systemctl extra target", command: `systemctl stop ufw nginx`},
		{name: "audit status", command: `auditctl -s`},
		{name: "delete audit rules", command: `auditctl -D`},
		{name: "dynamic state", command: `setenforce "$STATE"`},
		{name: "conditional disable", command: `test -f /tmp/lab && auditctl -e 0`},
		{name: "redirected disable", command: `auditctl -e 0 2>/dev/null`},
		{name: "conditional service stop", command: `test -f /tmp/lab && systemctl stop ufw`},
		{name: "redirected service stop", command: `systemctl stop ufw 2>/dev/null`},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{
				Tool: "shell", Command: test.command, CWD: "/repo", DialectHint: DialectPOSIX,
			})
			if got := ExactLinuxSecurityControlDisable(facts); got != test.want {
				t.Fatalf("proof=%t want=%t facts=%#v", got, test.want, facts)
			}
		})
	}
}
