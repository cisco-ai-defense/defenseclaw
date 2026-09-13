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
		{name: "stop audit service through legacy service", command: `service auditd stop`, want: true},
		{name: "stop audit service through legacy service and sudo", command: `sudo service auditd stop`, want: true},
		{name: "restore audit subsystem", command: `auditctl -e 1`},
		{name: "lock audit configuration", command: `auditctl -e 2`},
		{name: "restore selinux", command: `setenforce Enforcing`},
		{name: "start firewall service", command: `systemctl start ufw`},
		{name: "restart audit service", command: `systemctl restart auditd`},
		{name: "stop ordinary service", command: `systemctl stop nginx`},
		{name: "sudo ordinary service", command: `sudo systemctl stop nginx`},
		{name: "systemctl extra target", command: `systemctl stop ufw nginx`},
		{name: "audit status", command: `auditctl -s`},
		{name: "delete all audit rules", command: `auditctl -D`, want: true},
		{name: "delete exact audit rule", command: `sudo auditctl -d exit,always -F arch=b64 -S execve -k exec-trace`, want: true},
		{name: "add audit rule", command: `auditctl -a exit,always -S execve`},
		{name: "audit watch", command: `auditctl -w /etc/passwd -p wa`},
		{name: "dynamic audit key", command: `auditctl -d exit,always -S execve -k "$KEY"`},
		{name: "unknown audit delete option", command: `auditctl -d exit,always --future value`},
		{name: "dynamic state", command: `setenforce "$STATE"`},
		{name: "conditional disable", command: `test -f /tmp/lab && auditctl -e 0`},
		{name: "redirected disable", command: `auditctl -e 0 2>/dev/null`},
		{name: "conditional service stop", command: `test -f /tmp/lab && systemctl stop ufw`},
		{name: "redirected service stop", command: `systemctl stop ufw 2>/dev/null`},
		{name: "legacy service status", command: `service auditd status`},
		{name: "legacy service start", command: `service auditd start`},
		{name: "legacy service restart", command: `service auditd restart`},
		{name: "legacy service other target", command: `service ssh stop`},
		{name: "legacy service extra argument", command: `service auditd stop now`},
		{name: "legacy service pipeline", command: `service auditd stop | cat`},
		{name: "legacy service redirect", command: `service auditd stop >/tmp/result`},
		{name: "legacy service expansion", command: `service "$SERVICE" stop`},
		{name: "legacy service conditional", command: `test -f /tmp/lab && service auditd stop`},
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

func TestExactLinuxSecurityControlDisableRejectsLegacyServiceArgv(t *testing.T) {
	facts := Analyze(Input{
		Tool: "exec", Argv: []string{"service", "auditd", "stop"}, CWD: "/repo",
		DialectHint: DialectArgv,
	})
	if ExactLinuxSecurityControlDisable(facts) {
		t.Fatalf("argv-only legacy service unexpectedly proved disablement: %#v", facts)
	}
}
