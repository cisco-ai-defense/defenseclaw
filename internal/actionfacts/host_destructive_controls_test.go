// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

func TestExactMacOSUnifiedLogErase(t *testing.T) {
	tests := []struct {
		name    string
		command string
		want    bool
	}{
		{name: "direct", command: `log erase --all`, want: true},
		{name: "sudo", command: `sudo log erase --all`, want: true},
		{name: "destructive with ttl sibling", command: "sudo log erase --all\nsudo log erase --ttl", want: true},
		{name: "ttl maintenance", command: `sudo log erase --ttl`},
		{name: "query", command: `log show --last 1h`},
		{name: "dynamic", command: `log erase "$SCOPE"`},
		{name: "conditional", command: `test -f /tmp/lab && log erase --all`},
		{name: "pipeline", command: `log erase --all | cat`},
		{name: "redirect", command: `log erase --all >/dev/null`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{Tool: "shell", Command: test.command, DialectHint: DialectPOSIX})
			if got := ExactMacOSUnifiedLogErase(facts); got != test.want {
				t.Fatalf("ExactMacOSUnifiedLogErase() = %v, want %v; facts=%#v", got, test.want, facts)
			}
		})
	}
}

func TestExactLinuxMagicSysRqDestruction(t *testing.T) {
	tests := []struct {
		name    string
		command string
		want    bool
	}{
		{name: "reboot quoted", command: `echo "b" > /proc/sysrq-trigger`, want: true},
		{name: "kill all compact redirect", command: `echo i>/proc/sysrq-trigger`, want: true},
		{name: "poweroff", command: `echo o > /proc/sysrq-trigger`, want: true},
		{name: "enable then reboot pair", command: "echo 1> /proc/sys/kernel/sysrq\necho b> /proc/sysrq-trigger", want: true},
		{name: "enable only", command: `echo 1 > /proc/sys/kernel/sysrq`},
		{name: "sync key", command: `echo s > /proc/sysrq-trigger`},
		{name: "dynamic key", command: `echo "$KEY" > /proc/sysrq-trigger`},
		{name: "dynamic target", command: `echo b > "$TARGET"`},
		{name: "append", command: `echo b >> /proc/sysrq-trigger`},
		{name: "stderr", command: `echo b 2> /proc/sysrq-trigger`},
		{name: "conditional", command: `test -f /tmp/lab && echo b > /proc/sysrq-trigger`},
		{name: "pipeline", command: `echo b | tee /proc/sysrq-trigger`},
		{name: "inert text", command: `printf '%s\n' 'echo b > /proc/sysrq-trigger'`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{Tool: "shell", Command: test.command, DialectHint: DialectPOSIX})
			if got := ExactLinuxMagicSysRqDestruction(facts); got != test.want {
				t.Fatalf("ExactLinuxMagicSysRqDestruction() = %v, want %v; facts=%#v", got, test.want, facts)
			}
		})
	}
}

func TestExactPOSIXHostHalt(t *testing.T) {
	tests := []struct {
		name    string
		command string
		want    bool
	}{
		{name: "power off", command: `halt -p`, want: true},
		{name: "reboot", command: `halt -r`, want: true},
		{name: "bare halt", command: `halt`},
		{name: "wtmp only", command: `halt -w`},
		{name: "force", command: `halt -f`},
		{name: "extra operand", command: `halt -p now`},
		{name: "sudo wrapper", command: `sudo halt -p`},
		{name: "generic reboot", command: `reboot`},
		{name: "generic shutdown", command: `shutdown -h now`},
		{name: "conditional", command: `test -f /tmp/window && halt -p`},
		{name: "pipeline", command: `halt -r | cat`},
		{name: "redirect", command: `halt -p >/dev/null`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{Tool: "shell", Command: test.command, DialectHint: DialectPOSIX})
			if got := ExactPOSIXHostHalt(facts); got != test.want {
				t.Fatalf("ExactPOSIXHostHalt() = %v, want %v; facts=%#v", got, test.want, facts)
			}
		})
	}
}

func TestExactPOSIXSystemLogDestruction(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		command string
		want    bool
	}{
		{name: "null overwrite", command: `cat /dev/null > /var/log/messages`, want: true},
		{name: "zero overwrite", command: `cat /dev/zero > /var/log/security`, want: true},
		{name: "truncate short", command: `truncate -s 0 /var/log/auth.log`, want: true},
		{name: "truncate long", command: `truncate --size=0 /var/log/audit/audit.log`, want: true},
		{name: "remove", command: `rm -rf /var/log/syslog`, want: true},
		{name: "empty echo", command: `echo '' > /var/log/messages`, want: true},
		{name: "unlink", command: `unlink /var/log/messages`, want: true},
		{name: "journal vacuum", command: `journalctl --vacuum-time=0`, want: true},
		{name: "sudo journal vacuum", command: `sudo journalctl --vacuum-time=0`, want: true},
		{name: "read", command: `cat /var/log/messages`},
		{name: "append null", command: `cat /dev/null >> /var/log/messages`},
		{name: "nonempty echo", command: `echo maintenance > /var/log/messages`},
		{name: "application log", command: `truncate -s 0 /var/log/nginx/access.log`},
		{name: "rotated log", command: `rm -rf /var/log/messages.1`},
		{name: "bounded vacuum", command: `journalctl --vacuum-time=2d`},
		{name: "dynamic path", command: `truncate -s 0 "$LOG"`},
		{name: "extra remove target", command: `rm -rf /var/log/messages /var/log/security`},
		{name: "conditional", command: `test -f /tmp/attack && truncate -s 0 /var/log/messages`},
		{name: "pipeline", command: `cat /dev/null | tee /var/log/messages`},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			facts := Analyze(Input{Tool: "shell", Command: test.command, DialectHint: DialectPOSIX})
			if got := ExactPOSIXSystemLogDestruction(facts); got != test.want {
				t.Fatalf("ExactPOSIXSystemLogDestruction() = %v, want %v; facts=%#v", got, test.want, facts)
			}
		})
	}
}
