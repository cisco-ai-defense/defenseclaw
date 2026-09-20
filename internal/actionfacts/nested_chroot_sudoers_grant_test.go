// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

func TestExactPOSIXNestedChrootUnrestrictedSudoersGrant(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name    string
		command string
	}{
		{
			name: "dev shm host root",
			command: `chroot /dev/shm/.cache-7d607b/host /bin/bash -c ` +
				`'printf "logship ALL=(ALL) NOPASSWD:ALL\\n" >/etc/sudoers.d/logship'`,
		},
		{
			name: "tmp host root",
			command: `chroot /tmp/.ICE-unix/.sess-29f0f4/host /bin/bash -c ` +
				`'printf "scanner ALL=(ALL) NOPASSWD:ALL\\n" >/etc/sudoers.d/scanner'`,
		},
		{
			name: "var tmp host root",
			command: `/usr/sbin/chroot /var/tmp/.stage/host /bin/bash -c ` +
				`'printf "dbreader ALL=(ALL:ALL) NOPASSWD: ALL\\n" >/etc/sudoers.d/dbreader'`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			facts := Analyze(Input{
				Tool: "shell", Command: test.command, DialectHint: DialectPOSIX,
			})
			if facts.Authoritative() ||
				!ExactPOSIXNestedChrootUnrestrictedSudoersGrant(facts) {
				t.Fatalf("exact proof rejected: parse=%+v commands=%+v", facts.Parse, facts.Commands)
			}
		})
	}
}

func TestExactPOSIXNestedChrootUnrestrictedSudoersGrantStructuredArgv(t *testing.T) {
	t.Parallel()

	facts := Analyze(Input{
		Tool: "exec",
		Argv: []string{
			"chroot", "/tmp/static-host-root", "/bin/bash", "-c",
			`printf "service_user ALL=(ALL) NOPASSWD:ALL\\n" >/etc/sudoers.d/service_user`,
		},
		DialectHint: DialectPOSIX,
	})
	if !ExactPOSIXNestedChrootUnrestrictedSudoersGrant(facts) {
		t.Fatalf("structured argv proof rejected: parse=%+v commands=%+v", facts.Parse, facts.Commands)
	}
}

func TestExactPOSIXNestedChrootUnrestrictedSudoersGrantRejectsNearMisses(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name    string
		command string
	}{
		{name: "non temp root", command: `chroot /host /bin/bash -c 'printf "alice ALL=(ALL) NOPASSWD:ALL\\n" >/etc/sudoers.d/alice'`},
		{name: "temp root itself", command: `chroot /tmp /bin/bash -c 'printf "alice ALL=(ALL) NOPASSWD:ALL\\n" >/etc/sudoers.d/alice'`},
		{name: "cleaned traversal root", command: `chroot /tmp/stage/../host /bin/bash -c 'printf "alice ALL=(ALL) NOPASSWD:ALL\\n" >/etc/sudoers.d/alice'`},
		{name: "newline in root", command: "chroot '/tmp/host\nroot' /bin/bash -c 'printf \"alice ALL=(ALL) NOPASSWD:ALL\\\\n\" >/etc/sudoers.d/alice'"},
		{name: "chroot option", command: `chroot --userspec=0:0 /tmp/host /bin/bash -c 'printf "alice ALL=(ALL) NOPASSWD:ALL\\n" >/etc/sudoers.d/alice'`},
		{name: "option terminator", command: `chroot -- /tmp/host /bin/bash -c 'printf "alice ALL=(ALL) NOPASSWD:ALL\\n" >/etc/sudoers.d/alice'`},
		{name: "sudo wrapper", command: `sudo chroot /tmp/host /bin/bash -c 'printf "alice ALL=(ALL) NOPASSWD:ALL\\n" >/etc/sudoers.d/alice'`},
		{name: "alternate bash path", command: `chroot /tmp/host /usr/bin/bash -c 'printf "alice ALL=(ALL) NOPASSWD:ALL\\n" >/etc/sudoers.d/alice'`},
		{name: "alternate shell", command: `chroot /tmp/host /bin/sh -c 'printf "alice ALL=(ALL) NOPASSWD:ALL\\n" >/etc/sudoers.d/alice'`},
		{name: "bash wrapper option", command: `chroot /tmp/host /bin/bash --noprofile -c 'printf "alice ALL=(ALL) NOPASSWD:ALL\\n" >/etc/sudoers.d/alice'`},
		{name: "dynamic child", command: `chroot /tmp/host /bin/bash -c "printf '$USER ALL=(ALL) NOPASSWD:ALL\\n' >/etc/sudoers.d/alice"`},
		{name: "dynamic principal", command: `chroot /tmp/host /bin/bash -c 'printf "$USER ALL=(ALL) NOPASSWD:ALL\\n" >/etc/sudoers.d/alice'`},
		{name: "command substitution", command: `chroot /tmp/host /bin/bash -c 'printf "$(id -un) ALL=(ALL) NOPASSWD:ALL\\n" >/etc/sudoers.d/alice'`},
		{name: "additional command", command: `chroot /tmp/host /bin/bash -c 'printf "alice ALL=(ALL) NOPASSWD:ALL\\n" >/etc/sudoers.d/alice; chmod 0440 /etc/sudoers.d/alice'`},
		{name: "and command", command: `chroot /tmp/host /bin/bash -c 'printf "alice ALL=(ALL) NOPASSWD:ALL\\n" >/etc/sudoers.d/alice && echo done'`},
		{name: "newline command", command: "chroot /tmp/host /bin/bash -c 'printf \"alice ALL=(ALL) NOPASSWD:ALL\\\\n\" >/etc/sudoers.d/alice\nchmod 0440 /etc/sudoers.d/alice'"},
		{name: "outer redirect", command: `chroot /tmp/host /bin/bash -c 'printf "alice ALL=(ALL) NOPASSWD:ALL\\n" >/etc/sudoers.d/alice' >/tmp/status`},
		{name: "pipeline", command: `chroot /tmp/host /bin/bash -c 'printf "alice ALL=(ALL) NOPASSWD:ALL\\n" >/etc/sudoers.d/alice' | cat`},
		{name: "append redirect", command: `chroot /tmp/host /bin/bash -c 'printf "alice ALL=(ALL) NOPASSWD:ALL\\n" >>/etc/sudoers.d/alice'`},
		{name: "stderr redirect", command: `chroot /tmp/host /bin/bash -c 'printf "alice ALL=(ALL) NOPASSWD:ALL\\n" 2>/etc/sudoers.d/alice'`},
		{name: "host-prefixed target", command: `chroot /tmp/host /bin/bash -c 'printf "alice ALL=(ALL) NOPASSWD:ALL\\n" >/tmp/host/etc/sudoers.d/alice'`},
		{name: "sudoers file", command: `chroot /tmp/host /bin/bash -c 'printf "alice ALL=(ALL) NOPASSWD:ALL\\n" >/etc/sudoers'`},
		{name: "drop-in subdirectory", command: `chroot /tmp/host /bin/bash -c 'printf "alice ALL=(ALL) NOPASSWD:ALL\\n" >/etc/sudoers.d/team/alice'`},
		{name: "dynamic drop-in", command: `chroot /tmp/host /bin/bash -c 'printf "alice ALL=(ALL) NOPASSWD:ALL\\n" >/etc/sudoers.d/$USER'`},
		{name: "unsafe drop-in name", command: `chroot /tmp/host /bin/bash -c 'printf "alice ALL=(ALL) NOPASSWD:ALL\\n" >/etc/sudoers.d/alice~'`},
		{name: "root grant", command: `chroot /tmp/host /bin/bash -c 'printf "root ALL=(ALL) NOPASSWD:ALL\\n" >/etc/sudoers.d/root'`},
		{name: "tabbed root grant", command: `chroot /tmp/host /bin/bash -c 'printf "root\\tALL=(ALL) NOPASSWD:ALL\\n" >/etc/sudoers.d/root'`},
		{name: "root group grant", command: `chroot /tmp/host /bin/bash -c 'printf "%%root ALL=(ALL) NOPASSWD:ALL\\n" >/etc/sudoers.d/root-group'`},
		{name: "all principals grant", command: `chroot /tmp/host /bin/bash -c 'printf "ALL ALL=(ALL) NOPASSWD:ALL\\n" >/etc/sudoers.d/all'`},
		{name: "restricted grant", command: `chroot /tmp/host /bin/bash -c 'printf "alice ALL=(ALL) NOPASSWD:/usr/bin/id\\n" >/etc/sudoers.d/alice'`},
		{name: "extra sudoers line", command: `chroot /tmp/host /bin/bash -c 'printf "Defaults env_reset\\nalice ALL=(ALL) NOPASSWD:ALL\\n" >/etc/sudoers.d/alice'`},
		{name: "printf operand", command: `chroot /tmp/host /bin/bash -c 'printf "%s\\n" "alice ALL=(ALL) NOPASSWD:ALL" >/etc/sudoers.d/alice'`},
		{name: "echo writer", command: `chroot /tmp/host /bin/bash -c 'echo "alice ALL=(ALL) NOPASSWD:ALL" >/etc/sudoers.d/alice'`},
		{name: "nested shell", command: `chroot /tmp/host /bin/bash -c 'sh -c '\''printf "alice ALL=(ALL) NOPASSWD:ALL\\n" >/etc/sudoers.d/alice'\'''`},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			facts := Analyze(Input{
				Tool: "shell", Command: test.command, DialectHint: DialectPOSIX,
			})
			if ExactPOSIXNestedChrootUnrestrictedSudoersGrant(facts) {
				t.Fatalf("near miss produced proof: parse=%+v commands=%+v", facts.Parse, facts.Commands)
			}
		})
	}
}
