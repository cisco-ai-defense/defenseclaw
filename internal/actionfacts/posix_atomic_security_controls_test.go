// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

func TestExactPAMPasswordCapture(t *testing.T) {
	debug := parseCommandAs(`echo "session required pam_tty_audit.so enable=* log_passwd" >> /etc/pam.d/sshd`, DialectPOSIX, 1, 0)
	classifyOutput(&debug)
	if len(debug.commands) != 1 || !hasFactOperation(debug.commands[0], OperationPolicyBypass) {
		t.Fatalf("direct classification omitted PAM semantics: %+v", debug.commands)
	}
	for _, test := range []struct {
		name    string
		command string
		want    bool
	}{
		{
			name:    "source append log passwd",
			command: `echo "session required pam_tty_audit.so enable=* log_passwd" >> /etc/pam.d/sshd`,
			want:    true,
		},
		{
			name:    "literal overwrite alternate option",
			command: `echo 'session required pam_tty_audit.so enable=* log_password' > /etc/pam.d/login`,
			want:    true,
		},
		{name: "missing all users", command: `echo "session required pam_tty_audit.so log_passwd" >> /etc/pam.d/sshd`},
		{name: "missing password logging", command: `echo "session required pam_tty_audit.so enable=*" >> /etc/pam.d/sshd`},
		{name: "nearby module", command: `echo "session required pam_tty_audit_fake.so enable=* log_passwd" >> /etc/pam.d/sshd`},
		{name: "commented entry", command: `echo "# session required pam_tty_audit.so enable=* log_passwd" >> /etc/pam.d/sshd`},
		{name: "dynamic entry", command: `echo "session required pam_tty_audit.so enable=$USERS log_passwd" >> /etc/pam.d/sshd`},
		{name: "dynamic target", command: `echo "session required pam_tty_audit.so enable=* log_passwd" >> "/etc/pam.d/$SERVICE"`},
		{name: "nested target", command: `echo "session required pam_tty_audit.so enable=* log_passwd" >> /etc/pam.d/testing/sshd`},
		{name: "outside pam", command: `echo "session required pam_tty_audit.so enable=* log_passwd" >> /tmp/sshd`},
		{name: "stdout descriptor copy", command: `echo "session required pam_tty_audit.so enable=* log_passwd" 2>&1`},
		{name: "pipeline", command: `echo "session required pam_tty_audit.so enable=* log_passwd" | tee -a /etc/pam.d/sshd`},
		{name: "conditional", command: `test -f /tmp/lab && echo "session required pam_tty_audit.so enable=* log_passwd" >> /etc/pam.d/sshd`},
		{name: "extra command", command: "echo \"session required pam_tty_audit.so enable=* log_passwd\" >> /etc/pam.d/sshd\nwhoami"},
		{name: "inert printf", command: `printf '%s\n' 'echo "session required pam_tty_audit.so enable=* log_passwd" >> /etc/pam.d/sshd'`},
		{name: "shell wrapper", command: `sh -c 'echo "session required pam_tty_audit.so enable=* log_passwd" >> /etc/pam.d/sshd'`},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{
				Tool: "shell", Command: test.command, CWD: "/repo", DialectHint: DialectPOSIX,
			})
			if got := ExactPAMPasswordCapture(facts); got != test.want {
				direct := false
				if len(facts.Commands) == 1 {
					direct = exactPAMPasswordCaptureCommand(facts.Commands[0])
				}
				t.Fatalf("proof=%t direct=%t want=%t parse=%+v commands=%+v", got, direct, test.want, facts.Parse, facts.Commands)
			}
		})
	}
}

func TestExactPOSIXLoggingHardeningDisable(t *testing.T) {
	for _, test := range []struct {
		name    string
		command string
		want    bool
	}{
		{name: "journald storage none", command: `sed -i 's/Storage=auto/Storage=none/' /etc/systemd/journald.conf`, want: true},
		{name: "journald through sudo", command: `sudo sed --in-place 's/Storage=auto/Storage=none/' /etc/systemd/journald.conf`, want: true},
		{name: "freebsd syslog stop disable", command: "service syslogd stop\nsysrc syslogd_enable=\"NO\"", want: true},
		{name: "freebsd syslog sudo", command: "sudo service syslogd stop\nsudo sysrc syslogd_enable=\"NO\"", want: true},
		{name: "disable aslr", command: `sysctl -w kernel.randomize_va_space=0`, want: true},
		{name: "disable aslr sudo", command: `sudo sysctl -w kernel.randomize_va_space=0`, want: true},
		{name: "freebsd pf stop disable", command: "service pf stop\nservice pf disable", want: true},
		{name: "ufw logging off", command: `ufw logging off`, want: true},
		{name: "journald restoration", command: `sed -i 's/Storage=none/Storage=auto/' /etc/systemd/journald.conf`},
		{name: "journald dynamic target", command: `sed -i 's/Storage=auto/Storage=none/' "$CONF"`},
		{name: "journald backup suffix", command: `sed -i.bak 's/Storage=auto/Storage=none/' /etc/systemd/journald.conf`},
		{name: "journald extra command", command: "sed -i 's/Storage=auto/Storage=none/' /etc/systemd/journald.conf\nwhoami"},
		{name: "syslog stop only", command: `service syslogd stop`},
		{name: "syslog disable only", command: `sysrc syslogd_enable="NO"`},
		{name: "syslog restore", command: "service syslogd stop\nsysrc syslogd_enable=\"YES\""},
		{name: "syslog reverse order", command: "sysrc syslogd_enable=\"NO\"\nservice syslogd stop"},
		{name: "aslr restore", command: `sysctl -w kernel.randomize_va_space=2`},
		{name: "aslr query", command: `sysctl kernel.randomize_va_space`},
		{name: "aslr dynamic", command: `sysctl -w kernel.randomize_va_space="$STATE"`},
		{name: "aslr conditional", command: `test -f /tmp/lab && sysctl -w kernel.randomize_va_space=0`},
		{name: "pf stop only", command: `service pf stop`},
		{name: "pf disable only", command: `service pf disable`},
		{name: "pf restore", command: "service pf stop\nservice pf enable"},
		{name: "pf extra command", command: "service pf stop\nwhoami\nservice pf disable"},
		{name: "ufw logging on", command: `ufw logging on`},
		{name: "ufw disable is different control", command: `ufw disable`},
		{name: "ufw extra option", command: `ufw --force logging off`},
		{name: "inert text", command: `printf '%s\n' 'ufw logging off'`},
		{name: "shell wrapper", command: `sh -c 'ufw logging off'`},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{
				Tool: "shell", Command: test.command, CWD: "/repo", DialectHint: DialectPOSIX,
			})
			if got := ExactPOSIXLoggingHardeningDisable(facts); got != test.want {
				t.Fatalf("proof=%t want=%t parse=%+v commands=%+v", got, test.want, facts.Parse, facts.Commands)
			}
		})
	}
}
