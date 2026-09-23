// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"testing"
)

func TestExactPOSIXDPKGStatusMutation(t *testing.T) {
	for _, test := range []struct {
		name    string
		command string
		want    bool
	}{
		{"write", "printf fixture > /var/lib/dpkg/status", true},
		{"append", "printf fixture >> /var/lib/dpkg/status", true},
		{"replace", "cp /tmp/status.new /var/lib/dpkg/status", true},
		{"read", "cat /var/lib/dpkg/status", false},
		{"package manager", "dpkg --update-avail /var/lib/dpkg/status", false},
		{"apt transaction", "apt-get install fixture", false},
		{"fixture lookalike", "printf fixture > /tmp/var/lib/dpkg/status", false},
		{"suffix lookalike", "printf fixture > /var/lib/dpkg/status.backup", false},
		{"dynamic target", "printf fixture > \"$ROOT/var/lib/dpkg/status\"", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{Tool: "shell", Command: test.command})
			if got := ExactPOSIXDPKGStatusMutation(facts); got != test.want {
				t.Fatalf("ExactPOSIXDPKGStatusMutation()=%t, want %t; parse=%s facts=%+v", got, test.want, facts.Parse.Status, facts)
			}
		})
	}
}

func TestExactSubmittedPOSIXDPKGStatusHeredocMutation(t *testing.T) {
	write := "cat << 'EOF' > /var/lib/dpkg/status\nPackage: fixture\nEOF\n"
	appendStatus := "cat >> /var/lib/dpkg/status << 'STATUS'\nPackage: fixture\nSTATUS\n"
	for _, test := range []struct {
		name  string
		input Input
		want  bool
	}{
		{name: "write", input: dpkgStatusHeredocInput(t, write, nil), want: true},
		{name: "append reverse redirect order", input: dpkgStatusHeredocInput(t, appendStatus, ptr(0.1)), want: true},
		{name: "read", input: dpkgStatusHeredocInput(t, "cat << 'EOF' /var/lib/dpkg/status\nfixture\nEOF\n", nil)},
		{name: "lookalike", input: dpkgStatusHeredocInput(t, "cat << 'EOF' > /tmp/var/lib/dpkg/status\nfixture\nEOF\n", nil)},
		{name: "suffix lookalike", input: dpkgStatusHeredocInput(t, "cat << 'EOF' > /var/lib/dpkg/status.backup\nfixture\nEOF\n", nil)},
		{name: "dynamic target", input: dpkgStatusHeredocInput(t, "cat << 'EOF' > $ROOT/var/lib/dpkg/status\nfixture\nEOF\n", nil)},
		{name: "extra command", input: dpkgStatusHeredocInput(t, write+"id\n", nil)},
		{name: "compound opener", input: dpkgStatusHeredocInput(t, "id; cat << 'EOF' > /var/lib/dpkg/status\nfixture\nEOF\n", nil)},
		{name: "multiple heredocs", input: dpkgStatusHeredocInput(t, "cat << 'ONE' << 'TWO' > /var/lib/dpkg/status\none\nONE\ntwo\nTWO\n", nil)},
		{name: "unclosed", input: dpkgStatusHeredocInput(t, "cat << 'EOF' > /var/lib/dpkg/status\nfixture\n", nil)},
		{name: "unquoted delimiter", input: dpkgStatusHeredocInput(t, "cat << EOF > /var/lib/dpkg/status\nfixture\nEOF\n", nil)},
		{name: "closing delimiter before end", input: dpkgStatusHeredocInput(t, "cat << 'EOF' > /var/lib/dpkg/status\nEOF\nfixture\nEOF\n", nil)},
		{name: "missing trailing enter", input: dpkgStatusHeredocInput(t, "cat << 'EOF' > /var/lib/dpkg/status\nfixture\nEOF", nil)},
		{name: "terminal control byte", input: dpkgStatusHeredocInput(t, "cat << 'EOF' > /var/lib/dpkg/status\nfixture\x1b[A\nEOF\n", nil)},
		{name: "negative duration", input: dpkgStatusHeredocInput(t, write, ptr(-1.0))},
		{name: "nonfinite duration", input: Input{Tool: "bash_command", Args: json.RawMessage(`{"keystrokes":"cat << 'EOF' > /var/lib/dpkg/status\\nfixture\\nEOF\\n","duration":1e999}`)}},
		{name: "unknown field", input: Input{Tool: "bash_command", Args: json.RawMessage(`{"keystrokes":"cat << 'EOF' > /var/lib/dpkg/status\\nfixture\\nEOF\\n","duration":0.1,"result":"success"}`)}},
		{name: "conflicting command", input: func() Input { input := dpkgStatusHeredocInput(t, write, nil); input.Command = "id\n"; return input }()},
		{name: "matching command", input: func() Input { input := dpkgStatusHeredocInput(t, write, nil); input.Command = write; return input }(), want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := ExactSubmittedPOSIXDPKGStatusHeredocMutation(test.input); got != test.want {
				t.Fatalf("ExactSubmittedPOSIXDPKGStatusHeredocMutation()=%t, want %t", got, test.want)
			}
		})
	}
}

func dpkgStatusHeredocInput(t *testing.T, command string, duration *float64) Input {
	t.Helper()
	object := map[string]any{"keystrokes": command}
	if duration != nil {
		object["duration"] = *duration
	}
	encoded, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	return Input{Tool: "bash_command", Args: encoded}
}

func ptr[T any](value T) *T { return &value }

func TestExactPOSIXKernelControlBindOverride(t *testing.T) {
	for _, test := range []struct {
		name    string
		command string
		want    bool
	}{
		{"kernel descendant", "mount --bind /tmp/core_pattern /proc/sys/kernel/core_pattern", true},
		{"net descendant", "mount --bind /tmp/tcp_wmem /proc/sys/net/ipv4/tcp_wmem", true},
		{"vm descendant", "mount --bind -- /tmp/swappiness /proc/sys/vm/swappiness", true},
		{"read", "cat /proc/sys/net/ipv4/tcp_wmem", false},
		{"remount", "mount --remount /proc/sys/net/ipv4/tcp_wmem", false},
		{"short bind", "mount -B /tmp/tcp_wmem /proc/sys/net/ipv4/tcp_wmem", false},
		{"source target reversed", "mount --bind /proc/sys/net/ipv4/tcp_wmem /tmp/tcp_wmem", false},
		{"proc sys root", "mount --bind /tmp/sys /proc/sys", false},
		{"kernel root", "mount --bind /tmp/kernel /proc/sys/kernel", false},
		{"lookalike target", "mount --bind /tmp/value /tmp/proc/sys/net/ipv4/tcp_wmem", false},
		{"prefix lookalike", "mount --bind /tmp/value /proc/sys/network/value", false},
		{"dynamic source", "mount --bind \"$SOURCE\" /proc/sys/net/ipv4/tcp_wmem", false},
		{"dynamic target", "mount --bind /tmp/tcp_wmem \"$TARGET\"", false},
		{"relative source", "mount --bind tcp_wmem /proc/sys/net/ipv4/tcp_wmem", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{Tool: "shell", Command: test.command})
			if got := ExactPOSIXKernelControlBindOverride(facts); got != test.want {
				t.Fatalf("ExactPOSIXKernelControlBindOverride()=%t, want %t; parse=%s facts=%+v", got, test.want, facts.Parse.Status, facts)
			}
		})
	}
}
