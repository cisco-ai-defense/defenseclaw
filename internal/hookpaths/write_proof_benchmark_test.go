// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "testing"

func BenchmarkShellWriteOperands(b *testing.B) {
	command := `printf '%s\n' marker >> /tmp/project/report.txt`
	for b.Loop() {
		ShellWriteOperands(command, "/tmp/project", "/tmp/home")
	}
}

func BenchmarkLiteralWriteOperands(b *testing.B) {
	command := `python3 -c 'open("report.txt","a").write("marker")'`
	for b.Loop() {
		LiteralWriteOperands(command, "/tmp/project", "/tmp/home")
	}
}
