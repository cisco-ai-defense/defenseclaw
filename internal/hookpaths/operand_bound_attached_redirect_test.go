// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"strings"
	"testing"
)

func TestRedirectsWrittenAgainstAWordCountTowardTheCallBound(t *testing.T) {
	for _, row := range []struct{ name, command string }{
		{"after an argument", "echo x" + strings.Repeat(">f", 5000)},
		{"after the program", "echo" + strings.Repeat(">f", 5000)},
		{"after a quoted argument", "echo \"x\"" + strings.Repeat(">f", 5000)},
	} {
		t.Run(row.name, func(t *testing.T) {
			_, over := BoundCommandOperands(row.command, "", "")
			if !over {
				t.Errorf("5000 ordinary redirect targets did not enter the call bound")
			}
		})
	}
}
