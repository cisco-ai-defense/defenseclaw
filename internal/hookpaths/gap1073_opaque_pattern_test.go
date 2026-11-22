// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"fmt"
	"testing"
)

// TestGAP1073OpaqueScanKeepsDrivePatterns: the opaque scan of an unknown
// program word skips a pattern token without a drive prefix, as the text
// scan does (rel-1-0-10:GAP-1073), but a drive-prefixed keys path in that
// text, a pattern included, is still a target (rel-1-0-10:GAP-0991).
func TestGAP1073OpaqueScanKeepsDrivePatterns(t *testing.T) {
	home := "C:/fixture/home"
	cwd := home + "/project"
	for i, target := range []string{
		home + "/.ssh/authorized_keys",
		home + "/.ssh/authorized_k*",
		home + "/.ssh/authorized_key?",
		home + "/.ssh/authorized_k[e]ys",
	} {
		for j, form := range []string{"cp new.pub %s", "tee -a %s < new.pub", "cat new.pub >> %s"} {
			t.Run(fmt.Sprintf("%d/%d", i, j), func(t *testing.T) {
				command := "$T send '" + fmt.Sprintf(form, target) + "'"
				if !actionPosixTargetMention(command, cwd, home, 0, false, nil) {
					t.Fatal("protected drive path missing from text reading")
				}
			})
		}
	}
}
