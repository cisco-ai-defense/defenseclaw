// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"fmt"
	"testing"
)

func TestGAP0991DrivePathInUnknownProgramText(t *testing.T) {
	home := "C:/fixture/home"
	cwd := home + "/project"
	for i, form := range []string{"cp new.pub %s", "tee -a %s < new.pub", "cat new.pub >> %s"} {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			command := "$T send '" + fmt.Sprintf(form, home+"/.ssh/authorized_keys") + "'"
			if !actionPosixTargetMention(command, cwd, home, 0, false, nil) {
				t.Fatal("protected drive path missing from text reading")
			}
		})
	}
}
