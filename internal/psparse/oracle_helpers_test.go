// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package psparse

import (
	"fmt"
	"os/exec"
)

func sprintf(f string, a ...any) string { return fmt.Sprintf(f, a...) }

func fmtSscan(s string, a ...any) (int, error) { return fmt.Sscan(s, a...) }

func tailStderr(err error) string {
	if ee, ok := err.(*exec.ExitError); ok {
		s := string(ee.Stderr)
		if len(s) > 800 {
			return s[len(s)-800:]
		}
		return s
	}
	return err.Error()
}
