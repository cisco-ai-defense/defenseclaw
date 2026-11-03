// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"errors"
	"time"
)

// Windows publishes no clean-session entry: a per-user read-only folder
// there needs its own ACL design. Hooks keep the refusal during an outage.

func WriteForeignHookCleanMirrors(string, string, SessionKey, string, time.Time) error {
	return errors.New("no clean-session entry on Windows")
}

func DropForeignHookCleanMirrors(string, string, SessionKey) error { return nil }

func DropForeignHookCleanMirrorsForAccount(string, string) error { return nil }

func ForeignHookCleanServiceUID(string) (int, error) {
	return -1, errors.New("no clean-session entry on Windows")
}

func CheckForeignHookCleanMirror(ForeignHookCleanMirrorCheck) error {
	return errors.New("no clean-session entry on Windows")
}
