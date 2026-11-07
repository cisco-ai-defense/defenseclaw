// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package safefile

import "errors"

// A non-Windows rename does not drop the name, but validation can still
// observe the old and new file identities in one read attempt.
func transientReadError(err error) bool { return errors.Is(err, ErrReadIdentityChanged) }
