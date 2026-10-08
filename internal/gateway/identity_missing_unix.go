// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"errors"
	osuser "os/user"

	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// definitiveMissingAccount reports a directory lookup error that says the uid
// has no account: the NSS resolver's not-found, or os/user's unknown uid. The
// cache counts it as a failing lookup only until the directory answers for
// another account (GAP-0696, GAP-0712).
func definitiveMissingAccount(err error) bool {
	var unknown osuser.UnknownUserIdError
	return unixidentity.IsNotFound(err) || errors.As(err, &unknown)
}
