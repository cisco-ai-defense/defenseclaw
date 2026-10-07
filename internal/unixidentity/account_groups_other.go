//go:build !windows && !darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package unixidentity

import (
	"context"
	"os/user"
)

// platformAccountGroupIDs trusts os/user's listing here (ids, listErr).
// Linux directory accounts resolve through the NSSResolver, not through
// os/user.
func platformAccountGroupIDs(_ context.Context, _ commandRunner, _ *user.User, ids []string, listErr error) ([]string, error) {
	return ids, listErr
}
