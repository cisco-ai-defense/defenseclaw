// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import "github.com/defenseclaw/defenseclaw/internal/unixidentity"

func definitiveMissingAccount(err error) bool { return unixidentity.IsNotFound(err) }
