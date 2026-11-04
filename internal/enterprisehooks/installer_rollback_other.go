// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !darwin

package enterprisehooks

import "github.com/defenseclaw/defenseclaw/internal/gateway/connector"

// Other hosts keep their existing rollback: a failed install tears the
// connector down.
func keepProtectedHooksOnRepairFailure(connector.HookContractLockEntry) bool { return false }

func reportProtectedHookRepairFailure(string, string, error) {}

func clearProtectedHookRepairFailure(string, string) {}
