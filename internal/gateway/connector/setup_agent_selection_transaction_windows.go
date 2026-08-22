// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import "errors"

// ProtectedSetupAgentSelectionTransaction is unavailable on native Windows;
// its enterprise managed-policy path does not use Darwin setup receipts.
type ProtectedSetupAgentSelectionTransaction struct{}

func PrepareProtectedSetupAgentSelectionTransaction(string, string) (*ProtectedSetupAgentSelectionTransaction, error) {
	return nil, errors.New("protected setup selection transactions are unavailable on native Windows")
}

func (*ProtectedSetupAgentSelectionTransaction) Acquire() error {
	return errors.New("protected setup selection transactions are unavailable on native Windows")
}

func (*ProtectedSetupAgentSelectionTransaction) Release() error { return nil }
