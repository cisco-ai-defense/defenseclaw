//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"github.com/defenseclaw/defenseclaw/internal/hookcli"
)

func init() {
	describeManagedConfigLoadError = func(err error) error {
		if err == nil {
			return nil
		}
		if _, standalone := hookcli.ManagedHostWindowsStandalone(); !standalone {
			return err
		}
		if text := hookcli.WindowsEnterpriseNamePrincipals(err.Error()); text != err.Error() {
			return &describedTrustError{text: text, err: err}
		}
		return err
	}
}

// describedTrustError is a trust refusal with the accounts named; it still
// unwraps to the original error.
type describedTrustError struct {
	text string
	err  error
}

func (e *describedTrustError) Error() string { return e.text }
func (e *describedTrustError) Unwrap() error { return e.err }
