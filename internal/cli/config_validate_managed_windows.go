// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

// Windows keeps the validator's diagnostic; its managed Setup words it.
func configValidatePlainRefusal(error, configV8WireFailure, string, string) (string, bool) {
	return "", false
}

// configValidateCredentialsDir leaves credential references to the source's
// own path on Windows.
func configValidateCredentialsDir(string) string { return "" }
