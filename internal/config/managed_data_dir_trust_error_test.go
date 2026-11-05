// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"testing"
)

// The Cowork source plan tells a data_dir ACL refusal apart with errors.As;
// the message and the wrapped walk error stay as before.
func TestManagedDataDirTrustErrorKeepsMessageAndCause(t *testing.T) {
	cause := errors.New(`C:\ProgramData\Cisco\DefenseClaw\runtime: BUILTIN\Users (S-1-5-32-545)`)
	var err error = &ManagedDataDirTrustError{Err: cause}
	want := "config: managed_enterprise data_dir trust check failed: " + cause.Error()
	if err.Error() != want {
		t.Fatalf("message = %q, want %q", err.Error(), want)
	}
	if !errors.Is(err, cause) {
		t.Fatal("the walk error is not unwrapped")
	}
	var drift *ManagedDataDirTrustError
	if !errors.As(err, &drift) {
		t.Fatal("errors.As does not find the data_dir refusal")
	}
}
