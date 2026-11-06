// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package safefile

// InDataFileTransaction runs the publication operation on platforms whose
// ordinary rename already keeps the old or new name available to readers.
func InDataFileTransaction(_, _ string, operation func() error) error { return operation() }

// InDataBytesTransaction runs the publication operation on other platforms.
func InDataBytesTransaction(_ []byte, _ string, operation func() error) error { return operation() }
