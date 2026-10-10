// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"errors"
	"fmt"
	"strconv"
)

// ErrConfigNotWritable marks an OS refusal to replace a connector config.
// The concrete error also carries the target path and preserves the OS cause.
var ErrConfigNotWritable = errors.New("connector config file cannot be written")

type ConfigNotWritableError struct {
	Path  string
	Cause error
}

func (e *ConfigNotWritableError) Error() string {
	return fmt.Sprintf("connector config file %s cannot be written: %v", strconv.Quote(e.Path), e.Cause)
}

func (e *ConfigNotWritableError) Unwrap() error { return e.Cause }

func (e *ConfigNotWritableError) Is(target error) bool { return target == ErrConfigNotWritable }

func configWriteError(path string, err error) error {
	if configWritePermissionDenied(err) {
		return &ConfigNotWritableError{Path: path, Cause: err}
	}
	return err
}
