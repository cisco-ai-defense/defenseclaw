// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package main

import (
	"context"
	"errors"
)

func runDriver(context.Context, options, wrapperAdmission, map[string]any, *cleanupOwner) error {
	return errors.New("fixed outer driver requires native Linux amd64")
}

func bootstrap([]string, wrapperAdmission) (map[string]any, *cleanupOwner, error) {
	return map[string]any{"scope": scope, "passed": false, "execution_performed": false}, &cleanupOwner{}, errors.New("fixed outer driver requires native Linux amd64")
}
