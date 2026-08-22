// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package main

import "errors"

const devinPinnedCLIVersion = "3000.4.25"

func verifyDevinExecutableAdmission(string) error { return errors.New("windows-only operation") }
