// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !darwin && !linux

package connector

import "os"

func validateCodexCodeGuardTreeParentCustody(string) error { return nil }

func validateCodexCodeGuardPrivateStateDirectory(string) error { return nil }

func validateCodexCodeGuardTreeEntryCustody(string, os.FileInfo) error { return nil }
