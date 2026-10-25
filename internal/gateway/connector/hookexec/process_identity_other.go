// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package hookexec

// processStartIsAbsolute: macOS and Windows keep a process's start as the
// time it was created, which a later clock step does not move.
const processStartIsAbsolute = true

// processIdentityOf names a process as install.sh records it on Linux; no
// installer writes that record here.
func processIdentityOf(int) (string, bool) { return "", false }
