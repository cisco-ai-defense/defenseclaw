// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"fmt"
	"os"
)

// ownedFileStateFingerprint reads no content on Windows: the guardian
// fingerprints the agent's own config after every pass and on its write
// events, and an open read handle there makes the agent's next write fail
// with a sharing violation. An in-place rewrite still changes the
// modification time; the interval pass covers one that also restores it.
func ownedFileStateFingerprint(_ string, info os.FileInfo) string {
	return fmt.Sprintf("meta:%d:%d:%o", info.Size(), info.ModTime().UnixNano(), info.Mode().Perm())
}
