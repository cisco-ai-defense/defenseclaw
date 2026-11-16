// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisehooks

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// ownedFileFingerprintMaxBytes bounds the file a fingerprint reads; a larger
// file reads as unreadable, which a change to or from a readable file still
// tells apart.
const ownedFileFingerprintMaxBytes = 16 << 20

// ownedFileStateFingerprint is the content digest and permission bits.
func ownedFileStateFingerprint(path string, info os.FileInfo) string {
	data, err := safefile.ReadRegularFileBounded(path, ownedFileFingerprintMaxBytes)
	if err != nil {
		return "unreadable"
	}
	sum := sha256.Sum256(data)
	return fmt.Sprintf("sha256:%s:mode:%o", hex.EncodeToString(sum[:]), info.Mode().Perm())
}
