//go:build linux || darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// acpHomePrincipalPeerRefusal binds a home principal to its loopback caller
// when the gateway cannot see the enrolled home: the managed Linux service
// runs with systemd ProtectHome=yes, so acpHomePrincipalUID found no home and
// every request of the home's own owner was refused (GAP-1151). The caller's
// home in the account database (NSS, so directory accounts resolve too) must
// be the enrolled home and hold the recorded user data directory; another
// account's home is a copied credential. A caller with no known home, or a
// record without a data directory, is not verified.
func acpHomePrincipalPeerRefusal(r *http.Request, digest, dataDir string) string {
	if len(digest) != 64 || !filepath.IsAbs(dataDir) || filepath.Clean(dataDir) != dataDir {
		return acpCallerAccountUnverifiedReason
	}
	uid, err := acpLoopbackPeerUID(r)
	if err != nil || uid < 0 {
		if err != nil {
			fmt.Fprintf(os.Stderr, "[sidecar-api] ACP caller account unavailable: %v\n", err)
		}
		return acpCallerAccountUnverifiedReason
	}
	home := normalizeManagedHookPeerHome(managedHookPeerHome(uid))
	if home == "" {
		return acpCallerAccountUnverifiedReason
	}
	if fmt.Sprintf("%x", sha256.Sum256([]byte(home))) != digest ||
		(dataDir != home && !strings.HasPrefix(dataDir, home+string(filepath.Separator))) {
		return acpCallerAccountMismatchReason
	}
	return ""
}

// acpHomePrincipalUID finds the enrolled home inside the service-owned
// directory record. A home principal stores a digest, so walk ancestors of
// its recorded user data directory until one matches. Missing older records
// fail closed; they can be repaired by enrolling again.
func acpHomePrincipalUID(digest, dataDir string) (int, bool) {
	if len(digest) != 64 || !filepath.IsAbs(dataDir) || filepath.Clean(dataDir) != dataDir {
		return 0, false
	}
	for home := dataDir; ; home = filepath.Dir(home) {
		if fmt.Sprintf("%x", sha256.Sum256([]byte(home))) == digest {
			info, err := os.Lstat(home)
			if err != nil || !info.IsDir() {
				return 0, false
			}
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok {
				return 0, false
			}
			return int(stat.Uid), true
		}
		if parent := filepath.Dir(home); parent == home {
			return 0, false
		}
	}
}
