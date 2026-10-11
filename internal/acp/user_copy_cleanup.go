// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package acp

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// EnterpriseUserCopyCleanup is the user copy of a revoked enrollment that
// could not be removed because its Windows user was signed out: only the
// signed-in user can write in a profile. The copy no longer authenticates;
// the hook enumerator removes it at the user's next sign-in (GAP-0718).
type EnterpriseUserCopyCleanup struct {
	SID        string `json:"sid"`
	ClientID   string `json:"client"`
	AgentID    string `json:"agent"`
	UserHome   string `json:"user_home"`
	TokenFile  string `json:"token_file"`
	RecordedAt string `json:"recorded_at"`
}

const (
	maxEnterpriseUserCopyCleanups     = 4096
	maxEnterpriseUserCopyCleanupBytes = 4 << 20
)

func enterpriseUserCopyCleanupPath(dataDir string) string {
	return filepath.Join(dataDir, "acp", "user-copy-cleanup.json")
}

// EnterpriseUserCopyCleanups returns the user copies waiting for removal.
func EnterpriseUserCopyCleanups(dataDir string) ([]EnterpriseUserCopyCleanup, error) {
	if strings.TrimSpace(dataDir) == "" {
		return nil, errors.New("ACP enterprise credential data directory is empty")
	}
	body, err := safefile.ReadRegularFileBounded(enterpriseUserCopyCleanupPath(dataDir), maxEnterpriseUserCopyCleanupBytes)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var entries []EnterpriseUserCopyCleanup
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, err
	}
	return entries, nil
}

// UpdateEnterpriseUserCopyCleanups replaces the waiting user copies with
// what update returns, under the credential mutation lock. A damaged list is replaced.
func UpdateEnterpriseUserCopyCleanups(dataDir string, update func([]EnterpriseUserCopyCleanup) []EnterpriseUserCopyCleanup) error {
	if strings.TrimSpace(dataDir) == "" {
		return errors.New("ACP enterprise credential data directory is empty")
	}
	enterpriseCredentialMutationMu.Lock()
	defer enterpriseCredentialMutationMu.Unlock()
	return withEnterpriseCredentialMutationLock(dataDir, func() error {
		entries, _ := EnterpriseUserCopyCleanups(dataDir)
		next := update(entries)
		if len(next) > maxEnterpriseUserCopyCleanups {
			return fmt.Errorf("ACP user copy cleanup list has %d entries; limit is %d", len(next), maxEnterpriseUserCopyCleanups)
		}
		path := enterpriseUserCopyCleanupPath(dataDir)
		if len(next) == 0 {
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			return nil
		}
		body, err := json.MarshalIndent(next, "", "  ")
		if err != nil {
			return err
		}
		return writeEnterpriseCredentialFile(dataDir, path, "ACP user copy cleanup list", append(body, '\n'))
	})
}
