// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package acp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// The revoked-credential records name the enrollment a revoked bearer was
// issued to by its non-secret key ID, so the authentication failure row of
// a guard that still presents it names whose credential it is: on Windows,
// where the gateway cannot tell the account of a loopback caller, the row
// named no one (GAP-0354). They hold no bearer and expire.
const (
	revokedEnterpriseCredentialRetention = 30 * 24 * time.Hour
	maxRevokedEnterpriseCredentials      = 4096
	maxRevokedEnterpriseCredentialBytes  = 4 << 10
)

// RevokedEnterpriseCredential is the scope of a revoked enrollment.
type RevokedEnterpriseCredential struct {
	Principal string    `json:"principal"`
	ClientID  string    `json:"client"`
	AgentID   string    `json:"agent"`
	Profile   string    `json:"profile"`
	RevokedAt time.Time `json:"revoked_at"`
}

func revokedEnterpriseCredentialDir(dataDir string) string {
	return filepath.Join(dataDir, "acp", "enterprise-revoked-keys")
}

// recordRevokedEnterpriseCredential keeps the scope of a credential being
// revoked; the caller holds the mutation lock. Old and excess records go.
func recordRevokedEnterpriseCredential(dataDir string, credential EnterpriseCredential, now time.Time) error {
	dir := revokedEnterpriseCredentialDir(dataDir)
	if entries, err := os.ReadDir(dir); err == nil {
		type aged struct {
			name string
			at   time.Time
		}
		var kept []aged
		for _, entry := range entries {
			info, infoErr := entry.Info()
			if infoErr != nil || entry.IsDir() || now.Sub(info.ModTime()) > revokedEnterpriseCredentialRetention {
				_ = os.Remove(filepath.Join(dir, entry.Name()))
				continue
			}
			kept = append(kept, aged{entry.Name(), info.ModTime()})
		}
		sort.Slice(kept, func(i, j int) bool { return kept[i].at.Before(kept[j].at) })
		for len(kept) >= maxRevokedEnterpriseCredentials {
			_ = os.Remove(filepath.Join(dir, kept[0].name))
			kept = kept[1:]
		}
	}
	body, err := json.Marshal(RevokedEnterpriseCredential{
		Principal: credential.Principal, ClientID: credential.ClientID, AgentID: credential.AgentID,
		Profile: credential.Profile, RevokedAt: now.UTC(),
	})
	if err != nil {
		return err
	}
	path := filepath.Join(dir, HTTPAuthKeyID(credential.Token)+".json")
	return writeEnterpriseCredentialFile(dataDir, path, "ACP revoked credential record", append(body, '\n'))
}

// RevokedEnterpriseCredentialForKeyID returns the scope of the revoked
// credential with this key ID, while its record is kept.
func RevokedEnterpriseCredentialForKeyID(dataDir, keyID string) (RevokedEnterpriseCredential, bool) {
	if !validCredentialKeyID(keyID) {
		return RevokedEnterpriseCredential{}, false
	}
	body, err := safefile.ReadRegularFileBounded(filepath.Join(revokedEnterpriseCredentialDir(dataDir), keyID+".json"), maxRevokedEnterpriseCredentialBytes)
	if err != nil {
		return RevokedEnterpriseCredential{}, false
	}
	var revoked RevokedEnterpriseCredential
	if json.Unmarshal(body, &revoked) != nil || revoked.Principal == "" ||
		time.Since(revoked.RevokedAt) > revokedEnterpriseCredentialRetention {
		return RevokedEnterpriseCredential{}, false
	}
	return revoked, true
}
