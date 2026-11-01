// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package devicekeys gathers what the account join key needs on a
// standalone device (the signed tenant, the tenant secrets, the accounts in
// the guardian's identity spool) and computes the account_join block of the
// root-only status. Keys are computed when the status is rendered and never
// stored.
package devicekeys

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/accountjoin"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// StateFileName is the root-only record of the highest generation the device
// reported, next to the lifecycle state. Removing it allows a lower one.
const StateFileName = "account-join-generation.json"

// Sources are the device inputs.
type Sources struct {
	Config       config.EnterpriseAccountJoinConfig
	SecureClient bool
	// Tenant reads the tenant ID of the verified bundle anchors.
	Tenant func() (string, error)
	// ReadSecret reads a protected credential; managed.ErrNoServiceCredential
	// when it is not stored.
	ReadSecret func(name string) ([]byte, error)
	// SpoolDir is the identity spool and SpoolTrust its trust check.
	SpoolDir   string
	SpoolTrust func(path, label string) error
	// StatePath is the highest-generation record ("" keeps none).
	StatePath string
	GOOS      string
	Now       time.Time
}

// Report computes the account_join block; nil when the feature is off and
// no key would be computed (the block is omitted).
func Report(s Sources) *accountjoin.Report {
	if !s.Config.On() || s.SecureClient {
		return nil
	}
	now := s.Now
	if now.IsZero() {
		now = time.Now()
	}
	in := accountjoin.Input{On: true, Now: now}
	if s.Tenant != nil {
		if tenant, err := s.Tenant(); err == nil {
			in.Tenant = tenant
		}
	}
	highest := readHighest(s.StatePath)
	in.Generations = accountjoin.Generations{
		Current:      uint32(s.Config.Generation),
		Next:         uint32(s.Config.NextGeneration),
		NextNotAfter: s.Config.NextNotAfterTime(),
		Highest:      highest,
	}
	var secretErr bool
	if s.ReadSecret != nil {
		in.Generations.CurrentSecret, secretErr = readSecret(s.ReadSecret, accountjoin.SecretName)
		if s.Config.NextGeneration != 0 {
			var nextErr bool
			in.Generations.NextSecret, nextErr = readSecret(s.ReadSecret, accountjoin.NextSecretName)
			secretErr = secretErr || nextErr
		}
	}
	in.Accounts = SpoolAccounts(s.SpoolDir, s.SpoolTrust, s.GOOS)
	report, newHighest := accountjoin.Compute(in)
	if secretErr {
		report.ReasonCodes = appendReason(report.ReasonCodes, accountjoin.ReasonSecretUnreadable)
		sort.Strings(report.ReasonCodes)
	}
	if newHighest > highest {
		_ = writeHighest(s.StatePath, newHighest)
	}
	return &report
}

// readSecret returns nil for a credential that is not stored; failed is a
// credential that exists but cannot be read (secret_unreadable).
func readSecret(read func(string) ([]byte, error), name string) (value []byte, failed bool) {
	value, err := read(name)
	if err == nil && len(value) > 0 {
		return value, false
	}
	clear(value)
	if err == nil || errors.Is(err, managed.ErrNoServiceCredential) {
		return nil, false
	}
	return nil, true
}

func appendReason(reasons []string, reason string) []string {
	for _, r := range reasons {
		if r == reason {
			return reasons
		}
	}
	return append(reasons, reason)
}

// SpoolAccounts lists the accounts of the identity spool with only the
// identifiers the guardian verified: on Linux the SID SSSD holds for the uid
// (the account's domain objectSid), on Windows the record's SID when the
// directory translated it to a UPN (a domain account; local accounts have
// none), and the UPN only from InfoPipe, the macOS identity store or the
// Windows name translation (never a derived or kept one). LastSeen is when
// the guardian last wrote the record.
func SpoolAccounts(dir string, trust func(path, label string) error, goos string) []accountjoin.Account {
	var out []accountjoin.Account
	if dir == "" || trust == nil {
		return nil
	}
	enterprisehooks.WalkIdentitySpoolRecords(dir, trust, func(record enterprisehooks.IdentitySpoolRecord) bool {
		account := accountjoin.Account{LastSeen: record.UpdatedAt}
		verifiedUPN := false
		switch record.UPNSource {
		case enterprisehooks.UPNSourceInfoPipe, enterprisehooks.UPNSourceIdentityStore, enterprisehooks.UPNSourceTranslateName:
			verifiedUPN = true
		}
		if verifiedUPN {
			account.UPN = strings.TrimSpace(record.Facts.UPN)
		}
		switch goos {
		case "linux":
			account.SID = strings.TrimSpace(record.AccountSID)
		case "windows":
			if record.UPNSource == enterprisehooks.UPNSourceTranslateName {
				account.SID = strings.TrimSpace(record.Key)
			}
		}
		out = append(out, account)
		return true
	})
	return out
}

type highestRecord struct {
	HighestGeneration uint32 `json:"highest_generation"`
}

func readHighest(path string) uint32 {
	if path == "" {
		return 0
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) > 4096 {
		return 0
	}
	var record highestRecord
	if json.Unmarshal(data, &record) != nil {
		return 0
	}
	return record.HighestGeneration
}

func writeHighest(path string, highest uint32) error {
	if path == "" {
		return nil
	}
	data, err := json.Marshal(highestRecord{HighestGeneration: highest})
	if err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".account-join-*")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	if err := temp.Chmod(0o600); err != nil {
		temp.Close()
		return err
	}
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(temp.Name(), path)
}
