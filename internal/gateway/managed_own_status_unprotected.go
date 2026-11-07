// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// ownStatusUnprotectedAgents reads the enumerator's last completed scan; a
// seam for tests. An error means the scan is unknown.
var ownStatusUnprotectedAgents = readManagedUnprotectedAgents

// ownStatusConfigStamp is the config generation and digest the installed
// config.yaml carries; a seam for tests. It is the check the administrator's
// status makes on the same scan (enterpriseunix describeUnprotectedAgents).
var ownStatusConfigStamp = installedConfigStamp

// readManagedUnprotectedAgents reads the gateway's copy of the enumerator's
// unprotected-agents record (managed.HookGuardianUnprotectedAgentsFile): the
// same completed scan the administrator's status and verify report, published
// with the guardian ledger's ownership and mode because the original is
// root-only. The scan counts only when the administrator's status would count
// it: present, trusted, parsed, recent, written by this install and, when
// bindToConfig is set, stamped with the installed config's generation and
// digest. A copy that is missing, unreadable, old, of another install or of
// another config is an unknown scan (an error), never "no agent found": a
// completed scan that found nothing is a record with no agents.
func readManagedUnprotectedAgents(dataDir, configPath string, bindToConfig bool) ([]enterprisehooks.UnprotectedAgent, error) {
	path := filepath.Join(managed.HookGuardianAuthorizationDir(dataDir), managed.HookGuardianUnprotectedAgentsFile)
	record, err := readGuardianRecord(func() (unprotectedScanRecord, error) {
		if err := validateManagedGuardianAuthorization(path, "unprotected agents record"); err != nil {
			return unprotectedScanRecord{}, err
		}
		file, err := os.Open(path)
		if err != nil {
			return unprotectedScanRecord{}, fmt.Errorf("open unprotected agents record: %w", err)
		}
		defer file.Close()
		info, err := file.Stat()
		if err != nil {
			return unprotectedScanRecord{}, fmt.Errorf("stat unprotected agents record: %w", err)
		}
		data, err := io.ReadAll(io.LimitReader(file, enterprisehooks.UnprotectedAgentsMaxBytes+1))
		if err != nil {
			return unprotectedScanRecord{}, fmt.Errorf("read unprotected agents record: %w", err)
		}
		return unprotectedScanRecord{data: data, modTime: info.ModTime()}, nil
	})
	if err != nil {
		return nil, err
	}
	agents, err := enterprisehooks.ParseUnprotectedAgents(record.data)
	if err != nil {
		return nil, err
	}
	if enterprisehooks.UnprotectedAgentsRecordStale(record.modTime, time.Now()) {
		return nil, errors.New("the unprotected agents record is not from a recent scan")
	}
	if enterprisehooks.UnprotectedAgentsRecordGeneration(record.data) != enterprisehooks.UnprotectedAgentsGeneration() {
		return nil, errors.New("the unprotected agents record is from another install")
	}
	if bindToConfig {
		generation, digest, err := ownStatusConfigStamp(configPath)
		if err != nil {
			return nil, fmt.Errorf("the installed config generation is unknown: %w", err)
		}
		if enterprisehooks.UnprotectedAgentsRecordConfigGeneration(record.data) != generation ||
			enterprisehooks.UnprotectedAgentsRecordConfigSHA256(record.data) != digest {
			return nil, errors.New("the unprotected agents record is from another config generation")
		}
	}
	return agents, nil
}

// unprotectedScanRecord is the record's bytes and the time of its scan.
type unprotectedScanRecord struct {
	data    []byte
	modTime time.Time
}

// installedConfigStamp is the generation and digest of the installed
// config.yaml: the generation record must name the bytes on disk.
func installedConfigStamp(configPath string) (uint64, string, error) {
	if strings.TrimSpace(configPath) == "" {
		return 0, "", errors.New("no config path")
	}
	state, err := configwrite.ReadGenerationState(configPath)
	if err != nil {
		return 0, "", err
	}
	if state.Generation == 0 || state.ConfigSHA256 == "" {
		return 0, "", errors.New("the generation record is incomplete")
	}
	installed, err := os.ReadFile(configPath)
	if err != nil {
		return 0, "", err
	}
	if configwrite.SHA256Hex(installed) != state.ConfigSHA256 {
		return 0, "", errors.New("the config digest differs from config.yaml")
	}
	return state.Generation, state.ConfigSHA256, nil
}

// ownStatusCaller is the verified caller an own-status answer is for: a Unix
// uid, or a Windows SID, and the account name when the OS names it.
type ownStatusCaller struct {
	uid  *int
	sid  string
	name string
}

// owns reports whether an unprotected-agent entry is the caller's: matched by
// the entry's uid or SID, and by account name only when it carries neither.
func (c ownStatusCaller) owns(agent enterprisehooks.UnprotectedAgent) bool {
	switch {
	case agent.UID != nil:
		return c.uid != nil && *c.uid == *agent.UID
	case strings.TrimSpace(agent.SID) != "":
		return c.sid != "" && strings.EqualFold(c.sid, strings.TrimSpace(agent.SID))
	}
	if c.uid != nil {
		// Unix account names are exact.
		return c.name != "" && c.name == agent.User
	}
	return ownStatusSameAccount(c.name, agent.User)
}

// ownStatusSameAccount compares account names; on Windows a name may carry
// its domain, which the other side may omit.
func ownStatusSameAccount(a, b string) bool {
	a, b = strings.TrimSpace(a), strings.TrimSpace(b)
	if a == "" || b == "" {
		return false
	}
	if strings.EqualFold(a, b) {
		return true
	}
	_, aShort, aDomain := strings.Cut(a, `\`)
	_, bShort, bDomain := strings.Cut(b, `\`)
	if !aDomain && !bDomain {
		return false
	}
	if !aDomain {
		aShort = a
	}
	if !bDomain {
		bShort = b
	}
	return strings.EqualFold(aShort, bShort)
}

// ownUnprotectedAgents maps the caller's own entries of the last completed
// scan by connector; "" holds an account-level entry (an account whose home
// is untrusted), which covers every connector. ok is false when the scan is
// unknown: the caller's protection is then not confirmed. The record is read
// the way the administrator's status reads it; on Unix it must be stamped
// with the installed config.
func (a *APIServer) ownUnprotectedAgents(cfg *config.Config, caller ownStatusCaller) (map[string][]enterprisehooks.UnprotectedAgent, bool) {
	agents, err := ownStatusUnprotectedAgents(a.configDataDir(), cfg.ConfigFilePath, caller.uid != nil)
	if err != nil {
		return nil, false
	}
	mine := make(map[string][]enterprisehooks.UnprotectedAgent)
	for _, agent := range agents {
		if caller.owns(agent) {
			mine[agent.Connector] = append(mine[agent.Connector], agent)
		}
	}
	return mine, true
}

// ownUnprotectedGap is the caller's entries that make connector unprotected:
// its own, or the account-level ones.
func ownUnprotectedGap(mine map[string][]enterprisehooks.UnprotectedAgent, connector string) ([]enterprisehooks.UnprotectedAgent, bool) {
	gap := append(append([]enterprisehooks.UnprotectedAgent(nil), mine[connector]...), mine[""]...)
	return gap, len(gap) > 0
}

// ownUnprotectedReasonsMax bounds how many reasons one row names.
const ownUnprotectedReasonsMax = 2

// ownUnprotectedState is the own-status row for a connector the scan lists as
// unprotected for the caller. Its text is the administrator's warning for
// those agents, reason and remedy included; several installs of one connector
// with different reasons (a Kiro CLI and IDE) each show theirs.
func ownUnprotectedState(agents []enterprisehooks.UnprotectedAgent) map[string]any {
	var reasons []string
	for _, agent := range agents {
		reason := strings.TrimSpace(agent.Reason)
		if reason == "" {
			reason = agent.Code
		}
		if !slices.Contains(reasons, reason) {
			reasons = append(reasons, reason)
		}
	}
	text := strings.Join(reasons[:min(len(reasons), ownUnprotectedReasonsMax)], "; ")
	if more := len(reasons) - ownUnprotectedReasonsMax; more > 0 {
		text += fmt.Sprintf("; and %d more", more)
	}
	return map[string]any{"protected": false, "state": "not protected: " + text}
}
