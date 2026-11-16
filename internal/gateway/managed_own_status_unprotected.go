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

// ownMatch is whose an unprotected-agent entry is, as far as the caller can
// tell.
type ownMatch int

const (
	// ownNotMine: the entry names another uid, SID or account.
	ownNotMine ownMatch = iota
	// ownMine: the entry carries the caller uid or SID, or the caller account name.
	ownMine
	// ownUnresolved: the entry names no uid or SID, and its account name
	// cannot be compared with the caller: the status cannot name the caller
	// account (the OS lookup failed), or the enumerator could not name the
	// entry account. It may be the caller, so it confirms nothing.
	ownUnresolved
)

// match reports whose an unprotected-agent entry is: by the entry uid or SID,
// and by account name only when it carries neither.
func (c ownStatusCaller) match(agent enterprisehooks.UnprotectedAgent) ownMatch {
	switch {
	case agent.UID != nil:
		return ownBool(c.uid != nil && *c.uid == *agent.UID)
	case strings.TrimSpace(agent.SID) != "":
		return ownBool(c.sid != "" && strings.EqualFold(c.sid, strings.TrimSpace(agent.SID)))
	}
	user := strings.TrimSpace(agent.User)
	if user == "" || user == enterprisehooks.UnprotectedUnknownAccount || strings.TrimSpace(c.name) == "" {
		return ownUnresolved
	}
	if c.uid != nil {
		// Unix account names are exact.
		return ownBool(c.name == agent.User)
	}
	return ownBool(ownStatusSameAccount(c.name, agent.User))
}

func ownBool(mine bool) ownMatch {
	if mine {
		return ownMine
	}
	return ownNotMine
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

// ownScan is the caller view of the enumerator last completed scan.
type ownScan struct {
	// known is false when the scan is unknown: the caller protection is then
	// not confirmed.
	known bool
	// mine holds the caller own entries by connector; "" holds an
	// account-level entry (an account whose home is untrusted), which covers
	// every connector.
	mine map[string][]enterprisehooks.UnprotectedAgent
	// unresolved holds the connectors with an entry that may be the caller
	// (ownUnresolved), "" for an account-level one.
	unresolved map[string]bool
}

// ownUnprotectedAgents reads the scan for the caller. The record is read the
// way the administrator status reads it; on Unix it must be stamped with the
// installed config.
func (a *APIServer) ownUnprotectedAgents(cfg *config.Config, caller ownStatusCaller) ownScan {
	agents, err := ownStatusUnprotectedAgents(a.configDataDir(), cfg.ConfigFilePath, caller.uid != nil)
	if err != nil {
		return ownScan{}
	}
	scan := ownScan{known: true, mine: make(map[string][]enterprisehooks.UnprotectedAgent), unresolved: make(map[string]bool)}
	for _, agent := range agents {
		switch caller.match(agent) {
		case ownMine:
			scan.mine[agent.Connector] = append(scan.mine[agent.Connector], agent)
		case ownUnresolved:
			scan.unresolved[agent.Connector] = true
		}
	}
	return scan
}

// state is the own-status row the scan decides for connector, or false when
// the scan finds nothing against the caller. An unknown scan, and an entry
// that may be the caller but cannot be matched, are not confirmed; the
// caller own entries, and the account-level ones, are not protected with the
// administrator warning for those agents.
func (s ownScan) state(connector string) (map[string]any, bool) {
	if !s.known {
		return ownNotConfirmed(ownCauseScanUnknown), true
	}
	gap := append(append([]enterprisehooks.UnprotectedAgent(nil), s.mine[connector]...), s.mine[""]...)
	if len(gap) > 0 {
		return ownUnprotectedState(gap), true
	}
	if s.unresolved[connector] || s.unresolved[""] {
		return ownNotConfirmed(ownCauseScanUnmatched), true
	}
	return nil, false
}

// ownUnprotectedReasonsMax bounds how many reasons one row names.
const ownUnprotectedReasonsMax = 2

// ownUnprotectedState is the own-status row for a connector the scan lists as
// unprotected for the caller. Its text is the administrator's warning for
// those agents followed by ownScanNextStep: the recorded reasons are free
// text and not all of them name a remedy, and the machine code is never shown.
// Several installs of one connector with different reasons (a Kiro CLI and
// IDE) each show theirs.
func ownUnprotectedState(agents []enterprisehooks.UnprotectedAgent) map[string]any {
	var reasons []string
	for _, agent := range agents {
		reason := ownScanReason(agent.Reason)
		if reason == "" {
			continue
		}
		if !slices.Contains(reasons, reason) {
			reasons = append(reasons, reason)
		}
	}
	if len(reasons) == 0 {
		return ownNotProtected(ownCauseNoUnprotectedReason)
	}
	text := strings.Join(reasons[:min(len(reasons), ownUnprotectedReasonsMax)], "; ")
	if more := len(reasons) - ownUnprotectedReasonsMax; more > 0 {
		text += fmt.Sprintf("; and %d more", more)
	}
	return ownNotProtected(ownScanCause(text))
}
