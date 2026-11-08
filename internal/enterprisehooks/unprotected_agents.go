// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

// The standalone enumerator records installed agents and surfaces that
// DefenseClaw cannot cover. An earlier enrolled Kiro CLI below the headless
// hook floor remains installed for interactive sessions, but is still
// uncovered. The record sits next to the manifest for status and verify.

// UnprotectedAgentsFileName is the record the standalone enumerator writes
// next to the guardian manifest (root-only on Linux and macOS; SYSTEM and
// Administrators only on Windows).
const UnprotectedAgentsFileName = "unprotected-agents.json"

// UnprotectedAgentsMaxBytes bounds the record a reader accepts.
const UnprotectedAgentsMaxBytes = 4 << 20

// The enumerator runs every five minutes. Three missed cycles mean its last
// result can no longer establish which agent copies are runnable now.
const UnprotectedAgentsMaxAge = 16 * time.Minute

// UnprotectedAgentsRecordStale uses the protected file's mtime as evidence
// of the latest completed scan. The writer refreshes it even for an empty,
// unchanged result.
func UnprotectedAgentsRecordStale(modTime, now time.Time) bool {
	return now.Sub(modTime) > UnprotectedAgentsMaxAge || modTime.After(now.Add(5*time.Minute))
}

// UnprotectedAgentsGeneration is the install generation a record carries:
// the DefenseClaw build that wrote it. The enumerator and status/verify run
// the same installed build, so a record whose generation differs was
// written before the current install, upgrade or downgrade and proves
// nothing about the agents runnable now, however recent it is (GAP-1454).
func UnprotectedAgentsGeneration() string { return version.Current().BinaryVersion }

// UnprotectedAgentsRecordGeneration is the generation data carries; ""
// for a record written before records carried one (1.0.4 and earlier).
func UnprotectedAgentsRecordGeneration(data []byte) string {
	var record struct {
		Generation string `json:"generation"`
	}
	if json.Unmarshal(data, &record) != nil {
		return ""
	}
	return record.Generation
}

// UnprotectedAgentsRecordFromEarlierInstall describes a record of another
// generation for UnprotectedAgentsScanPending.
func UnprotectedAgentsRecordFromEarlierInstall(written string) string {
	if written == "" {
		written = "an earlier release"
	}
	return "from an earlier install (written by " + boundedStatusText(written, 64) + ", this install is " + UnprotectedAgentsGeneration() + ")"
}

// UnprotectedAgentsRecordMissing describes a record no scan has published.
const UnprotectedAgentsRecordMissing = "missing (no scan has published it yet)"

// UnprotectedAgentsStaleError is a record UnprotectedAgentsRecordStale
// rejects; Age describes it (UnprotectedAgentsRecordAge).
type UnprotectedAgentsStaleError struct{ Age string }

func (e UnprotectedAgentsStaleError) Error() string {
	return "enterprise hooks: unprotected-agents record is stale (" + e.Age + ")"
}

// UnprotectedAgentsRecordAge describes how old the record is.
func UnprotectedAgentsRecordAge(modTime, now time.Time) string {
	if modTime.After(now) {
		return "dated " + modTime.Sub(now).Round(time.Second).String() + " in the future"
	}
	return now.Sub(modTime).Round(time.Second).String() + " old"
}

// UnprotectedAgentsScanPending is the one NOT COVERED row status and verify
// show for a missing or stale record, as right after a fresh install or an
// upgrade: a warning, not a verify failure, because no agent is known to be
// unprotected and enforcement is unchanged (GAP-1430). An unreadable record
// still fails verify.
func UnprotectedAgentsScanPending(age, remedy string) string {
	return "NOT COVERED (scan pending): the enumerator's unprotected-agents record is " + age +
		" (limit " + UnprotectedAgentsMaxAge.String() + "), so agents installed since its last scan are not proven protected; " +
		"enforcement is unchanged; the record refreshes on the next scheduled scan (every five minutes), or now with: " + remedy
}

// Status codes for an unprotected agent.
// UnixAgentUnversionedReasonPrefix starts the discovery reason for an agent
// whose CLI exists for the user but printed no usable version. The
// enumerator cannot select a hook contract for it, so it reports the agent
// as unprotected instead of skipping it silently.
const UnixAgentUnversionedReasonPrefix = "installed, but its version could not be read: "

// UnixAgentUnversionedContractSuffix ends the hook_contract_unverified
// reason the Linux and macOS enumerator writes for such an agent.
const UnixAgentUnversionedContractSuffix = "; its managed hook contract cannot be verified"

const (
	// UnprotectedCodeHookContractUnverified: the agent's version has no
	// verified DefenseClaw hook contract.
	UnprotectedCodeHookContractUnverified = "hook_contract_unverified"
	// UnprotectedCodeInstallScanIncomplete means an enrolled user's install
	// locations could not be fully inspected within the scan bound.
	UnprotectedCodeInstallScanIncomplete = "agent_install_scan_incomplete"
	// UnprotectedCodeKiroCLIBelowHookFloor: old kiro-cli has a headless
	// engine that never loads the hook, even when an earlier release left
	// interactive hooks installed for the account.
	UnprotectedCodeKiroCLIBelowHookFloor = "kiro_cli_below_hook_floor"
	// UnprotectedCodeAgentUnprotected: any other reason the agent could not
	// be enrolled.
	UnprotectedCodeAgentUnprotected = "agent_unprotected"
	// UnprotectedCodeKiroIDEBelowGlobalHooksFloor: the user's Kiro IDE is
	// older than KiroIDEGlobalHooksFloor and does not read the global hook
	// file the guardian writes.
	UnprotectedCodeKiroIDEBelowGlobalHooksFloor = "kiro_ide_below_global_hooks_floor"
	// UnprotectedCodeHomeUntrusted: an eligible account whose home is
	// untrusted and that has no agent the enumerator could list; the entry
	// names the account, not a connector.
	UnprotectedCodeHomeUntrusted = "home_untrusted"
	// UnprotectedCodeOpenCodeV1: the account can run OpenCode V1, which
	// cannot run the OpenCode V2 plugin DefenseClaw installs, so OpenCode is
	// not protected for it (opencode_v1.go).
	UnprotectedCodeOpenCodeV1 = "opencode_v1_unprotected"
)

// UnprotectedCodeLeavesCoverageIncomplete reports whether an unprotected
// agent with code makes coverage_complete false, on every OS: no hook
// contract, an incomplete install scan, a headless CLI path without hooks,
// an IDE that cannot read global hooks (GAP-0151), or OpenCode V1, which
// cannot run the V2 plugin (rel-1-0-6 GAP-0037). Every entry makes
// security_complete false.
func UnprotectedCodeLeavesCoverageIncomplete(code string) bool {
	switch code {
	case UnprotectedCodeHookContractUnverified, UnprotectedCodeInstallScanIncomplete, UnprotectedCodeKiroCLIBelowHookFloor,
		UnprotectedCodeKiroIDEBelowGlobalHooksFloor, UnprotectedCodeOpenCodeV1:
		return true
	}
	return false
}

// unprotectedReasonMaxRunes bounds the user-influenced reason text.
const unprotectedReasonMaxRunes = 400

// UnprotectedAgent is one installed agent or surface the enumerator found
// that DefenseClaw cannot fully cover.
type UnprotectedAgent struct {
	User      string `json:"user"`
	SID       string `json:"sid,omitempty"`
	UID       *int   `json:"uid,omitempty"`
	Connector string `json:"connector"`
	Version   string `json:"version,omitempty"`
	// InstallPath distinguishes multiple runnable copies of the same CLI.
	InstallPath string `json:"install_path,omitempty"`
	// Surface, Host and HostVersion describe an app or extension install
	// (connector.AgentSurface); Version is then its engine version. Empty
	// for a CLI install.
	Surface     string `json:"surface,omitempty"`
	Host        string `json:"host,omitempty"`
	HostVersion string `json:"host_version,omitempty"`
	// Refusal is set for a surface refused under
	// enterprise.enrollment.unverified_versions: refuse (RefusalEnforced
	// or RefusalMissing).
	Refusal string `json:"refusal,omitempty"`
	Code    string `json:"code"`
	Reason  string `json:"reason"`
}

type unprotectedAgentsFile struct {
	Version          int    `json:"version"`
	Generation       string `json:"generation,omitempty"`
	ConfigGeneration uint64 `json:"config_generation,omitempty"`
	ConfigSHA256     string `json:"config_sha256,omitempty"`
	// ScanInProgress marks the record the enumerator writes when a cycle
	// starts on a config the previous record does not name: the stamp is the
	// new config's, the agents are the previous scan's, and the scan of the new
	// config has not finished. It is never a completed scan; the cycle's
	// final record replaces it (GAP-0782).
	ScanInProgress bool               `json:"scan_in_progress,omitempty"`
	Agents         []UnprotectedAgent `json:"agents"`
}

// UnprotectedAgentsPath is the unprotected-agents record for manifestPath.
func UnprotectedAgentsPath(manifestPath string) string {
	return filepath.Join(filepath.Dir(filepath.Clean(manifestPath)), UnprotectedAgentsFileName)
}

// ReadUnprotectedAgentsRecord reads the record at path as status reads it:
// a regular file within UnprotectedAgentsMaxBytes that carries the platform
// record protection (unprotectedAgentsRecordTrusted), and the time of the
// scan it holds (the file modification time the writer refreshes every
// cycle). A record status would refuse is refused here, so nothing derived
// from it is trusted either. The enumerator mirrors these bytes for the
// gateway.
func ReadUnprotectedAgentsRecord(path string) ([]byte, time.Time, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, time.Time{}, err
	}
	if !info.Mode().IsRegular() {
		return nil, time.Time{}, fmt.Errorf("enterprise hooks: %s is not a regular file", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, time.Time{}, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, time.Time{}, err
	}
	if !os.SameFile(info, opened) {
		return nil, time.Time{}, fmt.Errorf("enterprise hooks: %s changed while it was read", path)
	}
	if err := unprotectedAgentsRecordTrusted(path, opened); err != nil {
		return nil, time.Time{}, err
	}
	data, err := io.ReadAll(io.LimitReader(file, UnprotectedAgentsMaxBytes+1))
	if err != nil {
		return nil, time.Time{}, err
	}
	if len(data) > UnprotectedAgentsMaxBytes {
		return nil, time.Time{}, fmt.Errorf("enterprise hooks: %s exceeds %d bytes", path, UnprotectedAgentsMaxBytes)
	}
	return data, opened.ModTime(), nil
}

// UnprotectedUnknownAccount is the user of an entry for an agent whose account
// could not be identified in the cycle (Windows running-agent scan).
const UnprotectedUnknownAccount = "(unknown account)"

// UnprotectedCodeForReason classifies an admission reason.
func UnprotectedCodeForReason(reason string) string {
	if strings.Contains(reason, "kiro-cli ") && strings.Contains(reason, "is below "+connector.KiroCLIHookFloor) {
		return UnprotectedCodeKiroCLIBelowHookFloor
	}
	if strings.Contains(reason, "Kiro IDE version ") &&
		strings.Contains(reason, "is below the certified minimum "+KiroIDEGlobalHooksFloor) {
		return UnprotectedCodeKiroIDEBelowGlobalHooksFloor
	}
	if strings.Contains(reason, "not verified against a known hook contract") ||
		strings.Contains(reason, "not covered by a known hook contract") {
		return UnprotectedCodeHookContractUnverified
	}
	return UnprotectedCodeAgentUnprotected
}

// Message is the operator-facing status line for one agent.
func (a UnprotectedAgent) Message() string {
	name := strings.TrimSpace(a.Connector)
	if version := strings.TrimSpace(a.Version); version != "" {
		name += " " + version
	}
	if path := strings.TrimSpace(a.InstallPath); path != "" {
		name += " at " + path
	}
	who := strings.TrimSpace(a.User)
	if sid := strings.TrimSpace(a.SID); sid != "" {
		if who == "" {
			who = sid
		} else {
			who += " (" + sid + ")"
		}
	}
	if surface := strings.TrimSpace(a.Surface); surface != "" {
		name += " (" + surface
		if host := strings.TrimSpace(a.Host); host != "" {
			name += " in " + host
		}
		if hostVersion := strings.TrimSpace(a.HostVersion); hostVersion != "" {
			name += " " + hostVersion
		}
		name += ")"
	}
	if name == "" {
		return fmt.Sprintf("user %s is not enrolled: %s", who, strings.TrimSpace(a.Reason))
	}
	return fmt.Sprintf("%s for user %s is not protected: %s", name, who, strings.TrimSpace(a.Reason))
}

// MarshalUnprotectedAgents serializes agents deterministically (sorted, one
// entry per user and connector, except separate Kiro CLI and IDE surfaces)
// so an unchanged set rewrites nothing.
func MarshalUnprotectedAgents(agents []UnprotectedAgent) ([]byte, error) {
	return MarshalUnprotectedAgentsForConfig(agents, 0, "")
}

// MarshalUnprotectedAgentsForConfig binds a completed Unix scan to the
// config generation and config digest the enumerator observed before
// loading its inputs. The digest is the identity: a generation number can be
// reused when the generation record is rebuilt, a digest cannot name another
// config. Zero and empty keep older records and platforms without a
// lifecycle generation readable; status cannot infer their config freshness
// from these fields.
func MarshalUnprotectedAgentsForConfig(agents []UnprotectedAgent, configGeneration uint64, configSHA256 string) ([]byte, error) {
	return marshalUnprotectedAgents(agents, configGeneration, configSHA256, false)
}

// MarshalUnprotectedAgentsScanStarted is the record of a scan of the config
// (generation, digest) that has started and not finished: it carries the
// previous scan's agents so status keeps reporting them, and reads as pending
// until the cycle's final record replaces it.
func MarshalUnprotectedAgentsScanStarted(previous []UnprotectedAgent, configGeneration uint64, configSHA256 string) ([]byte, error) {
	return marshalUnprotectedAgents(previous, configGeneration, configSHA256, true)
}

func marshalUnprotectedAgents(agents []UnprotectedAgent, configGeneration uint64, configSHA256 string, scanInProgress bool) ([]byte, error) {
	normalized := normalizeUnprotectedAgents(agents)
	data, err := json.MarshalIndent(unprotectedAgentsFile{Version: 1, Generation: UnprotectedAgentsGeneration(), ConfigGeneration: configGeneration, ConfigSHA256: configSHA256, ScanInProgress: scanInProgress, Agents: normalized}, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// UnprotectedAgentsRecordScanInProgress reports a record written when a scan
// started and not yet replaced by its result.
func UnprotectedAgentsRecordScanInProgress(data []byte) bool {
	var record struct {
		ScanInProgress bool `json:"scan_in_progress"`
	}
	return json.Unmarshal(data, &record) == nil && record.ScanInProgress
}

// UnprotectedAgentsRecordConfigGeneration is the config generation a
// completed scan covered, or zero for a legacy record.
func UnprotectedAgentsRecordConfigGeneration(data []byte) uint64 {
	var record struct {
		ConfigGeneration uint64 `json:"config_generation"`
	}
	if json.Unmarshal(data, &record) != nil {
		return 0
	}
	return record.ConfigGeneration
}

// UnprotectedAgentsRecordConfigSHA256 is the config digest a completed scan
// covered, or empty for a legacy record.
func UnprotectedAgentsRecordConfigSHA256(data []byte) string {
	var record struct {
		ConfigSHA256 string `json:"config_sha256"`
	}
	if json.Unmarshal(data, &record) != nil {
		return ""
	}
	return record.ConfigSHA256
}

// ParseUnprotectedAgents decodes a record written by MarshalUnprotectedAgents.
func ParseUnprotectedAgents(data []byte) ([]UnprotectedAgent, error) {
	if len(data) > UnprotectedAgentsMaxBytes {
		return nil, errors.New("enterprise hooks: unprotected agents record is too large")
	}
	var record unprotectedAgentsFile
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, fmt.Errorf("enterprise hooks: parse unprotected agents record: %w", err)
	}
	if record.Version != 1 {
		return nil, fmt.Errorf("enterprise hooks: unprotected agents record version %d is not supported", record.Version)
	}
	out := make([]UnprotectedAgent, 0, len(record.Agents))
	for _, agent := range record.Agents {
		accountOnly := agent.Code == UnprotectedCodeHomeUntrusted
		if accountOnly {
			agent.Connector, agent.Version, agent.InstallPath, agent.Surface, agent.Host, agent.HostVersion = "", "", "", "", "", ""
		}
		if (strings.TrimSpace(agent.Connector) == "" && !accountOnly) || (strings.TrimSpace(agent.User) == "" && strings.TrimSpace(agent.SID) == "") {
			continue
		}
		if agent.Code != UnprotectedCodeHookContractUnverified && agent.Code != UnprotectedCodeInstallScanIncomplete && agent.Code != UnprotectedCodeSurfaceUnverified &&
			agent.Code != UnprotectedCodeKiroCLIBelowHookFloor &&
			agent.Code != UnprotectedCodeKiroIDEBelowGlobalHooksFloor && agent.Code != UnprotectedCodeOpenCodeV1 && !accountOnly {
			agent.Code = UnprotectedCodeAgentUnprotected
		}
		if agent.Refusal != RefusalEnforced && agent.Refusal != RefusalMissing {
			agent.Refusal = ""
		}
		out = append(out, agent)
	}
	return normalizeUnprotectedAgents(out), nil
}

func normalizeUnprotectedAgents(agents []UnprotectedAgent) []UnprotectedAgent {
	byKey := map[string]UnprotectedAgent{}
	for _, agent := range agents {
		agent.User = boundedStatusText(agent.User, 128)
		agent.SID = boundedStatusText(agent.SID, 128)
		agent.Connector = strings.ToLower(boundedStatusText(agent.Connector, 64))
		agent.Version = boundedStatusText(agent.Version, 128)
		agent.InstallPath = boundedStatusText(agent.InstallPath, 512)
		agent.Surface = strings.ToLower(boundedStatusText(agent.Surface, 32))
		agent.Host = boundedStatusText(agent.Host, 64)
		agent.HostVersion = boundedStatusText(agent.HostVersion, 128)
		agent.Reason = boundedStatusText(agent.Reason, unprotectedReasonMaxRunes)
		if agent.Code == "" {
			agent.Code = UnprotectedCodeForReason(agent.Reason)
		}
		agent = classifyOpenCodeV1(agent)
		key := strings.ToLower(agent.SID) + "\x00" + agent.User + "\x00" + agent.Connector + "\x00" + agent.Surface + "\x00" + agent.Host + "\x00" + agent.InstallPath + "\x00" + agent.Version + "\x00" + agent.Code
		if agent.Connector == "kiro" {
			// One Kiro row can describe two installed products (kiro-cli and
			// the IDE), each with its own reason. Forms are also told apart by
			// the install their reason names first (AssessKiro).
			form, _, _ := strings.Cut(agent.Reason, ";")
			key += "\x00" + form
		}
		byKey[key] = agent
	}
	out := make([]UnprotectedAgent, 0, len(byKey))
	for _, agent := range byKey {
		out = append(out, agent)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].User != out[j].User {
			return out[i].User < out[j].User
		}
		if out[i].SID != out[j].SID {
			return out[i].SID < out[j].SID
		}
		if out[i].Connector != out[j].Connector {
			return out[i].Connector < out[j].Connector
		}
		if out[i].Surface != out[j].Surface {
			return out[i].Surface < out[j].Surface
		}
		if out[i].InstallPath != out[j].InstallPath {
			return out[i].InstallPath < out[j].InstallPath
		}
		return out[i].Host < out[j].Host
	})
	return out
}

// boundedStatusText keeps one line of at most limit runes of printable text.
func boundedStatusText(value string, limit int) string {
	value = strings.TrimSpace(value)
	var b strings.Builder
	count := 0
	for _, r := range value {
		if count >= limit {
			b.WriteString("...")
			break
		}
		if r < 0x20 || r == 0x7f {
			r = ' '
		}
		b.WriteRune(r)
		count++
	}
	return b.String()
}
