// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Hermes (~/.hermes/config.yaml) and Devin (~/.config/devin/config.json)
// keep the account's own settings (model, provider, permissions, MCP servers)
// in the same file as the hooks DefenseClaw registers. An edited file keeps
// them: setup replaces DefenseClaw's hooks only. A file that went missing was
// recreated with DefenseClaw's hooks alone, so the account's settings were
// gone while verify read ok (GAP-0564). DefenseClaw now keeps a copy of the
// file as it last verified (the last known good copy, beside the connector's
// managed backup record) and puts it back, else the file as it was before
// DefenseClaw's first setup, before it registers its hooks again. With
// neither, the hooks are restored alone and a notice records that the
// account's settings could not be put back; the standalone guardian reports
// it (AgentConfigStatus) and the enterprise status and verify warn about it
// until the account has settings in the file again.
//
// Every OS keeps them: the Windows managed runtime's rollback of a first
// install, which removes only the names it knows in
// connector_backups\<connector>, knows theirs (AgentConfigBackupLeaves,
// GAP-0588).

// Where a missing agent config was put back from.
const (
	// AgentConfigFromLastGood is the copy taken when the file last verified.
	AgentConfigFromLastGood = "last_good"
	// AgentConfigFromPristine is the file as DefenseClaw's first setup found it.
	AgentConfigFromPristine = "pristine"
	// AgentConfigHooksOnly is no copy: DefenseClaw's hooks were restored alone.
	AgentConfigHooksOnly = "hooks_only"
)

const agentConfigCopyVersion = 1

// agentConfigSpec is a connector whose hook config is the agent's own
// settings file.
type agentConfigSpec struct {
	connector string
	// logical is the connector's managed backup logical name for the file.
	logical string
	label   string
	path    func(SetupOpts) string
	// keys returns the top-level keys of a document the agent reads
	// (false: not one).
	keys func([]byte) ([]string, bool)
}

func agentConfigSpecFor(connectorName string) (agentConfigSpec, bool) {
	switch strings.ToLower(strings.TrimSpace(connectorName)) {
	case "hermes":
		return agentConfigSpec{connector: "hermes", logical: "config.yaml", label: "Hermes config", path: hermesConfigPath, keys: yamlTopKeys}, true
	case "devin":
		return agentConfigSpec{connector: "devin", logical: "config", label: "Devin config", path: devinHooksPath, keys: jsoncTopKeys}, true
	}
	return agentConfigSpec{}, false
}

// agentConfigCopy is the last known good copy of an agent config file.
type agentConfigCopy struct {
	Version int    `json:"version"`
	Path    string `json:"path"`
	SHA256  string `json:"sha256"`
	Bytes   []byte `json:"bytes"`
}

// agentConfigNotice records how setup recreated a missing agent config.
type agentConfigNotice struct {
	Version int    `json:"version"`
	Path    string `json:"path"`
	Source  string `json:"source"`
	// SettingsLost is set when DefenseClaw saw settings of the account in the
	// file (before its first setup, or in a copy that no longer reads) and
	// could not put them back. It stays set across another loss of the file
	// until the account has settings in it again: the file recreated without
	// them is then the copy, which holds DefenseClaw's hooks only.
	SettingsLost bool   `json:"settings_lost,omitempty"`
	At           string `json:"at"`
}

// The copy and the notice sit beside the managed backup record. Their names
// do not end in .json, which the backup records' walk reads.
func (s agentConfigSpec) copyPath(dataDir string) string {
	record := managedFileBackupPath(dataDir, s.connector, s.logical)
	return strings.TrimSuffix(record, ".json") + ".last-good"
}

func (s agentConfigSpec) noticePath(dataDir string) string {
	record := managedFileBackupPath(dataDir, s.connector, s.logical)
	return strings.TrimSuffix(record, ".json") + ".restore-notice"
}

// AgentConfigBackupLeaves names the files the agent config of connectorName
// keeps in connector_backups/<connector> beside its managed backup record
// (the last known good copy and the restore notice); none for a connector
// without one.
func AgentConfigBackupLeaves(connectorName string) []string {
	spec, ok := agentConfigSpecFor(connectorName)
	if !ok {
		return nil
	}
	return []string{filepath.Base(spec.copyPath("")), filepath.Base(spec.noticePath(""))}
}

// agentConfigMaxBytes bounds the files read and kept.
const agentConfigMaxBytes = 1 << 20

func yamlTopKeys(data []byte) ([]string, bool) {
	if len(data) > agentConfigMaxBytes {
		return nil, false
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, true
	}
	var doc map[string]interface{}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, false
	}
	return agentConfigTopKeys(doc), true
}

func jsoncTopKeys(data []byte) ([]string, bool) {
	if len(data) > agentConfigMaxBytes {
		return nil, false
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, true
	}
	normalized, err := normalizeCopilotJSONC(data)
	if err != nil {
		return nil, false
	}
	var doc map[string]interface{}
	decoder := json.NewDecoder(bytes.NewReader(normalized))
	decoder.UseNumber()
	if err := decoder.Decode(&doc); err != nil || doc == nil {
		return nil, false
	}
	return agentConfigTopKeys(doc), true
}

func agentConfigTopKeys(doc map[string]interface{}) []string {
	keys := make([]string, 0, len(doc))
	for key := range doc {
		keys = append(keys, key)
	}
	return keys
}

// hasSettings reports whether a file holds anything but DefenseClaw's hooks
// field.
func (s agentConfigSpec) hasSettings(data []byte) bool {
	keys, ok := s.keys(data)
	if !ok {
		return true // not a document setup wrote: the account's own
	}
	for _, key := range keys {
		if key != "hooks" {
			return true
		}
	}
	return false
}

func (s agentConfigSpec) readCopy(dataDir, configPath string) (agentConfigCopy, bool) {
	data, info, err := readManagedTarget(s.copyPath(dataDir))
	if err != nil || info == nil || !info.Mode().IsRegular() || len(data) > 4*agentConfigMaxBytes {
		return agentConfigCopy{}, false
	}
	var copy agentConfigCopy
	if json.Unmarshal(data, &copy) != nil || copy.Version != agentConfigCopyVersion ||
		!sameManagedTargetPath(copy.Path, configPath) || copy.SHA256 != sha256Hex(copy.Bytes) {
		return agentConfigCopy{}, false
	}
	if _, ok := s.keys(copy.Bytes); !ok {
		return agentConfigCopy{}, false
	}
	return copy, true
}

// recordCopy keeps the agent config as it is now as the last known good
// copy. A missing or unparseable file is not kept, and a file without the
// account's settings (DefenseClaw's hooks only, or empty: one recreated
// after a loss, say) does not replace a copy that has them, so the next loss
// still puts them back.
func (s agentConfigSpec) recordCopy(dataDir, configPath string) error {
	data, info, err := readManagedTarget(configPath)
	if err != nil || info == nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return nil
	}
	if _, ok := s.keys(data); !ok {
		return nil
	}
	if existing, ok := s.readCopy(dataDir, configPath); ok &&
		(bytes.Equal(existing.Bytes, data) || (s.hasSettings(existing.Bytes) && !s.hasSettings(data))) {
		return nil
	}
	body, err := json.Marshal(agentConfigCopy{
		Version: agentConfigCopyVersion,
		Path:    configPath,
		SHA256:  sha256Hex(data),
		Bytes:   data,
	})
	if err != nil {
		return err
	}
	path := s.copyPath(dataDir)
	if err := ensureManagedBackupDirRestricted(filepath.Dir(path)); err != nil {
		return err
	}
	return atomicWriteFile(path, append(body, '\n'), 0o600)
}

// seedMissing puts back an agent config that went missing after DefenseClaw
// managed it, before setup registers the hooks in it again: the last known
// good copy, else the file as DefenseClaw's first setup found it. The copy
// is bound to the file's path, so it is put back even when the managed
// backup record is gone. A first setup (neither the record nor the copy) or
// a file that is there changes nothing. It returns where the file came from
// ("" when it did nothing).
func (s agentConfigSpec) seedMissing(dataDir, configPath string) (string, error) {
	if _, err := os.Lstat(configPath); err == nil || !errors.Is(err, os.ErrNotExist) {
		return "", nil // there, a dangling link or unreadable: not a missing file
	}
	copy, haveCopy := s.readCopy(dataDir, configPath)
	backup, err := loadManagedFileBackupPath(managedFileBackupPath(dataDir, s.connector, s.logical))
	switch {
	case err == nil:
		if _, err := validateManagedFileBackupTarget(backup, s.connector, s.logical, configPath); err != nil {
			return "", err
		}
	case !os.IsNotExist(err):
		return "", err
	case !haveCopy:
		if _, copyErr := os.Lstat(s.copyPath(dataDir)); copyErr != nil {
			return "", nil // a first setup
		}
		// The backup record is gone but a copy is there that no longer
		// reads: DefenseClaw saw settings it cannot put back (GAP-0612).
	}
	haveRecord := err == nil
	notice := agentConfigNotice{Version: agentConfigCopyVersion, Path: configPath, Source: AgentConfigHooksOnly,
		At: time.Now().UTC().Format(time.RFC3339)}
	var seed []byte
	mode := os.FileMode(0o600)
	pristine := haveRecord && backup.Existed && len(bytes.TrimSpace(backup.PristineBytes)) > 0
	switch {
	case haveCopy:
		seed, notice.Source = copy.Bytes, AgentConfigFromLastGood
	case pristine:
		if _, ok := s.keys(backup.PristineBytes); ok {
			seed, notice.Source = backup.PristineBytes, AgentConfigFromPristine
			if perm := os.FileMode(backup.Mode).Perm(); perm != 0 {
				mode = perm
			}
		}
	}
	if previous, ok := s.readNotice(dataDir); ok && previous.SettingsLost && sameManagedTargetPath(previous.Path, configPath) &&
		(seed == nil || !s.hasSettings(seed)) {
		// The file was lost before without the account's settings, and they
		// are not back: what is put back now (the copy taken of the file
		// recreated then) has none either.
		notice.SettingsLost = true
	}
	if seed == nil {
		// DefenseClaw saw settings it cannot put back: a file before its
		// first setup, or a copy that is there but no longer reads.
		_, copyErr := os.Lstat(s.copyPath(dataDir))
		notice.SettingsLost = notice.SettingsLost || pristine || copyErr == nil
	} else if err := atomicWriteFile(configPath, seed, mode); err != nil {
		return "", fmt.Errorf("put back %s %s: %w", s.label, configPath, err)
	}
	if err := s.writeNotice(dataDir, notice); err != nil {
		return notice.Source, err
	}
	return notice.Source, nil
}

func (s agentConfigSpec) writeNotice(dataDir string, notice agentConfigNotice) error {
	body, err := json.Marshal(notice)
	if err != nil {
		return err
	}
	path := s.noticePath(dataDir)
	if err := ensureManagedBackupDirRestricted(filepath.Dir(path)); err != nil {
		return err
	}
	return atomicWriteFile(path, append(body, '\n'), 0o600)
}

func (s agentConfigSpec) readNotice(dataDir string) (agentConfigNotice, bool) {
	data, info, err := readManagedTarget(s.noticePath(dataDir))
	if err != nil || info == nil || len(data) > 64<<10 {
		return agentConfigNotice{}, false
	}
	var notice agentConfigNotice
	if json.Unmarshal(data, &notice) != nil || notice.Version != agentConfigCopyVersion {
		return agentConfigNotice{}, false
	}
	return notice, true
}

// removeCopies removes the last known good copy and the notice (teardown:
// they hold the account's settings and describe a file DefenseClaw no longer
// manages).
func (s agentConfigSpec) removeCopies(dataDir string) error {
	var errs []error
	for _, path := range []string{s.copyPath(dataDir), s.noticePath(dataDir)} {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// seedMissingAgentConfig and recordAgentConfigCopy are setup's: no-ops for
// a connector without an agent config spec.
func seedMissingAgentConfig(connectorName, dataDir, configPath string) error {
	if spec, ok := agentConfigSpecFor(connectorName); ok {
		_, err := spec.seedMissing(dataDir, configPath)
		return err
	}
	return nil
}

func recordAgentConfigCopy(connectorName, dataDir, configPath string) {
	if spec, ok := agentConfigSpecFor(connectorName); ok {
		_ = spec.recordCopy(dataDir, configPath) // best effort: the next verify keeps it too
	}
}

// What the standalone guardian reports for an account's agent config
// (AgentConfigStatus). The enterprise status and verify word them; the
// worker's answer carries only the code, as the account controls the worker.
const (
	// AgentConfigRestoredLastGood: the file went missing and the last
	// known good copy was put back.
	AgentConfigRestoredLastGood = "restored_last_good"
	// AgentConfigRestoredPristine: the file went missing and the file as
	// DefenseClaw's first setup found it was put back.
	AgentConfigRestoredPristine = "restored_pristine"
	// AgentConfigRecreatedHooksOnly: the file went missing and DefenseClaw
	// had no copy of it, so it holds DefenseClaw's hooks only.
	AgentConfigRecreatedHooksOnly = "recreated_hooks_only"
	// AgentConfigSettingsLost: as AgentConfigRecreatedHooksOnly, and
	// DefenseClaw saw settings of the account in it that it could not put
	// back; reported until the account has settings in the file again.
	AgentConfigSettingsLost = "settings_lost"
	// AgentConfigNativeOTLPTakeBackPending: the Codex or Claude Code config
	// of the account keeps a native OTLP exporter an earlier per-user install
	// wrote, which the managed install could not remove
	// (NativeOTLPTakeBackPending, GAP-1839).
	AgentConfigNativeOTLPTakeBackPending = "native_otlp_take_back_pending"
	// AgentConfigNativeOTLPUnchecked (Codex, Claude Code on standalone
	// Windows): a configuration the account's agent reads reaches, through
	// a link or outside the profile, a file the account does not own, so
	// the guardian could not check it for an earlier per-user native OTLP
	// exporter (GAP-0929). Its hooks are in place: a warning, not a failed
	// row.
	AgentConfigNativeOTLPUnchecked = "native_otlp_unchecked"
	// AgentConfigNativeOTLPMarkedRemoved (Codex, Claude Code on standalone
	// Windows): the managed install removed an exporter of an earlier
	// per-user install that only its DefenseClaw markers and an unserved
	// loopback port proved, and kept a copy of the file (GAP-0836). Reported
	// while the copy is there.
	AgentConfigNativeOTLPMarkedRemoved = "native_otlp_marked_removed"
)

// ValidAgentConfigStatus reports whether code is one AgentConfigStatus
// returns ("" included).
func ValidAgentConfigStatus(code string) bool {
	switch code {
	case "", AgentConfigRestoredLastGood, AgentConfigRestoredPristine, AgentConfigRecreatedHooksOnly, AgentConfigSettingsLost,
		AgentConfigNativeOTLPUnchecked, AgentConfigNativeOTLPTakeBackPending, AgentConfigNativeOTLPMarkedRemoved:
		return true
	}
	return false
}

// AgentConfigStatus is what the standalone guardian reports for an
// account's agent config (Hermes, Devin) after setup (since: the setup's
// start) or after a verify that passed (since zero, refresh): a file this
// setup put back from a copy or recreated with DefenseClaw's hooks alone,
// and, until the account has settings in it again, one recreated without
// the settings DefenseClaw saw (AgentConfigSettingsLost). After a verify
// that passed the file is kept as the last known good copy, and a notice
// that no longer applies is removed. "" when there is nothing to report,
// for other connectors.
func AgentConfigStatus(connectorName string, opts SetupOpts, since time.Time, refresh bool) string {
	spec, ok := agentConfigSpecFor(connectorName)
	if !ok {
		return ""
	}
	configPath := spec.path(opts)
	if strings.TrimSpace(configPath) == "" {
		return ""
	}
	status := ""
	if notice, ok := spec.readNotice(opts.DataDir); ok && sameManagedTargetPath(notice.Path, configPath) {
		at, _ := time.Parse(time.RFC3339, notice.At)
		data, info, _ := readManagedTarget(configPath)
		settingsBack := info != nil && spec.hasSettings(data)
		switch {
		case notice.SettingsLost && !settingsBack:
			status = AgentConfigSettingsLost
		case since.IsZero() || at.Before(since.Add(-time.Second)):
			// Reported by the setup that recreated the file.
		case notice.Source == AgentConfigFromLastGood && settingsBack:
			status = AgentConfigRestoredLastGood
		case notice.Source == AgentConfigFromPristine && settingsBack:
			status = AgentConfigRestoredPristine
		// A copy put back that held DefenseClaw's hooks only (a file setup
		// created, say) is reported as hooks only, not as the user's settings
		// (GAP-0612).
		default:
			status = AgentConfigRecreatedHooksOnly
		}
		if refresh && (!notice.SettingsLost || settingsBack) {
			_ = os.Remove(spec.noticePath(opts.DataDir))
		}
	}
	if refresh {
		_ = spec.recordCopy(opts.DataDir, configPath)
	}
	return status
}

// nativeOTLPConfigFiles names, per connector, the agent configuration an
// AgentConfigNativeOTLPUnchecked notice is about.
var nativeOTLPConfigFiles = map[string]string{"codex": "a Codex config.toml", "claudecode": "a Claude Code settings.json"}

// nativeOTLPUncheckedNotice words AgentConfigNativeOTLPUnchecked for the
// administrator's status and verify (warning native_otlp_config_unchecked):
// which configuration of which account the guardian could not check, and
// the remedy, never its path or values.
func nativeOTLPUncheckedNotice(connectorName, user string) (string, bool) {
	file, ok := nativeOTLPConfigFiles[connectorName]
	if !ok {
		return "", false
	}
	return fmt.Sprintf("%s for user %s: %s that the agent reads reaches a file the account does not own, through a link or "+
		"outside the profile, so DefenseClaw cannot check it for a native OTLP exporter from an earlier per-user install, "+
		"and repair leaves it as it is (it revokes that install's DefenseClaw credential): replace it with the account's "+
		"own file, or remove the link, and the next repair checks it", connectorName, user, file), true
}

// agentConfigFiles names, per connector, the agent config a notice is about.
var agentConfigFiles = map[string]string{"hermes": "Hermes config.yaml", "devin": "Devin config.json"}

// AgentConfigNotice words a guardian's agent config notice for the
// administrator's status and verify (warning agent_settings_not_restored):
// what happened to the agent config of connectorName for user (code, an
// AgentConfigStatus code). False for a code or connector it does not word,
// which the per-user side may have written: only the known ones are.
func AgentConfigNotice(connectorName, user, code string) (string, bool) {
	if code == AgentConfigNativeOTLPTakeBackPending {
		return nativeOTLPTakeBackPendingNotice(connectorName, user)
	}
	if code == AgentConfigNativeOTLPUnchecked {
		return nativeOTLPUncheckedNotice(connectorName, user)
	}
	if code == AgentConfigNativeOTLPMarkedRemoved {
		return nativeOTLPMarkedRemovedNotice(connectorName, user)
	}
	file, ok := agentConfigFiles[connectorName]
	if !ok {
		return "", false
	}
	var what string
	switch code {
	case AgentConfigSettingsLost:
		what = "went missing and DefenseClaw had no copy of it to put back, so it holds DefenseClaw's hooks only: that user must enter the account's own settings in it (model, provider) again"
	case AgentConfigRecreatedHooksOnly:
		what = "went missing and DefenseClaw had no copy of it, so the guardian recreated it with DefenseClaw's hooks only: if that user had settings in it, they must be entered again"
	case AgentConfigRestoredLastGood:
		what = "went missing; the guardian put back DefenseClaw's last copy of it, with that user's settings, and changes made after that copy are not in it"
	case AgentConfigRestoredPristine:
		what = "went missing; the guardian put back the file as DefenseClaw's first setup found it, and changes made after that are not in it"
	default:
		return "", false
	}
	return fmt.Sprintf("%s for user %s: the %s %s", connectorName, user, file, what), true
}

// nativeOTLPMarkedRemovedNotice words AgentConfigNativeOTLPMarkedRemoved.
func nativeOTLPMarkedRemovedNotice(connectorName, user string) (string, bool) {
	var file, what string
	switch connectorName {
	case "codex":
		file, what = `.codex\config.toml`, "[otel] exporter tables"
	case "claudecode":
		file, what = `.claude\settings.json`, "OTEL_* env entries"
	default:
		return "", false
	}
	return fmt.Sprintf("%s for user %s: the managed install removed the %s of an earlier per-user DefenseClaw install from the account's %s "+
		"(a 127.0.0.1 endpoint on a port the managed gateway does not serve, with DefenseClaw's x-defenseclaw-source and x-defenseclaw-client headers), "+
		"so the agent no longer sends prompt telemetry to a port another account could hold; a copy of the file as it was is beside it (%s%s): "+
		"if that exporter was the account's own collector, put it back from the copy; delete the copy to clear this notice",
		connectorName, user, what, file, file, NativeOTLPMarkedOrphanBackupSuffix), true
}

// nativeOTLPTakeBackPendingNotice words AgentConfigNativeOTLPTakeBackPending.
func nativeOTLPTakeBackPendingNotice(connectorName, user string) (string, bool) {
	var file, step string
	switch connectorName {
	case "codex":
		file, step = `.codex\config.toml`, "the [otel] exporter tables an earlier DefenseClaw setup wrote (a 127.0.0.1 endpoint with a DefenseClaw bearer)"
	case "claudecode":
		file, step = `.claude\settings.json`, "the OTEL_* entries and CLAUDE_CODE_ENABLE_TELEMETRY an earlier DefenseClaw setup wrote in its env block"
	default:
		return "", false
	}
	return fmt.Sprintf("%s for user %s: the account's %s still holds the native OTLP exporter of an earlier per-user DefenseClaw install, which the managed install could not remove (it could not read or write that file as the account, for example on a network share while the account was signed out); its DefenseClaw credential is revoked, but the agent may still send prompt telemetry to a port no DefenseClaw process holds: as that user, remove %s, then run repair (or the next ensure), which checks again and clears this warning", connectorName, user, file, step), true
}
