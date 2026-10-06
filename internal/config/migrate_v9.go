// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/config/internal/cfgtxn"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/policies"
)

// The v8 to v9 migration moves admin intent into config.yaml: data.json
// admission and guardrail values, the *_actions keys,
// watch.allow_list_bypass_scan, rule_pack_dir, the v8 scanner keys,
// update_check and (OSS only) the operator block/allow rows of audit.db.
// It is the one implementation: `defenseclaw-gateway config migrate --to 9`,
// the Python CONFIG_MIGRATIONS[8] step and enterprise ensure all call it,
// and the gateway runs it in memory (read-only) on a v8 file at load.

// Files the migration writes next to config.yaml or under policy_dir.
const (
	// MigrationV9RecordFile is the evidence record (MigrationRecord).
	MigrationV9RecordFile = "migration-v9.json"
	// ConfigV8BackupSuffix is appended to config.yaml for the pre-migration
	// bytes, which the upgrade rollback restores.
	ConfigV8BackupSuffix = ".v8.bak"
	// DataJSONMigratedSuffix is appended to <policy_dir>/rego/data.json
	// once its values have moved into config.
	DataJSONMigratedSuffix = ".migrated-v9"
)

// MigrationRecordSchemaVersion versions the migration-v9.json shape.
const MigrationRecordSchemaVersion = 1

// ErrMigrateV9NotImplemented was returned by the frozen stub. Nothing returns
// it now; it stays for callers compiled against the stub contract.
var ErrMigrateV9NotImplemented = errors.New("config: the config_version 9 migration is not implemented yet")

// MigrateV9Input names the migration inputs.
type MigrateV9Input struct {
	// ConfigPath is the v8 config.yaml.
	ConfigPath string
	// Source is the v8 bytes; when nil they are read from ConfigPath.
	Source []byte
	// DataJSONPath is <policy_dir>/rego/data.json; "" or missing is skipped.
	DataJSONPath string
	// PolicyDir is the resolved policy_dir. A v8 rule_pack_dir is a preset
	// only when it is <PolicyDir>/guardrail/<name>, which is where the v9
	// rule_pack name resolves; any other directory becomes a custom pack.
	// Empty derives it from DataJSONPath, then from the document.
	PolicyDir string
	// DataDir is the resolved data_dir: the moved inline scanner key goes to
	// its .env and its signature-packs/ are listed. Empty resolves it the way
	// the config loader does (MigrationDataDir).
	DataDir string
	// AuditDBPath is audit.db, whose operator actions rows move into
	// asset_policy. Empty skips them; managed standalone always skips them
	// and reports the count as a local_enforcement_entries_ignored warning.
	AuditDBPath string
	// Managed is true on StandaloneEnterprise() hosts.
	Managed bool
	// DryRun computes the result without writing anything.
	DryRun bool
	// InMemory migrates for a read-only load: nothing is written and
	// audit.db is only read.
	InMemory bool
	// RulePackDigest returns the hex RulePackSummary digest of a rule-pack
	// directory (guardrail.LoadRulePack(dir).Summary().Digest). The config
	// package can not import the guardrail package, so callers that may meet
	// a custom rule_pack_dir pass it; without it such a directory is a
	// migration error.
	RulePackDigest func(dir string) (string, error)
}

// MigrateV9Result is the outcome of one migration.
type MigrateV9Result struct {
	// Migrated is the config_version 9 document.
	Migrated []byte
	// Record is the evidence written to MigrationV9RecordFile.
	Record MigrationRecord
	// Written lists the files written (empty for DryRun and InMemory).
	Written []string
	// EnvKey and EnvValue are the inline scanner key the migration moves out
	// of config.yaml (scanners.skill_scanner.virustotal_api_key). A
	// committing run writes it to <data_dir>/.env; a DryRun or InMemory
	// caller that installs Migrated must place it itself. EnvValue is a
	// secret: never print or record it.
	EnvKey   string `json:"-"`
	EnvValue string `json:"-"`
}

// MigrationRecord is migration-v9.json: every value moved and every
// conflict. Values are rendered without secrets.
type MigrationRecord struct {
	SchemaVersion int    `json:"schema_version"`
	FromVersion   int    `json:"from_version"`
	ToVersion     int    `json:"to_version"`
	MigratedAt    string `json:"migrated_at"`
	// Actor is "migration" or "lifecycle".
	Actor string `json:"actor"`
	// SourceSHA256 and ResultSHA256 are the config bytes before and after.
	SourceSHA256 string `json:"source_sha256"`
	ResultSHA256 string `json:"result_sha256"`
	// Moved lists every value written to a v9 key.
	Moved []MigrationMove `json:"moved"`
	// Conflicts lists values that disagreed; data.json wins over the
	// *_actions keys because enforcement read it.
	Conflicts []MigrationConflict `json:"conflicts"`
	// Removed lists v8 keys dropped without a v9 value (no reader).
	Removed []string `json:"removed,omitempty"`
	// ActionsRowsMoved counts audit.db actions rows moved to asset_policy.
	ActionsRowsMoved int `json:"actions_rows_moved"`
	// ActionsRowsIgnored counts rows left in place on a managed host.
	ActionsRowsIgnored int `json:"actions_rows_ignored,omitempty"`
	// Notes are behaviour changes the operator should know about (for
	// example block_at now applies on every path).
	Notes []string `json:"notes,omitempty"`
	// Acknowledged is set by `defenseclaw config migrate --ack`.
	Acknowledged bool `json:"acknowledged,omitempty"`
}

// MigrationMove is one value moved from a v8 source to a v9 key.
type MigrationMove struct {
	// Source is "config", "data.json" or "audit.db".
	Source string `json:"source"`
	// From is the source path, for example skill_actions.high or
	// data.json:config.scan_on_install or actions:<id>.
	From string `json:"from"`
	// To is the v9 config path.
	To string `json:"to"`
	// Value is the display-safe value written.
	Value any `json:"value,omitempty"`
}

// MigrationConflict is a v9 key with disagreeing v8 sources.
type MigrationConflict struct {
	To     string `json:"to"`
	Kept   string `json:"kept"`
	Lost   string `json:"lost"`
	Reason string `json:"reason"`
}

// LocalEnforcementEntriesIgnored is the warning code a managed migration
// records (in Notes) when audit.db holds operator block/allow rows that the
// admin config replaces.
const LocalEnforcementEntriesIgnored = "local_enforcement_entries_ignored"

// MigrationRecordPath is migration-v9.json next to configPath.
func MigrationRecordPath(configPath string) string {
	return filepath.Join(filepath.Dir(configPath), MigrationV9RecordFile)
}

// MigrateV9 migrates a config_version 8 source to config_version 9. A source
// that is already at 9 returns it unchanged with nothing written.
func MigrateV9(ctx context.Context, in MigrateV9Input) (*MigrateV9Result, error) {
	path := strings.TrimSpace(in.ConfigPath)
	if path == "" {
		path = ConfigPath()
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("config: resolve %s: %w", path, err)
	}
	source := in.Source
	if source == nil {
		if source, err = os.ReadFile(abs); err != nil {
			return nil, fmt.Errorf("config: read %s: %w", abs, err)
		}
	}
	m := &v9Migrator{in: in, configPath: abs}
	m.record = MigrationRecord{
		SchemaVersion: MigrationRecordSchemaVersion,
		FromVersion:   ObservabilityV8ConfigVersion,
		ToVersion:     ConfigVersionV9,
		MigratedAt:    time.Now().UTC().Format(time.RFC3339),
		Actor:         "migration",
		SourceSHA256:  cfgtxn.SHA256Hex(source),
		Moved:         []MigrationMove{},
		Conflicts:     []MigrationConflict{},
	}
	if in.Managed {
		m.record.Actor = "lifecycle"
	}
	migrated, already, err := m.migrate(source)
	if err != nil {
		return nil, err
	}
	m.record.ResultSHA256 = cfgtxn.SHA256Hex(migrated)
	result := &MigrateV9Result{Migrated: migrated, Record: m.record, EnvKey: m.envKey, EnvValue: m.envValue}
	if already {
		result.Record.FromVersion = ConfigVersionV9
		return result, nil
	}
	if err := ValidateCandidate(abs, migrated); err != nil {
		return nil, fmt.Errorf("config: the migrated config_version 9 document does not validate: %w", err)
	}
	if in.DryRun || in.InMemory {
		return result, nil
	}
	written, err := m.commit(ctx, source, migrated)
	result.Written = written
	result.Record = m.record
	return result, err
}

// NeedsMigrationV9 reports whether raw is a config_version 8 document.
func NeedsMigrationV9(raw []byte) bool {
	var doc struct {
		ConfigVersion int `yaml:"config_version"`
	}
	return yaml.Unmarshal(raw, &doc) == nil && doc.ConfigVersion == ObservabilityV8ConfigVersion
}

// MigrateV8InMemory is the gateway's read-only load of a config_version 8
// file (spec 2.0): it returns the config_version 9 bytes the migration would
// write, so the data.json admission and thresholds, the *_actions keys and,
// on a per-user install, the operator rows of audit.db keep applying until
// the file is migrated. Nothing is written. raw comes back unchanged for a
// config_version 9 file and on a Secure Client host, whose path does not
// change; on a migration error it comes back unchanged with the error, for
// the caller to report.
func MigrateV8InMemory(configFile string, raw []byte, rulePackDigest func(dir string) (string, error)) ([]byte, error) {
	if !NeedsMigrationV9(raw) {
		return raw, nil
	}
	var doc yaml.Node
	if yaml.Unmarshal(raw, &doc) != nil {
		return raw, nil
	}
	root := v8DocumentRoot(&doc)
	if root == nil || root.Kind != yaml.MappingNode || v9SecureClientDocument(root) {
		return raw, nil
	}
	dataDir := migrationDataDir(configFile, root)
	policyDir := expandPath(strings.TrimSpace(yamlScalarValue(v8YAMLMapValue(root, "policy_dir"))))
	if policyDir == "" {
		policyDir = filepath.Join(dataDir, "policies")
	}
	managedHost := StandaloneManagedSource(raw)
	in := MigrateV9Input{
		ConfigPath: configFile, Source: raw, PolicyDir: policyDir, DataDir: dataDir,
		DataJSONPath: filepath.Join(policyDir, "rego", "data.json"),
		Managed:      managedHost, InMemory: true, RulePackDigest: rulePackDigest,
	}
	if !managedHost {
		local := v8YAMLMapValue(v8YAMLMapValue(root, "observability"), "local")
		auditDB := expandPath(strings.TrimSpace(yamlScalarValue(v8YAMLMapValue(local, "path"))))
		if auditDB == "" {
			auditDB = filepath.Join(dataDir, "audit.db")
		}
		in.AuditDBPath = auditDB
	}
	result, err := MigrateV9(context.Background(), in)
	if err != nil {
		return raw, err
	}
	// The v8 file still holds the inline key; the v9 document names its
	// variable instead, so the variable carries the key for this process
	// (the scanners inherit it) until the file is migrated. A value already
	// in the environment or .env wins, as it does for any api_key_env.
	if result.EnvKey != "" && os.Getenv(result.EnvKey) == "" {
		_ = os.Setenv(result.EnvKey, result.EnvValue)
	}
	return result.Migrated, nil
}

// MigratedFrom reports whether the config at configPath is still the
// config_version 9 migration of a v8 source: migration-v9.json next to it
// records sourceSHA256 as the input and installedSHA256 as the result (both
// hex). A lifecycle that compares an administrator's v8 file with the
// installed config uses it, so the same v8 file is not drift once the
// upgrade migrated it.
func MigratedFrom(configPath, sourceSHA256, installedSHA256 string) bool {
	record, ok := readMigrationRecord(configPath)
	return ok && strings.EqualFold(record.SourceSHA256, sourceSHA256) &&
		strings.EqualFold(record.ResultSHA256, installedSHA256)
}

// MigratedSource reports whether migration-v9.json next to configPath
// records sourceSHA256 (hex) as the v8 input it migrated.
func MigratedSource(configPath, sourceSHA256 string) bool {
	record, ok := readMigrationRecord(configPath)
	return ok && strings.EqualFold(record.SourceSHA256, sourceSHA256)
}

func readMigrationRecord(configPath string) (MigrationRecord, bool) {
	var record MigrationRecord
	raw, err := os.ReadFile(MigrationRecordPath(configPath))
	if err != nil || json.Unmarshal(raw, &record) != nil {
		return MigrationRecord{}, false
	}
	return record, record.SourceSHA256 != ""
}

// AcknowledgeMigrationV9 marks migration-v9.json next to configPath as read
// (`defenseclaw config migrate --ack`), so doctor stops reporting it.
func AcknowledgeMigrationV9(configPath string) error {
	recordPath := MigrationRecordPath(configPath)
	raw, err := os.ReadFile(recordPath)
	if err != nil {
		return err
	}
	var record MigrationRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		return fmt.Errorf("config: decode %s: %w", recordPath, err)
	}
	record.Acknowledged = true
	return writeMigrationRecord(recordPath, record)
}

func writeMigrationRecord(path string, record MigrationRecord) error {
	encoded, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	return cfgtxn.WriteFileDurable(path, append(encoded, '\n'), 0o600)
}

type v9Migrator struct {
	in         MigrateV9Input
	configPath string
	root       *yaml.Node
	record     MigrationRecord
	// rows are the audit.db rows moved into asset_policy, cleared after the
	// config commit.
	rows []v9ActionRow
	// envKey is an inline scanner key moved to .env on commit.
	envKey, envValue string
	// rego are the pre-9 Rego modules under <policy_dir>/rego that commit
	// replaces with the shipped module (nil data retires the file).
	rego []v9RegoRefresh
	// globalPackPosture is the posture the gateway gives the global v8
	// rule_pack_dir ("" when none was set); the data.json thresholds are
	// compared with it.
	globalPackPosture string
}

type v9RegoRefresh struct {
	path string
	data []byte
}

func (m *v9Migrator) moved(source, from, to string, value any) {
	m.record.Moved = append(m.record.Moved, MigrationMove{Source: source, From: from, To: to, Value: value})
}

func (m *v9Migrator) note(format string, args ...any) {
	m.record.Notes = append(m.record.Notes, fmt.Sprintf(format, args...))
}

func (m *v9Migrator) migrate(source []byte) ([]byte, bool, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(source, &doc); err != nil {
		return nil, false, fmt.Errorf("config: parse %s: %w", m.configPath, err)
	}
	root := v8DocumentRoot(&doc)
	if root == nil || root.Kind != yaml.MappingNode {
		return nil, false, fmt.Errorf("config: %s root must be a mapping", m.configPath)
	}
	m.root = root
	versionNode := v8YAMLMapValue(root, "config_version")
	var version int
	if versionNode == nil || versionNode.Decode(&version) != nil {
		return nil, false, fmt.Errorf("config: %s has no integer config_version", m.configPath)
	}
	switch {
	case version == ConfigVersionV9:
		return source, true, nil
	case version != ObservabilityV8ConfigVersion:
		return nil, false, fmt.Errorf("config: the config_version 9 migration reads config_version 8, not %d", version)
	}

	data, err := readV9DataJSON(m.in.DataJSONPath)
	if err != nil {
		return nil, false, err
	}
	if err := m.migrateRulePacks(root); err != nil {
		return nil, false, err
	}
	m.migrateAdmission(root, data)
	m.migrateThresholds(root, data)
	if err := m.migrateScanners(root); err != nil {
		return nil, false, err
	}
	m.migrateSignaturePacks(root)
	if node := v9Pop(root, "update_check"); node != nil {
		var check bool
		if node.Decode(&check) == nil {
			v9Set(root, v9Scalar(check), "update", "check")
			m.moved("config", "update_check", "update.check", check)
		}
	}
	m.migrateTelemetryAliases(root)
	if err := m.migrateActionsRows(root); err != nil {
		return nil, false, err
	}
	if err := m.planRegoRefresh(); err != nil {
		return nil, false, err
	}
	versionNode.Value = fmt.Sprint(ConfigVersionV9)
	versionNode.Tag = "!!int"

	var out bytes.Buffer
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return nil, false, fmt.Errorf("config: encode the migrated config: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, false, fmt.Errorf("config: encode the migrated config: %w", err)
	}
	return out.Bytes(), false, nil
}

// migrateTelemetryAliases retires the telemetry attribute alias switch. Since
// config_version 9 telemetry carries only canonical attribute names, so
// observability.trace_policy.compatibility_aliases is dropped (recorded in
// Removed) and a configured resource attribute deployment.environment becomes
// deployment.environment.name. A host that exports to a backend is told its
// queries and dashboards must use the canonical names. Keep this until the
// config_version 8 migration is dropped (1.1.0).
func (m *v9Migrator) migrateTelemetryAliases(root *yaml.Node) {
	observability := v8YAMLMapValue(root, "observability")
	if observability == nil || observability.Kind != yaml.MappingNode {
		return
	}
	if policy := v8YAMLMapValue(observability, "trace_policy"); policy != nil {
		if v9Pop(policy, "compatibility_aliases") != nil {
			m.record.Removed = append(m.record.Removed, "observability.trace_policy.compatibility_aliases")
		}
		if policy.Kind == yaml.MappingNode && len(policy.Content) == 0 {
			v9Pop(observability, "trace_policy")
		}
	}
	const from, to = "deployment.environment", "deployment.environment.name"
	attributes := v8YAMLMapValue(v8YAMLMapValue(observability, "resource"), "attributes")
	if node := v9Pop(attributes, from); node != nil {
		prefix := "observability.resource.attributes."
		if v8YAMLMapValue(attributes, to) == nil {
			v9Set(attributes, node, to)
			m.moved("config", prefix+from, prefix+to, node.Value)
		} else if v8YAMLMapValue(attributes, to).Value != node.Value {
			m.record.Conflicts = append(m.record.Conflicts, MigrationConflict{
				To: prefix + to, Kept: to, Lost: from,
				Reason: "both spellings were set to different values; the canonical name wins",
			})
		}
	}
	if len(v9SeqItems(v8YAMLMapValue(observability, "destinations"))) > 0 {
		m.note("telemetry no longer carries the alias attributes deployment.environment, deployment.mode and " +
			"defenseclaw.device.id; queries, dashboards and alerts on an exported backend must use " +
			"deployment.environment.name, defenseclaw.deployment.mode and defenseclaw.device.public_key_fingerprint")
	}
}

// commit writes the migration under config.yaml.lock: the v8 backup, the
// config (generation +1), the record, the data.json rename, the inline key
// move and finally the audit.db rows.
func (m *v9Migrator) commit(ctx context.Context, source, migrated []byte) ([]string, error) {
	txn, err := cfgtxn.Begin(ctx, m.configPath, 0)
	if err != nil {
		return nil, err
	}
	defer txn.Close()
	current, mode, exists, err := txn.Read()
	if err != nil {
		return nil, err
	}
	if !exists || !bytes.Equal(current, source) {
		return nil, errors.New("config: config.yaml changed while the config_version 9 migration ran; run it again")
	}
	var written []string
	backup := m.configPath + ConfigV8BackupSuffix
	if err := cfgtxn.WriteFileDurable(backup, source, mode); err != nil {
		return written, err
	}
	written = append(written, backup)
	if m.envKey != "" {
		envPath := filepath.Join(m.dataDir(), ".env")
		if err := appendDotEnvKey(envPath, m.envKey, m.envValue); err != nil {
			return written, fmt.Errorf("config: move the inline scanner key to %s: %w", envPath, err)
		}
		written = append(written, envPath)
	}
	if _, err := txn.Commit(migrated, mode, m.record.Actor, "config_version 9 migration"); err != nil {
		return written, err
	}
	written = append(written, m.configPath)
	if dj := strings.TrimSpace(m.in.DataJSONPath); dj != "" {
		if _, statErr := os.Stat(dj); statErr == nil {
			if err := os.Rename(dj, dj+DataJSONMigratedSuffix); err != nil {
				m.note("could not rename %s: %v", dj, err)
			} else {
				written = append(written, dj+DataJSONMigratedSuffix)
			}
		}
	}
	for _, module := range m.rego {
		if err := m.refreshRegoModule(module); err != nil {
			m.note("could not replace the pre-9 module %s: %v; the gateway refuses it and uses the config-driven fallback", module.path, err)
			continue
		}
		written = append(written, module.path+DataJSONMigratedSuffix)
	}
	// Rows are cleared only after the config commit, so a failure leaves
	// them enforcing from the table and recorded in config: never lost.
	if len(m.rows) > 0 {
		if err := clearV9ActionRows(m.in.AuditDBPath, m.rows); err != nil {
			m.note("audit.db rows were copied to asset_policy but not cleared: %v", err)
		}
	}
	recordPath := MigrationRecordPath(m.configPath)
	if err := writeMigrationRecord(recordPath, m.record); err != nil {
		return written, err
	}
	written = append(written, recordPath)
	return written, nil
}

// dataDir is the data_dir the runtime uses for this config.
func (m *v9Migrator) dataDir() string {
	if dir := strings.TrimSpace(m.in.DataDir); dir != "" {
		return dir
	}
	return migrationDataDir(m.configPath, m.root)
}

// MigrationDataDir resolves the data_dir of the config at configPath the way
// the config loader does: the document's data_dir, else the layout data
// directory of a managed Unix standalone config, else DEFENSECLAW_HOME when
// configPath is the DEFENSECLAW_CONFIG file, else the config's folder.
func MigrationDataDir(configPath string, raw []byte) string {
	var doc yaml.Node
	_ = yaml.Unmarshal(raw, &doc)
	return migrationDataDir(configPath, v8DocumentRoot(&doc))
}

func migrationDataDir(configPath string, root *yaml.Node) string {
	if dir := strings.TrimSpace(yamlScalarValue(v8YAMLMapValue(root, "data_dir"))); dir != "" {
		// "~/..." is valid v8; it names the home directory, not a folder
		// relative to the working directory.
		return expandPath(dir)
	}
	configFile := filepath.Clean(configPath)
	if layout, ok := standaloneLayoutDataDir(configFile, root); ok {
		return layout
	}
	if env := strings.TrimSpace(os.Getenv(managed.ConfigPathEnv)); env != "" && filepath.Clean(env) == configFile {
		return DefaultDataPath()
	}
	return filepath.Dir(configFile)
}

// appendDotEnvKey adds key=value to a private .env unless the key is already
// defined there.
func appendDotEnvKey(path, key, value string) error {
	existing, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	updated, changed := DotEnvWithKey(existing, key, value)
	if !changed {
		return nil
	}
	return cfgtxn.WriteFileDurable(path, updated, 0o600)
}

// DotEnvWithKey returns the .env bytes existing with key=value appended, and
// false when key is already defined there (existing is then unchanged).
func DotEnvWithKey(existing []byte, key, value string) ([]byte, bool) {
	for _, line := range strings.Split(string(existing), "\n") {
		name, _, ok := strings.Cut(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "export ")), "=")
		if ok && strings.TrimSpace(name) == key {
			return existing, false
		}
	}
	var out bytes.Buffer
	out.Write(existing)
	if len(existing) > 0 && !bytes.HasSuffix(existing, []byte("\n")) {
		out.WriteByte('\n')
	}
	fmt.Fprintf(&out, "%s=%s\n", key, value)
	return out.Bytes(), true
}

// ---------------------------------------------------------------------------
// Rego modules

// v9LegacyRegoData matches the data.json documents a pre-9 admission,
// guardrail or skill_actions module read. Since 9 those values are
// evaluation input, so such a module sees nothing and fails open.
var v9LegacyRegoData = regexp.MustCompile(`\bdata\.(config|actions|scanner_overrides|first_party_allow_list|guardrail|severity_ranking)\b`)

// planRegoRefresh finds the pre-9 vendor modules left under
// <policy_dir>/rego: init only seeded missing files, so an upgrade keeps the
// old ones. On a per-user install they are replaced with the shipped module
// (skill_actions.rego, removed in 9, is retired); on a managed host the
// admin owns policy_dir, so they are only reported.
func (m *v9Migrator) planRegoRefresh() error {
	dir := filepath.Join(m.policyDir(), "rego")
	shipped := map[string][]byte{}
	files, err := policyassets.Files()
	if err != nil {
		return fmt.Errorf("config: read the shipped Rego modules: %w", err)
	}
	for _, f := range files {
		if strings.HasPrefix(f.Path, "rego/") {
			shipped[strings.TrimPrefix(f.Path, "rego/")] = f.Data
		}
	}
	for _, name := range []string{"admission.rego", "guardrail.rego", "skill_actions.rego"} {
		path := filepath.Join(dir, name)
		raw, err := os.ReadFile(path)
		if err != nil || !v9LegacyRegoData.Match(raw) {
			continue
		}
		if m.in.Managed {
			m.note("%s is a pre-9 module that reads data.json; the gateway refuses it and uses the config-driven "+
				"admission and thresholds until the admin replaces it with the shipped module", path)
			continue
		}
		m.rego = append(m.rego, v9RegoRefresh{path: path, data: shipped[name]})
		if shipped[name] == nil {
			m.note("%s (removed in 9) is kept as %s%s", path, name, DataJSONMigratedSuffix)
		} else {
			m.note("%s is a pre-9 module that reads data.json; it is kept as %s%s and replaced with the shipped module",
				path, name, DataJSONMigratedSuffix)
		}
	}
	return nil
}

func (m *v9Migrator) refreshRegoModule(module v9RegoRefresh) error {
	info, err := os.Stat(module.path)
	if err != nil {
		return err
	}
	if err := os.Rename(module.path, module.path+DataJSONMigratedSuffix); err != nil {
		return err
	}
	if module.data == nil {
		return nil
	}
	return cfgtxn.WriteFileDurable(module.path, module.data, info.Mode().Perm())
}

// ---------------------------------------------------------------------------
// data.json

type v9DataJSONAction struct {
	Install string `json:"install"`
	File    string `json:"file"`
	Runtime string `json:"runtime"`
}

type v9DataJSON struct {
	present bool
	raw     map[string]json.RawMessage
	Config  struct {
		AllowListBypassScan *bool `json:"allow_list_bypass_scan"`
		ScanOnInstall       *bool `json:"scan_on_install"`
	}
	Actions             map[string]v9DataJSONAction            `json:"actions"`
	ScannerOverrides    map[string]map[string]v9DataJSONAction `json:"scanner_overrides"`
	FirstPartyAllowList *[]struct {
		TargetType         string   `json:"target_type"`
		TargetName         string   `json:"target_name"`
		Reason             string   `json:"reason"`
		SourcePathContains []string `json:"source_path_contains"`
	} `json:"first_party_allow_list"`
	Guardrail struct {
		BlockThreshold  *int   `json:"block_threshold"`
		AlertThreshold  *int   `json:"alert_threshold"`
		CiscoTrustLevel string `json:"cisco_trust_level"`
	} `json:"guardrail"`
}

func readV9DataJSON(path string) (*v9DataJSON, error) {
	data := &v9DataJSON{}
	if strings.TrimSpace(path) == "" {
		return data, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return data, nil
		}
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	if err := json.Unmarshal(raw, data); err != nil {
		return nil, fmt.Errorf("config: decode %s: %w", path, err)
	}
	if err := json.Unmarshal(raw, &data.raw); err != nil {
		return nil, fmt.Errorf("config: decode %s: %w", path, err)
	}
	data.present = true
	return data, nil
}

var v9Severities = []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

// v9BuiltinAdmissionAction is the shipped data.json action for a type and
// severity, the default the v9 admission compiler reproduces.
func v9BuiltinAdmissionAction(assetType, severity string) SeverityAction {
	quarantine := SeverityAction{Install: InstallBlock, File: FileActionQuarantine, Runtime: RuntimeDisable}
	warn := SeverityAction{Install: InstallNone, File: FileActionNone, Runtime: RuntimeEnable}
	switch {
	case assetType == AdmissionTypeMCP && severity == "MEDIUM":
		return quarantine
	case assetType == AdmissionTypeMCP && severity == "LOW":
		return SeverityAction{Install: InstallNone, File: FileActionNone, Runtime: RuntimeDisable}
	case severity == "CRITICAL" || severity == "HIGH":
		return quarantine
	default:
		return warn
	}
}

var v9BuiltinFirstParty = map[string][]AdmissionFirstParty{
	AdmissionTypeSkill: {{
		Name: "codeguard",
		SourcePathContains: []string{".openclaw/workspace/skills/codeguard", ".openclaw/skills/codeguard",
			".zeptoclaw/skills/codeguard", ".claude/skills/codeguard"},
		Reason: "first-party DefenseClaw skill",
	}},
	AdmissionTypePlugin: {{
		Name: "defenseclaw",
		SourcePathContains: []string{".openclaw/extensions/defenseclaw", ".zeptoclaw/extensions/defenseclaw",
			".claude/extensions/defenseclaw", ".codex/extensions/defenseclaw", ".config/amp/plugins/defenseclaw.ts"},
		Reason: "first-party DefenseClaw plugin",
	}},
}

func (a v9DataJSONAction) config() SeverityAction {
	out := SeverityAction{
		Install: InstallAction(strings.ToLower(strings.TrimSpace(a.Install))),
		File:    FileAction(strings.ToLower(strings.TrimSpace(a.File))),
	}
	switch strings.ToLower(strings.TrimSpace(a.Runtime)) {
	case "block", "disable":
		out.Runtime = RuntimeDisable
	default:
		out.Runtime = RuntimeEnable
	}
	if out.Install == "" {
		out.Install = InstallNone
	}
	if out.File == "" {
		out.File = FileActionNone
	}
	return out
}

// v9ActionNode renders a triple as its shorthand when one matches.
func v9ActionNode(action SeverityAction) (*yaml.Node, any) {
	switch action {
	case SeverityAction{Install: InstallBlock, File: FileActionQuarantine, Runtime: RuntimeDisable}:
		return v9Scalar(AdmissionActionQuarantine), AdmissionActionQuarantine
	case SeverityAction{Install: InstallBlock, File: FileActionNone, Runtime: RuntimeDisable}:
		return v9Scalar(AdmissionActionBlock), AdmissionActionBlock
	case SeverityAction{Install: InstallNone, File: FileActionNone, Runtime: RuntimeEnable}:
		return v9Scalar(AdmissionActionWarn), AdmissionActionWarn
	}
	node := v9Mapping(
		"install", v9Scalar(string(action.Install)),
		"file", v9Scalar(string(action.File)),
		"runtime", v9Scalar(string(action.Runtime)),
	)
	return node, map[string]string{"install": string(action.Install), "file": string(action.File), "runtime": string(action.Runtime)}
}

func (m *v9Migrator) migrateAdmission(root *yaml.Node, data *v9DataJSON) {
	// The v8 keys enforcement never read: removed, with a conflict when an
	// operator customised them away from what data.json enforced.
	legacy := map[string]map[string]SeverityAction{}
	for key, assetType := range map[string]string{
		"skill_actions": AdmissionTypeSkill, "mcp_actions": AdmissionTypeMCP, "plugin_actions": AdmissionTypePlugin,
	} {
		node := v9Pop(root, key)
		if node == nil {
			continue
		}
		m.record.Removed = append(m.record.Removed, key)
		var decoded map[string]SeverityAction
		if node.Decode(&decoded) != nil {
			continue
		}
		legacy[assetType] = decoded
	}
	if watch := v8YAMLMapValue(root, "watch"); watch != nil {
		node := v9Pop(watch, "allow_list_bypass_scan")
		if watch.Kind == yaml.MappingNode && len(watch.Content) == 0 {
			v9Pop(root, "watch")
		}
		if node != nil {
			m.record.Removed = append(m.record.Removed, "watch.allow_list_bypass_scan")
			var bypass bool
			enforced := !data.present || (data.Config.AllowListBypassScan != nil && *data.Config.AllowListBypassScan)
			if node.Decode(&bypass) == nil && !bypass && enforced {
				m.record.Conflicts = append(m.record.Conflicts, MigrationConflict{
					To: "admission.defaults.allow_list_bypass_scan", Kept: "data.json:true",
					Lost: "watch.allow_list_bypass_scan:false", Reason: "enforcement read data.json; watch.allow_list_bypass_scan had no reader",
				})
			}
		}
	}

	if !data.present {
		return
	}
	for _, key := range []string{"policy_name", "max_enforcement_delay_seconds"} {
		var cfg map[string]json.RawMessage
		if json.Unmarshal(data.raw["config"], &cfg) == nil {
			if _, ok := cfg[key]; ok {
				m.record.Removed = append(m.record.Removed, "data.json:config."+key)
			}
		}
	}
	for _, key := range []string{"severity_ranking", "audit"} {
		if _, ok := data.raw[key]; ok {
			m.record.Removed = append(m.record.Removed, "data.json:"+key)
		}
	}
	for _, item := range []struct {
		key   string
		value *bool
	}{
		{"scan_on_install", data.Config.ScanOnInstall},
		{"allow_list_bypass_scan", data.Config.AllowListBypassScan},
	} {
		key, value := item.key, item.value
		// v8 Rego skipped the install scan only when scan_on_install was
		// == false, so an absent value scanned; it bypassed the scan for
		// allow-listed assets only when allow_list_bypass_scan was == true,
		// so an absent value did not bypass.
		enforced := value != nil && *value
		if key == "scan_on_install" {
			enforced = value == nil || *value
		}
		if !enforced {
			v9Set(root, v9Scalar(false), "admission", "defaults", key)
			m.moved("data.json", "data.json:config."+key, "admission.defaults."+key, false)
		}
	}

	for _, assetType := range []string{AdmissionTypeSkill, AdmissionTypeMCP, AdmissionTypePlugin} {
		effective := map[string]SeverityAction{}
		differs := false
		for _, severity := range v9Severities {
			action, ok := data.ScannerOverrides[assetType][severity]
			if !ok {
				action, ok = data.Actions[severity]
			}
			value := v9BuiltinAdmissionAction(assetType, severity)
			if ok {
				value = action.config()
			}
			effective[severity] = value
			if value != v9BuiltinAdmissionAction(assetType, severity) {
				differs = true
			}
		}
		if differs {
			for _, severity := range v9Severities {
				node, display := v9ActionNode(effective[severity])
				lower := strings.ToLower(severity)
				v9Set(root, node, "admission", assetType, "actions", lower)
				m.moved("data.json", "data.json:actions."+severity, "admission."+assetType+".actions."+lower, display)
			}
		}
		if old, ok := legacy[assetType]; ok {
			m.legacyActionConflicts(assetType, old, effective)
		}
	}

	if data.FirstPartyAllowList != nil {
		byType := map[string][]AdmissionFirstParty{}
		for _, entry := range *data.FirstPartyAllowList {
			byType[entry.TargetType] = append(byType[entry.TargetType], AdmissionFirstParty{
				Name: entry.TargetName, SourcePathContains: entry.SourcePathContains, Reason: entry.Reason,
			})
		}
		for _, assetType := range []string{AdmissionTypeSkill, AdmissionTypeMCP, AdmissionTypePlugin} {
			if v9SameFirstParty(byType[assetType], v9BuiltinFirstParty[assetType]) {
				continue
			}
			list := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
			names := []string{}
			for _, entry := range byType[assetType] {
				paths := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Style: yaml.FlowStyle}
				for _, p := range entry.SourcePathContains {
					paths.Content = append(paths.Content, v9Scalar(p))
				}
				item := v9Mapping("name", v9Scalar(entry.Name), "source_path_contains", paths)
				if entry.Reason != "" {
					item.Content = append(item.Content, v9Scalar("reason"), v9Scalar(entry.Reason))
				}
				list.Content = append(list.Content, item)
				names = append(names, entry.Name)
			}
			v9Set(root, list, "admission", assetType, "first_party_allow_list")
			m.moved("data.json", "data.json:first_party_allow_list", "admission."+assetType+".first_party_allow_list", names)
		}
	} else {
		// An older data.json without the list allowed nothing first party.
		for _, assetType := range []string{AdmissionTypeSkill, AdmissionTypePlugin} {
			v9Set(root, &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Style: yaml.FlowStyle},
				"admission", assetType, "first_party_allow_list")
			m.moved("data.json", "data.json:first_party_allow_list", "admission."+assetType+".first_party_allow_list", []string{})
		}
	}
}

// legacyActionConflicts records a conflict for every severity an operator
// customised in a *_actions key away from what data.json enforced.
func (m *v9Migrator) legacyActionConflicts(assetType string, old, effective map[string]SeverityAction) {
	defaults := map[string]SeverityAction{}
	switch assetType {
	case AdmissionTypeSkill:
		d := DefaultSkillActions()
		defaults = map[string]SeverityAction{"critical": d.Critical, "high": d.High, "medium": d.Medium, "low": d.Low, "info": d.Info}
	case AdmissionTypeMCP:
		d := DefaultMCPActions()
		defaults = map[string]SeverityAction{"critical": d.Critical, "high": d.High, "medium": d.Medium, "low": d.Low, "info": d.Info}
	case AdmissionTypePlugin:
		d := DefaultPluginActions()
		defaults = map[string]SeverityAction{"critical": d.Critical, "high": d.High, "medium": d.Medium, "low": d.Low, "info": d.Info}
	}
	for _, severity := range v9Severities {
		lower := strings.ToLower(severity)
		value, ok := old[lower]
		if !ok || v9NormalAction(value) == v9NormalAction(defaults[lower]) {
			continue
		}
		if v9NormalAction(value) == effective[severity] {
			continue
		}
		m.record.Conflicts = append(m.record.Conflicts, MigrationConflict{
			To:     "admission." + assetType + ".actions." + lower,
			Kept:   "data.json:" + v9ActionString(effective[severity]),
			Lost:   assetType + "_actions." + lower + ":" + v9ActionString(v9NormalAction(value)),
			Reason: "enforcement read data.json; " + assetType + "_actions only filled unknown severities",
		})
	}
}

func v9NormalAction(a SeverityAction) SeverityAction {
	if a.Install == "" {
		a.Install = InstallNone
	}
	if a.File == "" {
		a.File = FileActionNone
	}
	if a.Runtime == "" {
		a.Runtime = RuntimeEnable
	}
	return a
}

func v9ActionString(a SeverityAction) string {
	return fmt.Sprintf("install=%s,file=%s,runtime=%s", a.Install, a.File, a.Runtime)
}

func v9SameFirstParty(a, b []AdmissionFirstParty) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Name != b[i].Name || strings.Join(a[i].SourcePathContains, "\x00") != strings.Join(b[i].SourcePathContains, "\x00") {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// Guardrail thresholds and rule packs

var v9RankNames = map[int]string{4: "CRITICAL", 3: "HIGH", 2: "MEDIUM", 1: "LOW"}

// v9RankOf is the data.json rank of a severity name (0 when unknown).
func v9RankOf(name string) int {
	for rank, n := range v9RankNames {
		if n == name {
			return rank
		}
	}
	return 0
}

// v9PostureRanks are the block and alert ranks of a built-in pack posture
// (the folder-name table the gateway used in v8).
func v9PostureRanks(pack string) (int, int) {
	switch pack {
	case "strict":
		return 2, 1
	case "permissive":
		return 4, 3
	default:
		return 4, 2
	}
}

func (m *v9Migrator) migrateThresholds(root *yaml.Node, data *v9DataJSON) {
	guardrail := v8YAMLMapValue(root, "guardrail")
	if v9AnyThresholdSet(guardrail) {
		m.note("guardrail block_at/alert_at now apply to hook prompts, hook tool calls and the LLM proxy alike")
	}
	if !data.present {
		return
	}
	pack := m.globalPackPosture
	if pack == "" {
		pack = "default"
		if name := yamlScalarValue(v8YAMLMapValue(guardrail, "rule_pack")); name == "strict" || name == "permissive" {
			pack = name
		}
	}
	packBlock, packAlert := v9PostureRanks(pack)
	shippedBlock, shippedAlert := v9PostureRanks("default")
	for _, item := range []struct {
		key     string
		value   *int
		pack    int
		shipped int
	}{
		{"block_at", data.Guardrail.BlockThreshold, packBlock, shippedBlock},
		{"alert_at", data.Guardrail.AlertThreshold, packAlert, shippedAlert},
	} {
		if item.value == nil {
			continue
		}
		if set := strings.ToUpper(strings.TrimSpace(yamlScalarValue(v8YAMLMapValue(guardrail, item.key)))); set != "" {
			// The config value wins (spec 2.2), but in v8 it only governed
			// hook tool calls: a stricter data.json level was the LLM
			// proxy's, and the proxy now follows the config value.
			if lost, ok := v9RankNames[*item.value]; ok && *item.value < v9RankOf(set) {
				m.record.Conflicts = append(m.record.Conflicts, MigrationConflict{
					To: "guardrail." + item.key, Kept: "config:guardrail." + item.key + ":" + set,
					Lost:   "data.json:guardrail." + strings.Replace(item.key, "_at", "_threshold", 1) + ":" + lost,
					Reason: "the stricter data.json level applied to the LLM proxy; guardrail." + item.key + " now applies to the proxy too",
				})
			}
			continue
		}
		if *item.value == item.pack {
			continue
		}
		// v8 hook prompts and tool calls took the pack posture, and only the
		// proxy read data.json. The shipped data.json value was never a
		// choice (selecting a pack left it alone), and a value looser than
		// the pack would weaken the hook paths under one threshold model: in
		// both cases the pack default stays.
		if *item.value == item.shipped {
			m.note("data.json guardrail %s (%s) is the shipped value; the LLM proxy now follows the %s pack default",
				strings.Replace(item.key, "_at", "_threshold", 1), v9RankNames[*item.value], pack)
			continue
		}
		name, ok := v9RankNames[*item.value]
		if !ok {
			m.note("data.json guardrail %s threshold %d has no severity name; the pack default applies", item.key, *item.value)
			continue
		}
		if *item.value > item.pack {
			m.record.Conflicts = append(m.record.Conflicts, MigrationConflict{
				To: "guardrail." + item.key, Kept: "pack-default:" + pack + ":" + v9RankNames[item.pack],
				Lost:   "data.json:guardrail." + strings.Replace(item.key, "_at", "_threshold", 1) + ":" + name,
				Reason: "the pack posture governed hook prompts and tool calls; the looser data.json level only applied to the LLM proxy",
			})
			continue
		}
		v9Set(root, v9Scalar(name), "guardrail", item.key)
		m.moved("data.json", "data.json:guardrail."+strings.Replace(item.key, "_at", "_threshold", 1), "guardrail."+item.key, name)
		guardrail = v8YAMLMapValue(root, "guardrail")
	}
	if level := strings.TrimSpace(data.Guardrail.CiscoTrustLevel); level != "" && level != "full" {
		v9Set(root, v9Scalar(level), "guardrail", "cisco_trust_level")
		m.moved("data.json", "data.json:guardrail.cisco_trust_level", "guardrail.cisco_trust_level", level)
	}
	for _, key := range []string{"hilt", "patterns", "severity_mappings", "severity_rank"} {
		var g map[string]json.RawMessage
		if json.Unmarshal(data.raw["guardrail"], &g) == nil {
			if _, ok := g[key]; ok {
				m.record.Removed = append(m.record.Removed, "data.json:guardrail."+key)
			}
		}
	}
}

func v9AnyThresholdSet(guardrail *yaml.Node) bool {
	set := func(scope *yaml.Node) bool {
		return strings.TrimSpace(yamlScalarValue(v8YAMLMapValue(scope, "block_at"))) != "" ||
			strings.TrimSpace(yamlScalarValue(v8YAMLMapValue(scope, "alert_at"))) != ""
	}
	if guardrail == nil {
		return false
	}
	if set(guardrail) {
		return true
	}
	for _, scope := range v9ChildMappings(v8YAMLMapValue(guardrail, "connectors")) {
		if set(scope.node) {
			return true
		}
	}
	for _, profile := range v9ChildMappings(v8YAMLMapValue(guardrail, "profiles")) {
		if set(profile.node) {
			return true
		}
		for _, scope := range v9ChildMappings(v8YAMLMapValue(profile.node, "connectors")) {
			if set(scope.node) {
				return true
			}
		}
	}
	return false
}

type v9NamedNode struct {
	name string
	node *yaml.Node
}

func v9ChildMappings(m *yaml.Node) []v9NamedNode {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	var out []v9NamedNode
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i+1].Kind == yaml.MappingNode {
			out = append(out, v9NamedNode{m.Content[i].Value, m.Content[i+1]})
		}
	}
	return out
}

var (
	v9BuiltinPacks   = map[string]bool{"default": true, "strict": true, "permissive": true}
	v9PackNameUnsafe = regexp.MustCompile(`[^a-z0-9_-]+`)
)

// migrateRulePacks turns every rule_pack_dir into rule_pack (+ rules and
// custom_packs).
func (m *v9Migrator) migrateRulePacks(root *yaml.Node) error {
	guardrail := v8YAMLMapValue(root, "guardrail")
	if guardrail == nil || guardrail.Kind != yaml.MappingNode {
		return nil
	}
	scopes := []struct {
		path string
		node *yaml.Node
	}{{"guardrail", guardrail}}
	for _, c := range v9ChildMappings(v8YAMLMapValue(guardrail, "connectors")) {
		scopes = append(scopes, struct {
			path string
			node *yaml.Node
		}{"guardrail.connectors." + c.name, c.node})
	}
	for _, p := range v9ChildMappings(v8YAMLMapValue(guardrail, "profiles")) {
		scopes = append(scopes, struct {
			path string
			node *yaml.Node
		}{"guardrail.profiles." + p.name, p.node})
		for _, c := range v9ChildMappings(v8YAMLMapValue(p.node, "connectors")) {
			scopes = append(scopes, struct {
				path string
				node *yaml.Node
			}{"guardrail.profiles." + p.name + ".connectors." + c.name, c.node})
		}
	}
	for _, scope := range scopes {
		node := v9Pop(scope.node, "rule_pack_dir")
		if node == nil {
			continue
		}
		dir := strings.TrimSpace(node.Value)
		if dir == "" {
			m.record.Removed = append(m.record.Removed, scope.path+".rule_pack_dir")
			continue
		}
		name, protections, err := m.rulePackFor(guardrail, dir)
		if err != nil {
			return fmt.Errorf("config: %s.rule_pack_dir: %w", scope.path, err)
		}
		if scope.path == "guardrail" {
			// A custom pack keeps the posture of its folder, which its new
			// name (custom-strict, a stem) no longer shows.
			m.globalPackPosture = v9DirPosture(expandPath(dir))
		}
		v9Set(scope.node, v9Scalar(name), "rule_pack")
		m.moved("config", scope.path+".rule_pack_dir", scope.path+".rule_pack", name)
		if len(protections) > 0 {
			list := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Style: yaml.FlowStyle}
			for _, p := range protections {
				list.Content = append(list.Content, v9Scalar(p))
			}
			v9Set(scope.node, list, "rules", "protections")
			m.moved("config", scope.path+".rule_pack_dir", scope.path+".rules.protections", protections)
		}
	}
	return nil
}

// v9DirPosture is the posture the gateway gives a rule-pack directory: the
// manifest posture (defenseclaw-pack.json, guardrail.ReadPackPosture), else
// the folder-name table (strict, permissive, else default).
func v9DirPosture(dir string) string {
	if raw, err := os.ReadFile(filepath.Join(dir, "defenseclaw-pack.json")); err == nil && len(raw) <= 1<<20 {
		var manifest struct {
			Posture string `json:"posture"`
		}
		if json.Unmarshal(raw, &manifest) == nil {
			switch posture := strings.ToLower(strings.TrimSpace(manifest.Posture)); posture {
			case "default", "strict", "permissive":
				return posture
			}
		}
	}
	switch base := strings.ToLower(filepath.Base(filepath.Clean(dir))); base {
	case "strict", "permissive":
		return base
	}
	return "default"
}

// policyDir is the policy_dir the v9 preset names resolve under.
func (m *v9Migrator) policyDir() string {
	if dir := strings.TrimSpace(m.in.PolicyDir); dir != "" {
		return dir
	}
	if dj := strings.TrimSpace(m.in.DataJSONPath); dj != "" {
		return filepath.Dir(filepath.Dir(dj))
	}
	if dir := strings.TrimSpace(yamlScalarValue(v8YAMLMapValue(m.root, "policy_dir"))); dir != "" {
		return dir
	}
	return filepath.Join(m.dataDir(), "policies")
}

func v9SameDir(a, b string) bool {
	a, b = filepath.Clean(expandPath(a)), filepath.Clean(expandPath(b))
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

func (m *v9Migrator) rulePackFor(guardrail *yaml.Node, dir string) (string, []string, error) {
	clean := filepath.Clean(dir)
	base := strings.ToLower(filepath.Base(clean))
	parent := filepath.Base(filepath.Dir(clean))
	if base == "balanced" {
		base = "default"
	}
	if v9BuiltinPacks[base] && v9SameDir(clean, filepath.Join(m.policyDir(), "guardrail", filepath.Base(clean))) {
		return base, nil, nil
	}
	if strings.HasPrefix(parent, "protected-") && v9BuiltinPacks[base] {
		var manifest struct {
			Protection []string `json:"protection"`
		}
		raw, err := os.ReadFile(filepath.Join(clean, "defenseclaw-pack.json"))
		if err == nil && json.Unmarshal(raw, &manifest) == nil {
			return base, manifest.Protection, nil
		}
		m.note("%s has no readable defenseclaw-pack.json; migrated as the %s pack without its protections", dir, base)
		return base, nil, nil
	}
	if m.in.RulePackDigest == nil {
		return "", nil, fmt.Errorf("custom rule pack %s needs a digest; run `defenseclaw-gateway config migrate`", dir)
	}
	digest, err := m.in.RulePackDigest(clean)
	if err != nil {
		return "", nil, fmt.Errorf("load custom rule pack %s: %w", dir, err)
	}
	stem := strings.Trim(v9PackNameUnsafe.ReplaceAllString(base, "-"), "-_")
	if stem == "" || v9BuiltinPacks[stem] {
		stem = strings.TrimRight("custom-"+stem, "-")
	}
	if len(stem) > 60 {
		stem = stem[:60]
	}
	packs := v8YAMLMapValue(guardrail, "custom_packs")
	name := stem
	for suffix := 2; ; suffix++ {
		existing := v8YAMLMapValue(packs, name)
		if existing == nil || yamlScalarValue(v8YAMLMapValue(existing, "path")) == clean {
			break
		}
		name = fmt.Sprintf("%s-%d", stem, suffix)
	}
	if v8YAMLMapValue(packs, name) == nil {
		v9Set(guardrail, v9Mapping("path", v9Scalar(clean), "digest", v9Scalar("sha256:"+digest)), "custom_packs", name)
		m.moved("config", "rule_pack_dir", "guardrail.custom_packs."+name, map[string]string{"path": clean, "digest": "sha256:" + digest})
	}
	return name, nil, nil
}

// ---------------------------------------------------------------------------
// Scanners

var v9SkillPolicies = map[string]bool{"strict": true, "balanced": true, "permissive": true, "low-noise": true, "quiet": true}

func (m *v9Migrator) migrateScanners(root *yaml.Node) error {
	scanners := v8YAMLMapValue(root, "scanners")
	skill := v8YAMLMapValue(scanners, "skill_scanner")
	if skill == nil || skill.Kind != yaml.MappingNode {
		v9Set(root, v9Scalar("quiet"), "scanners", "skill_scanner", "policy")
		m.moved("config", "scanners.skill_scanner.policy", "scanners.skill_scanner.policy", "quiet")
	} else if err := m.migrateSkillScanner(skill); err != nil {
		return err
	}
	if mcp := v8YAMLMapValue(v8YAMLMapValue(root, "scanners"), "mcp_scanner"); mcp != nil && mcp.Kind == yaml.MappingNode {
		if v9Pop(mcp, "binary") != nil {
			m.record.Removed = append(m.record.Removed, "scanners.mcp_scanner.binary")
		}
		if node := v8YAMLMapValue(mcp, "analyzers"); node != nil && node.Kind == yaml.ScalarNode {
			list := v9MCPAnalyzers(strings.Split(node.Value, ","))
			seq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Style: yaml.FlowStyle}
			for _, a := range list {
				seq.Content = append(seq.Content, v9Scalar(a))
			}
			v9Set(mcp, seq, "analyzers")
			m.moved("config", "scanners.mcp_scanner.analyzers", "scanners.mcp_scanner.analyzers", list)
		} else if node != nil && node.Kind == yaml.SequenceNode {
			var items []string
			if node.Decode(&items) == nil {
				list := v9MCPAnalyzers(items)
				if strings.Join(list, ",") != strings.Join(items, ",") {
					seq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Style: yaml.FlowStyle}
					for _, a := range list {
						seq.Content = append(seq.Content, v9Scalar(a))
					}
					v9Set(mcp, seq, "analyzers")
					m.moved("config", "scanners.mcp_scanner.analyzers", "scanners.mcp_scanner.analyzers", list)
				}
			}
		}
		if v9NonEmptyLLM(v8YAMLMapValue(mcp, "llm")) && v8YAMLMapValue(mcp, "judge_source") == nil {
			v9Set(mcp, v9Scalar(ScannerJudgeOverride), "judge_source")
			m.moved("config", "scanners.mcp_scanner.llm", "scanners.mcp_scanner.judge_source", ScannerJudgeOverride)
		}
	}
	return nil
}

// v9MCPAnalyzers turns the v8 CSV (or a list) into the v9 list: "auto" or
// empty alone is [] (auto), and "auto" inside a list - which the setup
// wizard produced and which dropped YARA - becomes yara plus the rest.
// v9MCPScannerAnalyzers are the analyzers the pinned mcp-scanner has
// (schema $defs.mcpScannerAnalyzer).
var v9MCPScannerAnalyzers = map[string]bool{"api": true, "yara": true, "llm": true, "behavioral": true, "readiness": true}

// v9MCPAnalyzers is the v9 list of a v8 analyzers value; a name the pinned
// mcp-scanner does not have is dropped (it ignored it at scan time).
func v9MCPAnalyzers(items []string) []string {
	out := []string{}
	seen := map[string]bool{}
	hasAuto := false
	for _, item := range items {
		item = strings.ToLower(strings.TrimSpace(item))
		switch {
		case item == "":
		case item == "auto":
			hasAuto = true
		case !v9MCPScannerAnalyzers[item]:
		case !seen[item]:
			seen[item] = true
			out = append(out, item)
		}
	}
	if hasAuto && len(out) > 0 && !seen["yara"] {
		out = append([]string{"yara"}, out...)
	}
	return out
}

func (m *v9Migrator) migrateSkillScanner(skill *yaml.Node) error {
	const prefix = "scanners.skill_scanner."
	if v9Pop(skill, "binary") != nil {
		m.record.Removed = append(m.record.Removed, prefix+"binary")
	}
	policy := strings.TrimSpace(yamlScalarValue(v8YAMLMapValue(skill, "policy")))
	switch {
	case policy == "":
		v9Set(skill, v9Scalar("quiet"), "policy")
		m.moved("config", prefix+"policy", prefix+"policy", "quiet")
	case v9SkillPolicies[policy] || policy == "custom":
	default:
		raw, err := os.ReadFile(policy)
		if err != nil {
			v9Set(skill, v9Scalar("quiet"), "policy")
			m.record.Conflicts = append(m.record.Conflicts, MigrationConflict{
				To: prefix + "policy", Kept: "quiet", Lost: policy,
				Reason: "the policy file could not be read, so it could not be pinned by digest",
			})
			break
		}
		v9Set(skill, v9Scalar("custom"), "policy")
		ref := v9Mapping("path", v9Scalar(policy), "digest", v9Scalar("sha256:"+cfgtxn.SHA256Hex(raw)))
		v9Set(skill, ref, "policy_file")
		m.moved("config", prefix+"policy", prefix+"policy_file", map[string]string{"path": policy})
	}
	useVT := v9Pop(skill, "use_virustotal")
	keyEnv := v9Pop(skill, "virustotal_api_key_env")
	inlineKey := v9Pop(skill, "virustotal_api_key")
	envName := strings.TrimSpace(yamlScalarValue(keyEnv))
	if inline := strings.TrimSpace(yamlScalarValue(inlineKey)); inline != "" {
		if envName == "" {
			envName = "VIRUSTOTAL_API_KEY"
		}
		m.envKey, m.envValue = envName, inline
		m.moved("config", prefix+"virustotal_api_key", ".env:"+envName, "<redacted>")
	} else if inlineKey != nil {
		m.record.Removed = append(m.record.Removed, prefix+"virustotal_api_key")
	}
	var enabled bool
	if useVT != nil && useVT.Decode(&enabled) == nil && enabled {
		v9Set(skill, v9Scalar(true), "analyzers", "virustotal", "enabled")
		m.moved("config", prefix+"use_virustotal", prefix+"analyzers.virustotal.enabled", true)
	} else if useVT != nil {
		m.record.Removed = append(m.record.Removed, prefix+"use_virustotal")
	}
	if envName != "" && (enabled || m.envKey != "") {
		v9Set(skill, v9Scalar(envName), "analyzers", "virustotal", "api_key_env")
		m.moved("config", prefix+"virustotal_api_key_env", prefix+"analyzers.virustotal.api_key_env", envName)
	} else if keyEnv != nil {
		m.record.Removed = append(m.record.Removed, prefix+"virustotal_api_key_env")
	}
	if node := v9Pop(skill, "use_aidefense"); node != nil {
		var aid bool
		if node.Decode(&aid) == nil && aid {
			v9Set(skill, v9Scalar(true), "analyzers", "aidefense", "enabled")
			m.moved("config", prefix+"use_aidefense", prefix+"analyzers.aidefense.enabled", true)
		} else {
			m.record.Removed = append(m.record.Removed, prefix+"use_aidefense")
		}
	}
	if v9NonEmptyLLM(v8YAMLMapValue(skill, "llm")) && v8YAMLMapValue(skill, "judge_source") == nil {
		v9Set(skill, v9Scalar(ScannerJudgeOverride), "judge_source")
		m.moved("config", prefix+"llm", prefix+"judge_source", ScannerJudgeOverride)
	}
	return nil
}

func v9NonEmptyLLM(node *yaml.Node) bool {
	if node == nil || node.Kind != yaml.MappingNode {
		return false
	}
	var plain map[string]any
	if node.Decode(&plain) != nil {
		return false
	}
	for _, value := range plain {
		switch v := value.(type) {
		case nil:
		case string:
			if strings.TrimSpace(v) != "" {
				return true
			}
		case int:
			if v != 0 {
				return true
			}
		case bool:
			if v {
				return true
			}
		case map[string]any:
			if len(v) > 0 {
				return true
			}
		default:
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// AI discovery signature packs

// migrateSignaturePacks lists the packs installed under
// <data_dir>/signature-packs in ai_discovery.signature_packs: v8 loaded that
// folder implicitly, and since 9 only configured packs load.
func (m *v9Migrator) migrateSignaturePacks(root *yaml.Node) {
	dataDir := m.dataDir()
	installed, _ := filepath.Glob(filepath.Join(dataDir, "signature-packs", "*.json"))
	if len(installed) == 0 {
		return
	}
	discovery := v8YAMLMapValue(root, "ai_discovery")
	listed := map[string]bool{}
	packs := v8YAMLMapValue(discovery, "signature_packs")
	for _, item := range v9SeqItems(packs) {
		listed[filepath.Clean(expandPath(item.Value))] = true
	}
	var added []string
	for _, path := range installed {
		if !listed[filepath.Clean(path)] {
			added = append(added, path)
		}
	}
	if len(added) == 0 {
		return
	}
	if packs == nil || packs.Kind != yaml.SequenceNode {
		packs = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		v9Set(root, packs, "ai_discovery", "signature_packs")
	}
	for _, path := range added {
		packs.Content = append(packs.Content, v9Scalar(path))
	}
	m.moved("config", filepath.Join(dataDir, "signature-packs", "*.json"), "ai_discovery.signature_packs", added)
}

// ---------------------------------------------------------------------------
// audit.db actions rows

type v9ActionRow struct {
	id, targetType, targetName, sourcePath, reason, connector string
	state                                                     map[string]string
}

func (m *v9Migrator) migrateActionsRows(root *yaml.Node) error {
	path := strings.TrimSpace(m.in.AuditDBPath)
	if path == "" {
		return nil
	}
	if _, err := os.Stat(path); err != nil {
		return nil
	}
	// A Secure Client gateway keeps reading operator rows from the table
	// (PolicyEngine.legacyOperatorRows), so they stay there untouched.
	if v9SecureClientDocument(root) {
		m.note("Secure Client host: the operator block/allow entries in audit.db stay in place")
		return nil
	}
	rows, err := readV9ActionRows(path)
	if err != nil && m.in.Managed {
		// A managed host never moves the rows, it only counts them, so an
		// unreadable audit.db does not stop the admin config.
		m.note("%s: could not count the local block/allow entries in %s (%v); the admin config is the policy",
			LocalEnforcementEntriesIgnored, path, err)
		return nil
	}
	if err != nil {
		return fmt.Errorf("config: read operator rows from %s: %w", path, err)
	}
	if m.in.Managed {
		m.record.ActionsRowsIgnored = len(rows)
		if len(rows) > 0 {
			m.note("%s: %d local block/allow entries in audit.db are ignored; the admin config is the policy",
				LocalEnforcementEntriesIgnored, len(rows))
		}
		return nil
	}
	for _, row := range rows {
		list := "denied"
		if row.state["install"] == "allow" {
			list = "allowed"
		}
		if !m.appendAssetRule(root, row, list) {
			m.note("audit.db row %s (%s) has an unknown type and stays in the table", row.id, row.targetType)
			continue
		}
		m.rows = append(m.rows, row)
	}
	m.record.ActionsRowsMoved = len(m.rows)
	return nil
}

// v9SecureClientDocument reports whether the document is a managed
// deployment on the Secure Client profile (pinned or configured).
func v9SecureClientDocument(root *yaml.Node) bool {
	mode := normalizeDeploymentMode(yamlScalarValue(v8YAMLMapValue(root, "deployment_mode")))
	if env := strings.TrimSpace(os.Getenv(managed.DeploymentModeEnv)); env != "" {
		mode = normalizeDeploymentMode(env)
	}
	if !managed.IsManagedEnterprise(mode) {
		return false
	}
	declared := yamlScalarValue(v8YAMLMapValue(v8YAMLMapValue(root, "enterprise"), "profile"))
	profile, err := managed.ResolveEnterpriseProfile(runtime.GOOS, mode, os.Getenv(managed.EnterpriseProfileEnv), declared)
	if err != nil {
		// An unresolvable pin is never treated as permission to move rows.
		return !managed.IsStandaloneProfile(managed.NormalizeEnterpriseProfile(declared))
	}
	return managed.IsSecureClientProfile(profile)
}

func (m *v9Migrator) appendAssetRule(root *yaml.Node, row v9ActionRow, list string) bool {
	name, connector := row.targetName, row.connector
	switch row.targetType {
	case AdmissionTypeSkill, AdmissionTypeMCP, AdmissionTypePlugin:
	case AdmissionTypeTool:
		if strings.HasPrefix(name, "@") {
			if conn, tool, ok := strings.Cut(name[1:], "/"); ok {
				connector, name = conn, tool
			}
		} else if i := strings.LastIndex(name, "/"); i >= 0 {
			// <source>/<tool>: the source was audit-only.
			name = name[i+1:]
		}
	default:
		return false
	}
	target := v8YAMLMapValue(v8YAMLMapValue(v8YAMLMapValue(root, "asset_policy"), row.targetType), list)
	for _, existing := range v9SeqItems(target) {
		if yamlScalarValue(v8YAMLMapValue(existing, "name")) == name &&
			yamlScalarValue(v8YAMLMapValue(existing, "connector")) == connector {
			m.moved("audit.db", "actions:"+row.id, "asset_policy."+row.targetType+"."+list, name)
			return true
		}
	}
	item := v9Mapping("name", v9Scalar(name))
	if connector != "" {
		item.Content = append(item.Content, v9Scalar("connector"), v9Scalar(connector))
	}
	if row.reason != "" {
		item.Content = append(item.Content, v9Scalar("reason"), v9Scalar(row.reason))
	}
	// v8 pinned allows to their source_path (admission.rego
	// _allow_entry_path_matches) but matched blocks by name and type only,
	// and the CLI recorded the resolved copy's path on a global block. A
	// pinned deny would stop matching other copies and name-only checks.
	if list == "allowed" && row.sourcePath != "" && row.targetType != AdmissionTypeTool {
		paths := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Style: yaml.FlowStyle}
		paths.Content = append(paths.Content, v9Scalar(row.sourcePath))
		item.Content = append(item.Content, v9Scalar("source_path_contains"), paths)
	}
	if target == nil || target.Kind != yaml.SequenceNode {
		target = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		v9Set(root, target, "asset_policy", row.targetType, list)
	}
	target.Content = append(target.Content, item)
	m.moved("audit.db", "actions:"+row.id, "asset_policy."+row.targetType+"."+list, name)
	return true
}

// ---------------------------------------------------------------------------
// YAML node helpers

func v9SeqItems(node *yaml.Node) []*yaml.Node {
	if node == nil || node.Kind != yaml.SequenceNode {
		return nil
	}
	return node.Content
}

func v9Scalar(value any) *yaml.Node {
	var node yaml.Node
	_ = node.Encode(value)
	return &node
}

func v9Mapping(pairs ...any) *yaml.Node {
	node := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	for i := 0; i+1 < len(pairs); i += 2 {
		node.Content = append(node.Content, v9Scalar(pairs[i].(string)), pairs[i+1].(*yaml.Node))
	}
	return node
}

// v9Set sets keys under m, creating mappings (a null value becomes a
// mapping) and replacing the leaf.
func v9Set(m *yaml.Node, value *yaml.Node, keys ...string) {
	cur := m
	for i, key := range keys {
		last := i == len(keys)-1
		var found *yaml.Node
		for j := 0; j+1 < len(cur.Content); j += 2 {
			if cur.Content[j].Value == key {
				if last {
					value.HeadComment, value.LineComment = cur.Content[j+1].HeadComment, cur.Content[j+1].LineComment
					cur.Content[j+1] = value
					return
				}
				found = cur.Content[j+1]
				break
			}
		}
		if found == nil {
			if last {
				cur.Content = append(cur.Content, v9Scalar(key), value)
				return
			}
			found = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			cur.Content = append(cur.Content, v9Scalar(key), found)
		}
		if found.Kind != yaml.MappingNode {
			*found = yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		}
		cur = found
	}
}

// v9Pop removes key from mapping m and returns its value, or nil.
func v9Pop(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			value := m.Content[i+1]
			// A comment above the removed key stays with the next key.
			if comment := m.Content[i].HeadComment; comment != "" && i+2 < len(m.Content) {
				next := m.Content[i+2]
				next.HeadComment = strings.TrimSpace(comment + "\n" + next.HeadComment)
			}
			m.Content = append(m.Content[:i], m.Content[i+2:]...)
			return value
		}
	}
	return nil
}
