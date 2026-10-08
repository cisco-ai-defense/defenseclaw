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
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/open-policy-agent/opa/ast"
	"golang.org/x/text/unicode/norm"
	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/config/internal/cfgtxn"
	"github.com/defenseclaw/defenseclaw/internal/configs"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/policies"
)

// The v8 to v9 migration moves admin intent into config.yaml: data.json
// admission and guardrail values, the *_actions keys,
// watch.allow_list_bypass_scan, rule_pack_dir, the v8 scanner keys,
// update_check, the reserved privacy: section and (OSS only) the operator
// block/allow rows of audit.db and a legacy custom-providers.json overlay.
// The runtime Config has no field for any of those keys; the migration reads
// them from the raw YAML.
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
	// RulePackDigest returns the hex pin digest of a rule-pack directory
	// (guardrail.RulePackDigest: the pack's own files). The config
	// package can not import the guardrail package, so callers that may meet
	// a custom rule_pack_dir pass it; without it such a directory is a
	// migration error.
	RulePackDigest func(dir string) (string, error)
	// RebaseRulePack plans the 1.0 copy of a custom rule-pack directory whose
	// action rule files are 0.8.x copies of the default pack's, which enforce
	// nothing in 1.0 (guardrail.PlanRulePackRebase); a nil plan needs none.
	// Without it such a pack is pinned as it is (GAP-0360).
	RebaseRulePack func(dir string) (*RulePackRebasePlan, error)
}

// RulePackRebasePlan is guardrail.RulePackRebase, which this package can not
// import: the rebased pack's files and FilesDigest, and what changed.
type RulePackRebasePlan struct {
	Files                                   map[string][]byte
	Digest                                  string
	Updated                                 int
	Carried, Expressed, AlertOnly, Disabled []string
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
	// Pending is true until the v9 config commit succeeds. A retry can
	// finish a record left pending by an interruption after the commit.
	Pending bool `json:"pending,omitempty"`
	// Acknowledged is set by `defenseclaw config migrate --ack`.
	Acknowledged bool `json:"acknowledged,omitempty"`
}

// MigrationMove is one value moved from a v8 source to a v9 key.
type MigrationMove struct {
	// Source is "config", "data.json", "audit.db" or "custom-providers.json".
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
		if record, ok := readMigrationRecord(abs); ok && record.Pending &&
			strings.EqualFold(record.ResultSHA256, cfgtxn.SHA256Hex(source)) {
			record.Pending = false
			if !in.DryRun && !in.InMemory {
				recordPath := MigrationRecordPath(abs)
				if err := writeMigrationRecord(recordPath, record); err != nil {
					return result, err
				}
				result.Written = append(result.Written, recordPath)
			}
			result.Record = record
		}
		return result, nil
	}
	if err := ValidateCandidate(abs, migrated); err != nil {
		return nil, fmt.Errorf("config: the migrated config_version 9 document does not validate: %w", err)
	}
	// A rebased pack is written only during commit; its digest cannot be
	// checked on disk during the dry run. Other referenced assets already
	// exist and can be checked before either a preview or a commit.
	if len(m.rebasedPacks) == 0 {
		if err := ValidateCandidateAssets(abs, migrated); err != nil {
			return nil, fmt.Errorf("config: the migrated config_version 9 assets do not validate: %w", err)
		}
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
	return decodeSourceYAML(raw, &doc) == nil && doc.ConfigVersion == ObservabilityV8ConfigVersion
}

// MigrateV8InMemory is the gateway's read-only load of a config_version 8
// file (spec 2.0): it returns the config_version 9 bytes the migration would
// write, so the data.json admission and thresholds, the *_actions keys and,
// on a per-user install, the operator rows of audit.db keep applying until
// the file is migrated. Nothing is written. raw comes back unchanged for a
// config_version 9 file and on a Secure Client host, whose path does not
// change; on a migration error it comes back unchanged with the error, and
// the caller refuses the file (InMemoryMigrationError).
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

// InMemoryMigrationError is the load error for a config_version 8 file whose
// in-memory migration failed. The file is refused rather than run as v8:
// from config_version 9 on enforcement reads admission and the block/allow
// lists only from config, so a raw v8 document would silently drop its
// data.json admission policy and its audit.db block/allow entries.
func InMemoryMigrationError(configFile string, err error) error {
	return fmt.Errorf("config: %s is config_version 8 and its config_version 9 migration failed, so it is not loaded (its admission and block/allow policy would not apply): %w; fix the cause, then run `defenseclaw migrate`", configFile, err)
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
	return ok && !record.Pending && strings.EqualFold(record.SourceSHA256, sourceSHA256)
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
	rows              []v9ActionRow
	auditRowsSnapshot []v9ActionRow
	auditRowsRead     bool
	// envKey is an inline scanner key moved to .env on commit.
	envKey, envValue string
	// rego are the pre-9 Rego modules under <policy_dir>/rego that commit
	// replaces with the shipped module (nil data retires the file).
	rego []v9RegoRefresh
	// providersOverlay is the legacy custom-providers.json folded into
	// llm_providers; commit writes providerCAs and retires the file.
	providersOverlay string
	providerCAs      []v9RegoRefresh
	// retired are the unmodified 0.8 copies of retired policy files that
	// commit removes.
	retired []string
	// seedPacks maps a missing rule-pack folder to the shipped pack commit
	// writes there (planShippedPacks).
	seedPacks map[string]string
	// rebasedPacks maps a new rule-pack folder to the files commit writes
	// there, and rebasedFrom a custom pack folder to its rebased copy.
	rebasedPacks   map[string]map[string][]byte
	rebasedFrom    map[string]string
	rebasedDigests map[string]string
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
	if err := m.migrateSignaturePacks(root); err != nil {
		return nil, false, err
	}
	if node := v9Pop(root, "update_check"); node != nil {
		var check bool
		if node.Decode(&check) == nil {
			v9Set(root, v9Scalar(check), "update", "check")
			m.moved("config", "update_check", "update.check", check)
		}
	}
	m.migrateTelemetryAliases(root)
	m.migratePrivacy(root)
	m.migrateRegistrySources(root)
	if err := m.migrateActionsRows(root); err != nil {
		return nil, false, err
	}
	m.migrateCustomProviders(root)
	if err := m.planRegoRefresh(); err != nil {
		return nil, false, err
	}
	// A Secure Client policy folder is the deployment's, not the user's.
	if !v9SecureClientDocument(root) {
		m.planRetiredPolicyFiles()
		m.planShippedPacks()
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
// config (generation +1), the record, the data.json rename (not on a
// managed host), the inline key move and finally the audit.db rows.
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
	// Reserve audit.db before writing config so a changed operator decision
	// cannot be committed from a stale snapshot.
	var auditDB *sql.DB
	if m.auditRowsRead && !m.in.Managed {
		auditDB, err = lockV9ActionRows(ctx, m.in.AuditDBPath, m.auditRowsSnapshot)
		if err != nil {
			return nil, fmt.Errorf("config: %w", err)
		}
		defer auditDB.Close()
		defer func() { _, _ = auditDB.Exec("ROLLBACK") }()
	}
	var written []string
	// config.yaml.v8.bak is written once: it holds the config the first
	// migration replaced, the 0.8.x file a rollback restores. A later
	// config_version 8 source (a v9 file relabelled 8 by hand, which no key
	// test can tell from a 0.8.x file, or a 0.8.x file edited after a
	// rollback) is saved next to it instead (GAP-0307, GAP-0544).
	backup := m.configPath + ConfigV8BackupSuffix
	earlier, err := os.ReadFile(backup)
	switch {
	case err == nil && bytes.Equal(earlier, source):
	case err == nil:
		kept := freeSiblingPath(backup + "." + migrationStamp())
		if err := cfgtxn.WriteFileDurable(kept, source, mode); err != nil {
			return written, err
		}
		written = append(written, kept)
		m.note("%s keeps the config the first config_version 9 migration replaced; this migration's "+
			"config_version 8 source is saved as %s", backup, kept)
	case errors.Is(err, fs.ErrNotExist):
		if err := cfgtxn.WriteFileDurable(backup, source, mode); err != nil {
			return written, err
		}
		written = append(written, backup)
	default:
		return written, fmt.Errorf("config: read %s: %w", backup, err)
	}
	// Before the config that pins them.
	for _, dir := range slices.Sorted(maps.Keys(m.rebasedPacks)) {
		if err := writeRebasedRulePack(dir, m.rebasedPacks[dir]); err != nil {
			return written, fmt.Errorf("config: write the rebased rule pack %s: %w", dir, err)
		}
		written = append(written, dir)
	}
	// A committed v9 config can reference these packs immediately. Install
	// every missing shipped pack first, and leave v8 available if any fails.
	for _, dir := range slices.Sorted(maps.Keys(m.seedPacks)) {
		if err := seedShippedRulePack(dir, m.seedPacks[dir]); err != nil {
			return written, fmt.Errorf("config: seed the shipped %s rule pack at %s: %w", m.seedPacks[dir], dir, err)
		}
		written = append(written, dir)
	}
	if m.envKey != "" {
		envPath := filepath.Join(m.dataDir(), ".env")
		if err := appendDotEnvKey(envPath, m.envKey, m.envValue); err != nil {
			return written, fmt.Errorf("config: move the inline scanner key to %s: %w", envPath, err)
		}
		written = append(written, envPath)
	}
	// Provider CA files and the evidence record must exist before the
	// committed config can reference them. An obstructed record path then
	// leaves the v8 config available for a retry.
	if err := m.writeProviderCAs(&written); err != nil {
		return written, err
	}
	recordPath := MigrationRecordPath(m.configPath)
	// The record of an earlier migration is kept next to the new one: it
	// lists what the 0.8.x upgrade moved, which a later run cannot know. A
	// record this source left pending (an interrupted run) is replaced.
	if earlier, err := os.ReadFile(recordPath); err == nil {
		var previous MigrationRecord
		retry := json.Unmarshal(earlier, &previous) == nil && previous.Pending &&
			strings.EqualFold(previous.SourceSHA256, m.record.SourceSHA256)
		if !retry {
			kept := freeSiblingPath(strings.TrimSuffix(recordPath, ".json") + "." + migrationStamp() + ".json")
			if err := cfgtxn.WriteFileDurable(kept, earlier, 0o600); err != nil {
				return written, err
			}
			written = append(written, kept)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return written, fmt.Errorf("config: read %s: %w", recordPath, err)
	}
	m.record.Pending = true
	if err := writeMigrationRecord(recordPath, m.record); err != nil {
		return written, err
	}
	written = append(written, recordPath)
	if _, err := txn.Commit(migrated, mode, m.record.Actor, "config_version 9 migration"); err != nil {
		return written, err
	}
	written = append(written, m.configPath)
	// On a managed host the admin owns policy_dir (as planRegoRefresh
	// reports): its data.json stays, so a rollback to the v8 config finds it.
	// A file outside the data home stays too: the installer's rollback copy
	// does not cover it, so renaming it would leave a rolled-back 1.0.0 gateway
	// without its policy data (see leftOutsideRollbackCopy).
	if dj := strings.TrimSpace(m.in.DataJSONPath); dj != "" && !m.in.Managed && !m.leftOutsideRollbackCopy(dj) {
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
	if m.providersOverlay != "" && !m.leftOutsideRollbackCopy(m.providersOverlay) {
		m.retireProvidersOverlay(&written)
	}
	for _, path := range m.retired {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			m.note("could not remove the retired policy file %s: %v; nothing reads it", path, err)
		}
	}
	// Rows are cleared only after the config commit, so a failure leaves
	// them enforcing from the table and recorded in config: never lost.
	if len(m.rows) > 0 && !m.leftOutsideRollbackCopy(m.in.AuditDBPath) {
		if err := clearV9ActionRowsDB(auditDB, m.rows); err != nil {
			return written, fmt.Errorf("config: clean up migrated audit.db rows: %w", err)
		}
	}
	if auditDB != nil {
		if _, err := auditDB.Exec("COMMIT"); err != nil {
			return written, fmt.Errorf("config: commit audit.db cleanup: %w", err)
		}
	}
	// Mark the record committed and refresh notes from post-commit cleanup.
	m.record.Pending = false
	if err := writeMigrationRecord(recordPath, m.record); err != nil {
		return written, err
	}
	return written, nil
}

// migrationStamp names the copies a migration keeps beside an earlier one's
// files (UTC, second resolution).
func migrationStamp() string {
	return time.Now().UTC().Format("20060102T150405Z")
}

// freeSiblingPath is path, or path with the first free ".N" suffix.
func freeSiblingPath(path string) string {
	candidate := path
	for n := 2; ; n++ {
		if _, err := os.Lstat(candidate); errors.Is(err, fs.ErrNotExist) {
			return candidate
		}
		candidate = fmt.Sprintf("%s.%d", path, n)
	}
}

// leftOutsideRollbackCopy reports whether the migration must leave path as it is. The
// installer saves a rollback copy of the data home only (the directory holding
// config.yaml, and DEFENSECLAW_HOME), so a failed upgrade or `defenseclaw
// rollback` puts config.yaml back but not a data.json, Rego module,
// custom-providers.json or audit.db that policy_dir, data_dir or
// observability.local.path place elsewhere. Those stay as they are (their
// content is already in config.yaml, and a 1.0 gateway still finds them) and a
// note says so. Managed hosts follow the lifecycle's own rollback and are
// not affected.
func (m *v9Migrator) leftOutsideRollbackCopy(path string) bool {
	path = strings.TrimSpace(path)
	if path == "" || m.in.Managed {
		return false
	}
	for _, home := range []string{filepath.Dir(m.configPath), DefaultDataPath()} {
		if rel, err := filepath.Rel(home, path); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return false
		}
	}
	m.note("%s is outside the data home, so the upgrade's rollback copy does not cover it; it was left as it is", path)
	return true
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

// v9RegoReadsLegacyData inspects references in parsed rules, not comments or
// string literals. A custom module that only mentions a v8 key in prose must
// keep its active enforcement rules.
func v9RegoReadsLegacyData(name string, raw []byte) (bool, error) {
	mod, err := ast.ParseModuleWithOpts(name, string(raw), ast.ParserOptions{RegoVersion: ast.RegoV1})
	if err != nil {
		return false, err
	}
	legacy := false
	ast.WalkRefs(mod, func(ref ast.Ref) bool {
		if len(ref) < 2 || !ref[0].Equal(ast.DefaultRootDocument) {
			return false
		}
		key, ok := ref[1].Value.(ast.String)
		if ok && v9LegacyRegoData.MatchString("data."+string(key)) {
			legacy = true
		}
		return legacy
	})
	return legacy, nil
}

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
		if err != nil {
			continue
		}
		legacy, parseErr := v9RegoReadsLegacyData(name, raw)
		if parseErr != nil {
			m.note("%s could not be parsed to check its data references (%v); it was left in place", path, parseErr)
			continue
		}
		if !legacy {
			continue
		}
		if m.in.Managed || m.leftOutsideRollbackCopy(path) {
			m.note("%s is a pre-9 module that reads data.json; the gateway refuses it and uses the config-driven "+
				"admission and thresholds until it is replaced with the shipped module", path)
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

// v9RetiredPolicyFiles are the policy files 0.8.x could leave under
// <policy_dir>/rego that 1.0 no longer ships: the firewall and audit Rego
// modules (seeded by init) and the data file the firewall dry runs read
// (never seeded by the wheel, but carried by source installs). Every release
// from 0.5.0 to 0.8.10 carried them byte for byte (SHA-256 below), so a copy
// that still matches was never edited. Remove this table with the v8 to v9
// migration (1.1.0).
var v9RetiredPolicyFiles = []struct{ name, sha256 string }{
	{"firewall.rego", "cc51d978cf63b63f5bb0f21c4710019d106e9bcf7f9100536d35525b8d4ce5a5"},
	{"audit.rego", "a40b408b08f976153e5937220efaaeb73460055b3ba10831061b5be55ae2c108"},
	{"data-sandbox.json", "a1cfab935ac600eefb57d027093b6e615f9e7fa2139febebc034d05527ef7cc4"},
}

// planRetiredPolicyFiles removes the unmodified 0.8 copies of the retired
// policy files. An edited copy belongs to the operator: it stays, and the
// report says so. On a managed host the admin owns policy_dir, so the files
// are only reported. A copy outside the data home stays as well: the 0.8
// gateway a rollback restores still loads it (leftOutsideRollbackCopy).
func (m *v9Migrator) planRetiredPolicyFiles() {
	dir := filepath.Join(m.policyDir(), "rego")
	for _, file := range v9RetiredPolicyFiles {
		path := filepath.Join(dir, file.name)
		info, err := os.Lstat(path)
		if err != nil {
			continue
		}
		var raw []byte
		if info.Mode().IsRegular() && info.Size() <= 1<<20 {
			raw, _ = os.ReadFile(path)
		}
		sum := sha256.Sum256(bytes.ReplaceAll(raw, []byte("\r\n"), []byte("\n")))
		switch {
		case raw == nil || hex.EncodeToString(sum[:]) != file.sha256:
			m.note("%s was changed after install and is kept; 1.0 no longer ships or reads it (the firewall and audit "+
				"Rego policies are retired)", path)
		case m.in.Managed:
			m.note("%s is the unmodified 0.8 copy of a retired policy; nothing reads it, remove it", path)
		case m.leftOutsideRollbackCopy(path):
			// Kept, and noted there.
		default:
			m.retired = append(m.retired, path)
			m.note("%s, the unmodified 0.8 copy of a retired policy, is removed", path)
		}
	}
}

// planShippedPacks finds the rule-pack folders config_version 9 reads that are
// missing. An empty 0.8 rule_pack_dir selected the packs embedded in the
// gateway; after the migration the implicit default pack is
// <data_dir>/policies/guardrail/default and a built-in rule_pack name is
// <policy_dir>/guardrail/<name>. init seeds those folders, but a home without
// them (removed, or a policy_dir init never filled) would stop the gateway
// at start, so commit writes the shipped pack there (GAP-0150). A managed host
// installs the vendor packs with its lifecycle.
func (m *v9Migrator) planShippedPacks() {
	if m.in.Managed {
		return
	}
	want := map[string]string{filepath.Join(expandPath(m.dataDir()), "policies", "guardrail", "default"): "default"}
	for _, name := range BuiltinRulePacks {
		want[filepath.Join(expandPath(m.policyDir()), "guardrail", name)] = name
	}
	for dir, name := range want {
		if _, err := os.Lstat(dir); !errors.Is(err, os.ErrNotExist) {
			continue
		}
		if m.seedPacks == nil {
			m.seedPacks = map[string]string{}
		}
		m.seedPacks[filepath.Clean(dir)] = name
		m.note("%s was missing; the shipped %s rule pack is written there (config_version 9 reads the rule pack from that folder)", dir, name)
	}
}

// seedShippedRulePack writes the embedded pack name to dir, which must not
// exist: the files go to a sibling folder that is renamed into place.
func seedShippedRulePack(dir, name string) error {
	files, err := policyassets.Files()
	if err != nil {
		return err
	}
	prefix := "guardrail/" + name + "/"
	staging := dir + ".seeding"
	_ = os.RemoveAll(staging)
	wrote := false
	for _, f := range files {
		rel, ok := strings.CutPrefix(f.Path, prefix)
		if !ok {
			continue
		}
		target := filepath.Join(staging, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return err
		}
		if err := cfgtxn.WriteFileDurable(target, f.Data, 0o600); err != nil {
			_ = os.RemoveAll(staging)
			return err
		}
		wrote = true
	}
	if !wrote {
		return fmt.Errorf("this build ships no %s rule pack", name)
	}
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		_ = os.RemoveAll(staging)
		return err
	}
	if err := os.Rename(staging, dir); err != nil {
		_ = os.RemoveAll(staging)
		return err
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
	// What enforcement read: data.json, or the built-in defaults where there
	// is none (a managed layout never has one).
	source, read := "data.json", "data.json"
	if !data.present {
		source, read = "defaults", "the built-in defaults, there being no data.json"
	}
	// The v8 keys enforcement never read: removed, with a conflict when an
	// operator customised them away from what was enforced.
	legacy := map[string]map[string]SeverityAction{}
	for _, item := range []struct{ key, assetType string }{
		{"skill_actions", AdmissionTypeSkill}, {"mcp_actions", AdmissionTypeMCP}, {"plugin_actions", AdmissionTypePlugin},
	} {
		key, assetType := item.key, item.assetType
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
					To: "admission.defaults.allow_list_bypass_scan", Kept: source + ":true",
					Lost: "watch.allow_list_bypass_scan:false", Reason: "enforcement read " + read + "; watch.allow_list_bypass_scan had no reader",
				})
			}
		}
	}

	if !data.present {
		for assetType, old := range legacy {
			effective := map[string]SeverityAction{}
			for _, severity := range v9Severities {
				effective[severity] = v9BuiltinAdmissionAction(assetType, severity)
			}
			m.legacyActionConflicts(assetType, v9WithoutConfigured(old, v9ConfiguredActions(root, assetType)), effective, source, read)
		}
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
			if kept := v9ConfiguredBool(root, "defaults", key); kept != nil {
				if *kept {
					m.keptConfig("admission.defaults."+key, "admission.defaults."+key+":true", "data.json:config."+key+":false")
				}
				continue
			}
			v9Set(root, v9Scalar(false), "admission", "defaults", key)
			m.moved("data.json", "data.json:config."+key, "admission.defaults."+key, false)
		}
	}

	for _, assetType := range []string{AdmissionTypeSkill, AdmissionTypeMCP, AdmissionTypePlugin} {
		configured := v9ConfiguredActions(root, assetType)
		effective := map[string]SeverityAction{}
		from := map[string]string{}
		// differs: data.json customised the type. pin: it did so at a
		// severity the file does not set, so the severities the file leaves
		// unset are written; otherwise they keep their v9 default. A
		// severity the file sets is never overwritten.
		differs, pin := false, false
		for _, severity := range v9Severities {
			action, ok := data.ScannerOverrides[assetType][severity]
			from[severity] = "data.json:scanner_overrides." + assetType + "." + severity
			if !ok {
				action, ok = data.Actions[severity]
				from[severity] = "data.json:actions." + severity
			}
			value := v9BuiltinAdmissionAction(assetType, severity)
			if ok {
				value = action.config()
			} else {
				from[severity] = "defaults:" + severity
			}
			effective[severity] = value
			if value != v9BuiltinAdmissionAction(assetType, severity) {
				_, set := configured[severity]
				differs, pin = true, pin || !set
			}
		}
		if differs {
			for _, severity := range v9Severities {
				lower := strings.ToLower(severity)
				if kept, ok := configured[severity]; ok {
					if lost := v9ActionLabel(effective[severity]); kept.label != lost {
						m.keptConfig("admission."+assetType+".actions."+lower, kept.from+":"+kept.label, from[severity]+":"+lost)
					}
					continue
				}
				if !pin {
					continue
				}
				node, display := v9ActionNode(effective[severity])
				v9Set(root, node, "admission", assetType, "actions", lower)
				m.moved("data.json", "data.json:actions."+severity, "admission."+assetType+".actions."+lower, display)
			}
		}
		if old, ok := legacy[assetType]; ok {
			m.legacyActionConflicts(assetType, v9WithoutConfigured(old, configured), effective, source, read)
		}
	}

	if data.FirstPartyAllowList != nil {
		byType := map[string][]AdmissionFirstParty{}
		for _, entry := range *data.FirstPartyAllowList {
			switch entry.TargetType {
			case AdmissionTypeSkill, AdmissionTypeMCP, AdmissionTypePlugin:
			default:
				m.note("data.json first_party_allow_list entry %q has the unknown type %q and is not migrated",
					entry.TargetName, entry.TargetType)
				continue
			}
			if len(entry.SourcePathContains) == 0 {
				// v8 matched an entry without source_path_contains on any
				// path, and skipped the scan for it only where
				// allow_list_bypass_scan was true. A first-party entry needs
				// a path marker now, so where the bypass applies the closest
				// equal is a name-only asset_policy allow, which always skips
				// the scan. Elsewhere v8 scanned the asset anyway, so the
				// entry never changed a verdict and is dropped.
				if !v9AllowListBypassed(root, entry.TargetType) {
					m.note("data.json first_party_allow_list entry %q has no source_path_contains and was dropped: allow_list_bypass_scan is off for %s, so it was scanned at any path and the entry had no effect",
						entry.TargetName, entry.TargetType)
					continue
				}
				m.addAssetRule(root, "data.json", "data.json:first_party_allow_list", v9ActionRow{
					targetType: entry.TargetType, targetName: entry.TargetName, reason: entry.Reason,
				}, "allowed", entry.TargetName, "")
				m.note("data.json first_party_allow_list entry %q has no source_path_contains; it became asset_policy.%s.allowed (any path)",
					entry.TargetName, entry.TargetType)
				continue
			}
			byType[entry.TargetType] = append(byType[entry.TargetType], AdmissionFirstParty{
				Name: entry.TargetName, SourcePathContains: entry.SourcePathContains, Reason: entry.Reason,
			})
		}
		for _, assetType := range []string{AdmissionTypeSkill, AdmissionTypeMCP, AdmissionTypePlugin} {
			if v9SameFirstParty(byType[assetType], v9BuiltinFirstParty[assetType]) ||
				m.keepConfiguredFirstParty(root, assetType, byType[assetType]) {
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
			if m.keepConfiguredFirstParty(root, assetType, nil) {
				continue
			}
			v9Set(root, &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Style: yaml.FlowStyle},
				"admission", assetType, "first_party_allow_list")
			m.moved("data.json", "data.json:first_party_allow_list", "admission."+assetType+".first_party_allow_list", []string{})
		}
	}
}

// migratePrivacy drops the reserved privacy: section, which config_version 9
// does not have. A v8 loader refused privacy.disable_redaction, so it was
// never applied; a true value is reported, and redaction stays as
// observability.redaction_profiles sets it.
func (m *v9Migrator) migratePrivacy(root *yaml.Node) {
	section := v9Pop(root, "privacy")
	if section == nil {
		return
	}
	if section.Kind != yaml.MappingNode || len(section.Content) == 0 {
		m.record.Removed = append(m.record.Removed, "privacy")
		return
	}
	for index := 0; index+1 < len(section.Content); index += 2 {
		key := section.Content[index].Value
		m.record.Removed = append(m.record.Removed, "privacy."+key)
		var disabled bool
		if key == "disable_redaction" && section.Content[index+1].Decode(&disabled) == nil && disabled {
			m.note("privacy.disable_redaction: true was dropped: no config_version 8 or 9 runtime applies it; " +
				"redaction follows observability.redaction_profiles (set a destination's redaction_profile to none to send unredacted data)")
		}
	}
}

// migrateRegistrySources drops registries.sources[].auto_sync and
// sync_interval_hours, reserved for a scheduled sync that never shipped:
// nothing read them, and `defenseclaw registry sync` is the only ingest path.
// Keep this until the config_version 8 migration is dropped (1.1.0).
func (m *v9Migrator) migrateRegistrySources(root *yaml.Node) {
	sources := v8YAMLMapValue(v8YAMLMapValue(root, "registries"), "sources")
	for index, source := range v9SeqItems(sources) {
		for _, key := range []string{"auto_sync", "sync_interval_hours"} {
			if v9Pop(source, key) != nil {
				m.record.Removed = append(m.record.Removed, fmt.Sprintf("registries.sources[%d].%s", index, key))
			}
		}
	}
}

// legacyActionConflicts records a conflict for every severity an operator
// customised in a *_actions key away from what was enforced (source names
// where that came from, read says it in a sentence).
func (m *v9Migrator) legacyActionConflicts(assetType string, old, effective map[string]SeverityAction, source, read string) {
	defaults := v9LegacyActionDefaults(assetType)
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
			Kept:   source + ":" + v9ActionString(effective[severity]),
			Lost:   assetType + "_actions." + lower + ":" + v9ActionString(v9NormalAction(value)),
			Reason: "enforcement read " + read + "; " + assetType + "_actions only filled unknown severities",
		})
	}
}

// v9LegacyActionDefaults are the 0.8.x defaults of a *_actions key: a value
// equal to its default was never customised. Only MCP servers blocked
// install at CRITICAL and HIGH.
func v9LegacyActionDefaults(assetType string) map[string]SeverityAction {
	none := SeverityAction{File: FileActionNone, Runtime: RuntimeEnable, Install: InstallNone}
	block := SeverityAction{File: FileActionNone, Runtime: RuntimeEnable, Install: InstallBlock}
	defaults := map[string]SeverityAction{"critical": none, "high": none, "medium": none, "low": none, "info": none}
	if assetType == AdmissionTypeMCP {
		defaults["critical"], defaults["high"] = block, block
	}
	return defaults
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

// v9AllowListBypassed reports whether allow-listed assets of assetType skip
// the scan under the migrated document, resolved as CompileAdmission does:
// admission.<type>, then admission.defaults, then the built-in true.
func v9AllowListBypassed(root *yaml.Node, assetType string) bool {
	for _, scope := range []string{assetType, "defaults"} {
		if bypass := v9ConfiguredBool(root, scope, "allow_list_bypass_scan"); bypass != nil {
			return *bypass
		}
	}
	return true
}

// v9ConfiguredBool is the boolean admission.<scope>.<key> the document sets,
// or nil when it sets none.
func v9ConfiguredBool(root *yaml.Node, scope, key string) *bool {
	node := v8YAMLMapValue(v8YAMLMapValue(v8YAMLMapValue(root, "admission"), scope), key)
	var value bool
	if node == nil || node.Kind != yaml.ScalarNode || node.ShortTag() == "!!null" || node.Decode(&value) != nil {
		return nil
	}
	return &value
}

// keptConfig records a value the config_version 8 file already sets under
// admission: (config set, policy activate and the TUI write there before the
// file is migrated). It wins over data.json, as guardrail block_at does, and
// the data.json value is the loss.
func (m *v9Migrator) keptConfig(to, kept, lost string) {
	m.record.Conflicts = append(m.record.Conflicts, MigrationConflict{
		To: to, Kept: "config:" + kept, Lost: lost,
		Reason: "the config_version 8 file already set it, and the config value wins",
	})
}

// v9ConfiguredAction is an admission action the document already sets: its
// key and its shorthand or triple.
type v9ConfiguredAction struct{ from, label string }

// v9ConfiguredActions are the severities of assetType whose action the
// document already sets, resolved as CompileAdmission does:
// admission.<type>.actions, then admission.defaults.actions except for skill,
// where the scanner gate comes before the defaults.
func v9ConfiguredActions(root *yaml.Node, assetType string) map[string]v9ConfiguredAction {
	scopes := []string{assetType}
	if assetType != AdmissionTypeSkill {
		scopes = append(scopes, "defaults")
	}
	out := map[string]v9ConfiguredAction{}
	for _, scope := range scopes {
		actions := v8YAMLMapValue(v8YAMLMapValue(v8YAMLMapValue(root, "admission"), scope), "actions")
		for _, severity := range v9Severities {
			lower := strings.ToLower(severity)
			node := v8YAMLMapValue(actions, lower)
			var action AdmissionAction
			if _, done := out[severity]; done || node == nil || node.ShortTag() == "!!null" || node.Decode(&action) != nil {
				continue
			}
			label := action.Shorthand
			if label == "" {
				label = v9ActionLabel(v9NormalAction(action.Triple))
			}
			out[severity] = v9ConfiguredAction{from: "admission." + scope + ".actions." + lower, label: label}
		}
	}
	return out
}

// v9WithoutConfigured drops from a *_actions map the severities the document
// sets under admission: that later choice supersedes the never-read key.
func v9WithoutConfigured(old map[string]SeverityAction, configured map[string]v9ConfiguredAction) map[string]SeverityAction {
	for severity := range configured {
		delete(old, strings.ToLower(severity))
	}
	return old
}

// v9ActionLabel is the shorthand an action matches, else its triple.
func v9ActionLabel(action SeverityAction) string {
	_, display := v9ActionNode(action)
	if shorthand, ok := display.(string); ok {
		return shorthand
	}
	return v9ActionString(action)
}

// keepConfiguredFirstParty reports whether the document already sets the
// first-party list of assetType (admission.<type>, else admission.defaults,
// as CompileAdmission resolves it). That list wins over the data.json list,
// and a conflict is recorded when they differ.
func (m *v9Migrator) keepConfiguredFirstParty(root *yaml.Node, assetType string, data []AdmissionFirstParty) bool {
	names := func(list []AdmissionFirstParty) string {
		out := make([]string, 0, len(list))
		for _, entry := range list {
			out = append(out, entry.Name)
		}
		return "[" + strings.Join(out, ",") + "]"
	}
	for _, scope := range []string{assetType, "defaults"} {
		node := v8YAMLMapValue(v8YAMLMapValue(v8YAMLMapValue(root, "admission"), scope), "first_party_allow_list")
		var kept []AdmissionFirstParty
		if node == nil || node.ShortTag() == "!!null" || node.Decode(&kept) != nil {
			continue
		}
		if !v9SameFirstParty(kept, data) {
			m.keptConfig("admission."+assetType+".first_party_allow_list",
				"admission."+scope+".first_party_allow_list:"+names(kept), "data.json:first_party_allow_list:"+names(data))
		}
		return true
	}
	return false
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
		m.pinStricterScopePostures(guardrail, item.key, *item.value)
	}
	for _, item := range []struct {
		key     string
		value   *int
		shipped int
	}{
		{"block_at", data.Guardrail.BlockThreshold, shippedBlock},
		{"alert_at", data.Guardrail.AlertThreshold, shippedAlert},
	} {
		if item.value != nil {
			m.keepProxyConnectorLevel(root, item.key, *item.value, item.shipped)
		}
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

// keepProxyConnectorLevel keeps the data.json level the v8 LLM proxy enforced
// for the connector it served. v8 guardrail.rego read only data.json, whatever
// that connector's own pack or block_at said; v9 resolves the proxy's levels
// for that connector (spec 2.2), so its guardrail.connectors entry would now
// govern the proxy. Its own key still wins, as a recorded conflict. A pack
// default looser than the data.json level is pinned at the connector, unless
// the level is the shipped one, which was never a choice (as for the global
// key). A connector that inherits the global key or pack is covered by the
// global migration above.
func (m *v9Migrator) keepProxyConnectorLevel(root *yaml.Node, key string, rank, shipped int) {
	guardrail := v8YAMLMapValue(root, "guardrail")
	connector := v9ProxyConnector(root)
	name, named := v9RankNames[rank]
	if connector == "" || !named {
		return
	}
	var scope v9NamedNode
	for _, c := range v9ChildMappings(v8YAMLMapValue(guardrail, "connectors")) {
		if normalizeConnectorKey(c.name) == connector {
			scope = c
			break
		}
	}
	if scope.node == nil {
		return
	}
	path := "guardrail.connectors." + scope.name
	legacy := "data.json:guardrail." + strings.Replace(key, "_at", "_threshold", 1)
	if set := strings.ToUpper(strings.TrimSpace(yamlScalarValue(v8YAMLMapValue(scope.node, key)))); set != "" {
		if rank < v9RankOf(set) {
			m.record.Conflicts = append(m.record.Conflicts, MigrationConflict{
				To: path + "." + key, Kept: "config:" + path + "." + key + ":" + set, Lost: legacy + ":" + name,
				Reason: "the stricter data.json level applied to the " + connector + " LLM proxy; " + path + "." + key + " now applies to the proxy too",
			})
		}
		return
	}
	posture := m.scopePackPosture(guardrail, scope.node)
	if posture == "" || strings.TrimSpace(yamlScalarValue(v8YAMLMapValue(guardrail, key))) != "" {
		return
	}
	block, alert := v9PostureRanks(posture)
	own := block
	if key == "alert_at" {
		own = alert
	}
	if own <= rank {
		return
	}
	if rank == shipped {
		m.note("data.json guardrail %s (%s) is the shipped value; the %s LLM proxy now follows the %s pack default of %s",
			strings.Replace(key, "_at", "_threshold", 1), name, connector, posture, path)
		return
	}
	v9Set(scope.node, v9Scalar(name), key)
	m.moved("data.json", legacy, path+"."+key, name)
	m.note("%s.%s is set to the data.json level (%s) the %s LLM proxy enforced, so the %s pack default (%s) does not loosen the proxy; it now applies to that connector's hook prompts and tool calls too",
		path, key, name, connector, posture, v9RankNames[own])
}

// v9ProxyConnector is the connector the v8 LLM proxy served:
// guardrail.connector, else claw.mode, else openclaw (the gateway's
// configuredConnectorName and resolveActiveConnector), when it is a built-in
// proxy connector (proxyShouldBindForConfiguredConnector). It is "" for a
// hook connector, whose traffic never reached the proxy, so data.json never
// applied to it (and for a plugin connector, which is not resolved here).
func v9ProxyConnector(root *yaml.Node) string {
	name := normalizeConnectorKey(yamlScalarValue(v8YAMLMapValue(v8YAMLMapValue(root, "guardrail"), "connector")))
	if name == "" {
		name = normalizeConnectorKey(yamlScalarValue(v8YAMLMapValue(v8YAMLMapValue(root, "claw"), "mode")))
	}
	switch name {
	case "", "openclaw":
		return "openclaw"
	case "zeptoclaw":
		return name
	}
	return ""
}

// pinStricterScopePostures keeps a connector or profile pack posture that is
// stricter than the data.json level just written to the global key. In v8
// that scope's hook prompts and tool calls took its own pack posture; in v9
// the global key would win over the pack default, so the posture level is
// pinned at the scope (spec 2.2 precedence).
func (m *v9Migrator) pinStricterScopePostures(guardrail *yaml.Node, key string, rank int) {
	for _, scope := range v9GuardrailScopes(guardrail)[1:] {
		posture := m.scopePackPosture(guardrail, scope.node)
		if posture == "" || strings.TrimSpace(yamlScalarValue(v8YAMLMapValue(scope.node, key))) != "" {
			continue
		}
		block, alert := v9PostureRanks(posture)
		own := block
		if key == "alert_at" {
			own = alert
		}
		if own >= rank {
			continue
		}
		v9Set(scope.node, v9Scalar(v9RankNames[own]), key)
		m.moved("config", scope.name+".rule_pack", scope.name+"."+key, v9RankNames[own])
		m.note("%s.%s is pinned to the %s pack posture (%s) so the global guardrail.%s from data.json does not loosen it",
			scope.name, key, posture, v9RankNames[own], key)
	}
}

// scopePackPosture is the posture of the pack a scope selects ("" when it
// selects none and inherits): a preset's own name, else the posture of the
// custom pack's directory.
func (m *v9Migrator) scopePackPosture(guardrail, scope *yaml.Node) string {
	name := strings.TrimSpace(yamlScalarValue(v8YAMLMapValue(scope, "rule_pack")))
	switch {
	case name == "":
		return ""
	case v9BuiltinPacks[name]:
		return name
	}
	if path := strings.TrimSpace(yamlScalarValue(v8YAMLMapValue(v8YAMLMapValue(v8YAMLMapValue(guardrail, "custom_packs"), name), "path"))); path != "" {
		return v9DirPosture(expandPath(path))
	}
	return ""
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

// v9GuardrailScopes are the guardrail scopes that select a pack and
// thresholds: global, guardrail.connectors.<c>, guardrail.profiles.<p> and
// guardrail.profiles.<p>.connectors.<c>. The global scope is first.
func v9GuardrailScopes(guardrail *yaml.Node) []v9NamedNode {
	scopes := []v9NamedNode{{"guardrail", guardrail}}
	for _, c := range v9ChildMappings(v8YAMLMapValue(guardrail, "connectors")) {
		scopes = append(scopes, v9NamedNode{"guardrail.connectors." + c.name, c.node})
	}
	for _, p := range v9ChildMappings(v8YAMLMapValue(guardrail, "profiles")) {
		scopes = append(scopes, v9NamedNode{"guardrail.profiles." + p.name, p.node})
		for _, c := range v9ChildMappings(v8YAMLMapValue(p.node, "connectors")) {
			scopes = append(scopes, v9NamedNode{"guardrail.profiles." + p.name + ".connectors." + c.name, c.node})
		}
	}
	return scopes
}

// migrateRulePacks turns every rule_pack_dir into rule_pack (+ rules and
// custom_packs).
func (m *v9Migrator) migrateRulePacks(root *yaml.Node) error {
	guardrail := v8YAMLMapValue(root, "guardrail")
	if guardrail == nil || guardrail.Kind != yaml.MappingNode {
		return nil
	}
	for _, scope := range v9GuardrailScopes(guardrail) {
		node := v9Pop(scope.node, "rule_pack_dir")
		if node == nil {
			continue
		}
		dir := strings.TrimSpace(node.Value)
		if dir == "" {
			m.record.Removed = append(m.record.Removed, scope.name+".rule_pack_dir")
			if scope.name == "guardrail" && m.embeddedPackDropped() {
				m.record.Conflicts = append(m.record.Conflicts, MigrationConflict{
					To: "guardrail.rule_pack", Kept: "pack-default:default", Lost: "config:guardrail.rule_pack_dir:embedded",
					Reason: "an empty rule_pack_dir selected the gateway's embedded rule packs; config_version 9 selects the default pack of policy_dir (or the shipped default pack), whose rules, suppressions and judge prompts differ. Review that pack, or set guardrail.rule_pack",
				})
			}
			continue
		}
		if name := strings.TrimSpace(yamlScalarValue(v8YAMLMapValue(scope.node, "rule_pack"))); name != "" {
			// At one scope rule_pack wins over rule_pack_dir (the loader's
			// rulePackRefOf), so the directory never applied.
			m.record.Removed = append(m.record.Removed, scope.name+".rule_pack_dir")
			m.note("%s.rule_pack_dir (%s) was dropped: %s.rule_pack (%s) already selects the pack", scope.name, dir, scope.name, name)
			continue
		}
		name, protections, err := m.rulePackFor(guardrail, dir)
		if err != nil {
			return fmt.Errorf("config: %s.rule_pack_dir: %w", scope.name, err)
		}
		if scope.name == "guardrail" {
			// A custom pack keeps the posture of its folder, which its new
			// name (custom-strict, a stem) no longer shows.
			m.globalPackPosture = v9DirPosture(expandPath(dir))
		}
		v9Set(scope.node, v9Scalar(name), "rule_pack")
		m.moved("config", scope.name+".rule_pack_dir", scope.name+".rule_pack", name)
		if len(protections) > 0 {
			list := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Style: yaml.FlowStyle}
			for _, p := range protections {
				list.Content = append(list.Content, v9Scalar(p))
			}
			v9Set(scope.node, list, "rules", "protections")
			m.moved("config", scope.name+".rule_pack_dir", scope.name+".rules.protections", protections)
		}
	}
	return nil
}

// embeddedPackDropped reports whether dropping an empty rule_pack_dir changes
// the pack: config_version 9 keeps the embedded packs only for a standalone
// Windows host without a policy_dir of its own (standaloneRulePackDefault);
// everywhere else the implicit default pack is a folder.
func (m *v9Migrator) embeddedPackDropped() bool {
	return !(runtime.GOOS == "windows" && m.in.Managed &&
		strings.TrimSpace(yamlScalarValue(v8YAMLMapValue(m.root, "policy_dir"))) == "")
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
	if v9BuiltinPacks[base] {
		// The shipped pack of the standalone layout is product-owned: a
		// package update replaces it, so it is never pinned by digest. The
		// preset name resolves to it while policy_dir has no such folder
		// (Config.ResolveRulePackDir).
		if layout, ok := standaloneUnixLayoutForConfig(m.configPath); ok &&
			v9SameDir(clean, filepath.Join(layout.VendorPolicyDir, "guardrail", filepath.Base(clean))) {
			shadow := filepath.Join(m.policyDir(), "guardrail", base)
			if _, err := os.Stat(shadow); errors.Is(err, fs.ErrNotExist) {
				return base, nil, nil
			}
			m.note("%s is the shipped %s pack, but %s exists and the %s name selects it; the shipped pack is pinned as a custom pack, which a package update that changes it refuses until it is pinned again",
				dir, base, shadow, base)
		}
	}
	// A protected-* folder is a concrete rule pack. Its manifest names the
	// inputs that created it, but cannot prove its rules were not edited later.
	// Pin the actual files so a local rule cannot disappear on upgrade.
	if strings.HasPrefix(parent, "protected-") && v9BuiltinPacks[base] {
		m.note("%s is a composed rule pack; its current files are pinned as a custom pack to preserve local edits", dir)
	}
	if m.in.RulePackDigest == nil {
		return "", nil, fmt.Errorf("custom rule pack %s needs a digest; run `defenseclaw-gateway config migrate`", dir)
	}
	target, digest, err := m.rebaseRulePack(dir, clean)
	if err != nil {
		return "", nil, err
	}
	if target == clean {
		if digest, err = m.in.RulePackDigest(clean); err != nil {
			return "", nil, fmt.Errorf("load custom rule pack %s: %w", dir, err)
		}
	}
	stem := strings.Trim(v9PackNameUnsafe.ReplaceAllString(v9PackNameASCII(base), "-"), "-_")
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
		if existing == nil || yamlScalarValue(v8YAMLMapValue(existing, "path")) == target {
			break
		}
		name = fmt.Sprintf("%s-%d", stem, suffix)
	}
	if v8YAMLMapValue(packs, name) == nil {
		v9Set(guardrail, v9Mapping("path", v9Scalar(target), "digest", v9Scalar("sha256:"+digest)), "custom_packs", name)
		m.moved("config", "rule_pack_dir", "guardrail.custom_packs."+name, map[string]string{"path": target, "digest": "sha256:" + digest})
	}
	return name, nil, nil
}

// rebaseRulePack returns the folder and digest to pin for the custom pack at
// clean: a 0.8.x copy of the default pack's action rules enforced nothing in
// 1.0, where such a rule blocks only with an expression, and doctor still
// said PASS (GAP-0360). Its 1.0 copy goes next to it (commit writes it) and
// the folder stays for a rollback to 0.8.x. Any other pack is pinned as it is
// (digest ""). A managed host's packs belong to its administrator.
func (m *v9Migrator) rebaseRulePack(dir, clean string) (string, string, error) {
	if target, ok := m.rebasedFrom[clean]; ok {
		return target, m.rebasedDigests[target], nil
	}
	if m.in.RebaseRulePack == nil || m.in.Managed || m.in.InMemory {
		return clean, "", nil
	}
	plan, err := m.in.RebaseRulePack(clean)
	if err != nil {
		m.note("%s could not be rebased on the 1.0 default pack (%v): it is pinned as it is, and any 0.8.x copy of a "+
			"built-in command, path, agent-file or C2 rule in it only records matches; doctor names them", dir, err)
		return clean, "", nil
	}
	if plan == nil {
		return clean, "", nil
	}
	target := clean + "-1.0"
	for suffix := 2; ; suffix++ {
		if _, err := os.Lstat(target); errors.Is(err, fs.ErrNotExist) {
			if _, taken := m.rebasedPacks[target]; !taken {
				break
			}
		}
		target = fmt.Sprintf("%s-1.0-%d", clean, suffix)
	}
	if m.rebasedPacks == nil {
		m.rebasedPacks, m.rebasedFrom, m.rebasedDigests = map[string]map[string][]byte{}, map[string]string{}, map[string]string{}
	}
	m.rebasedPacks[target], m.rebasedFrom[clean], m.rebasedDigests[target] = plan.Files, target, plan.Digest
	kept := fmt.Sprintf("%d built-in rules are their 1.0 versions", plan.Updated)
	if len(plan.Disabled) > 0 {
		kept += fmt.Sprintf(", %s stay off (the copy had removed them)", strings.Join(plan.Disabled, ", "))
	}
	if len(plan.Carried) > 0 {
		kept += fmt.Sprintf("; your own rules were carried over: %s", strings.Join(plan.Carried, ", "))
	}
	if len(plan.Expressed) > 0 {
		kept += fmt.Sprintf("; these got an expression that blocks a command with their pattern as an argument "+
			"(review it): %s", strings.Join(plan.Expressed, ", "))
	}
	m.note("%s is a 0.8.x copy of the default pack's command, path, agent-file or C2 rules, which have no expression; "+
		"in 1.0 such a rule blocks only with one, so the pack enforced nothing. It was rebased on the 1.0 default "+
		"pack in %s, which is pinned instead (%s); %s is kept for a rollback to 0.8.x", dir, target, kept, dir)
	if len(plan.AlertOnly) > 0 {
		m.note("%s in %s have no expression, so in 1.0 they record matches but never block: give each an expression "+
			"over the parsed command (see the CEL rule authoring guide)", strings.Join(plan.AlertOnly, ", "), target)
	}
	return target, plan.Digest, nil
}

// writeRebasedRulePack writes a rebased pack to dir, which must not exist:
// the files go to a sibling folder that is renamed into place.
func writeRebasedRulePack(dir string, files map[string][]byte) error {
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		return err
	}
	staging, err := os.MkdirTemp(filepath.Dir(dir), filepath.Base(dir)+".rebasing-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(staging)
	for rel, data := range files {
		target := filepath.Join(staging, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return err
		}
		if err := cfgtxn.WriteFileDurable(target, data, 0o600); err != nil {
			_ = os.RemoveAll(staging)
			return err
		}
	}
	if err := os.Rename(staging, dir); err != nil {
		return err
	}
	return nil
}

// v9PackNameASCII folds a folder name to the letters a pack name keeps: an
// accented letter becomes its base letter, so "équipe sécu" is equipe-secu,
// where the name rule dropped it and left quipe-s-cu (GAP-0390).
func v9PackNameASCII(name string) string {
	var folded strings.Builder
	for _, r := range norm.NFKD.String(name) {
		if !unicode.Is(unicode.Mn, r) {
			folded.WriteRune(r)
		}
	}
	return folded.String()
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
// folder implicitly, and since 9 only configured packs load. Pin the bytes
// that v8 loaded so a managed standalone config can still apply.
func (m *v9Migrator) migrateSignaturePacks(root *yaml.Node) error {
	dataDir := m.dataDir()
	installed, _ := filepath.Glob(filepath.Join(dataDir, "signature-packs", "*.json"))
	if len(installed) == 0 {
		return nil
	}
	discovery := v8YAMLMapValue(root, "ai_discovery")
	listed := map[string]bool{}
	packs := v8YAMLMapValue(discovery, "signature_packs")
	pins := v8YAMLMapValue(discovery, "signature_pack_digests")
	for _, item := range v9SeqItems(packs) {
		listed[filepath.Clean(expandPath(item.Value))] = true
	}
	pinned := map[string]bool{}
	if pins != nil && pins.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(pins.Content); i += 2 {
			pinned[filepath.Clean(expandPath(pins.Content[i].Value))] = true
		}
	}
	secureClient := v9SecureClientDocument(root)
	var added []string
	addedPins := map[string]string{}
	for _, path := range installed {
		if !listed[filepath.Clean(path)] {
			added = append(added, path)
		}
		if secureClient || pinned[filepath.Clean(path)] {
			continue
		}
		raw, err := os.ReadFile(path) // #nosec G304 -- pack found in the configured data_dir.
		if err != nil {
			return fmt.Errorf("config: read signature pack %s: %w", path, err)
		}
		addedPins[path] = "sha256:" + cfgtxn.SHA256Hex(raw)
	}
	if len(added) > 0 {
		if packs == nil || packs.Kind != yaml.SequenceNode {
			packs = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
			v9Set(root, packs, "ai_discovery", "signature_packs")
		}
		for _, path := range added {
			packs.Content = append(packs.Content, v9Scalar(path))
		}
		m.moved("config", filepath.Join(dataDir, "signature-packs", "*.json"), "ai_discovery.signature_packs", added)
	}
	if len(addedPins) > 0 {
		if pins == nil || pins.Kind != yaml.MappingNode {
			pins = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			v9Set(root, pins, "ai_discovery", "signature_pack_digests")
		}
		for _, path := range installed {
			if digest, ok := addedPins[path]; ok {
				v9Set(pins, v9Scalar(digest), path)
			}
		}
		m.moved("config", filepath.Join(dataDir, "signature-packs", "*.json"), "ai_discovery.signature_pack_digests", addedPins)
	}
	return nil
}

// ---------------------------------------------------------------------------
// custom-providers.json

// ProvidersOverlayFile is the operator provider overlay in data_dir. From
// config_version 9 on it is derived from llm_providers (spec section 6).
const ProvidersOverlayFile = "custom-providers.json"

// migrateCustomProviders folds a legacy operator overlay (one without
// _derived_from) into llm_providers, so config.yaml is the one provider
// list: the gateway and the Python readers then see the same providers.
// An inline CA bundle moves to <data_dir>/provider-ca/<name>.pem. The
// in-memory load leaves it alone (the gateway still merges a legacy overlay
// itself), as does a managed host, whose provider list is the admin's. An
// overlay that uses request_overrides, which config can not hold, stays a
// live input and is reported.
func (m *v9Migrator) migrateCustomProviders(root *yaml.Node) {
	if m.in.InMemory {
		return
	}
	path := filepath.Join(m.dataDir(), ProvidersOverlayFile)
	raw, err := os.ReadFile(path) // #nosec G304 -- the data_dir provider overlay.
	if err != nil {
		return
	}
	var overlay configs.ProvidersConfig
	if err := json.Unmarshal(raw, &overlay); err != nil {
		m.note("%s is not valid JSON (%v); its providers were not moved to llm_providers", path, err)
		return
	}
	if overlay.DerivedFrom != "" || (len(overlay.Providers) == 0 && len(overlay.OllamaPorts) == 0) {
		return
	}
	if m.in.Managed {
		m.note("%s is a local provider overlay; on a managed host llm_providers comes from the admin config, so it was not moved", path)
		return
	}
	for _, p := range overlay.Providers {
		if len(p.RequestOverrides) > 0 {
			m.note("%s sets request_overrides for %q, which llm_providers can not hold; the file stays a live input", path, p.Name)
			return
		}
	}
	existing := map[string]bool{}
	for _, item := range v9SeqItems(v8YAMLMapValue(v8YAMLMapValue(root, "llm_providers"), "custom")) {
		existing[strings.ToLower(yamlScalarValue(v8YAMLMapValue(item, "name")))] = true
	}
	var custom []LLMCustomProvider
	var names []string
	for _, p := range overlay.Providers {
		name := strings.TrimSpace(p.Name)
		if name == "" || existing[strings.ToLower(name)] {
			continue
		}
		existing[strings.ToLower(name)] = true
		entry := LLMCustomProvider{
			Name: name, Domains: p.Domains, EnvKeys: p.EnvKeys, BaseProviderType: p.BaseProviderType,
			BaseURL: p.BaseURL, AllowedRequests: p.AllowedRequests, AvailableModels: p.AvailableModels,
			RequestPathOverrides: p.RequestPathOverrides, ExtraHeaders: p.ExtraHeaders,
		}
		if p.ProfileID != nil {
			entry.ProfileID = *p.ProfileID
		}
		if t := p.TLS; t != nil {
			entry.TLS = &LLMCustomProviderTLS{InsecureSkipVerify: t.InsecureSkipVerify}
			if pem := strings.TrimSpace(t.CACertPEM); pem != "" {
				ca := filepath.Join(m.dataDir(), "provider-ca", v9ProviderCAName(name))
				entry.TLS.CACertFile = ca
				m.providerCAs = append(m.providerCAs, v9RegoRefresh{path: ca, data: []byte(t.CACertPEM)})
			}
		}
		if b := p.Bedrock; b != nil {
			entry.Bedrock = &BedrockKeyConfig{Region: b.Region, AuthMode: b.AuthMode, AccessKeyEnv: b.AccessKeyEnv,
				SecretKeyEnv: b.SecretKeyEnv, SessionTokenEnv: b.SessionTokenEnv, ProfileName: b.ProfileName,
				InferenceProfile: b.InferenceProfile, DeploymentAliases: b.DeploymentAliases}
		}
		if v := p.Vertex; v != nil {
			entry.Vertex = &VertexKeyConfig{ProjectID: v.ProjectID, Region: v.Region, AuthMode: v.AuthMode,
				ServiceAccountJSONEnv: v.ServiceAccountJSONEnv}
		}
		if a := p.Azure; a != nil {
			entry.Azure = &AzureKeyConfig{Endpoint: a.Endpoint, APIVersion: a.APIVersion, AuthMode: a.AuthMode,
				DeploymentAliases: a.DeploymentAliases}
		}
		custom = append(custom, entry)
		names = append(names, name)
	}
	if len(custom) > 0 {
		list := v8YAMLMapValue(v8YAMLMapValue(root, "llm_providers"), "custom")
		if list == nil || list.Kind != yaml.SequenceNode {
			list = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
			v9Set(root, list, "llm_providers", "custom")
		}
		for _, entry := range custom {
			var node yaml.Node
			if err := node.Encode(entry); err != nil {
				m.note("could not move provider %q from %s: %v", entry.Name, path, err)
				return
			}
			list.Content = append(list.Content, &node)
		}
		m.moved(ProvidersOverlayFile, path, "llm_providers.custom", names)
	}
	if len(overlay.OllamaPorts) > 0 && v8YAMLMapValue(v8YAMLMapValue(root, "llm_providers"), "ollama_ports") == nil {
		ports := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Style: yaml.FlowStyle}
		for _, port := range overlay.OllamaPorts {
			ports.Content = append(ports.Content, v9Scalar(port))
		}
		v9Set(root, ports, "llm_providers", "ollama_ports")
		m.moved(ProvidersOverlayFile, path+":ollama_ports", "llm_providers.ollama_ports", overlay.OllamaPorts)
	}
	m.providersOverlay = path
}

// v9ProviderCAName gives each case-insensitive provider a stable CA path.
func v9ProviderCAName(name string) string {
	digest := sha256.Sum256([]byte(strings.ToLower(name)))
	return hex.EncodeToString(digest[:]) + ".pem"
}

// writeProviderCAs places TLS roots before the config commit. A failure must
// abort migration while the v8 config can still use its inline CA overlay.
func (m *v9Migrator) writeProviderCAs(written *[]string) error {
	for _, ca := range m.providerCAs {
		if err := os.MkdirAll(filepath.Dir(ca.path), 0o700); err != nil {
			return fmt.Errorf("config: create provider CA directory for %s: %w", ca.path, err)
		}
		if err := cfgtxn.WriteFileDurable(ca.path, ca.data, 0o600); err != nil {
			return fmt.Errorf("config: write provider CA bundle %s: %w", ca.path, err)
		}
		*written = append(*written, ca.path)
	}
	return nil
}

// retireProvidersOverlay renames the legacy overlay once its providers and
// CA files are in the committed config. The next config write renders the
// derived file.
func (m *v9Migrator) retireProvidersOverlay(written *[]string) {
	if err := os.Rename(m.providersOverlay, m.providersOverlay+DataJSONMigratedSuffix); err != nil {
		m.note("could not rename %s: %v", m.providersOverlay, err)
		return
	}
	*written = append(*written, m.providersOverlay+DataJSONMigratedSuffix)
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
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if m.in.Managed {
			m.note("%s: could not access %s (%v); the admin config is the policy",
				LocalEnforcementEntriesIgnored, path, err)
			return nil
		}
		return fmt.Errorf("config: access operator rows in %s: %w", path, err)
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
	if err != nil && m.in.InMemory && v9AuditDBDamaged(err) {
		// A damaged store is the daemon's to repair: it moves the file aside
		// and carries the entries over (audit.OpenDaemonStore), and the next
		// reload migrates them. Refusing here would stop that repair, and a
		// damaged store must not stop teardown either. Any other read error
		// still refuses the file, and a persisted migration always does.
		m.note("%s is damaged (%v); its block/allow entries are not migrated until the store is repaired", path, err)
		return nil
	}
	if err != nil {
		return fmt.Errorf("config: read operator rows from %s: %w", path, err)
	}
	m.auditRowsSnapshot, m.auditRowsRead = rows, true
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

// v9AuditDBDamaged reports whether err says the audit.db file itself is
// damaged, as opposed to busy, missing or not permitted (audit.isSQLiteCorrupt).
func v9AuditDBDamaged(err error) bool {
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "database disk image is malformed") ||
		strings.Contains(message, "file is not a database")
}

// SecureClientSource reports whether config bytes describe a Secure Client
// deployment (its deployment mode and profile, or their environment pins).
// The Secure Client integration stays on config_version 8, so `config
// migrate` leaves such a file unchanged (issue #1092).
func SecureClientSource(raw []byte) bool {
	var doc yaml.Node
	if yaml.Unmarshal(raw, &doc) != nil {
		return false
	}
	root := v8DocumentRoot(&doc)
	return root != nil && root.Kind == yaml.MappingNode && v9SecureClientDocument(root)
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
		// Only the @<connector>/<tool> form was scoped at runtime. A
		// <source>/<tool> row was audit-only, and v8 matched a bare name
		// exactly, so any other name keeps its whole text (a slash included)
		// and never becomes a global rule for its last segment.
		if strings.HasPrefix(name, "@") {
			if conn, tool, ok := strings.Cut(name[1:], "/"); ok {
				connector, name = conn, tool
			}
		}
	default:
		return false
	}
	m.addAssetRule(root, "audit.db", "actions:"+row.id, row, list, name, connector)
	return true
}

// addAssetRule appends one asset_policy rule unless an identical one exists.
func (m *v9Migrator) addAssetRule(root *yaml.Node, origin, from string, row v9ActionRow, list, name, connector string) {
	target := v8YAMLMapValue(v8YAMLMapValue(v8YAMLMapValue(root, "asset_policy"), row.targetType), list)
	for _, existing := range v9SeqItems(target) {
		if yamlScalarValue(v8YAMLMapValue(existing, "name")) != name ||
			yamlScalarValue(v8YAMLMapValue(existing, "connector")) != connector {
			continue
		}
		// An allow pinned to another path is a distinct rule. A name-only
		// comparison would drop it and then clear its audit install action.
		if list == "allowed" && row.targetType != AdmissionTypeTool {
			paths := v9SeqItems(v8YAMLMapValue(existing, "source_path_contains"))
			if row.sourcePath == "" && len(paths) != 0 {
				continue
			}
			if row.sourcePath != "" && (len(paths) != 1 || yamlScalarValue(paths[0]) != row.sourcePath) {
				continue
			}
		}
		m.moved(origin, from, "asset_policy."+row.targetType+"."+list, name)
		return
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
	m.moved(origin, from, "asset_policy."+row.targetType+"."+list, name)
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
