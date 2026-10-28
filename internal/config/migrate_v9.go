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
	"reflect"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/open-policy-agent/opa/ast" //nolint:staticcheck // The v8/v9 migration shares the legacy AST type with regodata until 1.1.
	"golang.org/x/text/unicode/norm"
	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/config/internal/cfgtxn"
	"github.com/defenseclaw/defenseclaw/internal/configs"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/policy/regodata"
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
	// DataJSONPath is the data.json the 0.8.x engine loaded (v8DataJSONIn);
	// "" or missing is skipped.
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
	// RebaseRulePack plans the 1.0 copy of a 0.8.x custom rule-pack directory
	// whose rules block a tool call with a pattern alone, which 1.0 does only
	// with an expression (guardrail.PlanRulePackRebase); a nil plan needs
	// none. Without it such a pack is pinned as it is (GAP-0360, GAP-1225).
	RebaseRulePack func(dir string) (*RulePackRebasePlan, error)
	// ack completes a pending record without its audit.db cleanup
	// (AcknowledgeMigrationV9).
	ack bool
}

// RulePackRebasePlan is guardrail.RulePackRebase, which this package can not
// import: the rebased pack's files and FilesDigest (no Files: the pack is
// pinned as it is), and what changed.
type RulePackRebasePlan struct {
	Files                                                   map[string][]byte
	Digest                                                  string
	Updated                                                 int
	Carried, Expressed, AlertOnly, Disabled, Merged, Linked []string
	// Renamed says which built-in rules the operator gave a pattern of their
	// own now have an ID of theirs ("CMD-RM-RF -> CUSTOM-CMD-RM-RF").
	Renamed []string
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
	// ProvidersFold is what the run did with a legacy custom-providers.json
	// (nil when there is none).
	ProvidersFold *ProvidersFold `json:"-"`
}

// ProvidersFold is what a migration did with a legacy custom-providers.json
// (one without _derived_from): the providers config.yaml took from it and
// where the file went, or why nothing was folded.
type ProvidersFold struct {
	// Overlay is the legacy file.
	Overlay string `json:"overlay"`
	// Folded names the providers llm_providers.custom took from it.
	Folded []string `json:"folded,omitempty"`
	// Retired is where the file was moved once config.yaml held all of it
	// ("" while it stays a live input).
	Retired string `json:"retired,omitempty"`
	// Refused says why nothing was folded; config.yaml and the file are
	// unchanged.
	Refused string `json:"refused,omitempty"`
	// Conflicts are the providers whose fields config.yaml and the file set
	// to different values.
	Conflicts []ProviderConflict `json:"conflicts,omitempty"`
	// Repeated are the providers the file names more than once with
	// different values for an extra_headers key.
	Repeated []ProviderConflict `json:"repeated,omitempty"`
	// HeadersAfterFold are the extra_headers the gateway sends only once the
	// file is no longer a live input: before 1.0.3 a same-name merge dropped
	// them, and the gateway keeps that rule while the file is one (GAP-0184).
	HeadersAfterFold []ProviderFields `json:"headers_after_fold,omitempty"`
	// Notes are this fold's migration notes.
	Notes []string `json:"notes,omitempty"`
}

// ProviderConflict is a provider config.yaml and the legacy overlay both
// name (or the overlay names twice), with the fields they set to different
// values (names only: a header value may be a credential). InUse says, per
// field, whose value the gateway uses while the file is a live input:
// "config.yaml", "custom-providers.json" or "none" (a header not sent).
type ProviderConflict struct {
	Provider string            `json:"provider"`
	Fields   []string          `json:"fields"`
	InUse    map[string]string `json:"in_use,omitempty"`
}

// ProviderFields is a provider with field names (never values).
type ProviderFields struct {
	Provider string   `json:"provider"`
	Fields   []string `json:"fields"`
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
	// Repaired lists values a later release set back because this migration
	// wrote them: a managed Cursor hook_fail_mode the 1.0.0-1.0.2 migration
	// rewrote to open (RepairMigratedCursorFailMode). ResultSHA256 is then
	// the repaired config.
	Repaired []MigrationMove `json:"repaired,omitempty"`
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
	// DetectionOnlyRules names the operator's own rules that blocked a tool
	// call on 0.8.x with their pattern and in 1.0, without an expression,
	// only record it; the upgrade prints them (GAP-1225).
	DetectionOnlyRules []string `json:"detection_only_rules,omitempty"`
	// RuleFileMerges says which rule files of a custom pack that shared a
	// category, which 1.0 refuses, were merged into one; the upgrade prints
	// them (GAP-1339).
	RuleFileMerges []string `json:"rule_file_merges,omitempty"`
	// RenamedRules says which 0.8.x built-in rules the operator gave a
	// pattern of their own were kept as rules of theirs under a new ID
	// ("CMD-RM-RF -> CUSTOM-CMD-RM-RF"): the built-in ID keeps the shipped
	// rule (GAP-1314). ExpressedRules names the operator's rules that got
	// an expression from their literal pattern and still block (GAP-1344).
	// The upgrade and doctor print them.
	RenamedRules   []string `json:"renamed_rules,omitempty"`
	ExpressedRules []string `json:"expressed_rules,omitempty"`
	// RulePackRebaseFailures names each 0.8.x custom pack whose 1.0 copy
	// could not be made, and why. It is pinned as it is, so its rules that
	// blocked a tool call with a pattern alone only record the match. The
	// upgrade, doctor and an audit alert at each gateway start name it until
	// the record is acknowledged (GAP-1358).
	RulePackRebaseFailures []string `json:"rule_pack_rebase_failures,omitempty"`
	// UnenforcedRegoData names each Rego module that reads a data document
	// 1.0 no longer provides and the migration did not move into config.yaml
	// (an operator's own data.json key): its rules that read it are not
	// enforced. It also names each 0.8.x vendor module the operator edited,
	// which the shipped module replaced, with its saved .migrated-v9 copy
	// (GAP-1498). The upgrade, config migrate, the managed lifecycle and
	// doctor print them until the record is acknowledged (GAP-1399).
	UnenforcedRegoData []string `json:"unenforced_rego_data,omitempty"`
	// UnscannableMCP names the MCP servers of the account the 1.0 scanner
	// refuses to start (a command path or a program other than npx or uvx
	// with a package). They keep running without a scan. The Python upgrade
	// step adds them after the commit, with the scanner's own check, and
	// prints them; doctor warns about each one still configured (GAP-1340).
	UnscannableMCP []MigrationUnscannableMCP `json:"unscannable_mcp,omitempty"`
	// AuditCleanup identifies only the copied operator rows. It lets a retry
	// finish cleanup after config commit without deleting later decisions.
	AuditCleanup *MigrationAuditCleanup `json:"audit_cleanup,omitempty"`
	// Pending is true until the v9 config and audit cleanup commit.
	Pending bool `json:"pending,omitempty"`
	// Acknowledged is set by `defenseclaw config migrate --ack`.
	Acknowledged bool `json:"acknowledged,omitempty"`
}

// MigrationAuditCleanup is the post-commit cleanup plan. Fingerprints avoid
// persisting raw audit reasons or action state in the migration record.
type MigrationAuditCleanup struct {
	Path    string                     `json:"path"`
	Skipped bool                       `json:"skipped,omitempty"`
	Rows    []MigrationAuditCleanupRow `json:"rows,omitempty"`
}

type MigrationAuditCleanupRow struct {
	ID          string `json:"id"`
	Fingerprint string `json:"fingerprint"`
}

// MigrationUnscannableMCP is one MCP server a scan refuses to start.
type MigrationUnscannableMCP struct {
	Name      string `json:"name"`
	Connector string `json:"connector"`
	Command   string `json:"command"`
	// Reason is the scanner's refusal.
	Reason string `json:"reason"`
	// RuntimeEffect says what the gateway does with the server.
	RuntimeEffect string `json:"runtime_effect"`
	// Fix is the defenseclaw mcp set command that makes it scannable.
	Fix string `json:"fix"`
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
	if in.ack && !already {
		return nil, errors.New("config: config.yaml is not on config_version 9 yet, so there is no committed migration " +
			"to complete; run `defenseclaw-gateway config migrate --to 9`")
	}
	m.record.ResultSHA256 = cfgtxn.SHA256Hex(migrated)
	result := &MigrateV9Result{Migrated: migrated, Record: m.record, EnvKey: m.envKey, EnvValue: m.envValue, ProvidersFold: m.fold}
	if already {
		result.Record.FromVersion = ConfigVersionV9
		// A config.yaml changed since the commit (config set, the TUI,
		// connector setup) still resumes the pre-9 Rego refresh and the
		// audit.db cleanup (GAP-1517, GAP-1533).
		if record, ok := readMigrationRecord(abs); ok && record.Pending {
			committed := strings.EqualFold(record.ResultSHA256, cfgtxn.SHA256Hex(source))
			switch {
			case !in.DryRun && !in.InMemory:
				if err := m.finishPending(ctx, source, record, in.ack); err != nil {
					return result, err
				}
				result.Written = append(result.Written, MigrationRecordPath(abs))
				record.Pending = false
				result.Record = record
			case committed:
				result.Record = record
			}
		}
		return result, m.foldProvidersOverlayV9(ctx, source, result)
	}
	if err := ValidateCandidate(abs, migrated); err != nil {
		return nil, fmt.Errorf("config: the migrated config_version 9 document does not validate: %w", err)
	}
	if err := m.validateAssets(abs, migrated); err != nil {
		return nil, fmt.Errorf("config: the migrated config_version 9 assets do not validate: %w", err)
	}
	if in.DryRun || in.InMemory {
		return result, nil
	}
	written, err := m.commit(ctx, source, migrated)
	result.Written = written
	result.Record = m.record
	return result, err
}

// validateAssets runs the asset check of a config write (ValidateCandidateAssets)
// on the migrated document, before a preview or a commit. A rebased pack is
// written only at commit, so the check reads it from a temporary copy of its
// files, which the custom_packs entry of the candidate points at; its pinned
// digest is checked against that copy. Skipping the whole check for a rebased
// pack let an unrelated reference the gateway refuses into config_version 9
// (GAP-1482).
func (m *v9Migrator) validateAssets(configPath string, migrated []byte) error {
	if len(m.rebasedPacks) == 0 || candidateAssetCheck == nil {
		return ValidateCandidateAssets(configPath, migrated)
	}
	candidate, err := LoadRuntimeV8InspectionCandidateFromBytes(configPath, migrated)
	if err != nil {
		return err
	}
	staging, err := os.MkdirTemp("", "defenseclaw-rebased-packs-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(staging)
	for _, name := range slices.Sorted(maps.Keys(candidate.Guardrail.CustomPacks)) {
		pack := candidate.Guardrail.CustomPacks[name]
		files, ok := m.rebasedPacks[filepath.Clean(pack.Path)]
		if !ok {
			continue
		}
		copied := filepath.Join(staging, name, filepath.Base(pack.Path))
		if err := writeRebasedRulePack(copied, files); err != nil {
			return fmt.Errorf("stage the rebased rule pack %s: %w", pack.Path, err)
		}
		pack.Path = copied
		candidate.Guardrail.CustomPacks[name] = pack
	}
	return CheckCandidateAssets(candidate)
}

// finishPending resumes the part after config commit under the config lock:
// the audit.db row cleanup and the pre-9 Rego module refresh. A missing
// cleanup snapshot cannot prove which operator rows were copied, so it
// remains pending for an operator to resolve. So does a module the gateway
// loads that still reads data.json (GAP-1497): the gateway refuses such a
// bundle, and the input-based modules of the operator stop applying with it.
// The row cleanup runs also when config.yaml changed since the commit: the
// rows were moved at the commit, and resumeV9ActionCleanup refuses a row
// whose fingerprint changed since, so a later config edit does not make
// clearing them unsafe (GAP-1533). A cleanup that cannot finish names
// `config migrate --ack`; with ack the cleanup is skipped, the Rego refresh
// still has to pass, and the record completes with the rows left in audit.db.
func (m *v9Migrator) finishPending(ctx context.Context, source []byte, record MigrationRecord, ack bool) error {
	configPath := m.configPath
	txn, err := cfgtxn.Begin(ctx, configPath, 0)
	if err != nil {
		return err
	}
	defer txn.Close()
	current, _, exists, err := txn.Read()
	if err != nil {
		return err
	}
	if !exists || !bytes.Equal(current, source) {
		return errors.New("config: config.yaml changed while finishing the config_version 9 migration; run it again")
	}
	latest, ok := readMigrationRecord(configPath)
	if !ok || !latest.Pending || latest.SourceSHA256 != record.SourceSHA256 ||
		latest.ResultSHA256 != record.ResultSHA256 {
		return errors.New("config: pending migration record changed while finishing config_version 9; run it again")
	}
	if !ack {
		if err := finishV9ActionCleanup(ctx, latest); err != nil {
			return fmt.Errorf("%w; the config_version 9 migration stays pending: run `defenseclaw-gateway config migrate "+
				"--to 9` again once that is fixed, or `defenseclaw-gateway config migrate --ack` to complete it and keep "+
				"the moved rows in audit.db", err)
		}
	}
	unenforced, err := m.resumeRegoRefresh()
	if err != nil {
		return err
	}
	for _, line := range unenforced {
		if !slices.Contains(latest.UnenforcedRegoData, line) {
			latest.UnenforcedRegoData = append(latest.UnenforcedRegoData, line)
		}
	}
	latest.Pending = false
	if ack {
		latest.Acknowledged = true
		if cleanup := latest.AuditCleanup; latest.ActionsRowsMoved > 0 && (cleanup == nil || !cleanup.Skipped) {
			latest.Notes = append(latest.Notes, "`config migrate --ack` completed the migration without the audit.db "+
				"cleanup: the operator rows it moved to config.yaml may still be in audit.db")
		}
	}
	return writeMigrationRecord(MigrationRecordPath(configPath), latest)
}

// finishV9ActionCleanup clears the operator rows a pending record moved from
// audit.db. A missing or incomplete snapshot cannot prove which rows were
// copied, so it is refused.
func finishV9ActionCleanup(ctx context.Context, record MigrationRecord) error {
	cleanup := record.AuditCleanup
	if cleanup == nil {
		if record.ActionsRowsMoved > 0 {
			return errors.New("config: pending migration record lacks an audit cleanup snapshot; operator review is required")
		}
		return nil
	}
	if cleanup.Skipped {
		return nil
	}
	if len(cleanup.Rows) != record.ActionsRowsMoved {
		return errors.New("config: pending migration record has an incomplete audit cleanup snapshot; operator review is required")
	}
	if err := resumeV9ActionCleanup(ctx, *cleanup); err != nil {
		return fmt.Errorf("config: finish migrated audit.db row cleanup: %w", err)
	}
	return nil
}

// resumeRegoRefresh runs the pre-9 Rego module refresh again for a commit that
// stopped after config.yaml (GAP-1497), then checks that no module the gateway
// loads still needs it. planRegoRefresh finds nothing once the modules are
// current, so a later retry changes nothing. It returns the
// unenforced_rego_data lines of the plan.
func (m *v9Migrator) resumeRegoRefresh() ([]string, error) {
	m.rego, m.record.Notes, m.record.UnenforcedRegoData = nil, nil, nil
	if err := m.planRegoRefresh(); err != nil {
		return nil, err
	}
	unenforced := m.record.UnenforcedRegoData
	if err := m.refreshRegoModules(nil); err != nil {
		return nil, err
	}
	m.rego = nil
	if err := m.planRegoRefresh(); err != nil {
		return nil, err
	}
	if len(m.rego) > 0 {
		return nil, fmt.Errorf("config: the pre-9 Rego module %s still reads data.json after its refresh; "+
			"the config_version 9 migration stays pending", m.rego[0].path)
	}
	return unenforced, nil
}

// NeedsMigrationV9 reports whether raw is a config_version 8 document.
func NeedsMigrationV9(raw []byte) bool {
	var doc struct {
		ConfigVersion int `yaml:"config_version"`
	}
	return decodeSourceYAML(raw, &doc) == nil && doc.ConfigVersion == ObservabilityV8ConfigVersion
}

// V8PolicyDataJSON resolves a config_version 8 policy_dir (as config.yaml
// spells it) to the folder config_version 9 names and the data.json the
// migration reads. 0.8.x did not expand a "~/" policy_dir: `policy activate`
// wrote <cwd>/~/<rest>/rego/data.json and its gateway read the same relative
// path, both from the home directory when run from a shell. When that literal
// folder holds a data.json at least as new as the expanded folder's, it is
// the one 0.8.x last activated and enforced, so it is the one migrated
// (GAP-1031).
func V8PolicyDataJSON(policyDir string) (dir, dataJSON string) {
	raw := strings.TrimSpace(policyDir)
	dir = expandPath(raw)
	dataJSON = v8DataJSONIn(dir)
	if dir == raw {
		return dir, dataJSON
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return dir, dataJSON
	}
	literal := v8DataJSONIn(filepath.Join(home, raw))
	written, err := os.Stat(literal)
	if err != nil || !written.Mode().IsRegular() {
		return dir, dataJSON
	}
	if expanded, err := os.Stat(dataJSON); err == nil && expanded.ModTime().After(written.ModTime()) {
		return dir, dataJSON
	}
	return dir, literal
}

// v8DataJSONIn is the data.json the 0.8.x engine (policy.New) loaded for
// policy_dir dir: <dir>/rego/data.json, or the data.json next to Rego modules
// kept flat in dir itself when <dir>/rego holds no modules (GAP-1453).
func v8DataJSONIn(dir string) string {
	nested := filepath.Join(dir, "rego", "data.json")
	if _, err := os.Stat(nested); err == nil || v8HasRegoModules(filepath.Join(dir, "rego")) {
		return nested
	}
	if flat := filepath.Join(dir, "data.json"); v8RegularFile(flat) {
		return flat
	}
	return nested
}

// v8HasRegoModules is the 0.8.x engine's hasRegoFiles: a folder with a .rego
// file, or one it could not list for another reason than its absence.
func v8HasRegoModules(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return !errors.Is(err, fs.ErrNotExist)
	}
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) == ".rego" {
			return true
		}
	}
	return false
}

func v8RegularFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

// MigrateV8InMemory is the gateway's read-only load of a config_version 8
// file (spec 2.0): it returns config_version 9 bytes with the migrated
// admission and thresholds, the *_actions keys and,
// on a per-user install, the operator rows of audit.db keep applying until
// the file is migrated. Nothing is written. raw comes back unchanged for a
// config_version 9 file and on a Secure Client host, whose path does not
// change; on a migration error it comes back unchanged with the error, and
// the caller refuses the file (InMemoryMigrationError). A custom 0.8.x rule
// pack keeps its original path and pin here; the runtime rebases the loaded
// pack in memory after verifying that pin.
func MigrateV8InMemory(configFile string, raw []byte, rulePackDigest func(dir string) (string, error)) ([]byte, error) {
	migrated, exportKey, err := MigrateV8InMemoryCandidate(configFile, raw, rulePackDigest)
	if err != nil {
		return migrated, err
	}
	exportKey()
	return migrated, nil
}

// MigrateV8InMemoryCandidate is MigrateV8InMemory for a load that may still
// be refused after it (a gateway reload): it does not touch the process
// environment. exportKey places the inline scanner key the way
// MigrateV8InMemory does; the caller runs it once the configuration is
// accepted, so a refused one never changes the key the running scanners
// read. exportKey is never nil.
func MigrateV8InMemoryCandidate(configFile string, raw []byte, rulePackDigest func(dir string) (string, error)) (migrated []byte, exportKey func(), err error) {
	noKey := func() {}
	if !NeedsMigrationV9(raw) {
		return raw, noKey, nil
	}
	var doc yaml.Node
	if yaml.Unmarshal(raw, &doc) != nil {
		return raw, noKey, nil
	}
	root := v8DocumentRoot(&doc)
	if root == nil || root.Kind != yaml.MappingNode || v9SecureClientDocument(root) {
		return raw, noKey, nil
	}
	dataDir := migrationDataDir(configFile, root)
	policyDir, dataJSON := V8PolicyDataJSON(yamlScalarValue(v8YAMLMapValue(root, "policy_dir")))
	if policyDir == "" {
		policyDir = filepath.Join(dataDir, "policies")
		dataJSON = v8DataJSONIn(policyDir)
	}
	managedHost := StandaloneManagedSource(raw)
	in := MigrateV9Input{
		ConfigPath: configFile, Source: raw, PolicyDir: policyDir, DataDir: dataDir,
		DataJSONPath: dataJSON,
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
		return raw, noKey, err
	}
	// The v8 file still holds the inline key; the v9 document names its
	// variable instead, so the variable carries the key for this process
	// (the scanners inherit it) until the file is migrated. A value already
	// in the environment or .env wins, as it does for any api_key_env; a
	// value an earlier in-memory load set is replaced, so a rotated inline
	// key applies on reload (GAP-0995).
	key, value := result.EnvKey, result.EnvValue
	return result.Migrated, func() { exportInMemoryKey(key, value) }, nil
}

// inMemoryExportedKeys holds the value each environment variable got from
// an in-memory migration of this process (exportInMemoryKey).
var inMemoryExportedKeys sync.Map // variable -> value

// exportInMemoryKey sets key to value for this process unless the
// environment holds a value this process did not set from an inline key.
func exportInMemoryKey(key, value string) {
	if key == "" {
		return
	}
	current := os.Getenv(key)
	if current != "" {
		exported, ok := inMemoryExportedKeys.Load(key)
		if !ok || exported.(string) != current {
			return
		}
	}
	if err := os.Setenv(key, value); err == nil {
		inMemoryExportedKeys.Store(key, value)
	}
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

// UnrebasedRulePacks returns the RulePackRebaseFailures of the committed
// migration recorded next to configPath, until it is acknowledged.
func UnrebasedRulePacks(configPath string) []string {
	record, ok := readMigrationRecord(configPath)
	if !ok || record.Pending || record.Acknowledged {
		return nil
	}
	return record.RulePackRebaseFailures
}

// ExpressedRulePackRules returns the ExpressedRules of the committed
// migration recorded next to configPath, acknowledged or not: the rules of
// a rebased 0.8.x custom pack that got an expression from their literal.
func ExpressedRulePackRules(configPath string) []string {
	record, ok := readMigrationRecord(configPath)
	if !ok || record.Pending {
		return nil
	}
	return record.ExpressedRules
}

// MigratedFromV8 returns the source digest of the committed config_version
// 9 migration of a v8 file recorded next to configPath. The gateway uses it
// to recognise its first start after a 0.8.x upgrade.
func MigratedFromV8(configPath string) (string, bool) {
	record, ok := readMigrationRecord(configPath)
	if !ok || record.Pending || record.FromVersion >= ConfigVersionV9 {
		return "", false
	}
	return record.SourceSHA256, true
}

func readMigrationRecord(configPath string) (MigrationRecord, bool) {
	var record MigrationRecord
	raw, err := os.ReadFile(MigrationRecordPath(configPath))
	if err != nil || json.Unmarshal(raw, &record) != nil {
		return MigrationRecord{}, false
	}
	return record, record.SourceSHA256 != ""
}

// AcknowledgeMigrationV9 marks migration-v9.json next to in.ConfigPath as
// read (`defenseclaw config migrate --ack`), so doctor stops reporting it. A
// record still pending after the config_version 9 commit is completed first,
// without the audit.db row cleanup that kept it pending; the pre-9 Rego
// refresh still has to pass (finishPending, GAP-1533).
func AcknowledgeMigrationV9(ctx context.Context, in MigrateV9Input) error {
	recordPath := MigrationRecordPath(in.ConfigPath)
	raw, err := os.ReadFile(recordPath)
	if err != nil {
		return err
	}
	var record MigrationRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		return fmt.Errorf("config: decode %s: %w", recordPath, err)
	}
	if record.Pending {
		in.ack, in.DryRun, in.InMemory = true, false, false
		_, err := MigrateV9(ctx, in)
		return err
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
	// dataJSON is the data.json the migration planned from; the commit
	// refuses one that changed since.
	dataJSON *v9DataJSON
	// rows are the audit.db rows moved into asset_policy, cleared after the
	// config commit.
	rows              []v9ActionRow
	auditRowsSnapshot []v9ActionRow
	auditRowsRead     bool
	// envKey is an inline scanner key moved to .env on commit.
	envKey, envValue string
	// rego are the pre-9 Rego modules the gateway loads (planRegoRefresh) that
	// commit replaces with the shipped module (nil data retires the file).
	rego []v9RegoRefresh
	// providersOverlay is the legacy custom-providers.json folded into
	// llm_providers; commit writes providerCAs and retires the file.
	providersOverlay string
	providerCAs      []v9RegoRefresh
	// fold is what migrateCustomProviders did with the overlay (nil when
	// there is none), and foldChanged whether it changed llm_providers.
	fold        *ProvidersFold
	foldChanged bool
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
	m.dataJSON = data
	m.migratePolicyDir(root)
	if err := m.migrateRulePacks(root); err != nil {
		return nil, false, err
	}
	m.migrateAdmission(root, data)
	m.migrateThresholds(root, data)
	// A managed config's Cursor fail mode is the administrator's choice and
	// its hooks honour it (owner decision 2026-10-20), so the migration keeps
	// it as written: rewriting a managed observe-mode "closed" to "open" would
	// open hooks the administrator never opened.
	if !v9ManagedDocument(root) {
		m.normalizeCursorFailMode(root)
	}
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
	m.migrateRetiredStandaloneSandbox(root)
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

// normalizeCursorFailMode closes a v8 Cursor open that action mode
// contradicts: Cursor's action hooks are closed. It never writes open. An
// observe-mode closed is the operator's outage choice, which this release's
// per-user Cursor hooks follow (connector.OutageHookFailMode); 1.0.0 to
// 1.0.3 rewrote it to open, which the hooks then followed while the gateway
// was down (r104 W3 G3-upg). Other connectors keep their independent fail
// mode.
func (m *v9Migrator) normalizeCursorFailMode(root *yaml.Node) {
	guardrail := v8YAMLMapValue(root, "guardrail")
	if guardrail == nil || guardrail.Kind != yaml.MappingNode {
		return
	}
	globalMode := yamlScalarValue(v8YAMLMapValue(guardrail, "mode"))
	contradicted := func(mode string, stored *yaml.Node) bool {
		return strings.EqualFold(strings.TrimSpace(mode), "action") &&
			!strings.EqualFold(strings.TrimSpace(stored.Value), "closed")
	}
	connectors := v8YAMLMapValue(guardrail, "connectors")
	if connectors != nil && connectors.Kind == yaml.MappingNode && len(connectors.Content) > 0 {
		for i := 0; i+1 < len(connectors.Content); i += 2 {
			if normalizeConnectorKey(connectors.Content[i].Value) != "cursor" {
				continue
			}
			entry := connectors.Content[i+1]
			if entry.Kind != yaml.MappingNode {
				continue
			}
			stored := v8YAMLMapValue(entry, "hook_fail_mode")
			if stored == nil {
				continue
			}
			mode := yamlScalarValue(v8YAMLMapValue(entry, "mode"))
			if strings.TrimSpace(mode) == "" {
				mode = globalMode
			}
			if contradicted(mode, stored) {
				stored.Value = "closed"
				m.moved("config", "guardrail.connectors.cursor.hook_fail_mode",
					"guardrail.connectors.cursor.hook_fail_mode", "closed")
			}
		}
		return
	}
	if normalizeConnectorKey(yamlScalarValue(v8YAMLMapValue(guardrail, "connector"))) != "cursor" {
		return
	}
	stored := v8YAMLMapValue(guardrail, "hook_fail_mode")
	if stored != nil && contradicted(globalMode, stored) {
		stored.Value = "closed"
		m.moved("config", "guardrail.hook_fail_mode", "guardrail.hook_fail_mode", "closed")
	}
}

// migratePolicyDir writes a "~/" policy_dir as the folder it names: the 1.0
// gateway reads policy_dir as written, so "~/team-policies" named no folder and
// it refused every policy reload ("read rego directory", GAP-1033). It also
// records where the migrated data.json came from when 0.8.x wrote it under the
// unexpanded path (V8PolicyDataJSON).
func (m *v9Migrator) migratePolicyDir(root *yaml.Node) {
	raw := strings.TrimSpace(yamlScalarValue(v8YAMLMapValue(root, "policy_dir")))
	dir := expandPath(raw)
	if dir == raw {
		return
	}
	v9Set(root, v9Scalar(dir), "policy_dir")
	m.moved("config", "policy_dir", "policy_dir", dir)
	if dj := strings.TrimSpace(m.in.DataJSONPath); dj != "" && filepath.Clean(dj) != v8DataJSONIn(dir) {
		m.note("0.8.x did not expand policy_dir %s and kept its policy data in %s; that data.json was migrated", raw, dj)
	}
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
// managed host), the inline key move and finally the audit.db rows. The
// inline key move holds .env.lock (after config.yaml.lock, the order every
// writer takes) until the commit or its undo is done, so a credential that
// keys set or setup saves meanwhile is never erased. A failure that leaves
// the v8 config.yaml in place takes the moved key back out of .env, so the
// command does not report that nothing was migrated while it is still there
// (GAP-0808); while config.yaml may hold the v9 file, which reads the key
// from .env, the key stays and the error says so.
func (m *v9Migrator) commit(ctx context.Context, source, migrated []byte) (written []string, err error) {
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
	if m.dataJSON.dataJSONChanged(m.in.DataJSONPath) {
		// Its edit would be neither in the v9 config nor read again.
		return nil, fmt.Errorf("config: %s changed while the config_version 9 migration ran; run it again", m.in.DataJSONPath)
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
	committed := false
	// The documented rollback path must hold the v8 source of this run.
	// Keep an older backup as a timestamped sibling before refreshing it.
	backup := m.configPath + ConfigV8BackupSuffix
	earlier, err := os.ReadFile(backup)
	switch {
	case err == nil && bytes.Equal(earlier, source):
	case err == nil:
		kept := freeSiblingPath(backup + "." + migrationStamp())
		if err := cfgtxn.WriteFileDurable(kept, earlier, 0o600); err != nil {
			return written, err
		}
		written = append(written, kept)
		m.note("previous backup %s saved as %s; rollback now restores this migration's config_version 8 source", backup, kept)
		fallthrough
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
		releaseEnv, lockErr := cfgtxn.LockFile(ctx, envPath, 0)
		if lockErr != nil {
			return written, fmt.Errorf("config: move the inline scanner key to %s: %w", envPath, lockErr)
		}
		// Registered before the undo, so it runs after it.
		defer releaseEnv()
		undo, appendErr := appendDotEnvKey(envPath, m.envKey, m.envValue)
		if undo != nil {
			written = append(written, envPath)
			defer func() {
				if committed || err == nil {
					return
				}
				// Commit puts the v8 bytes back when it fails, unless that
				// restore fails too; anything else on disk may be the v9
				// config, which reads the key from .env.
				if onDisk, readErr := os.ReadFile(m.configPath); readErr != nil || !bytes.Equal(onDisk, current) {
					err = fmt.Errorf("%w; %s keeps the moved scanner key because config.yaml may now read it from there", err, envPath)
					return
				}
				if undoErr := undo(); undoErr != nil {
					err = fmt.Errorf("%w; %s still holds the moved scanner key: %v", err, envPath, undoErr)
					return
				}
				written = slices.DeleteFunc(written, func(path string) bool { return path == envPath })
			}()
		}
		if appendErr != nil {
			return written, fmt.Errorf("config: move the inline scanner key to %s: %w", envPath, appendErr)
		}
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
	auditCleanup := false
	if len(m.rows) > 0 {
		outside := m.leftOutsideRollbackCopy(m.in.AuditDBPath)
		m.record.AuditCleanup = &MigrationAuditCleanup{
			Path: m.in.AuditDBPath, Skipped: outside,
		}
		if !outside {
			auditCleanup = true
			for _, row := range m.rows {
				m.record.AuditCleanup.Rows = append(m.record.AuditCleanup.Rows,
					MigrationAuditCleanupRow{ID: row.id, Fingerprint: v9ActionRowFingerprint(row)})
			}
		}
	}
	m.record.Pending = true
	if err := writeMigrationRecord(recordPath, m.record); err != nil {
		return written, err
	}
	written = append(written, recordPath)
	if _, err := commitV9Config(txn, current, migrated, exists, mode, cfgtxn.Writer{Actor: m.record.Actor, Reason: "config_version 9 migration"}); err != nil {
		return written, err
	}
	committed = true
	written = append(written, m.configPath)
	// On a managed host the admin owns policy_dir (as planRegoRefresh
	// reports): its data.json stays, so a rollback to the v8 config finds it.
	// A file outside the data home stays too: the installer's rollback copy
	// does not cover it, so renaming it would leave a rolled-back 1.0.0 gateway
	// without its policy data (see leftOutsideRollbackCopy).
	dj := strings.TrimSpace(m.in.DataJSONPath)
	// planned is where the data.json the migration planned from is now:
	// renamed first, so the bytes checked below are the ones retired.
	planned := dj
	if dj != "" && !m.in.Managed && !m.leftOutsideRollbackCopy(dj) {
		if _, statErr := os.Stat(dj); statErr == nil {
			if err := os.Rename(dj, dj+DataJSONMigratedSuffix); err != nil {
				m.note("could not rename %s: %v", dj, err)
			} else {
				planned = dj + DataJSONMigratedSuffix
			}
		}
	}
	if m.dataJSON.dataJSONChanged(planned) {
		// An edit made while config.yaml was written is in neither the v9
		// config nor anything a later run reads once config.yaml is v9: put
		// the v8 config back so the next run migrates it (GAP-1148).
		committed = false
		return m.undoDataJSONDrift(txn, current, migrated, mode, dj, planned, written)
	}
	if planned != dj {
		written = append(written, planned)
	}
	refreshErr := m.refreshRegoModules(&written)
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
	if auditCleanup {
		if err := clearV9ActionRowsDB(auditDB, m.rows); err != nil {
			return written, fmt.Errorf("config: clean up migrated audit.db rows: %w", err)
		}
	}
	if auditDB != nil {
		if _, err := auditDB.Exec("COMMIT"); err != nil {
			return written, fmt.Errorf("config: commit audit.db cleanup: %w", err)
		}
	}
	// A pre-9 module left in place keeps the record pending, and a retry
	// resumes its refresh (finishPending).
	m.record.Pending = refreshErr != nil
	if err := writeMigrationRecord(recordPath, m.record); err != nil {
		return written, err
	}
	return written, refreshErr
}

// undoDataJSONDrift puts the config_version 8 config.yaml back after a
// commit whose data.json (dj, now at planned) changed meanwhile, and
// returns the commit's error. A data.json it renamed goes back unless one
// was written at dj since. The caller's deferred undo then takes the moved
// scanner key back out of .env and leaves audit.db as it was.
func (m *v9Migrator) undoDataJSONDrift(txn *cfgtxn.Txn, source, migrated []byte, mode os.FileMode,
	dj, planned string, written []string) ([]string, error) {
	if planned != dj {
		if _, err := os.Lstat(dj); !errors.Is(err, fs.ErrNotExist) {
			m.note("%s was written again while the migration ran; the file it planned from is %s", dj, planned)
			written = append(written, planned)
		} else if err := os.Rename(planned, dj); err != nil {
			m.note("could not put %s back to %s: %v", planned, dj, err)
			written = append(written, planned)
		}
	}
	if _, err := txn.Commit(migrated, source, true, mode, cfgtxn.Writer{Actor: m.record.Actor, Reason: "config_version 9 migration undone"}); err != nil {
		return written, fmt.Errorf("config: %s changed while the config_version 9 migration ran, and config.yaml could not be put back to config_version 8 (%v): compare %s with config.yaml", dj, err, dj)
	}
	written = slices.DeleteFunc(written, func(path string) bool { return path == m.configPath })
	return written, fmt.Errorf("config: %s changed while the config_version 9 migration ran, so config.yaml was left at config_version 8; run it again", dj)
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
// installer saves a rollback copy of DEFENSECLAW_HOME, plus only the config
// file when DEFENSECLAW_CONFIG points outside that home. A failed upgrade
// or `defenseclaw rollback` puts config.yaml back but not a data.json, Rego module,
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
	resolvedPath, pathErr := filepath.EvalSymlinks(path)
	resolvedHome, homeErr := filepath.EvalSymlinks(DefaultDataPath())
	if pathErr == nil && homeErr == nil {
		rel, relErr := filepath.Rel(resolvedHome, resolvedPath)
		if relErr == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
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

// commitV9Config is txn.Commit; tests replace it to fail the commit.
var commitV9Config = func(txn *cfgtxn.Txn, expected, candidate []byte, expectedExists bool, mode os.FileMode, w cfgtxn.Writer) (cfgtxn.GenerationState, error) {
	return txn.Commit(expected, candidate, expectedExists, mode, w)
}

// writeDotEnvDurable is cfgtxn.WriteFileDurable; tests replace it to fail
// the .env write.
var writeDotEnvDurable = cfgtxn.WriteFileDurable

// appendDotEnvKey adds key=value to a private .env unless the key is already
// defined there; the caller holds .env.lock. undo is non-nil whenever the
// file may have changed, also when the write reports an error after its
// rename (a failed directory fsync). undo puts back the previous bytes or
// removes the file the write created; it leaves a file that no longer holds
// the bytes it wrote as it is and says so.
func appendDotEnvKey(path, key, value string) (undo func() error, err error) {
	existing, err := os.ReadFile(path)
	existed := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	updated, changed := DotEnvWithKey(existing, key, value)
	if !changed {
		return nil, nil
	}
	undo = func() error {
		onDisk, readErr := os.ReadFile(path)
		switch {
		case errors.Is(readErr, os.ErrNotExist):
			return nil
		case readErr != nil:
			return readErr
		case existed && bytes.Equal(onDisk, existing):
			return nil
		case !bytes.Equal(onDisk, updated):
			return fmt.Errorf("%s changed after the migration wrote it, so it was left as it is", path)
		case existed:
			return writeDotEnvDurable(path, existing, 0o600)
		default:
			return os.Remove(path)
		}
	}
	return undo, writeDotEnvDurable(path, updated, 0o600)
}

// DotEnvWithKey returns the .env bytes with a usable key. An existing
// nonempty assignment wins; an empty assignment is replaced so the inline
// v8 fallback remains available after migration.
func DotEnvWithKey(existing []byte, key, value string) ([]byte, bool) {
	lines := bytes.Split(existing, []byte("\n"))
	for i, line := range lines {
		entry := strings.TrimSpace(string(line))
		if entry == "" || strings.HasPrefix(entry, "#") {
			continue
		}
		name, current, ok := strings.Cut(entry, "=")
		if !ok || strings.TrimSpace(name) != key {
			continue
		}
		current = strings.TrimSpace(current)
		if current != "" && current != "\"\"" && current != "''" {
			return existing, false
		}
		equals := bytes.IndexByte(line, '=')
		updated := append([]byte(nil), line[:equals+1]...)
		updated = append(updated, value...)
		if bytes.HasSuffix(line, []byte("\r")) {
			updated = append(updated, '\r')
		}
		lines[i] = updated
		return bytes.Join(lines, []byte("\n")), true
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

// v9DataJSONDocs are the data.json documents the 0.8.x admission, guardrail
// and skill_actions modules read. The migration moves their values into
// config.yaml, where the shipped module and the config-driven fallback read
// them. Any other document a module reads, such as an operator's own key in
// data.json, has no config_version 9 home (GAP-1399).
var v9DataJSONDocs = map[string]bool{
	"data.config": true, "data.actions": true, "data.scanner_overrides": true,
	"data.first_party_allow_list": true, "data.guardrail": true, "data.severity_ranking": true,
}

// v9VendorRegoModules are the modules 0.8.x init seeded.
var v9VendorRegoModules = []string{"admission.rego", "guardrail.rego", "skill_actions.rego"}

// v9StockRegoDigests are the SHA-256 digests (CRLF read as LF) of the vendor
// modules 0.5.0 to 0.8.10 shipped, which init seeded byte for byte. A module
// that matches none holds edits of the operator, which the shipped module
// that replaces it does not carry (GAP-1498). Remove this table with the v8
// to v9 migration (1.1.0).
var v9StockRegoDigests = map[string][]string{
	"admission.rego": {
		"67a1831178e23d6bf8a4dd6d95ea53402c6827c6b1dc0536c8e7667c7586a53b", // 0.5.0 to 0.7.2
		"9dfe95603d4a738909795a4e77eb7315fc114768dee4f87ec9fab7759f8f30d5", // 0.8.0 to 0.8.10
	},
	"guardrail.rego":     {"18a563b37c0bec87a3743f566f4f4200bbac87977b783a290841d1aaeedfb753"},
	"skill_actions.rego": {"c3cb1ab336b9799ccecaef453cd33d583aeada0571e87092e1491c2c8ded924a"},
}

// v9StockRegoModule reports whether raw is a copy of the vendor module name
// that a 0.x release shipped.
func v9StockRegoModule(name string, raw []byte) bool {
	sum := sha256.Sum256(bytes.ReplaceAll(raw, []byte("\r\n"), []byte("\n")))
	return slices.Contains(v9StockRegoDigests[name], hex.EncodeToString(sum[:]))
}

// planRegoRefresh finds the modules the gateway loads that read a data
// document outside data.defenseclaw, which config_version 9 no longer
// provides: the gateway refuses such a bundle and uses the config-driven
// admission and thresholds (regodata, the check the policy engine runs). The
// gateway loads <policy_dir>/rego, or the modules kept flat in policy_dir
// when rego holds none (policy.resolveRegoDir), as 0.8.x did with them and
// their data.json (v8DataJSONIn, GAP-1453); a flat folder was left as it was
// and its custom block stopped applying without a word (GAP-1481). A
// pre-9 vendor module left by init (it only seeded missing files) is
// replaced on a per-user install with the shipped module (skill_actions.rego,
// removed in 9, is retired); on a managed host the admin owns policy_dir, so
// it is only reported. A document data.json held that the migration does not
// move is recorded in unenforced_rego_data: the rules that read it are no
// longer enforced, and the upgrade and doctor say so.
func (m *v9Migrator) planRegoRefresh() error {
	dir := filepath.Join(m.policyDir(), "rego")
	if !v8HasRegoModules(dir) {
		dir = m.policyDir()
	}
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
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	parsed, sources := map[string]*ast.Module{}, map[string][]byte{}
	for _, entry := range entries {
		name := entry.Name()
		if filepath.Ext(name) != ".rego" || !entry.Type().IsRegular() {
			continue
		}
		path := filepath.Join(dir, name)
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		mod, parseErr := ast.ParseModuleWithOpts(name, string(raw), ast.ParserOptions{RegoVersion: ast.RegoV1})
		if parseErr != nil {
			if slices.Contains(v9VendorRegoModules, name) {
				m.note("%s could not be parsed to check its data references (%v); it was left in place", path, parseErr)
			}
			continue
		}
		parsed[name], sources[name] = mod, raw
	}
	reads := map[string][]string{}
	for _, read := range regodata.OutsideReads(parsed, "data.defenseclaw.admission", "data.defenseclaw.guardrail") {
		reads[read.Module] = read.Docs
	}
	for _, name := range v9VendorRegoModules {
		if mod := parsed[name]; mod != nil && reads[name] == nil {
			if _, docs := regodata.ModuleReads(mod); len(docs) > 0 {
				reads[name] = docs
			}
		}
	}
	names := make([]string, 0, len(reads))
	for name := range reads {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		path := filepath.Join(dir, name)
		var effect string
		edited := false
		switch {
		case !slices.Contains(v9VendorRegoModules, name):
			m.note("%s reads %s, which config_version 9 no longer provides; the gateway refuses the Rego modules and "+
				"uses the config-driven admission and thresholds until it reads input instead", path, strings.Join(reads[name], ", "))
			effect = "the gateway refuses the Rego modules and uses the config-driven admission"
		case m.in.Managed || m.leftOutsideRollbackCopy(path):
			m.note("%s is a pre-9 module that reads data.json; the gateway refuses it and uses the config-driven "+
				"admission and thresholds until it is replaced with the shipped module", path)
			effect = "the gateway refuses the module and uses the config-driven admission"
		default:
			m.rego = append(m.rego, v9RegoRefresh{path: path, data: shipped[name]})
			edited = !v9StockRegoModule(name, sources[name])
			if shipped[name] == nil {
				m.note("%s (removed in 9) is kept as %s%s", path, name, DataJSONMigratedSuffix)
				effect = "the module is retired and kept as " + name + DataJSONMigratedSuffix
			} else {
				m.note("%s is a pre-9 module that reads data.json; it is kept as %s%s and replaced with the shipped module",
					path, name, DataJSONMigratedSuffix)
				effect = "the module is kept as " + name + DataJSONMigratedSuffix + " and replaced with the shipped one"
			}
		}
		var lost []string
		for _, doc := range reads[name] {
			if !v9DataJSONDocs[doc] {
				lost = append(lost, doc)
			}
		}
		if edited {
			// Rules added to a vendor module may read only the data.json
			// documents the migration moves; the shipped module still has none
			// of them (GAP-1498).
			read := ""
			if len(lost) > 0 {
				read = "; it reads " + strings.Join(lost, ", ") + ", which 1.0 no longer loads (no data.json)"
			}
			m.record.UnenforcedRegoData = append(m.record.UnenforcedRegoData, fmt.Sprintf(
				"%s differs from every copy 0.8.x shipped, so it holds rules added after install%s: %s, and those "+
					"rules are not enforced. The saved copy is %s%s. Express them in config.yaml (asset_policy, "+
					"admission) or in a module that reads input, then run `defenseclaw-gateway config migrate --ack`",
				path, read, effect, path, DataJSONMigratedSuffix))
			continue
		}
		if len(lost) > 0 {
			m.record.UnenforcedRegoData = append(m.record.UnenforcedRegoData, fmt.Sprintf(
				"%s reads %s, which 1.0 no longer loads (no data.json): the rules that use it are not enforced (%s). "+
					"Express them in config.yaml (asset_policy, admission) or in a module that reads input, then run "+
					"`defenseclaw-gateway config migrate --ack`", path, strings.Join(lost, ", "), effect))
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
// exist: the files go to a new sibling folder that is renamed into place. A
// fixed <dir>.seeding sibling was removed first, even when it was a custom
// pack the config selects (GAP-1490).
func seedShippedRulePack(dir, name string) error {
	files, err := policyassets.Files()
	if err != nil {
		return err
	}
	prefix := "guardrail/" + name + "/"
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		return err
	}
	staging, err := os.MkdirTemp(filepath.Dir(dir), filepath.Base(dir)+".seeding-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(staging)
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
			return err
		}
		wrote = true
	}
	if !wrote {
		return fmt.Errorf("this build ships no %s rule pack", name)
	}
	return os.Rename(staging, dir)
}

// refreshRegoModules replaces every planned pre-9 module. A failure is
// returned once the others ran: the gateway refuses a bundle that still holds
// a pre-9 module, so the migration must not be recorded as complete
// (GAP-1497).
func (m *v9Migrator) refreshRegoModules(written *[]string) error {
	var errs []error
	for _, module := range m.rego {
		if err := m.refreshRegoModule(module); err != nil {
			errs = append(errs, fmt.Errorf("replace the pre-9 Rego module %s: %w", module.path, err))
			continue
		}
		if written != nil {
			*written = append(*written, module.path+DataJSONMigratedSuffix)
		}
	}
	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("config: %w; the gateway refuses a pre-9 module, so the config_version 9 migration stays "+
		"pending: fix it and run `defenseclaw-gateway config migrate --to 9` again", errors.Join(errs...))
}

// refreshRegoModule keeps the pre-9 module as <name>.migrated-v9 and puts the
// shipped one in its place (nil data retires it). The copy is written before
// the module is replaced, so a stop leaves the module pre-9, which a retry
// refreshes (finishPending), or replaced: never missing.
func (m *v9Migrator) refreshRegoModule(module v9RegoRefresh) error {
	info, err := os.Stat(module.path)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(module.path)
	if err != nil {
		return err
	}
	if err := cfgtxn.WriteFileDurable(module.path+DataJSONMigratedSuffix, raw, info.Mode().Perm()); err != nil {
		return err
	}
	if module.data == nil {
		return os.Remove(module.path)
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
	// sum is the sha256 of the bytes read, which the commit compares the
	// file with (GAP-1148).
	sum    [sha256.Size]byte
	raw    map[string]json.RawMessage
	Config struct {
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
	data.present, data.sum = true, sha256.Sum256(raw)
	return data, nil
}

// dataJSONChanged reports whether the data.json at path is no longer the one
// the migration planned from: changed, created or removed since.
func (d *v9DataJSON) dataJSONChanged(path string) bool {
	if d == nil || strings.TrimSpace(path) == "" {
		return false
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return d.present
	}
	return err != nil || !d.present || sha256.Sum256(raw) != d.sum
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

// v9ShippedFirstParty are the first_party_allow_list entries data.json shipped
// before 1.0: the 0.8.0 to 0.8.10 list and the broader 0.4 to 0.7 one, which a
// bridge upgrade can carry. A shipped list was never an operator's choice
// (`policy activate` copied the same list from the preset), so it is not
// pinned: the 1.0 built-in list applies, as on a fresh install, and a migrated
// preset still matches its named policy in `policy list` (GAP-0971).
var v9ShippedFirstParty = map[string][][]AdmissionFirstParty{
	AdmissionTypeSkill: {
		{{Name: "codeguard", SourcePathContains: []string{".openclaw/workspace/skills/codeguard", ".openclaw/skills/codeguard",
			".zeptoclaw/skills/codeguard", ".claude/skills/codeguard", ".codex/skills/codeguard"}}},
		{{Name: "codeguard", SourcePathContains: []string{".defenseclaw", "workspace/skills/codeguard", "skills/codeguard",
			".openclaw/workspace/skills", ".openclaw/skills", ".zeptoclaw/skills", ".claude/skills", ".codex/skills"}}},
	},
	AdmissionTypePlugin: {
		{{Name: "defenseclaw", SourcePathContains: []string{".openclaw/extensions/defenseclaw", ".zeptoclaw/extensions/defenseclaw",
			".claude/extensions/defenseclaw", ".codex/extensions/defenseclaw"}}},
		{{Name: "defenseclaw", SourcePathContains: []string{".defenseclaw", "extensions/defenseclaw", ".openclaw/extensions",
			".zeptoclaw/extensions", ".claude/extensions", ".codex/extensions", ".codex-plugin"}}},
	},
}

func v9IsShippedFirstParty(assetType string, list []AdmissionFirstParty) bool {
	for _, shipped := range v9ShippedFirstParty[assetType] {
		if v9SameFirstParty(list, shipped) {
			return true
		}
	}
	return false
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
			if v9SameFirstParty(byType[assetType], v9BuiltinFirstParty[assetType]) {
				continue
			}
			if v9IsShippedFirstParty(assetType, byType[assetType]) {
				m.note("data.json first_party_allow_list for %s is the list DefenseClaw 0.x shipped; the 1.0 built-in list applies", assetType)
				continue
			}
			if m.keepConfiguredFirstParty(root, assetType, byType[assetType]) {
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
	return m.rebaseEditedPresetPacks(guardrail)
}

// rebaseEditedPresetPacks moves each scope that selects a default, strict or
// permissive folder of policy_dir that its operator edited in place onto the
// 1.0 copy of that folder, as rulePackFor does for a custom pack. The upgrade
// keeps such a folder as it is, so the 1.0 gateway refused its two rule files
// of one category (GAP-1479), and only recorded a match of its rules that
// blocked a tool call with a pattern alone and of its 0.8.x copies of the
// built-in action rules (GAP-1480, GAP-0360). The global scope selects the
// default pack when it names none (0.8.x init writes no rule_pack_dir). A
// folder that some 0.8.x release shipped and nobody edited keeps its preset
// name: the upgrade replaces it with this release's copy. A managed host's
// packs belong to its administrator, and a read-only load writes no copy.
func (m *v9Migrator) rebaseEditedPresetPacks(guardrail *yaml.Node) error {
	if m.in.RebaseRulePack == nil || m.in.RulePackDigest == nil || m.in.Managed || m.in.InMemory {
		return nil
	}
	rebased := map[string]string{}
	for _, scope := range v9GuardrailScopes(guardrail) {
		preset := strings.TrimSpace(yamlScalarValue(v8YAMLMapValue(scope.node, "rule_pack")))
		if preset == "" && scope.name == "guardrail" {
			preset = "default"
		}
		if !v9BuiltinPacks[preset] {
			continue
		}
		dir := filepath.Join(expandPath(m.policyDir()), "guardrail", preset)
		name, done := rebased[preset]
		if !done {
			var err error
			if name, err = m.rebaseEditedPresetPack(guardrail, preset, dir); err != nil {
				return fmt.Errorf("config: %s.rule_pack %s: %w", scope.name, preset, err)
			}
			rebased[preset] = name
		}
		if name == "" {
			continue
		}
		v9Set(scope.node, v9Scalar(name), "rule_pack")
		m.moved("config", dir, scope.name+".rule_pack", name)
		if scope.name == "guardrail" {
			m.globalPackPosture = v9DirPosture(dir)
		}
	}
	return nil
}

// rebaseEditedPresetPack pins the 1.0 copy of the preset folder dir when its
// operator edited it and returns the name of that custom pack; "" leaves the
// folder selected by its preset name: it is a pack 0.8.x shipped, needs no
// 1.0 copy, or could not be rebased (RulePackRebaseFailures names it).
func (m *v9Migrator) rebaseEditedPresetPack(guardrail *yaml.Node, preset, dir string) (string, error) {
	clean := filepath.Clean(dir)
	if info, err := os.Lstat(clean); err != nil || !info.IsDir() || v9Stock08Pack(preset, clean) {
		return "", nil
	}
	target, digest, err := m.rebaseRulePack(clean, clean)
	if err != nil || target == clean {
		return "", err
	}
	name := m.pinCustomPack(guardrail, preset, target, digest)
	m.note("%s is the %s pack edited in place; the upgrade keeps it as it is for a rollback to 0.8.x, and the config "+
		"selects its 1.0 copy %s as guardrail.custom_packs.%s instead of the %s preset", clean, preset, target, name, preset)
	return name, nil
}

// v9Stock08PackDigests are the digests (profile_digest of
// cli/defenseclaw/guardrail_profiles.py, whose STOCK_PROFILE_DIGESTS lists
// them too) of the default, strict and permissive packs that 0.8.0 to 0.8.3
// and 0.8.4 to 0.8.10 shipped. Keep until the config_version 8 migration is
// dropped (1.1.0).
var v9Stock08PackDigests = map[string][]string{
	"default": {"5b9ca53ad605b53d1d1618b51e52c658140d42190e6f903abaaca604ae145c93",
		"9dc9a1aa028a8b2232babe38e8519f864a1f6d3a6b3990150c2ec3f907d71b8a"},
	"strict": {"9a718f87b06f75cfb1f4fa223fc6f3692ced3ecc17c10b5c8b96fff617d5da67",
		"5b9b0f79c491c27b3feed63b90765091d37345621a95792ebcd34195abb097fd"},
	"permissive": {"fa8ca0ad415436e8b4f5d6043f36de782cfe27bfbfca83f27d2359b97914f5f7",
		"29ce292e52f2fac289d6567ec7994b1f17af98e3fd1c4a5e2084f8c8a97b5371"},
}

// v9Stock08Pack reports whether dir holds exactly the files of the preset
// pack some 0.8.x release shipped, by the digest the Python upgrade uses to
// refresh an unedited pack.
func v9Stock08Pack(preset, dir string) bool {
	digest, err := v9ProfileDigest(dir)
	return err == nil && slices.Contains(v9Stock08PackDigests[preset], digest)
}

// v9ProfileDigest is guardrail_profiles.profile_digest: the sha256 over the
// relative slash path of each file, a NUL, the hex sha256 of its bytes and a
// newline, in path order, leaving out dot files and __pycache__. A link or
// other non-regular file, or more files than a shipped pack has, is not a
// shipped pack.
func v9ProfileDigest(dir string) (string, error) {
	sums := map[string]string{}
	err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || path == dir {
			return err
		}
		if name := entry.Name(); strings.HasPrefix(name, ".") || name == "__pycache__" {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() || len(sums) >= 64 {
			return errors.New("not a shipped rule pack")
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		sums[filepath.ToSlash(rel)] = hex.EncodeToString(sum[:])
		return nil
	})
	if err != nil {
		return "", err
	}
	h := sha256.New()
	for _, rel := range slices.Sorted(maps.Keys(sums)) {
		h.Write([]byte(rel + "\x00" + sums[rel] + "\n"))
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// embeddedPackDropped reports whether dropping an empty rule_pack_dir changes
// the pack: config_version 9 keeps the embedded packs only for a standalone
// Windows host without a policy_dir of its own (standaloneRulePackDefault);
// everywhere else the implicit default pack is a folder.
func (m *v9Migrator) embeddedPackDropped() bool {
	return ((runtime.GOOS != "windows" || !(m.in.Managed)) || strings.TrimSpace(yamlScalarValue(v8YAMLMapValue(m.root, "policy_dir"))) != "")
}

// v9DirPosture is the posture the gateway gives a rule-pack directory: the
// manifest posture (defenseclaw-pack.json, guardrail.ReadPackPosture), else
// the folder-name table (strict, permissive, else default).
func v9DirPosture(dir string) string {
	if posture := packManifestPosture(dir); posture != "" {
		return posture
	}
	return packFolderPosture(dir)
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
	// Only default, strict and permissive are presets. 0.8.x never shipped a
	// guardrail/balanced folder, so one is the operator's own pack: it is
	// pinned under its own name, not mapped to the default folder (GAP-1452).
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
	if target == clean && digest == "" {
		if digest, err = m.in.RulePackDigest(clean); err != nil {
			return "", nil, fmt.Errorf("load custom rule pack %s: %w", dir, err)
		}
	}
	return m.pinCustomPack(guardrail, base, target, digest), nil, nil
}

// pinCustomPack names the folder target guardrail.custom_packs.<stem of
// base>, custom-<base> for a preset name, pinned by digest, and returns the
// name.
func (m *v9Migrator) pinCustomPack(guardrail *yaml.Node, base, target, digest string) string {
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
	return name
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
		digest, loadErr := m.in.RulePackDigest(clean)
		if loadErr != nil {
			// Nor does it load as it is: the rebase error names what to
			// change, such as two rule files of one category (GAP-1339).
			return "", "", fmt.Errorf("custom rule pack %s: %w", dir, err)
		}
		failure := fmt.Sprintf("%s could not be rebased on the 1.0 default pack (%v). It is pinned as it is, so its "+
			"0.8.x copies of built-in rules and its rules without an expression no longer block a tool call, they "+
			"only record the match: copy policies/guardrail/default to a new folder, add your rules with an "+
			"expression, then run defenseclaw guardrail use-pack <folder>", dir, err)
		m.record.RulePackRebaseFailures = append(m.record.RulePackRebaseFailures, failure)
		m.note("%s", failure)
		return clean, digest, nil
	}
	if plan == nil {
		return clean, "", nil
	}
	if m.rebasedPacks == nil {
		m.rebasedPacks, m.rebasedFrom, m.rebasedDigests = map[string]map[string][]byte{}, map[string]string{}, map[string]string{}
	}
	if plan.Files == nil {
		// Nothing to rewrite: pinned as it is, once per folder.
		m.rebasedFrom[clean] = clean
		m.noteDetectionOnly(dir, plan.AlertOnly)
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
	m.rebasedPacks[target], m.rebasedFrom[clean], m.rebasedDigests[target] = plan.Files, target, plan.Digest
	m.record.RenamedRules = append(m.record.RenamedRules, plan.Renamed...)
	m.record.ExpressedRules = append(m.record.ExpressedRules, plan.Expressed...)
	expressed := ""
	if len(plan.Expressed) > 0 {
		// GAP-1344, GAP-1478: 0.8.x matched the literal anywhere in the
		// tool call; the gateway runs the pattern over its text for these.
		expressed = fmt.Sprintf("these got an expression and, as on 0.8.x, block a tool call whose text holds "+
			"their literal (as a whole word when the pattern has \\b), file content a tool writes included: %s",
			strings.Join(plan.Expressed, ", "))
	}
	if len(plan.Merged) > 0 {
		// 1.0 refuses two rule files of one category; 0.8.x enforced only
		// the last of them (GAP-1339).
		for _, merged := range plan.Merged {
			m.record.RuleFileMerges = append(m.record.RuleFileMerges, target+": "+merged)
		}
		m.note("%s has rule files that share a category, which 1.0 refuses (0.8.x enforced only the last of them). "+
			"Its 1.0 copy %s has one file per category and keeps every rule: %s; %s is kept for a rollback to 0.8.x",
			dir, target, strings.Join(plan.Merged, "; "), dir)
	}
	if plan.Updated > 0 {
		kept := fmt.Sprintf("%d built-in rules are their 1.0 versions", plan.Updated)
		if len(plan.Disabled) > 0 {
			kept += fmt.Sprintf(", %s stay off (the copy had removed them)", strings.Join(plan.Disabled, ", "))
		}
		if len(plan.Carried) > 0 {
			kept += fmt.Sprintf("; your own rules were carried over: %s", strings.Join(plan.Carried, ", "))
		}
		if len(plan.Renamed) > 0 {
			// GAP-1314: under the built-in ID the gateway checks a match
			// against the shipped rule's meaning and drops the operator's.
			kept += fmt.Sprintf("; built-in rules you gave a pattern of your own are now rules of yours under a "+
				"new ID, next to the shipped rule (%s): use the new ID in audit searches and suppressions",
				strings.Join(plan.Renamed, ", "))
		}
		if expressed != "" {
			kept += "; " + expressed
		}
		m.note("%s is a 0.8.x copy of the default pack's command, path, agent-file or C2 rules, which have no expression; "+
			"in 1.0 such a rule blocks only with one, so the pack enforced nothing. It was rebased on the 1.0 default "+
			"pack in %s, which is pinned instead (%s); %s is kept for a rollback to 0.8.x", dir, target, kept, dir)
	} else if expressed != "" {
		// Only the operator's own rules changed (GAP-1225).
		m.note("%s has rules of yours that blocked a tool call with their pattern alone, which 1.0 does only with an "+
			"expression. Its 1.0 copy %s is pinned instead (%s); %s is kept for a rollback to 0.8.x",
			dir, target, expressed, dir)
	}
	if len(plan.Linked) > 0 {
		// 0.8.x read a rule file through a link; 1.0 refuses a link in a
		// pack (GAP-1346).
		m.note("%s reads files through links, which 1.0 refuses in a rule pack (%s). Its 1.0 copy %s holds the "+
			"files they point to and is pinned instead: edit the copy from now on; %s is kept for a rollback to 0.8.x",
			dir, strings.Join(plan.Linked, ", "), target, dir)
	}
	m.noteDetectionOnly(target, plan.AlertOnly)
	return target, plan.Digest, nil
}

// noteDetectionOnly names the operator's own rules that blocked a tool call
// on 0.8.x with their pattern and, with no expression, only record it in 1.0
// (GAP-1225). The upgrade prints DetectionOnlyRules.
func (m *v9Migrator) noteDetectionOnly(pack string, ids []string) {
	if len(ids) == 0 {
		return
	}
	m.record.DetectionOnlyRules = append(m.record.DetectionOnlyRules, ids...)
	m.note("%d custom rule(s) in %s now detection-only for tool calls: %s; add an expression, see policies/rules",
		len(ids), pack, strings.Join(ids, ", "))
}

// MigratedRuleLines is one line per rule of the operator's that the rebase
// of a custom pack changed: the rules that still block a tool call as on
// 0.8.x with an expression derived from their literal pattern (and under
// which ID, for a built-in rule they gave a pattern of their own, GAP-1314),
// and the detection-only ones (GAP-1469). `config migrate` prints them; the
// Python upgrade summary and doctor read the same record fields.
func MigratedRuleLines(r MigrationRecord) []string {
	was := map[string]string{}
	for _, renamed := range r.RenamedRules {
		if old, own, ok := strings.Cut(renamed, " -> "); ok {
			was[own] = old
		}
	}
	name := func(id string) string {
		if old := was[id]; old != "" {
			return fmt.Sprintf("%s (your edited %s; %s is the shipped 1.0 rule)", id, old, old)
		}
		return id
	}
	var lines []string
	for _, id := range r.ExpressedRules {
		lines = append(lines, name(id)+": enforced as on 0.8.x (its severity decides block or alert) when "+
			"the text of a tool call holds its literal (as a whole word when the pattern has \\b): a command "+
			"word, a quoted string, a file path, a network host or text a tool writes, such as file content")
	}
	for _, id := range r.DetectionOnlyRules {
		lines = append(lines, name(id)+": detection-only for tool calls in 1.0 (its pattern is not a literal); "+
			"add an expression to block")
	}
	return lines
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
	case v9SkillPolicies[policy]:
	case policy == SkillScannerPolicyCustom && v8YAMLMapValue(skill, "policy_file") != nil:
		// Already the config_version 9 form: the name and its pinned file.
	default:
		// Any other value is the path of a policy file. That includes a
		// file named custom: 0.8.x had no custom name, and keeping it as
		// one, with no policy_file, failed the upgrade (GAP-1286). The
		// file is pinned at the absolute path read here, so the 1.0
		// gateway finds it whatever directory it starts in.
		pinned, raw, err := m.v8SkillScannerPolicyFile(policy)
		if err != nil {
			return err
		}
		v9Set(skill, v9Scalar(SkillScannerPolicyCustom), "policy")
		ref := v9Mapping("path", v9Scalar(pinned), "digest", v9Scalar("sha256:"+cfgtxn.SHA256Hex(raw)))
		v9Set(skill, ref, "policy_file")
		m.moved("config", prefix+"policy", prefix+"policy_file", map[string]string{"path": pinned})
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

// v8SkillScannerPolicyFile reads the policy file a 0.8.x
// scanners.skill_scanner.policy names. 0.8.x passed a relative path to the
// scanner as written, so it resolved against the working directory of the
// scanning process: the gateway, which the 0.8.x daemon started in data_dir,
// or `defenseclaw skill scan` in the user's shell. The migration looks in
// data_dir first, then in its own working directory, so `defenseclaw migrate`
// upgrades the same home the same way from any directory (GAP-0004).
func (m *v9Migrator) v8SkillScannerPolicyFile(policy string) (string, []byte, error) {
	candidates := []string{policy}
	if !filepath.IsAbs(policy) {
		candidates = candidates[:0]
		if dir := strings.TrimSpace(m.dataDir()); dir != "" {
			if abs, err := filepath.Abs(filepath.Join(expandPath(dir), policy)); err == nil {
				candidates = append(candidates, abs)
			}
		}
		if abs, err := filepath.Abs(policy); err == nil && !slices.Contains(candidates, abs) {
			candidates = append(candidates, abs)
		}
	}
	for _, path := range candidates {
		raw, err := os.ReadFile(path)
		if err == nil {
			return path, raw, nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return "", nil, fmt.Errorf("config: read custom skill-scanner policy %q: %w", policy, err)
		}
	}
	return "", nil, fmt.Errorf("config: custom skill-scanner policy %q not found (looked for %s); "+
		"set scanners.skill_scanner.policy to the policy file's absolute path, then run `defenseclaw migrate`",
		policy, strings.Join(candidates, " and "))
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
// folder implicitly, and since 9 only configured packs load. A managed
// standalone host loads only pinned packs, so pin the bytes v8 loaded: the
// installed packs, and on a managed host also the files the configured
// signature_packs entries name, wherever they are (GAP-1287).
func (m *v9Migrator) migrateSignaturePacks(root *yaml.Node) error {
	dataDir := m.dataDir()
	installed, _ := filepath.Glob(filepath.Join(dataDir, "signature-packs", "*.json"))
	discovery := v8YAMLMapValue(root, "ai_discovery")
	packs := v8YAMLMapValue(discovery, "signature_packs")
	pins := v8YAMLMapValue(discovery, "signature_pack_digests")
	secureClient := v9SecureClientDocument(root)
	listed := map[string]bool{}
	var listedFiles []string
	for _, item := range v9SeqItems(packs) {
		entry := strings.TrimSpace(expandPath(strings.TrimSpace(item.Value)))
		if entry == "" {
			continue
		}
		listed[filepath.Clean(entry)] = true
		if m.in.Managed && !secureClient {
			files, err := v9SignaturePackFiles(entry)
			if err != nil {
				return err
			}
			listedFiles = append(listedFiles, files...)
		}
	}
	if len(installed) == 0 && len(listedFiles) == 0 {
		return nil
	}
	pinned := map[string]bool{}
	if pins != nil && pins.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(pins.Content); i += 2 {
			pinned[filepath.Clean(expandPath(pins.Content[i].Value))] = true
		}
	}
	var order []string
	installedPins, listedPins := map[string]string{}, map[string]string{}
	pin := func(path, why string, into map[string]string) error {
		path = filepath.Clean(path)
		if secureClient || pinned[path] {
			return nil
		}
		if _, done := installedPins[path]; done {
			return nil
		}
		if _, done := listedPins[path]; done {
			return nil
		}
		raw, err := os.ReadFile(path) // #nosec G304 -- a pack in the data_dir or named by ai_discovery.signature_packs.
		if err != nil {
			return fmt.Errorf("config: read signature pack %s (%s): %w; a managed host loads only the packs pinned in ai_discovery.signature_pack_digests, so the migration pins it: make the file readable, or remove it from ai_discovery.signature_packs, and run the upgrade again", path, why, err)
		}
		into[path] = "sha256:" + cfgtxn.SHA256Hex(raw)
		order = append(order, path)
		return nil
	}
	var added []string
	for _, path := range installed {
		if !listed[filepath.Clean(path)] {
			added = append(added, path)
		}
		if err := pin(path, "installed in the data_dir", installedPins); err != nil {
			return err
		}
	}
	for _, path := range listedFiles {
		if err := pin(path, "listed in ai_discovery.signature_packs", listedPins); err != nil {
			return err
		}
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
	if len(order) > 0 {
		if pins == nil || pins.Kind != yaml.MappingNode {
			pins = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			v9Set(root, pins, "ai_discovery", "signature_pack_digests")
		}
		for _, path := range order {
			digest, ok := installedPins[path]
			if !ok {
				digest = listedPins[path]
			}
			v9Set(pins, v9Scalar(digest), path)
		}
	}
	if len(installedPins) > 0 {
		m.moved("config", filepath.Join(dataDir, "signature-packs", "*.json"), "ai_discovery.signature_pack_digests", installedPins)
	}
	if len(listedPins) > 0 {
		m.moved("config", "ai_discovery.signature_packs", "ai_discovery.signature_pack_digests", listedPins)
	}
	return nil
}

// v9SignaturePackFiles lists the files one ai_discovery.signature_packs
// entry names, the way the catalog loader expands it: a directory is its
// *.json, a glob its *.json matches, a path the file. An entry that names no
// file yet has nothing to pin.
func v9SignaturePackFiles(entry string) ([]string, error) {
	pattern := entry
	if info, err := os.Stat(pattern); err == nil && info.IsDir() {
		pattern = filepath.Join(pattern, "*.json")
	}
	if strings.ContainsAny(pattern, "*?[") {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			return nil, fmt.Errorf("config: ai_discovery.signature_packs entry %s is not a valid glob: %w", entry, err)
		}
		var files []string
		for _, match := range matches {
			if info, err := os.Stat(match); err == nil && !info.IsDir() && strings.EqualFold(filepath.Ext(match), ".json") {
				files = append(files, match)
			}
		}
		return files, nil
	}
	if _, err := os.Stat(pattern); errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	return []string{pattern}, nil
}

// ---------------------------------------------------------------------------
// The retired openshell-sandbox (0.0.x) standalone integration

// migrateRetiredStandaloneSandbox resets what the retired openshell-sandbox
// (0.0.x) standalone integration left in a 0.8.x config. That integration
// recorded openshell.mode: standalone and the sandbox user's home
// (openshell.sandbox_home) beside its runtime pin (openshell.version,
// policy_dir, auto_pair, host_networking), and pointed guardrail.host (where the gateway
// API and the guardrail proxy listened) and gateway.host (the sandboxed
// OpenClaw gateway) at its veth link, 10.200.0.1 and 10.200.0.2 by default.
// It also pinned the OpenClaw home it moved (claw.openclaw_home_original,
// which 0.8.x wrote empty everywhere else). 1.0 drives no such sandbox,
// keeps no shim for those addresses and reads no pin, so the three keys go,
// on every config (a pin is named in a note, for the manual clean-up), and
// on a standalone one so do the two hosts (unless already loopback), which
// then take their defaults: the upgraded host binds and probes the API on
// loopback like every other one, instead of dialing a link nothing serves
// and rolling the upgrade back. Running it again changes nothing. The root
// units, network namespace, NAT rules and sandbox user the integration set
// up are removed by hand (the sandbox guide's "Remove a retired standalone
// sandbox").
// retiredOpenShellKeys are the openshell sub-keys of the retired 0.0.x
// integration, which 1.0 does not read.
var retiredOpenShellKeys = []string{"mode", "sandbox_home", "policy_dir", "version", "auto_pair", "host_networking"}

func (m *v9Migrator) migrateRetiredStandaloneSandbox(root *yaml.Node) {
	openshell := v8YAMLMapValue(root, "openshell")
	standalone := strings.TrimSpace(yamlScalarValue(v8YAMLMapValue(openshell, "mode"))) == "standalone"
	// Every sub-key of that integration goes: 1.0 reads none of them
	// (policy_dir and version pinned its 0.0.x runtime, 0.6.2 by default).
	for _, key := range retiredOpenShellKeys {
		if v9Pop(openshell, key) != nil {
			m.record.Removed = append(m.record.Removed, "openshell."+key)
		}
	}
	if pin := v9Pop(v8YAMLMapValue(root, "claw"), "openclaw_home_original"); pin != nil {
		m.record.Removed = append(m.record.Removed, "claw.openclaw_home_original")
		if home := strings.TrimSpace(yamlScalarValue(pin)); home != "" {
			m.note("claw.openclaw_home_original %s was the OpenClaw home the retired standalone sandbox moved; point claw.home_dir and claw.config_file back at it if they name the sandbox user's home", home)
		}
	}
	if !standalone {
		return
	}
	for _, section := range []string{"guardrail", "gateway"} {
		node := v8YAMLMapValue(root, section)
		switch host := strings.TrimSpace(yamlScalarValue(v8YAMLMapValue(node, "host"))); host {
		case "", "localhost", "127.0.0.1", "::1", "[::1]":
		default:
			v9Pop(node, "host")
			m.record.Removed = append(m.record.Removed, section+".host")
			m.note("%s.host %s was the retired standalone sandbox's network link; it is reset to its default", section, host)
		}
	}
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
//
// The fold keeps the provider registry the gateway used. A provider the
// overlay names twice becomes one entry with the 0.8.x overlay merge rules
// (configs.ApplyOverlay: the lists are unioned and the later entry's values
// win), as the gateway read the file; skipping the second entry lost its
// domains, env keys and settings (GAP-0709). A provider llm_providers.custom
// already has takes the overlay's other list items, map keys and the fields
// it leaves unset: the gateway applies llm_providers over the overlay, so
// config's values were the ones in use, except extra_headers, which a
// same-name merge dropped before 1.0.3 (configs.ApplyLegacyOverlay). When the
// overlay sets a field to a value other than config's, or names a provider
// twice with different values for a header, nothing is folded (GAP-0163):
// config.yaml and the file stay as they are, the gateway keeps merging the
// file with the rule it had (GAP-0184), and m.fold names each provider and
// field and whose value is in use, so no value in use changes and none is
// dropped unless the operator chooses it.
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
	type overlayEntry struct {
		key, name string
		node      *yaml.Node
		tls       bool
		ca        *v9RegoRefresh
	}
	var entries []*overlayEntry
	for _, p := range overlay.Providers {
		name := strings.TrimSpace(p.Name)
		if name == "" {
			continue
		}
		entry := LLMCustomProvider{
			Name: name, Domains: p.Domains, EnvKeys: p.EnvKeys, BaseProviderType: p.BaseProviderType,
			BaseURL: p.BaseURL, AllowedRequests: p.AllowedRequests, AvailableModels: p.AvailableModels,
			RequestPathOverrides: p.RequestPathOverrides, ExtraHeaders: p.ExtraHeaders,
		}
		if p.ProfileID != nil {
			entry.ProfileID = *p.ProfileID
		}
		var ca *v9RegoRefresh
		if t := p.TLS; t != nil {
			entry.TLS = &LLMCustomProviderTLS{InsecureSkipVerify: t.InsecureSkipVerify}
			if pem := strings.TrimSpace(t.CACertPEM); pem != "" {
				ca = &v9RegoRefresh{path: filepath.Join(m.dataDir(), "provider-ca", v9ProviderCAName(name)), data: []byte(t.CACertPEM)}
				entry.TLS.CACertFile = ca.path
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
		var node yaml.Node
		if err := node.Encode(entry); err != nil {
			m.note("could not move provider %q from %s: %v", entry.Name, path, err)
			return
		}
		entries = append(entries, &overlayEntry{key: strings.ToLower(name), name: name, node: &node, tls: entry.TLS != nil, ca: ca})
	}
	// The overlay's own same-name entries merge first, in file order.
	var folded []*overlayEntry
	index := map[string]*overlayEntry{}
	var twice []string
	shadowed := map[string][]string{}
	for _, e := range entries {
		first := index[e.key]
		if first == nil {
			index[e.key] = e
			folded = append(folded, e)
			continue
		}
		sameTLS := func(_, _ *yaml.Node) bool {
			return v9TLSInsecure(v8YAMLMapValue(first.node, "tls")) == v9TLSInsecure(v8YAMLMapValue(e.node, "tls")) &&
				bytes.Equal(v9CAData(first.ca), v9CAData(e.ca))
		}
		for _, field := range v9ProviderConflicts(first.node, e.node, sameTLS) {
			if !slices.Contains(shadowed[first.name], field) {
				shadowed[first.name] = append(shadowed[first.name], field)
			}
		}
		v9MergeOverlayProvider(first.node, e.node)
		// The later tls replaces the earlier one, with or without its CA.
		if e.tls {
			first.tls, first.ca = true, e.ca
		}
		if !slices.Contains(twice, first.name) {
			twice = append(twice, first.name)
		}
	}
	list := v8YAMLMapValue(v8YAMLMapValue(root, "llm_providers"), "custom")
	byName := map[string]*yaml.Node{}
	for _, item := range v9SeqItems(list) {
		if key := strings.ToLower(yamlScalarValue(v8YAMLMapValue(item, "name"))); byName[key] == nil {
			byName[key] = item
		}
	}
	var conflicts []ProviderConflict
	for _, e := range folded {
		into := byName[e.key]
		if into == nil {
			continue
		}
		ca := e.ca
		sameTLS := func(have, value *yaml.Node) bool {
			return v9TLSInsecure(have) == v9TLSInsecure(value) && v9ConfigCAMatches(have, ca)
		}
		if fields := v9ProviderConflicts(into, e.node, sameTLS); len(fields) > 0 {
			conflicts = append(conflicts, ProviderConflict{Provider: yamlScalarValue(v8YAMLMapValue(into, "name")), Fields: fields})
		}
	}
	var repeated []ProviderConflict
	for _, name := range twice {
		var fields []string
		for _, field := range shadowed[name] {
			if strings.HasPrefix(field, v9HeaderField) {
				fields = append(fields, field)
			}
		}
		if len(fields) > 0 {
			repeated = append(repeated, ProviderConflict{Provider: name, Fields: fields})
		}
	}
	// The headers the gateway sends now (the legacy merge rule, while the
	// file is a live input) and once config.yaml is the only input.
	overlayHeaders, configHeaders := v9OverlayHeaderProviders(overlay.Providers), v9ConfigHeaderProviders(v9SeqItems(list))
	live := v9RegistryHeaders(overlayHeaders, configHeaders, true)
	configValues := map[string]map[string]string{}
	for _, p := range configHeaders {
		if key := strings.ToLower(p.Name); configValues[key] == nil {
			configValues[key] = p.ExtraHeaders
		}
	}
	unsettled := map[string]bool{}
	for i := range conflicts {
		c := &conflicts[i]
		c.InUse = make(map[string]string, len(c.Fields))
		for _, field := range c.Fields {
			c.InUse[field] = v9InUseConfig
			if header, ok := strings.CutPrefix(field, v9HeaderField); ok {
				unsettled[strings.ToLower(c.Provider)+"\x00"+header] = true
				value, sent := live.get(c.Provider, header)
				switch config, set := configValues[strings.ToLower(c.Provider)][header]; {
				case !sent:
					c.InUse[field] = v9InUseNone
				case !set || config != value:
					c.InUse[field] = ProvidersOverlayFile
				}
			}
		}
	}
	for i := range repeated {
		c := &repeated[i]
		c.InUse = make(map[string]string, len(c.Fields))
		for _, field := range c.Fields {
			header := strings.TrimPrefix(field, v9HeaderField)
			unsettled[strings.ToLower(c.Provider)+"\x00"+header] = true
			c.InUse[field] = ProvidersOverlayFile
			if _, sent := live.get(c.Provider, header); !sent {
				c.InUse[field] = v9InUseNone
			}
		}
	}
	after := v9HeadersAfterFold(live, v9RegistryHeaders(overlayHeaders, configHeaders, false), unsettled)
	var sentLater string
	if len(after) > 0 {
		named := make([]string, 0, len(after))
		for _, p := range after {
			named = append(named, fmt.Sprintf("%s (%s)", p.Provider, strings.Join(p.Fields, ", ")))
		}
		sentLater = strings.Join(named, "; ")
	}
	if len(conflicts) > 0 || len(repeated) > 0 {
		var reasons []string
		for _, c := range conflicts {
			reasons = append(reasons, "config.yaml and the file set different values for "+v9ConflictText(c, "the file's value is in use"))
		}
		for _, c := range repeated {
			reasons = append(reasons, "the file sets different values for "+
				v9ConflictText(c, "the first entry's value is in use")+" in two entries of the same name")
		}
		then := ""
		if sentLater != "" {
			then = "; the gateway then also sends extra_headers it does not send now: " + sentLater
		}
		m.fold = &ProvidersFold{Overlay: path, Conflicts: conflicts, Repeated: repeated, HeadersAfterFold: after, Refused: fmt.Sprintf(
			"%s was not folded into config.yaml: %s. Neither file was changed, and the gateway keeps merging %s with "+
				"config.yaml as the release before did, so no value in use changed. Keep the value you want in "+
				"config.yaml (defenseclaw setup provider, or defenseclaw config set llm_providers.custom), remove the "+
				"other values or the file, then run `defenseclaw migrate` again: it moves the file's providers into "+
				"llm_providers.custom and retires the file, and config.yaml's value is then in use for every field%s",
			path, strings.Join(reasons, "; "), ProvidersOverlayFile, then)}
		m.note("%s", m.fold.Refused)
		return
	}
	var added []*yaml.Node
	var names, merged []string
	for _, e := range folded {
		if into := byName[e.key]; into != nil {
			tookTLS := e.tls && v9EmptyNode(v8YAMLMapValue(into, "tls"))
			if v9FillOverlayProvider(into, e.node) {
				m.foldChanged = true
			}
			if tookTLS && e.ca != nil {
				m.providerCAs = append(m.providerCAs, *e.ca)
			}
			name := yamlScalarValue(v8YAMLMapValue(into, "name"))
			merged = append(merged, name)
			names = append(names, name)
			continue
		}
		byName[e.key] = e.node
		added = append(added, e.node)
		names = append(names, e.name)
		if e.tls && e.ca != nil {
			m.providerCAs = append(m.providerCAs, *e.ca)
		}
	}
	if len(added) > 0 {
		if list == nil || list.Kind != yaml.SequenceNode {
			list = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
			v9Set(root, list, "llm_providers", "custom")
		}
		list.Content = append(list.Content, added...)
		m.foldChanged = true
	}
	if len(names) > 0 {
		m.moved(ProvidersOverlayFile, path, "llm_providers.custom", names)
	}
	if len(twice) > 0 {
		m.note("%s names provider(s) %s more than once; each became one entry, with the lists unioned and the "+
			"later entry's values kept, as the gateway read the file", path, strings.Join(twice, ", "))
	}
	for _, name := range twice {
		if fields := shadowed[name]; len(fields) > 0 {
			m.note("%s: the earlier %s values of %s were never in use (a later entry of the same name set them) and "+
				"are not in config.yaml; the retired file keeps them", path, strings.Join(fields, ", "), name)
		}
	}
	if len(merged) > 0 {
		m.note("%s and llm_providers.custom both name provider(s) %s; config.yaml kept its values and took the "+
			"file's other domains, keys and settings", path, strings.Join(merged, ", "))
	}
	if len(overlay.OllamaPorts) > 0 {
		ports := v8YAMLMapValue(v8YAMLMapValue(root, "llm_providers"), "ollama_ports")
		if ports == nil || ports.Kind != yaml.SequenceNode {
			ports = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Style: yaml.FlowStyle}
			v9Set(root, ports, "llm_providers", "ollama_ports")
		}
		seen := map[string]bool{}
		for _, item := range ports.Content {
			seen[item.Value] = true
		}
		var moved []int
		for _, port := range overlay.OllamaPorts {
			if key := fmt.Sprint(port); !seen[key] {
				seen[key] = true
				ports.Content = append(ports.Content, v9Scalar(port))
				moved = append(moved, port)
			}
		}
		if len(moved) > 0 {
			m.moved(ProvidersOverlayFile, path+":ollama_ports", "llm_providers.ollama_ports", moved)
			m.foldChanged = true
		}
	}
	if sentLater != "" {
		m.note("%s: once the file is no longer a live input, the gateway also sends %s, which it did not send while "+
			"it was one (before 1.0.3 a provider entry named like a built-in provider or like an earlier entry lost its "+
			"extra_headers); remove them from llm_providers.custom if they are not wanted", path, sentLater)
	}
	m.providersOverlay = path
	m.fold = &ProvidersFold{Overlay: path, Folded: names, HeadersAfterFold: after}
}

// The sides v9ProviderConflicts' fields can be in use from, besides
// ProvidersOverlayFile.
const (
	v9InUseConfig = "config.yaml"
	v9InUseNone   = "none"
	v9HeaderField = "extra_headers."
)

// v9ConflictText is "<provider> (<fields>: <whose value is in use>; ...)",
// field names only. fileInUse words a field whose value from the file is in
// use.
func v9ConflictText(c ProviderConflict, fileInUse string) string {
	var parts []string
	for _, side := range []string{v9InUseConfig, ProvidersOverlayFile, v9InUseNone} {
		var fields []string
		for _, field := range c.Fields {
			if c.InUse[field] == side {
				fields = append(fields, field)
			}
		}
		if len(fields) == 0 {
			continue
		}
		in := "config.yaml's value is in use"
		switch side {
		case ProvidersOverlayFile:
			in = fileInUse
		case v9InUseNone:
			in = "no value is in use, the header is not sent"
		}
		parts = append(parts, strings.Join(fields, ", ")+": "+in)
	}
	return c.Provider + " (" + strings.Join(parts, "; ") + ")"
}

// v9Headers is the extra_headers of each provider of a registry, by
// lower-case name, with the name the registry gives it.
type v9Headers map[string]configs.Provider

func (h v9Headers) get(provider, header string) (string, bool) {
	value, ok := h[strings.ToLower(provider)].ExtraHeaders[header]
	return value, ok
}

// v9RegistryHeaders is the extra_headers the gateway's registry holds when it
// merges the built-in providers, then overlay, then custom (llm_providers),
// with the legacy header rule (configs.ApplyLegacyOverlay, while the overlay
// is a live input) or the current one (configs.ApplyOverlay; for the
// fields no conflict holds, the registry once the overlay is folded).
func v9RegistryHeaders(overlay, custom []configs.Provider, legacy bool) v9Headers {
	reg, err := configs.LoadEmbeddedProviders()
	if err != nil || reg == nil {
		reg = &configs.ProvidersConfig{}
	}
	apply := configs.ApplyOverlay
	if legacy {
		apply = configs.ApplyLegacyOverlay
	}
	for _, providers := range [][]configs.Provider{overlay, custom} {
		cloned := make([]configs.Provider, 0, len(providers))
		for _, p := range providers {
			cloned = append(cloned, configs.Provider{Name: p.Name, ExtraHeaders: maps.Clone(p.ExtraHeaders)})
		}
		apply(reg, configs.ProvidersConfig{Providers: cloned})
	}
	out := make(v9Headers, len(reg.Providers))
	for _, p := range reg.Providers {
		out[strings.ToLower(p.Name)] = configs.Provider{Name: p.Name, ExtraHeaders: p.ExtraHeaders}
	}
	return out
}

// v9OverlayHeaderProviders is the name and extra_headers of each overlay
// entry, as the gateway reads them.
func v9OverlayHeaderProviders(in []configs.Provider) []configs.Provider {
	out := make([]configs.Provider, 0, len(in))
	for _, p := range in {
		out = append(out, configs.Provider{Name: p.Name, ExtraHeaders: p.ExtraHeaders})
	}
	return out
}

// v9ConfigHeaderProviders is the name and extra_headers of each
// llm_providers.custom item.
func v9ConfigHeaderProviders(items []*yaml.Node) []configs.Provider {
	var out []configs.Provider
	for _, item := range items {
		name := yamlScalarValue(v8YAMLMapValue(item, "name"))
		if strings.TrimSpace(name) == "" {
			continue
		}
		var headers map[string]string
		if node := v8YAMLMapValue(item, "extra_headers"); node != nil && node.Kind == yaml.MappingNode {
			if err := node.Decode(&headers); err != nil {
				headers = nil
			}
		}
		out = append(out, configs.Provider{Name: name, ExtraHeaders: headers})
	}
	return out
}

// v9HeadersAfterFold names, per provider in name order, the extra_headers
// (as "extra_headers.<key>", key order) that resolved sends and live does not
// send, or sends with another value, leaving out the unsettled keys
// ("<lower-case provider>\x00<key>") a conflict holds: their outcome is the
// operator's choice.
func v9HeadersAfterFold(live, resolved v9Headers, unsettled map[string]bool) []ProviderFields {
	var out []ProviderFields
	for _, key := range slices.Sorted(maps.Keys(resolved)) {
		p := resolved[key]
		var fields []string
		for _, header := range slices.Sorted(maps.Keys(p.ExtraHeaders)) {
			if unsettled[key+"\x00"+header] {
				continue
			}
			if value, sent := live.get(key, header); !sent || value != p.ExtraHeaders[header] {
				fields = append(fields, v9HeaderField+header)
			}
		}
		if len(fields) > 0 {
			out = append(out, ProviderFields{Provider: p.Name, Fields: fields})
		}
	}
	return out
}

// v9MergeOverlayProvider folds src, a later overlay entry, into dst, an
// earlier entry of the same name, with the 0.8.x overlay merge rules
// (configs.ApplyOverlay): a list gains the items it lacks, the string maps
// (request_path_overrides, extra_headers) take src's keys and any other field
// src sets replaces dst's. src holds only the fields its overlay entry sets.
func v9MergeOverlayProvider(dst, src *yaml.Node) {
	for i := 0; i+1 < len(src.Content); i += 2 {
		key, value := src.Content[i].Value, src.Content[i+1]
		have := v8YAMLMapValue(dst, key)
		switch {
		case key == "name":
		case have != nil && have.Kind == yaml.SequenceNode && value.Kind == yaml.SequenceNode:
			v9UnionSeq(have, value)
		case v9StringMapField(key) && have != nil && have.Kind == yaml.MappingNode && value.Kind == yaml.MappingNode:
			for j := 0; j+1 < len(value.Content); j += 2 {
				v9Set(have, value.Content[j+1], value.Content[j].Value)
			}
		default:
			v9Set(dst, value, key)
		}
	}
}

// v9FillOverlayProvider folds src, an overlay provider, into dst, the
// llm_providers.custom entry of the same name, once v9ProviderConflicts found
// no value to choose between: a list gains the items it lacks, a string map
// the keys it lacks, and a field dst leaves unset takes src's value. It
// reports whether dst changed.
func v9FillOverlayProvider(dst, src *yaml.Node) bool {
	changed := false
	for i := 0; i+1 < len(src.Content); i += 2 {
		key, value := src.Content[i].Value, src.Content[i+1]
		have := v8YAMLMapValue(dst, key)
		switch {
		case key == "name", v9EmptyNode(value):
		case v9EmptyNode(have):
			v9Set(dst, value, key)
			changed = true
		case have.Kind == yaml.SequenceNode && value.Kind == yaml.SequenceNode:
			if v9UnionSeq(have, value) {
				changed = true
			}
		case v9StringMapField(key) && have.Kind == yaml.MappingNode && value.Kind == yaml.MappingNode:
			for j := 0; j+1 < len(value.Content); j += 2 {
				if v8YAMLMapValue(have, value.Content[j].Value) == nil {
					v9Set(have, value.Content[j+1], value.Content[j].Value)
					changed = true
				}
			}
		}
	}
	return changed
}

// v9ProviderConflicts names the fields of src, an overlay provider, that dst,
// the provider of the same name it would fold into, sets to another value: a
// scalar or a block (bedrock, vertex, azure) both set differently, a key of
// request_path_overrides or extra_headers both map differently (named
// "<map>.<key>"), or a tls block sameTLS refuses. Lists never conflict (they
// are unioned), and a field either side leaves unset or empty does not
// either. Only names are returned: a header value may be a credential.
func v9ProviderConflicts(dst, src *yaml.Node, sameTLS func(have, value *yaml.Node) bool) []string {
	var fields []string
	for i := 0; i+1 < len(src.Content); i += 2 {
		key, value := src.Content[i].Value, src.Content[i+1]
		have := v8YAMLMapValue(dst, key)
		switch {
		case key == "name", v9EmptyNode(have), v9EmptyNode(value):
		case have.Kind == yaml.SequenceNode && value.Kind == yaml.SequenceNode:
		case v9StringMapField(key) && have.Kind == yaml.MappingNode && value.Kind == yaml.MappingNode:
			for j := 0; j+1 < len(value.Content); j += 2 {
				if old := v8YAMLMapValue(have, value.Content[j].Value); old != nil && !v9NodesEqual(old, value.Content[j+1]) {
					fields = append(fields, key+"."+value.Content[j].Value)
				}
			}
		case key == "tls":
			if !sameTLS(have, value) {
				fields = append(fields, key)
			}
		case !v9NodesEqual(have, value):
			fields = append(fields, key)
		}
	}
	return fields
}

// v9StringMapField reports the provider fields merged key by key.
func v9StringMapField(key string) bool {
	return key == "request_path_overrides" || key == "extra_headers"
}

// v9UnionSeq appends the items of src that dst lacks and reports whether it
// added one.
func v9UnionSeq(dst, src *yaml.Node) bool {
	seen := map[string]bool{}
	for _, item := range dst.Content {
		seen[item.Value] = true
	}
	added := false
	for _, item := range src.Content {
		if !seen[item.Value] {
			seen[item.Value] = true
			dst.Content = append(dst.Content, item)
			added = true
		}
	}
	return added
}

// v9EmptyNode reports an unset field: absent, null, an empty string, or an
// empty list or map.
func v9EmptyNode(node *yaml.Node) bool {
	if node == nil {
		return true
	}
	switch node.Kind {
	case yaml.ScalarNode:
		return node.Tag == "!!null" || node.Value == ""
	case yaml.SequenceNode, yaml.MappingNode:
		return len(node.Content) == 0
	}
	return false
}

// v9NodesEqual compares two YAML values by what they decode to.
func v9NodesEqual(a, b *yaml.Node) bool {
	var x, y any
	if a.Decode(&x) != nil || b.Decode(&y) != nil {
		return false
	}
	return reflect.DeepEqual(x, y)
}

// v9TLSInsecure reports a tls block's insecure_skip_verify.
func v9TLSInsecure(tls *yaml.Node) bool {
	return strings.EqualFold(yamlScalarValue(v8YAMLMapValue(tls, "insecure_skip_verify")), "true")
}

// v9CAData is an overlay CA bundle, nil for none.
func v9CAData(ca *v9RegoRefresh) []byte {
	if ca == nil {
		return nil
	}
	return ca.data
}

// v9ConfigCAMatches reports whether the CA file a config tls block names
// holds the overlay's CA bundle (both absent matches). A file that can not
// be read does not match.
func v9ConfigCAMatches(tls *yaml.Node, ca *v9RegoRefresh) bool {
	file := strings.TrimSpace(yamlScalarValue(v8YAMLMapValue(tls, "ca_cert_file")))
	if file == "" || ca == nil {
		return file == "" && ca == nil
	}
	raw, err := os.ReadFile(expandPath(file)) // #nosec G304 -- llm_providers.custom[].tls.ca_cert_file.
	return err == nil && strings.TrimSpace(string(raw)) == strings.TrimSpace(string(ca.data))
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
// derived file. A file an earlier migration retired keeps its name: the new
// one takes the first free ".N" suffix.
func (m *v9Migrator) retireProvidersOverlay(written *[]string) {
	target := freeSiblingPath(m.providersOverlay + DataJSONMigratedSuffix)
	if err := os.Rename(m.providersOverlay, target); err != nil {
		m.note("could not rename %s: %v", m.providersOverlay, err)
		return
	}
	if m.fold != nil {
		m.fold.Retired = target
	}
	*written = append(*written, target)
}

// foldProvidersOverlayV9 folds a legacy custom-providers.json next to a
// config that is already config_version 9 (one an operator wrote after the
// upgrade, or one a release before 1.0.3 left in place) into llm_providers
// with the rules of migrateCustomProviders, and retires it (GAP-0163).
// Before, the file stayed a live input that only the gateway merged. When
// config.yaml sets a field of the file to another value, or the result would
// not validate, nothing is written and result.ProvidersFold says why. The
// commit holds config.yaml.lock and needs the bytes MigrateV9 read; the
// installer's rollback copy of the data home puts back config.yaml and the
// file (a file outside the data home is left in place, as
// leftOutsideRollbackCopy says).
func (m *v9Migrator) foldProvidersOverlayV9(ctx context.Context, source []byte, result *MigrateV9Result) error {
	if m.in.InMemory || m.in.Managed || m.in.ack {
		return nil
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(source, &doc); err != nil {
		return fmt.Errorf("config: parse %s: %w", m.configPath, err)
	}
	root := v8DocumentRoot(&doc)
	if root == nil || root.Kind != yaml.MappingNode {
		return nil
	}
	m.root = root
	notes := len(m.record.Notes)
	m.migrateCustomProviders(root)
	fold := m.fold
	defer func() {
		if fold != nil {
			fold.Notes = append([]string(nil), m.record.Notes[notes:]...)
			result.ProvidersFold = fold
		}
	}()
	if fold == nil || fold.Refused != "" {
		return nil
	}
	folded := source
	if m.foldChanged {
		var out bytes.Buffer
		enc := yaml.NewEncoder(&out)
		enc.SetIndent(2)
		if err := enc.Encode(&doc); err != nil {
			return fmt.Errorf("config: encode the config with the providers of %s: %w", fold.Overlay, err)
		}
		if err := enc.Close(); err != nil {
			return fmt.Errorf("config: encode the config with the providers of %s: %w", fold.Overlay, err)
		}
		folded = out.Bytes()
		if err := ValidateCandidate(m.configPath, folded); err != nil {
			fold.Folded = nil
			fold.Refused = fmt.Sprintf("the providers of %s were not folded into config.yaml, which would not "+
				"validate with them (%v); neither file was changed, and the gateway keeps merging %s with config.yaml",
				fold.Overlay, err, ProvidersOverlayFile)
			m.note("%s", fold.Refused)
			return nil
		}
	}
	result.Migrated = folded
	if m.in.DryRun {
		return nil
	}
	txn, err := cfgtxn.Begin(ctx, m.configPath, 0)
	if err != nil {
		return err
	}
	defer txn.Close()
	current, mode, exists, err := txn.Read()
	if err != nil {
		return err
	}
	if !exists || !bytes.Equal(current, source) {
		return fmt.Errorf("config: config.yaml changed while %s was folded into it; run `defenseclaw migrate` again", fold.Overlay)
	}
	var written []string
	defer func() { result.Written = append(result.Written, written...) }()
	if err := m.writeProviderCAs(&written); err != nil {
		return err
	}
	if m.foldChanged {
		if _, err := commitV9Config(txn, current, folded, exists, mode,
			cfgtxn.Writer{Actor: m.record.Actor, Reason: "fold the legacy " + ProvidersOverlayFile + " into llm_providers"}); err != nil {
			return err
		}
		written = append(written, m.configPath)
	}
	if !m.leftOutsideRollbackCopy(fold.Overlay) {
		m.retireProvidersOverlay(&written)
	}
	return nil
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

// v9DocumentDeploymentMode is the document's deployment_mode, or its pin
// (managed.DeploymentModeEnv) when one is set.
func v9DocumentDeploymentMode(root *yaml.Node) string {
	mode := normalizeDeploymentMode(yamlScalarValue(v8YAMLMapValue(root, "deployment_mode")))
	if env := strings.TrimSpace(os.Getenv(managed.DeploymentModeEnv)); env != "" {
		mode = normalizeDeploymentMode(env)
	}
	return mode
}

// v9ManagedDocument reports whether the document is a managed deployment,
// on either profile.
func v9ManagedDocument(root *yaml.Node) bool {
	return managed.IsManagedEnterprise(v9DocumentDeploymentMode(root))
}

// v9SecureClientDocument reports whether the document is a managed
// deployment on the Secure Client profile (pinned or configured).
func v9SecureClientDocument(root *yaml.Node) bool {
	if !v9ManagedDocument(root) {
		return false
	}
	mode := v9DocumentDeploymentMode(root)
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
		// An audit deny is name-wide. Do not discard it beside a narrower
		// config rule; commit cleanup would then remove the only broad block.
		// Audit allows can carry a source path, but no other constraints.
		if row.targetType != AdmissionTypeTool {
			constrained := false
			for _, key := range []string{"url", "command", "transport"} {
				constrained = constrained || yamlScalarValue(v8YAMLMapValue(existing, key)) != ""
			}
			constrained = constrained || len(v9SeqItems(v8YAMLMapValue(existing, "args_prefix"))) != 0
			if constrained {
				continue
			}
			paths := v9SeqItems(v8YAMLMapValue(existing, "source_path_contains"))
			if list == "denied" && len(paths) != 0 {
				continue
			}
			if list == "allowed" && row.sourcePath == "" && len(paths) != 0 {
				continue
			}
			if list == "allowed" && row.sourcePath != "" && (len(paths) != 1 || yamlScalarValue(paths[0]) != row.sourcePath) {
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
