// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package enterprisebundle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// The bundle store of a standalone device (spec P1 sections 7 and 8).
//
// A bundle is copied into <etc>/bundles/.staging-<receipt id> and verified
// there, never at the path MDM dropped it, then renamed to an immutable
// <etc>/bundles/v<version>-<id8>-<receipt id> directory that the installed
// config points into. Legacy version names remain readable. bundle-state.json
// (current, last_good, floor) and receipts/ live in
// the root-only lifecycle directory. bundle-state.json is replaced
// atomically and changes only when a bundle is confirmed, so a crash at any
// point leaves the last good bundle in force and its directory in place.

const (
	// BundlesDirName is the store directory under the configuration
	// directory.
	BundlesDirName = "bundles"
	// StateFileName is the store state in the lifecycle directory.
	StateFileName = "bundle-state.json"
	// ReceiptsDirName holds one receipt per bundle in the lifecycle
	// directory.
	ReceiptsDirName = "receipts"

	StateSchemaVersion   = 1
	ReceiptSchemaVersion = 1
	// MaxReceipts is how many receipts the store keeps; older finished
	// ones are removed.
	MaxReceipts = 20
	// MaxErrorMessage bounds a receipt error message (bytes).
	MaxErrorMessage = 512

	stagingPrefix     = ".staging-"
	maxStoreFileBytes = 64 << 10
)

// Receipt states; see enterprisestatus for their meaning.
const (
	StateReceived  = enterprisestatus.BundleReceived
	StateVerified  = enterprisestatus.BundleVerified
	StateStaged    = enterprisestatus.BundleStaged
	StateApplied   = enterprisestatus.BundleApplied
	StateConfirmed = enterprisestatus.BundleConfirmed
	StateFailed    = enterprisestatus.BundleFailed
)

var (
	receiptIDPattern  = regexp.MustCompile(`^[br]-[0-7][0-9A-HJKMNP-TV-Z]{25}$`)
	versionDirPattern = regexp.MustCompile(`^v[1-9][0-9]{0,15}-[0-9A-HJKMNP-TV-Z]{8}(?:-[br]-[0-7][0-9A-HJKMNP-TV-Z]{25})?$`)
)

// nextState is the only forward move from each receipt state.
var nextState = map[string]string{
	StateReceived: StateVerified,
	StateVerified: StateStaged,
	StateStaged:   StateApplied,
	StateApplied:  StateConfirmed,
}

// CheckTransition refuses a receipt move other than one step forward, or
// failed from a state that is not finished. confirmed and failed are final.
func CheckTransition(from, to string) error {
	if from == StateConfirmed || from == StateFailed {
		return fmt.Errorf("bundle receipt is %s; a finished receipt does not change", from)
	}
	if _, known := nextState[from]; !known {
		return fmt.Errorf("unknown bundle receipt state %q", from)
	}
	if to == StateFailed || nextState[from] == to {
		return nil
	}
	return fmt.Errorf("bundle receipt cannot move from %s to %s", from, to)
}

// Finished reports a final receipt state.
func Finished(state string) bool { return state == StateConfirmed || state == StateFailed }

// Ref is a bundle the store holds in a version directory.
type Ref struct {
	BundleID string `json:"bundle_id"`
	Version  uint64 `json:"version"`
	// ManifestSHA256 is the hex SHA-256 of the manifest.json bytes.
	ManifestSHA256 string `json:"manifest_sha256"`
	// Dir is the version directory name under the store directory.
	Dir                   string `json:"dir"`
	SignerKeyID           string `json:"signer_key_id,omitempty"`
	EffectivePolicyDigest string `json:"effective_policy_digest,omitempty"`
	ConfigGeneration      uint64 `json:"config_generation,omitempty"`
	ConfirmedAt           string `json:"confirmed_at,omitempty"`
	RestartRequired       bool   `json:"restart_required,omitempty"`
}

func (r *Ref) validate() error {
	switch {
	case !ValidBundleID(r.BundleID):
		return errors.New("bundle_id is not a bundle id")
	case r.Version == 0 || r.Version > MaxVersion:
		return errors.New("version is out of range")
	case !validSHA256Hex(r.ManifestSHA256):
		return errors.New("manifest_sha256 is not a SHA-256 digest")
	case !validVersionDir(r.Dir, r.Version, r.BundleID):
		return errors.New("dir does not name the bundle version directory")
	}
	return nil
}

// State is bundle-state.json. The floor is the highest confirmed version;
// it only moves up, on confirm.
type State struct {
	SchemaVersion int    `json:"schema_version"`
	Current       *Ref   `json:"current,omitempty"`
	LastGood      *Ref   `json:"last_good,omitempty"`
	Floor         uint64 `json:"floor"`
	UpdatedAt     string `json:"updated_at,omitempty"`
}

// Confirmed is the current bundle for the version floor check.
func (s State) Confirmed() Confirmed {
	if s.Current == nil {
		return Confirmed{Version: s.Floor}
	}
	// A floor above the current version (a state no confirm writes) still
	// holds: the current bundle then no longer counts as already applied.
	return Confirmed{Version: max(s.Floor, s.Current.Version), BundleID: s.Current.BundleID, ManifestSHA256: s.Current.ManifestSHA256}
}

// held reports whether name is the version directory of the current or the
// last good bundle.
func (s State) held(name string) bool {
	return (s.Current != nil && s.Current.Dir == name) || (s.LastGood != nil && s.LastGood.Dir == name)
}

// Transition is one receipt state change.
type Transition struct {
	State string `json:"state"`
	At    string `json:"at"`
}

// Receipt is receipts/<receipt id>.json: how far one bundle got. The
// receipt id is the bundle id, or r-<ULID> for a bundle whose manifest could
// not be read. BundleID and Version are what the manifest claims until the
// receipt reaches verified.
type Receipt struct {
	SchemaVersion int    `json:"schema_version"`
	ReceiptID     string `json:"receipt_id"`
	BundleID      string `json:"bundle_id,omitempty"`
	Version       uint64 `json:"version,omitempty"`
	TenantID      string `json:"tenant_id,omitempty"`
	DeviceGroup   string `json:"device_group,omitempty"`
	SignerKeyID   string `json:"signer_key_id,omitempty"`
	Principal     string `json:"principal,omitempty"`
	// ChangeSummary is the manifest change_summary, set at verified.
	ChangeSummary  string       `json:"change_summary,omitempty"`
	ManifestSHA256 string       `json:"manifest_sha256,omitempty"`
	State          string       `json:"state"`
	Transitions    []Transition `json:"transitions"`
	ErrorCode      Code         `json:"error_code,omitempty"`
	ErrorMessage   string       `json:"error_message,omitempty"`
	ExpectedDigest string       `json:"expected_digest,omitempty"`
	// DigestComparable records that verify compared the signed digest on
	// this same product version and platform.
	DigestComparable      bool     `json:"digest_comparable,omitempty"`
	WarningCodes          []string `json:"warning_codes,omitempty"`
	DisabledByBundle      []string `json:"disabled_by_bundle,omitempty"`
	EffectivePolicyDigest string   `json:"effective_policy_digest,omitempty"`
	ConfigGeneration      uint64   `json:"config_generation,omitempty"`
	AppliedAt             string   `json:"applied_at,omitempty"`
	ConfirmedAt           string   `json:"confirmed_at,omitempty"`
	// SessionsRestartRequired is the live count when this receipt was confirmed.
	SessionsRestartRequired int    `json:"sessions_restart_required"`
	RolledBack              bool   `json:"rolled_back,omitempty"`
	EnforcingDigest         string `json:"enforcing_digest,omitempty"`
	Restart                 bool   `json:"restart,omitempty"`
	RestartRequired         bool   `json:"restart_required,omitempty"`
	// Dir is the version directory name once the bundle is staged.
	Dir string `json:"dir,omitempty"`
	// ConfigSHA256 is the hex SHA-256 of the config.yaml the apply installed
	// from this bundle, recorded when it reaches applied: settle compares it
	// with the committed deployment to tell a finished transaction from one
	// that was rolled back.
	ConfigSHA256 string `json:"config_sha256,omitempty"`
}

// ReceivedAt is the time of the first transition ("" when there is none).
func (r *Receipt) ReceivedAt() string {
	if len(r.Transitions) == 0 {
		return ""
	}
	return r.Transitions[0].At
}

// IsRefusal reports a failed delivery that never reached the staged state.
func (r *Receipt) IsRefusal() bool {
	if r.State != StateFailed {
		return false
	}
	for _, tr := range r.Transitions {
		if tr.State == StateStaged || tr.State == StateApplied {
			return false
		}
	}
	return true
}

func (r *Receipt) Refusal() *enterprisestatus.BundleRefusal {
	if !r.IsRefusal() || len(r.Transitions) == 0 {
		return nil
	}
	return &enterprisestatus.BundleRefusal{ReceiptID: r.ReceiptID, BundleID: r.BundleID,
		Version: r.Version, ErrorCode: string(r.ErrorCode), Time: r.Transitions[len(r.Transitions)-1].At,
		WarningCodes: append([]string(nil), r.WarningCodes...), DisabledByBundle: append([]string(nil), r.DisabledByBundle...)}
}

// DigestWarningCode classifies a difference between the signed expectation
// and the policy the gateway actually enforces. A cross-build signature
// cannot be compared, but the difference still deserves a visible warning.
func DigestWarningCode(expected, enforcing string, comparable bool) string {
	if expected == "" || enforcing == "" || expected == enforcing {
		return ""
	}
	if comparable {
		return WarnDigestDiffers
	}
	return WarnDigestUnverifiable
}

// Status is the result v2 bundle block for r, naming current when r is not
// the confirmed receipt of the bundle that enforces.
func (r *Receipt) Status(current *Ref) *enterprisestatus.BundleState {
	out := &enterprisestatus.BundleState{
		BundleID: r.BundleID, Version: r.Version, State: r.State, ErrorCode: string(r.ErrorCode),
		EffectivePolicyDigest: r.EffectivePolicyDigest, ConfigGeneration: r.ConfigGeneration,
		AppliedAt: r.AppliedAt, ConfirmedAt: r.ConfirmedAt,
		Restart: r.Restart, RestartRequired: r.RestartRequired,
		DisabledByBundle: append([]string(nil), r.DisabledByBundle...),
		WarningCodes:     append([]string(nil), r.WarningCodes...),
	}
	if current != nil && (current.BundleID != r.BundleID || r.State != StateConfirmed) {
		out.CurrentBundleID, out.CurrentVersion = current.BundleID, current.Version
	}
	return out
}

// VersionDirName is v<version>-<id8>, id8 the last eight (random) ULID
// characters of the bundle id.
func VersionDirName(version uint64, bundleID string) string {
	id8 := bundleID
	if len(id8) > 8 {
		id8 = id8[len(id8)-8:]
	}
	return "v" + strconv.FormatUint(version, 10) + "-" + id8
}

// VersionDirNameForReceipt gives each delivery an immutable destination.
// A retry can switch its config to this directory without touching a path
// named by the installed config, even when the earlier receipt was failed.
func VersionDirNameForReceipt(version uint64, bundleID, receiptID string) string {
	return VersionDirName(version, bundleID) + "-" + receiptID
}

// IsVersionDirName accepts current receipt-specific and legacy version
// directory names. It is shared by store collection and lifecycle modes.
func IsVersionDirName(name string) bool { return versionDirPattern.MatchString(name) }

func validVersionDir(name string, version uint64, bundleID string) bool {
	base := VersionDirName(version, bundleID)
	return name == base || (strings.HasPrefix(name, base+"-") && receiptIDPattern.MatchString(strings.TrimPrefix(name, base+"-")))
}

// Store is the bundle store of one device.
type Store struct {
	// BundlesDir is <etc>/bundles: staging and the version directories.
	BundlesDir string
	// LifecycleDir holds bundle-state.json and receipts/ (root only).
	LifecycleDir string
	// Now is the clock (time.Now when nil).
	Now func() time.Time
	// Entropy names receipts of unreadable bundles (crypto/rand when nil).
	Entropy io.Reader
	// PrivateStage protects a newly created staging directory before files
	// are copied into it (Windows uses a protected administrator-only ACL).
	PrivateStage func(root string) error
	// EnsureStageDirectory creates the staging root and each nested directory.
	// Windows supplies the protected AdminDirectory descriptor at creation.
	EnsureStageDirectory func(root, path string) error
	// PublishStageFile seals a new private staging file before verification.
	PublishStageFile func(path string) error
	// SealVersion makes a verified staging tree readable by the gateway
	// before it is renamed into its immutable version directory. When nil,
	// the store uses its platform-neutral read-only modes.
	SealVersion func(root string) error
	// PublishVersion grants traversal on the renamed version root after its
	// assets have been sealed. Windows keeps the staging root private until
	// the rename; Unix sets its group mode during SealVersion.
	PublishVersion func(root string) error
	// PublishReceipt applies the platform's public-file permissions after an
	// atomic replacement of receipt.json.
	PublishReceipt func(path string) error
	// EnsurePrivateDirectory creates the lifecycle and receipts directories
	// with the platform's private descriptor. Nil uses ordinary mkdir.
	EnsurePrivateDirectory func(path string) error
	// PublishPrivateFile seals an atomically replaced state or receipt file.
	PublishPrivateFile func(path string) error
}

func (s *Store) ensurePrivateDirectory(path string) error {
	if s.EnsurePrivateDirectory != nil {
		return s.EnsurePrivateDirectory(path)
	}
	return os.MkdirAll(path, 0o700)
}

func (s *Store) publishPrivateFile(path string) error {
	if s.PublishPrivateFile != nil {
		return s.PublishPrivateFile(path)
	}
	return nil
}

// NewStore returns the store at bundlesDir with its state in lifecycleDir.
func NewStore(bundlesDir, lifecycleDir string) *Store {
	return &Store{BundlesDir: bundlesDir, LifecycleDir: lifecycleDir}
}

// StoreFor is the store of the standalone layout of goos.
func StoreFor(goos string) (*Store, error) {
	layout, err := Layout(goos)
	if err != nil {
		return nil, err
	}
	return NewStore(filepath.Join(layout.ConfigDir, BundlesDirName), layout.LifecycleDir), nil
}

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

// stamp is RFC 3339 UTC with milliseconds, so receipts sort by time.
func stamp(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z07:00") }

// StatePath is the bundle-state.json path.
func (s *Store) StatePath() string { return filepath.Join(s.LifecycleDir, StateFileName) }

func (s *Store) receiptsDir() string { return filepath.Join(s.LifecycleDir, ReceiptsDirName) }

func (s *Store) receiptPath(id string) string { return filepath.Join(s.receiptsDir(), id+".json") }

func (s *Store) stagingPath(id string) string { return filepath.Join(s.BundlesDir, stagingPrefix+id) }

// VersionDir is the path of the version directory name.
func (s *Store) VersionDir(name string) string { return filepath.Join(s.BundlesDir, name) }

// LoadState reads bundle-state.json; a missing file is the empty state (no
// bundle confirmed yet). A file that is not a valid state is an error, never
// an empty state: that would lower the floor.
func (s *Store) LoadState() (State, error) {
	raw, err := readStoreFile(s.StatePath())
	if errors.Is(err, fs.ErrNotExist) {
		return State{SchemaVersion: StateSchemaVersion}, nil
	}
	if err != nil {
		return State{}, err
	}
	var st State
	if err := json.Unmarshal(raw, &st); err != nil {
		return State{}, fmt.Errorf("%s is not valid: %w", StateFileName, err)
	}
	if st.SchemaVersion < 1 {
		return State{}, fmt.Errorf("%s has no schema_version", StateFileName)
	}
	for name, ref := range map[string]*Ref{"current": st.Current, "last_good": st.LastGood} {
		if ref == nil {
			continue
		}
		if err := ref.validate(); err != nil {
			return State{}, fmt.Errorf("%s %s: %w", StateFileName, name, err)
		}
	}
	if st.Current != nil && st.Floor < st.Current.Version {
		return State{}, fmt.Errorf("%s floor %d is below the current version %d", StateFileName, st.Floor, st.Current.Version)
	}
	return st, nil
}

// saveState replaces bundle-state.json atomically (temp file, fsync,
// rename, directory fsync): a reader sees the old or the new state.
func (s *Store) saveState(st State) error {
	st.SchemaVersion = StateSchemaVersion
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	if err := s.ensurePrivateDirectory(s.LifecycleDir); err != nil {
		return err
	}
	if err := configwrite.WriteFileDurable(s.StatePath(), append(data, '\n'), 0o600); err != nil {
		return err
	}
	return s.publishPrivateFile(s.StatePath())
}

func (s *Store) writeReceipt(r *Receipt) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	if err := s.ensurePrivateDirectory(s.receiptsDir()); err != nil {
		return err
	}
	if err := configwrite.WriteFileDurable(s.receiptPath(r.ReceiptID), append(data, '\n'), 0o600); err != nil {
		return err
	}
	if err := s.publishPrivateFile(s.receiptPath(r.ReceiptID)); err != nil {
		return err
	}
	if Finished(r.State) {
		// Reporting only: the gateway reads receipt.json for the audit
		// event and the metrics. A failed write must not fail the apply,
		// whose outcome the root-only receipt and status already record.
		_ = s.writePublicReceipt(r)
	}
	return nil
}

// PublicReceiptPath is <etc>/bundles/receipt.json.
func (s *Store) PublicReceiptPath() string {
	return filepath.Join(s.BundlesDir, enterprisestatus.PublicReceiptName)
}

// writePublicReceipt replaces receipt.json with the finished receipt r and
// the bundle that enforces now. It leaves out the error message (it can
// quote loader detail), the manifest hash and the version directory.
func (s *Store) writePublicReceipt(r *Receipt) error {
	if refusal := r.Refusal(); refusal != nil {
		if previous, err := enterprisestatus.ReadPublicReceipt(s.PublicReceiptPath()); err == nil {
			previous.LastRefusal = refusal
			return s.publishReceipt(previous)
		}
	}
	out := enterprisestatus.PublicReceipt{
		SchemaVersion: enterprisestatus.PublicReceiptSchemaVersion, ReceiptID: r.ReceiptID,
		BundleID: r.BundleID, Version: r.Version, SignerKeyID: r.SignerKeyID, Principal: r.Principal,
		ChangeSummary: r.ChangeSummary, State: r.State, ErrorCode: string(r.ErrorCode),
		EffectivePolicyDigest: r.EffectivePolicyDigest, EnforcingDigest: r.EnforcingDigest,
		WarningCodes:     append([]string(nil), r.WarningCodes...),
		DisabledByBundle: append([]string(nil), r.DisabledByBundle...),
		ConfigGeneration: r.ConfigGeneration, AppliedAt: r.AppliedAt, ConfirmedAt: r.ConfirmedAt,
		SessionsRestartRequired: r.SessionsRestartRequired,
		RolledBack:              r.RolledBack, Restart: r.Restart, RestartRequired: r.RestartRequired,
	}
	if n := len(r.Transitions); n > 0 {
		out.FinishedAt = r.Transitions[n-1].At
	}
	if st, err := s.LoadState(); err == nil && st.Current != nil {
		out.CurrentBundleID, out.CurrentVersion = st.Current.BundleID, st.Current.Version
	}
	out.LastRefusal = r.Refusal()
	if out.LastRefusal == nil {
		_, out.LastRefusal, _ = s.Latest()
	}
	return s.publishReceipt(out)
}

func (s *Store) publishReceipt(out enterprisestatus.PublicReceipt) error {
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(s.BundlesDir, 0o755); err != nil {
		return err
	}
	if err := configwrite.WriteFileDurable(s.PublicReceiptPath(), append(data, '\n'), 0o644); err != nil {
		return err
	}
	if s.PublishReceipt != nil {
		return s.PublishReceipt(s.PublicReceiptPath())
	}
	return nil
}

// Latest separates a pre-staging refusal from the latest receipt that
// reached staging and may have affected the enforcing policy.
func (s *Store) Latest() (last *Receipt, refusal *enterprisestatus.BundleRefusal, err error) {
	receipts, err := s.Receipts()
	if err != nil {
		return nil, nil, err
	}
	for _, r := range receipts {
		if r.IsRefusal() {
			if refusal == nil {
				refusal = r.Refusal()
			}
		} else if last == nil {
			for _, tr := range r.Transitions {
				if tr.State == StateStaged {
					last = r
					break
				}
			}
		}
		if last != nil && refusal != nil {
			break
		}
	}
	return last, refusal, nil
}

// GenerationOptions is how the lifecycle records the config of the bundle
// receipt r in config.generation.json: as the bundle principal with the
// bundle change summary and the bundle fields. ok is false when r names no
// principal; the caller then records as the lifecycle.
func GenerationOptions(r *Receipt) (opt configwrite.Options, ok bool) {
	if r == nil || r.Principal == "" {
		return configwrite.Options{}, false
	}
	return configwrite.Options{Actor: r.Principal, Reason: configwrite.BundleReason(r.BundleID, r.Version, r.ChangeSummary),
		Lifecycle: true, Bundle: configwrite.BundleRef{ID: r.BundleID, Version: r.Version, SignerKeyID: r.SignerKeyID}}, true
}

// Receive starts the receipt of a bundle in state received. bundleID and
// version are what the still unverified manifest claims ("" and 0 when it
// could not be read).
func (s *Store) Receive(bundleID string, version uint64) (*Receipt, error) {
	at := s.now()
	r := &Receipt{SchemaVersion: ReceiptSchemaVersion, State: StateReceived,
		Transitions: []Transition{{State: StateReceived, At: stamp(at)}}}
	if ValidBundleID(bundleID) && s.receiptReusable(bundleID) {
		r.ReceiptID, r.BundleID, r.Version = bundleID, bundleID, version
	} else {
		// An unreadable manifest, or a bundle id whose receipt must stay:
		// confirmed (the bundle delivered again) or not finished (an
		// applied bundle the installed config may point at, which settle
		// still has to confirm or roll back): a receipt of its own.
		if ValidBundleID(bundleID) {
			r.BundleID, r.Version = bundleID, version
		}
		id, err := NewBundleID(at, s.Entropy)
		if err != nil {
			return nil, err
		}
		r.ReceiptID = "r-" + strings.TrimPrefix(id, "b-")
	}
	if err := s.writeReceipt(r); err != nil {
		return nil, err
	}
	return r, s.prune()
}

// receiptReusable reports whether a new receipt may take the id bundleID.
// Every delivery keeps its own history, including repeated refusals.
func (s *Store) receiptReusable(bundleID string) bool {
	_, err := readStoreFile(s.receiptPath(bundleID))
	return errors.Is(err, fs.ErrNotExist)
}

// Advance moves r one state forward (CheckTransition), applies update to
// it first and writes it.
func (s *Store) Advance(r *Receipt, next string, update func(*Receipt)) error {
	if next == StateFailed {
		return errors.New("use Fail to fail a bundle receipt")
	}
	if err := CheckTransition(r.State, next); err != nil {
		return err
	}
	if next == StateVerified && (!ValidBundleID(r.BundleID) || r.Version == 0) {
		return errors.New("a verified bundle receipt needs the bundle id and version")
	}
	if update != nil {
		update(r)
	}
	r.State = next
	r.Transitions = append(r.Transitions, Transition{State: next, At: stamp(s.now())})
	return s.writeReceipt(r)
}

// Fail ends r with code and a bounded message, and removes its staging
// copy. The version directory stays until the next garbage collection: a
// rollback may still point at it.
func (s *Store) Fail(r *Receipt, code Code, message string) error {
	if err := CheckTransition(r.State, StateFailed); err != nil {
		return err
	}
	r.ErrorCode, r.ErrorMessage = code, boundedMessage(message)
	r.State = StateFailed
	r.Transitions = append(r.Transitions, Transition{State: StateFailed, At: stamp(s.now())})
	if err := s.writeReceipt(r); err != nil {
		return err
	}
	return removeTree(s.stagingPath(r.ReceiptID))
}

// Discard removes the unfinished receipt r and its staging copy, for a
// delivery that turned out to be the bundle already applied: the confirmed
// receipt of that bundle stays the one status reports.
func (s *Store) Discard(r *Receipt) error {
	if Finished(r.State) {
		return fmt.Errorf("bundle receipt %s is %s; a finished receipt is kept", r.ReceiptID, r.State)
	}
	if err := removeTree(s.stagingPath(r.ReceiptID)); err != nil {
		return err
	}
	if err := os.Remove(s.receiptPath(r.ReceiptID)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return syncDir(s.receiptsDir())
}

// ReadVersion reads the bundle that ref names from its version directory
// and checks it again: the manifest bytes must be the ones confirmed
// (manifest_sha256) and every file must match files[]. A version directory
// is root-owned and read-only, so this guards against a damaged store, not
// an attacker who is root.
func (s *Store) ReadVersion(ref *Ref) (*Bundle, error) {
	if err := ref.validate(); err != nil {
		return nil, &Error{Code: CodeStateInvalid, Path: StateFileName, Detail: err.Error()}
	}
	b, err := ReadDir(s.VersionDir(ref.Dir))
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(b.Manifest)
	if hex.EncodeToString(sum[:]) != ref.ManifestSHA256 {
		return nil, refuse(CodeFileHashMismatch, ManifestName, "the stored manifest of bundle %s version %d is not the confirmed one", ref.BundleID, ref.Version)
	}
	m, err := DecodeManifest(b.Manifest)
	if err != nil {
		return nil, err
	}
	if err := CheckFiles(m, b); err != nil {
		return nil, err
	}
	return b, nil
}

// Stage copies b (manifest.json, manifest.sig and every file) into a fresh
// staging directory for r and returns it. Every file is created new
// (O_EXCL, no link followed) and fsynced. Verification reads this copy.
func (s *Store) Stage(r *Receipt, b *Bundle) (string, error) {
	if r.State != StateReceived {
		return "", fmt.Errorf("stage needs a received bundle receipt, not %s", r.State)
	}
	dir := s.stagingPath(r.ReceiptID)
	if err := removeTree(dir); err != nil {
		return "", err
	}
	if err := os.MkdirAll(s.BundlesDir, 0o755); err != nil {
		return "", err
	}
	if s.EnsureStageDirectory != nil {
		if err := s.EnsureStageDirectory(dir, dir); err != nil {
			return "", err
		}
	} else if err := os.Mkdir(dir, 0o700); err != nil {
		return "", err
	}
	if s.PrivateStage != nil {
		if err := s.PrivateStage(dir); err != nil {
			_ = removeTree(dir)
			return "", err
		}
	}
	files := map[string][]byte{}
	if b.Manifest != nil {
		files[ManifestName] = b.Manifest
	}
	if b.Signature != nil {
		files[SignatureName] = b.Signature
	}
	for _, name := range b.Paths() {
		if bad := checkBundlePath(name, false); bad != nil {
			_ = removeTree(dir)
			return "", bad
		}
		files[name] = b.Files[name]
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	dirs := map[string]bool{dir: true}
	for _, name := range names {
		full := filepath.Join(dir, filepath.FromSlash(name))
		parent := filepath.Dir(full)
		var dirErr error
		if s.EnsureStageDirectory != nil {
			dirErr = s.EnsureStageDirectory(dir, parent)
		} else {
			dirErr = os.MkdirAll(parent, 0o700)
		}
		if dirErr != nil {
			_ = removeTree(dir)
			return "", dirErr
		}
		dirs[parent] = true
		if err := writeNewFile(full, files[name]); err != nil {
			_ = removeTree(dir)
			return "", err
		}
		if s.PublishStageFile != nil {
			if err := s.PublishStageFile(full); err != nil {
				_ = removeTree(dir)
				return "", err
			}
		}
	}
	for d := range dirs {
		if err := syncDir(d); err != nil {
			_ = removeTree(dir)
			return "", err
		}
	}
	return dir, nil
}

// Promote turns the staging copy of a verified receipt into its immutable
// version directory (read-only files and directories, renamed into place,
// the store directory fsynced) and moves the receipt to staged. It returns
// the version directory.
func (s *Store) Promote(r *Receipt) (string, error) {
	if r.State != StateVerified {
		return "", fmt.Errorf("promote needs a verified bundle receipt, not %s", r.State)
	}
	name := VersionDirNameForReceipt(r.Version, r.BundleID, r.ReceiptID)
	staging, target := s.stagingPath(r.ReceiptID), s.VersionDir(name)
	if _, err := os.Lstat(target); err == nil {
		return "", fmt.Errorf("bundle version destination %s already exists", name)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	seal := s.SealVersion
	if seal == nil {
		seal = makeReadOnly
	}
	if err := seal(staging); err != nil {
		return "", err
	}
	if err := os.Rename(staging, target); err != nil {
		return "", err
	}
	if s.PublishVersion != nil {
		if err := s.PublishVersion(target); err != nil {
			return "", err
		}
	}
	if err := syncDir(s.BundlesDir); err != nil {
		return "", err
	}
	if err := s.Advance(r, StateStaged, func(r *Receipt) { r.Dir = name }); err != nil {
		return "", err
	}
	return target, nil
}

// Confirm makes the applied receipt r the current bundle: bundle-state.json
// moves current to last_good, sets current and raises the floor in one
// atomic replace; then the receipt is confirmed and version directories other
// than current and last_good are removed.
func (s *Store) Confirm(r *Receipt) (State, error) {
	if r.State != StateApplied {
		return State{}, fmt.Errorf("confirm needs an applied bundle receipt, not %s", r.State)
	}
	ref := &Ref{BundleID: r.BundleID, Version: r.Version, ManifestSHA256: r.ManifestSHA256, Dir: r.Dir,
		SignerKeyID: r.SignerKeyID, EffectivePolicyDigest: r.EffectivePolicyDigest, ConfigGeneration: r.ConfigGeneration,
		RestartRequired: r.RestartRequired}
	if err := ref.validate(); err != nil {
		return State{}, fmt.Errorf("bundle receipt %s: %w", r.ReceiptID, err)
	}
	if !digestPattern.MatchString(r.EffectivePolicyDigest) {
		return State{}, fmt.Errorf("bundle receipt %s has no effective policy digest to confirm", r.ReceiptID)
	}
	if code := DigestWarningCode(r.ExpectedDigest, r.EffectivePolicyDigest, r.DigestComparable); code != "" && !slices.Contains(r.WarningCodes, code) {
		r.WarningCodes = append(r.WarningCodes, code)
	}
	r.EnforcingDigest = r.EffectivePolicyDigest
	st, err := s.LoadState()
	if err != nil {
		return State{}, err
	}
	// The floor never goes down: only a version above it, or the current
	// bundle itself (same id and manifest) at it, becomes current.
	sameAsCurrent := st.Current != nil && st.Current.BundleID == ref.BundleID && st.Current.ManifestSHA256 == ref.ManifestSHA256
	if r.Version < st.Floor || (r.Version == st.Floor && !sameAsCurrent) {
		return State{}, refuse(CodeVersionNotNewer, "version", "bundle %s version %d is not above the confirmed floor %d", r.BundleID, r.Version, st.Floor)
	}
	at := stamp(s.now())
	ref.ConfirmedAt = at
	next := State{Current: ref, LastGood: st.LastGood, Floor: max(st.Floor, r.Version), UpdatedAt: at}
	if st.Current != nil && st.Current.BundleID != ref.BundleID {
		next.LastGood = st.Current
	}
	if err := s.saveState(next); err != nil {
		return State{}, err
	}
	next.SchemaVersion = StateSchemaVersion
	if err := s.Advance(r, StateConfirmed, func(r *Receipt) { r.ConfirmedAt = at }); err != nil {
		return next, err
	}
	return next, s.gc(next, nil)
}

// SettleReport is what Settle did.
type SettleReport struct {
	// Interrupted are the receipts ended as failed(interrupted).
	Interrupted []string
	// Completed are applied receipts that bundle-state.json already names
	// as current (the run stopped between the two writes): now confirmed.
	Completed []string
	// Unconfirmed are applied receipts the caller must re-check against the
	// gateway and then confirm or roll back.
	Unconfirmed []*Receipt
}

// Settle finishes what an interrupted run left, at the start of every
// lifecycle run (after the lifecycle restored any pending transaction):
// received, verified and staged receipts fail as interrupted (nothing was
// installed yet), an applied receipt that bundle-state.json names as
// current is confirmed, and other applied receipts are returned for the
// caller. Staging copies, temp files and version directories no state or
// open receipt refers to, and that are not in keep, are removed. keep names
// the version directories the installed config still uses (VersionDirsNamed):
// a bundle installed by a run that then failed it, with no last good bundle
// to return to or a rollback that did not finish, keeps enforcing from its
// directory, so that directory must stay.
func (s *Store) Settle(keep ...string) (SettleReport, error) {
	var report SettleReport
	st, err := s.LoadState()
	if err != nil {
		return report, err
	}
	receipts, err := s.Receipts()
	if err != nil {
		return report, err
	}
	kept := map[string]bool{}
	for _, name := range keep {
		kept[name] = true
	}
	for _, r := range receipts {
		switch r.State {
		case StateReceived, StateVerified, StateStaged:
			if err := s.Fail(r, CodeInterrupted, "the run that received this bundle ended before it was applied; the last good bundle kept enforcing"); err != nil {
				return report, err
			}
			report.Interrupted = append(report.Interrupted, r.ReceiptID)
		case StateApplied:
			if c := st.Current; c != nil && c.BundleID == r.BundleID && c.ManifestSHA256 == r.ManifestSHA256 {
				if err := s.Advance(r, StateConfirmed, func(r *Receipt) { r.ConfirmedAt = c.ConfirmedAt }); err != nil {
					return report, err
				}
				report.Completed = append(report.Completed, r.ReceiptID)
				continue
			}
			kept[r.Dir] = true
			report.Unconfirmed = append(report.Unconfirmed, r)
		}
	}
	return report, s.gc(st, kept)
}

// Receipts returns every readable receipt, newest first. An unreadable
// receipt file is skipped: it cannot be settled and never names a bundle
// that enforces.
func (s *Store) Receipts() ([]*Receipt, error) {
	entries, err := os.ReadDir(s.receiptsDir())
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []*Receipt
	for _, entry := range entries {
		id, ok := strings.CutSuffix(entry.Name(), ".json")
		if !ok || !receiptIDPattern.MatchString(id) || !entry.Type().IsRegular() {
			continue
		}
		raw, err := readStoreFile(s.receiptPath(id))
		if err != nil {
			continue
		}
		var r Receipt
		if json.Unmarshal(raw, &r) != nil || r.ReceiptID != id {
			continue
		}
		out = append(out, &r)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if a, b := out[i].ReceivedAt(), out[j].ReceivedAt(); a != b {
			return a > b
		}
		return out[i].ReceiptID > out[j].ReceiptID
	})
	return out, nil
}

// Summary is the result v2 bundle block: the latest receipt that reached
// staging and the current bundle; nil when neither exists.
func (s *Store) Summary() (*enterprisestatus.BundleState, error) {
	st, err := s.LoadState()
	if err != nil {
		return nil, err
	}
	last, _, err := s.Latest()
	if err != nil {
		return nil, err
	}
	if last != nil {
		return last.Status(st.Current), nil
	}
	if c := st.Current; c != nil {
		return &enterprisestatus.BundleState{BundleID: c.BundleID, Version: c.Version, State: StateConfirmed,
			EffectivePolicyDigest: c.EffectivePolicyDigest, ConfigGeneration: c.ConfigGeneration, ConfirmedAt: c.ConfirmedAt}, nil
	}
	return nil, nil
}

// prune keeps the MaxReceipts newest receipts; an unfinished one is never
// removed.
func (s *Store) prune() error {
	receipts, err := s.Receipts()
	if err != nil || len(receipts) <= MaxReceipts {
		return err
	}
	for _, r := range receipts[MaxReceipts:] {
		if !Finished(r.State) {
			continue
		}
		if err := os.Remove(s.receiptPath(r.ReceiptID)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return nil
}

// VersionDirsNamed returns the version directory names that raw, a rendered
// config.yaml, names under bundlesDir (the installed bundles directory, as
// RenderConfig writes it into the config).
func VersionDirsNamed(raw []byte, bundlesDir string) []string {
	prefix := regexp.MustCompile(regexp.QuoteMeta(filepath.Clean(bundlesDir)+string(filepath.Separator)) + `([0-9A-Za-z-]+)`)
	var names []string
	for _, m := range prefix.FindAllSubmatch(raw, -1) {
		if name := string(m[1]); IsVersionDirName(name) && !slices.Contains(names, name) {
			names = append(names, name)
		}
	}
	return names
}

// gc removes staging copies, version directories that are not current,
// last_good or in keep, and temp files a crashed atomic write left.
// Anything else in the store directory (an MDM inbox) is left alone.
func (s *Store) gc(st State, keep map[string]bool) error {
	var errs []error
	if entries, err := os.ReadDir(s.BundlesDir); err == nil {
		for _, entry := range entries {
			name := entry.Name()
			stale := strings.HasPrefix(name, stagingPrefix) ||
				(IsVersionDirName(name) && !st.held(name) && !keep[name])
			if stale {
				errs = append(errs, removeTree(filepath.Join(s.BundlesDir, name)))
			}
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		errs = append(errs, err)
	}
	for _, dir := range []string{s.LifecycleDir, s.receiptsDir()} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			name := entry.Name()
			if strings.HasPrefix(name, ".") && strings.HasSuffix(name, ".tmp") &&
				(strings.HasPrefix(name, "."+StateFileName+".") || dir == s.receiptsDir()) {
				errs = append(errs, os.Remove(filepath.Join(dir, name)))
			}
		}
	}
	return errors.Join(errs...)
}

func validSHA256Hex(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

// boundedMessage keeps a receipt message printable and at most
// MaxErrorMessage bytes.
func boundedMessage(message string) string {
	var b strings.Builder
	for _, r := range message {
		if r < 0x20 || r == 0x7f || !utf8.ValidRune(r) {
			r = ' '
		}
		if b.Len()+utf8.RuneLen(r) > MaxErrorMessage {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

// readStoreFile reads a regular, bounded store file without following a
// link.
func readStoreFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", filepath.Base(path))
	}
	if info.Size() > maxStoreFileBytes {
		return nil, fmt.Errorf("%s is larger than %d bytes", filepath.Base(path), maxStoreFileBytes)
	}
	return os.ReadFile(path)
}

// writeNewFile creates path (it must not exist), writes data and fsyncs.
func writeNewFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// makeReadOnly sets every file under root to 0444 and every directory to
// 0555, deepest first so the walk can still enter each directory.
func makeReadOnly(root string) error {
	var dirs []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		switch {
		case entry.IsDir():
			dirs = append(dirs, path)
		case entry.Type().IsRegular():
			return os.Chmod(path, 0o444)
		default:
			return fmt.Errorf("%s is not a regular file", path)
		}
		return nil
	})
	if err != nil {
		return err
	}
	for i := len(dirs) - 1; i >= 0; i-- {
		if err := syncDir(dirs[i]); err != nil {
			return err
		}
		if err := os.Chmod(dirs[i], 0o555); err != nil {
			return err
		}
	}
	return nil
}

// SealVersionForGroup gives one service group read and traversal rights to
// the verified tree. Ownership is set while staging remains private, and
// every entry is made read-only before the rename publishes it.
func SealVersionForGroup(root string, gid int, chown func(string, int, int) error) error {
	if gid < 0 || chown == nil {
		return errors.New("a service group and ownership operation are required")
	}
	var dirs []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			dirs = append(dirs, path)
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("%s is not a regular file", path)
		}
		if err := chown(path, 0, gid); err != nil {
			return err
		}
		return os.Chmod(path, 0o640)
	})
	if err != nil {
		return err
	}
	for i := len(dirs) - 1; i >= 0; i-- {
		if err := chown(dirs[i], 0, gid); err != nil {
			return err
		}
		if err := syncDir(dirs[i]); err != nil {
			return err
		}
		if err := os.Chmod(dirs[i], 0o750); err != nil {
			return err
		}
	}
	return nil
}

// removeTree removes root and everything below it, read-only entries
// included; a missing root is not an error. Links are removed, not followed.
func removeTree(root string) error {
	if _, err := os.Lstat(root); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	_ = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err == nil && entry.IsDir() {
			_ = os.Chmod(path, 0o700)
		} else if err == nil && entry.Type().IsRegular() && runtime.GOOS == "windows" {
			_ = os.Chmod(path, 0o600)
		}
		return nil
	})
	return os.RemoveAll(root)
}

// syncDir fsyncs a directory so a rename or a new entry in it is durable.
// Windows has no directory fsync; NTFS journals the rename.
func syncDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
