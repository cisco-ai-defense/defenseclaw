// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
)

// ConfigChangePin is what the record of a spooled change takes from the
// gateway that first offered it, and the digest of that record. The change
// event (its id, time and content) is the rest. The pin is written and
// flushed before any sink gets the record, and every later offer, after a
// restart (another run id, sidecar id or binary) or a config reload
// (another generation and digest) included, builds the record from the
// event and its pin and sends it only when its digest is the pinned one.
// So the audit row and every remote destination get the same record under
// the change's id.
type ConfigChangePin struct {
	RunID             string `json:"run_id,omitempty"`
	SidecarInstanceID string `json:"sidecar_instance_id,omitempty"`
	BinaryVersion     string `json:"binary_version"`
	ConfigGeneration  uint64 `json:"config_generation"`
	ConfigDigest      string `json:"config_digest"`
	// FloorOnly is the mandatory-floor form (collection admitted only it).
	FloorOnly bool `json:"floor_only,omitempty"`
	// RecordSHA256 is the SHA-256 of the canonical record's bytes.
	RecordSHA256 string `json:"record_sha256"`
}

// maxConfigChangePinBytes bounds a pin file read.
const maxConfigChangePinBytes = 4096

var (
	configChangePinKey    = lazyregexp.New(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)
	configChangePinDigest = lazyregexp.New(`^[0-9a-f]{64}$`)
)

func (pin ConfigChangePin) valid() bool {
	return pin.BinaryVersion != "" && pin.ConfigGeneration <= math.MaxInt64 &&
		observability.IsStableToken(pin.ConfigDigest) && configChangePinDigest.MatchString(pin.RecordSHA256)
}

// ConfigChangePins keeps one pin file per change event, named by the event
// id, in a folder of the gateway's data directory.
type ConfigChangePins struct {
	dir string
	// mkdir makes the pin folder so its entry survives a power loss.
	mkdir func(dir string) error
	// writeFile writes and flushes a pin file and its folder.
	writeFile func(path string, data []byte, mode os.FileMode) error
}

// NewConfigChangePins returns the pins kept in dir.
func NewConfigChangePins(dir string) *ConfigChangePins {
	return &ConfigChangePins{dir: dir, mkdir: configwrite.MkdirDurable, writeFile: configwrite.WriteFileDurable}
}

func (pins *ConfigChangePins) path(eventID string) (string, error) {
	if pins == nil || strings.TrimSpace(pins.dir) == "" {
		return "", errors.New("audit: a config change has no record pin folder")
	}
	if !configChangePinKey.MatchString(eventID) {
		return "", errors.New("audit: a config change pin needs a valid event id")
	}
	return filepath.Join(pins.dir, eventID+".json"), nil
}

// load reads the pin of eventID, and whether there is one. A pin that does
// not read or validate is an error: the record cannot be rebuilt as the one
// a sink may already have.
func (pins *ConfigChangePins) load(eventID string) (ConfigChangePin, bool, error) {
	path, err := pins.path(eventID)
	if err != nil {
		return ConfigChangePin{}, false, err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return ConfigChangePin{}, false, nil
	}
	if err != nil {
		return ConfigChangePin{}, false, fmt.Errorf("audit: read the record pin of change %s: %w", eventID, err)
	}
	if !info.Mode().IsRegular() {
		return ConfigChangePin{}, false, fmt.Errorf("audit: the record pin of change %s is not a regular file", eventID)
	}
	file, err := os.Open(path)
	if err != nil {
		return ConfigChangePin{}, false, fmt.Errorf("audit: read the record pin of change %s: %w", eventID, err)
	}
	defer file.Close() //nolint:errcheck
	raw, err := io.ReadAll(io.LimitReader(file, maxConfigChangePinBytes+1))
	if err != nil || len(raw) > maxConfigChangePinBytes {
		return ConfigChangePin{}, false, fmt.Errorf("audit: read the record pin of change %s", eventID)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var pin ConfigChangePin
	if err := decoder.Decode(&pin); err != nil || !pin.valid() {
		return ConfigChangePin{}, false, fmt.Errorf("audit: the record pin of change %s is invalid", eventID)
	}
	return pin, true, nil
}

// store writes the pin of eventID and flushes it and its folder (the
// folder's entry in its parent too, on Windows as well), so it survives a
// power loss before any sink gets the record: a lost pin would let a later
// offer build another record under the change's id.
func (pins *ConfigChangePins) store(eventID string, pin ConfigChangePin) error {
	path, err := pins.path(eventID)
	if err != nil {
		return err
	}
	if !pin.valid() {
		return fmt.Errorf("audit: the record pin of change %s is invalid", eventID)
	}
	if err := pins.mkdir(pins.dir); err != nil {
		return fmt.Errorf("audit: create the record pin folder: %w", err)
	}
	encoded, err := json.Marshal(pin)
	if err != nil {
		return err
	}
	if err := pins.writeFile(path, append(encoded, '\n'), 0o600); err != nil {
		return fmt.Errorf("audit: write the record pin of change %s: %w", eventID, err)
	}
	return nil
}

// Remove deletes the pin of a change every sink confirmed. A missing pin
// is not an error.
func (pins *ConfigChangePins) Remove(eventID string) error {
	path, err := pins.path(eventID)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// Prune removes the pins of the changes reported says are reported (left
// by a gateway that stopped between marking a change and removing its pin).
func (pins *ConfigChangePins) Prune(reported func(eventID string) bool) {
	if pins == nil || reported == nil {
		return
	}
	entries, err := os.ReadDir(pins.dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		id, ok := strings.CutSuffix(entry.Name(), ".json")
		if ok && entry.Type().IsRegular() && configChangePinKey.MatchString(id) && reported(id) {
			_ = pins.Remove(id)
		}
	}
}

// configChangeRecordDigestMigrationDescription names the audit migration
// that adds audit_events.record_sha256.
const configChangeRecordDigestMigrationDescription = "audit events: keep the canonical record digest of a spooled change"

// migrateAuditEventRecordDigest adds audit_events.record_sha256, the
// SHA-256 of the canonical record the row of a spooled change was written
// from (spooledChange.recordDigest). Every other row leaves it NULL. The
// column is additive: an earlier binary names its insert columns and never
// reads it.
func migrateAuditEventRecordDigest(ex dbExecer) error {
	present, err := tableExists(ex, "audit_events")
	if err != nil || !present {
		return err
	}
	exists, err := hasColumnDB(ex, "audit_events", "record_sha256")
	if err != nil || exists {
		return err
	}
	if _, err := ex.Exec(`ALTER TABLE audit_events ADD COLUMN record_sha256 TEXT`); err != nil {
		return fmt.Errorf("alter audit_events.record_sha256: %w", err)
	}
	return nil
}

// recordSHA256 is the digest a pin and a change's row keep of a record.
func recordSHA256(encoded []byte) string {
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

// storedChangeRow is what the audit row of a change keeps of its record:
// the local projection (projected_record_json), which copies every member
// of the canonical record but its body and field classes byte for byte,
// whether it is the mandatory-floor form, and the digest of the canonical
// record (record_sha256; empty on a row an earlier build wrote).
type storedChangeRow struct {
	envelope  []byte
	floorOnly bool
	digest    string
}

// storedChangeRow reads the audit row with id, and whether there is one. A
// store without a database holds none.
func (s *Store) storedChangeRow(ctx context.Context, id string) (storedChangeRow, bool, error) {
	if s == nil || s.db == nil {
		return storedChangeRow{}, false, nil
	}
	var envelope, payload, digest string
	err := s.scanRow(ctx, "audit_event_exists",
		s.db.QueryRowContext(ctx, `SELECT COALESCE(projected_record_json,''), COALESCE(payload_json,''),
			COALESCE(record_sha256,'') FROM audit_events WHERE id = ? LIMIT 1`, id), &envelope, &payload, &digest)
	if errors.Is(err, sql.ErrNoRows) {
		return storedChangeRow{}, false, nil
	}
	if err != nil {
		return storedChangeRow{}, false, fmt.Errorf("audit: look up audit event %s: %w", id, err)
	}
	var body struct {
		FloorOnly bool `json:"floor_only"`
	}
	_ = json.Unmarshal([]byte(payload), &body)
	return storedChangeRow{envelope: []byte(envelope), floorOnly: body.FloorOnly, digest: digest}, true, nil
}

// pin is the pin of the record the row holds: its run, sidecar, binary and
// config, read from its projection, and the digest stored with it. A row
// without a digest has no pin: the body of its record is not in its
// projection, so a rebuild cannot be told from another record.
func (row storedChangeRow) pin() (ConfigChangePin, error) {
	if !configChangePinDigest.MatchString(row.digest) {
		return ConfigChangePin{}, errors.New("audit: the stored change row keeps no record digest, so its record cannot be rebuilt")
	}
	envelope, err := decodeEnvelope(row.envelope)
	if err != nil {
		return ConfigChangePin{}, errors.New("audit: the stored change row has no valid record")
	}
	var correlation struct {
		RunID             string `json:"run_id"`
		SidecarInstanceID string `json:"sidecar_instance_id"`
	}
	var provenance struct {
		BinaryVersion    string `json:"binary_version"`
		ConfigGeneration int64  `json:"config_generation"`
		ConfigDigest     string `json:"config_digest"`
	}
	if json.Unmarshal(envelope["correlation"], &correlation) != nil ||
		json.Unmarshal(envelope["provenance"], &provenance) != nil || provenance.ConfigGeneration < 0 ||
		provenance.BinaryVersion == "" || !observability.IsStableToken(provenance.ConfigDigest) {
		return ConfigChangePin{}, errors.New("audit: the stored change row has no valid record provenance")
	}
	return ConfigChangePin{
		RunID: correlation.RunID, SidecarInstanceID: correlation.SidecarInstanceID,
		BinaryVersion: provenance.BinaryVersion, ConfigGeneration: uint64(provenance.ConfigGeneration),
		ConfigDigest: provenance.ConfigDigest, FloorOnly: row.floorOnly, RecordSHA256: row.digest,
	}, nil
}

// holds reports whether the row's projection is of record, whose canonical
// bytes are encoded: every member but the body and field classes is the
// record's, byte for byte, the form is the same, and the digest stored
// with the row, if it has one, is the record's. The body of a row without
// a digest is checked through the pin's digest.
func (row storedChangeRow) holds(record observability.Record, encoded []byte) bool {
	if record.IsFloorOnly() != row.floorOnly || (row.digest != "" && row.digest != recordSHA256(encoded)) {
		return false
	}
	canonical, err := decodeEnvelope(encoded)
	if err != nil {
		return false
	}
	stored, err := decodeEnvelope(row.envelope)
	if err != nil || len(stored) != len(canonical)+1 {
		return false
	}
	if _, ok := stored["projection"]; !ok {
		return false
	}
	for key, value := range canonical {
		if key == "body" || key == "field_classes" {
			continue
		}
		if !bytes.Equal(value, stored[key]) {
			return false
		}
	}
	return true
}

// spooledChange is one offer of a spooled change: its pin store and key,
// the pin (none on its first offer) and the stored row, if the store holds
// one.
type spooledChange struct {
	pins *ConfigChangePins
	key  string
	// id is the record id, and the audit row id, of the change.
	id     string
	pin    ConfigChangePin
	pinned bool
	// fromRow: the pin was read from the stored row (its pin file is
	// gone) and is written again once the record rebuilds as the row's.
	fromRow bool
	row     *storedChangeRow
	// lookupErr: the store could not say whether it holds the row.
	lookupErr error
}

// pinEvent gives the change's event the pinned run, sidecar and binary.
func (change *spooledChange) pinEvent(event *Event) {
	if change == nil || !change.pinned {
		return
	}
	event.RunID = change.pin.RunID
	event.SidecarInstanceID = change.pin.SidecarInstanceID
	event.BinaryVersion = change.pin.BinaryVersion
}

// context marks ctx with the pinned config, which the runtime accepts in
// place of the current generation for this record.
func (change *spooledChange) context(ctx context.Context) context.Context {
	if change == nil || !change.pinned {
		return ctx
	}
	return observability.WithPinnedProvenance(ctx, observability.PinnedProvenance{
		ConfigGeneration: change.pin.ConfigGeneration, ConfigDigest: change.pin.ConfigDigest,
	})
}

// builder wraps the record builder of the change: the first offer pins the
// record it builds, flushed, before it returns it to the runtime (so before
// any sink gets it); every later offer builds it on the pinned config and
// form and returns it only when it is the pinned record and, with a stored
// row, the row's record. Anything else is an error: no sink gets it.
func (change *spooledChange) builder(build RuntimeV8Builder) RuntimeV8Builder {
	return func(snapshot RuntimeV8BuildContext, admission router.Admission) (observability.Record, error) {
		floor := admission == router.AdmissionFloor
		if change.pinned {
			if floor != change.pin.FloorOnly {
				return observability.Record{}, fmt.Errorf(
					"audit: collection now admits another form of change %s than its pinned record, so it is not sent", change.key)
			}
			snapshot = RuntimeV8BuildContext{ConfigGeneration: change.pin.ConfigGeneration, ConfigDigest: change.pin.ConfigDigest}
		}
		record, err := build(snapshot, admission)
		if err != nil {
			return observability.Record{}, err
		}
		encoded, err := record.Bytes()
		if err != nil {
			return observability.Record{}, err
		}
		digest := recordSHA256(encoded)
		if change.row != nil && !change.row.holds(record, encoded) {
			return observability.Record{}, fmt.Errorf(
				"audit: the stored row of change %s is not its record, so the record is not sent", change.key)
		}
		if change.pinned {
			if digest != change.pin.RecordSHA256 {
				return observability.Record{}, fmt.Errorf(
					"audit: change %s does not rebuild as its pinned record, so it is not sent", change.key)
			}
			if !change.fromRow {
				return record, nil
			}
		}
		pin := change.pin
		if !change.pinned {
			correlation, provenance := record.Correlation(), record.Provenance()
			pin = ConfigChangePin{
				RunID: correlation.RunID, SidecarInstanceID: correlation.SidecarInstanceID,
				BinaryVersion: provenance.BinaryVersion, ConfigDigest: provenance.ConfigDigest,
				FloorOnly: floor,
			}
			if provenance.ConfigGeneration < 0 {
				return observability.Record{}, fmt.Errorf("audit: change %s has an invalid config generation", change.key)
			}
			pin.ConfigGeneration = uint64(provenance.ConfigGeneration)
		}
		pin.RecordSHA256 = digest
		if err := change.pins.store(change.key, pin); err != nil {
			return observability.Record{}, err
		}
		change.pin, change.pinned, change.fromRow = pin, true, false
		return record, nil
	}
}

// recordDigest is the digest the audit row of record keeps: that of its
// canonical bytes when record is the change's own record, none otherwise.
func (change *spooledChange) recordDigest(record observability.Record) (string, error) {
	if change == nil || change.id == "" || record.RecordID() != change.id {
		return "", nil
	}
	encoded, err := record.Bytes()
	if err != nil {
		return "", err
	}
	return recordSHA256(encoded), nil
}

type spooledChangeKey struct{}

func withSpooledChange(ctx context.Context, change *spooledChange) context.Context {
	return context.WithValue(ctx, spooledChangeKey{}, change)
}

func spooledChangeFrom(ctx context.Context) *spooledChange {
	if ctx == nil {
		return nil
	}
	change, _ := ctx.Value(spooledChangeKey{}).(*spooledChange)
	return change
}
