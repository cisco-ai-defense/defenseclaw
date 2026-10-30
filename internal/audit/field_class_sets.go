// Copyright 2026 Cisco Systems, Inc. and its affiliates
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
	"regexp"
	"strings"
)

// The field classes of a v8 event-history row (the redaction class of each
// body field) are the same for every row of a family: 1.0 to 1.4 KB that a
// hook decision stored again in each of its 8 rows, about 9 KB of audit.db
// per Claude Code tool call (#1384 lever 2). A standalone store keeps each
// distinct set once, in audit_field_class_sets, and the row's signed
// projection names it by digest instead:
//
//	"field_classes":{"$set":"<sha256 of the set's JSON>"}
//
// The digest is inside the projection, so projection_hash and payload_hmac
// still cover the classes: VerifyEventHistoryRecord also checks that the set
// is present and hashes to the digest. The member keeps its name and stays a
// JSON object, so a 1.0.4 or 1.0.5 binary reads these rows after a rollback:
// their readers take the body, outcome, correlation and provenance of a
// projection, never its field classes (config_change_pin.go skips the
// member), and their verifier hashes the stored bytes. Exports are built from
// the record in memory and carry the full classes. A Secure Client store keeps
// main's schema and writes the classes inline (#1092).
const fieldClassSetsSchema = `CREATE TABLE IF NOT EXISTS audit_field_class_sets (
	digest TEXT PRIMARY KEY CHECK (length(digest) = 64),
	classes_json TEXT NOT NULL
) WITHOUT ROWID`

const fieldClassSetInsertSQL = `INSERT OR IGNORE INTO audit_field_class_sets (digest, classes_json) VALUES (?, ?)`

// fieldClassSetMinBytes: a smaller set is stored inline; the reference
// ({"$set":"<64 hex>"}) is 74 bytes.
const fieldClassSetMinBytes = 160

// maxFieldClassSets bounds the table. Sets are per family and field shape, a
// few dozen in practice; past the bound new sets are written inline, so the
// table never grows with history. It is never pruned: a row that names a set
// needs it for as long as retention keeps the row.
const maxFieldClassSets = 4096

const fieldClassSetRefKey = "$set"

var fieldClassSetDigestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ensureFieldClassSets creates the set table on a standalone store. It is
// not a numbered migration: the schema version stays the one 1.0.5 wrote,
// and a Secure Client store keeps main's schema.
func (s *Store) ensureFieldClassSets() error {
	if s.secureClientSchema {
		s.fieldClassSets.Store(false)
		return nil
	}
	if _, err := s.db.Exec(fieldClassSetsSchema); err != nil {
		return fmt.Errorf("audit: create field class sets: %w", err)
	}
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM audit_field_class_sets`).Scan(&count); err != nil {
		return fmt.Errorf("audit: count field class sets: %w", err)
	}
	s.fieldClassSetCount.Store(int64(count))
	s.fieldClassSets.Store(true)
	return nil
}

// storedProjection returns the bytes a row keeps of projectedEnvelope: the
// same envelope with a large field_classes member replaced by a reference to
// its set, which is stored in tx. A Secure Client store, a small set, a full
// set table or an envelope that does not decode keeps the envelope as is.
func (s *Store) storedProjection(ctx context.Context, tx *sql.Tx, projectedEnvelope []byte) ([]byte, error) {
	if s == nil || !s.fieldClassSets.Load() {
		return projectedEnvelope, nil
	}
	envelope, err := decodeEnvelope(projectedEnvelope)
	if err != nil {
		return projectedEnvelope, nil
	}
	classes, present := envelope["field_classes"]
	if !present || len(classes) < fieldClassSetMinBytes || classes[0] != '{' {
		return projectedEnvelope, nil
	}
	// Only the member's value changes: the bytes before and after it stay as
	// the projection wrote them, so ExpandStoredProjection gives the
	// projection back byte for byte.
	member := append([]byte(`"field_classes":`), classes...)
	if bytes.Count(projectedEnvelope, member) != 1 {
		return projectedEnvelope, nil
	}
	sum := sha256.Sum256(classes)
	digest := hex.EncodeToString(sum[:])
	if s.fieldClassSetCount.Load() >= maxFieldClassSets {
		return projectedEnvelope, nil
	}
	// INSERT OR IGNORE in the row's transaction: a set that is present is
	// one primary-key probe of a small table and writes no page; a new set
	// commits with the first row that names it, or not at all.
	result, err := s.txExecPrepared(ctx, tx, "field_class_set_insert", fieldClassSetInsertSQL, digest, string(classes))
	if err != nil {
		return nil, err
	}
	if inserted, _ := result.RowsAffected(); inserted > 0 {
		s.fieldClassSetCount.Add(1)
	}
	return bytes.Replace(projectedEnvelope, member, fieldClassSetMember(digest), 1), nil
}

// fieldClassSetMember is the field_classes member of a row that names set
// digest.
func fieldClassSetMember(digest string) []byte {
	return []byte(`"field_classes":{"` + fieldClassSetRefKey + `":"` + digest + `"}`)
}

// fieldClassSetReference returns the digest a stored projection names, or
// "" when it holds its classes inline. ok is false for a malformed reference.
func fieldClassSetReference(projected []byte) (digest string, ok bool) {
	envelope, err := decodeEnvelope(projected)
	if err != nil {
		return "", true
	}
	classes, present := envelope["field_classes"]
	if !present || !bytes.Contains(classes, []byte(`"`+fieldClassSetRefKey+`"`)) {
		return "", true
	}
	var reference map[string]string
	if err := json.Unmarshal(classes, &reference); err != nil || len(reference) != 1 {
		return "", false
	}
	digest = reference[fieldClassSetRefKey]
	if !fieldClassSetDigestPattern.MatchString(digest) {
		return "", false
	}
	return digest, true
}

var errFieldClassSetMissing = errors.New("audit: field class set missing or altered")

// checkFieldClassSet verifies that the set a stored projection names is in
// the store and hashes to its digest.
func (s *Store) checkFieldClassSet(ctx context.Context, projected []byte) error {
	digest, ok := fieldClassSetReference(projected)
	if !ok {
		return errFieldClassSetMissing
	}
	if digest == "" {
		return nil
	}
	var classes string
	err := s.db.QueryRowContext(ctx, `SELECT classes_json FROM audit_field_class_sets WHERE digest = ?`, digest).Scan(&classes)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || strings.Contains(err.Error(), "no such table") {
			return errFieldClassSetMissing
		}
		return fmt.Errorf("audit: read field class set: %w", err)
	}
	sum := sha256.Sum256([]byte(classes))
	if hex.EncodeToString(sum[:]) != digest {
		return errFieldClassSetMissing
	}
	return nil
}

// ExpandStoredProjection returns a stored projection with the field classes
// of its set inline, as the record had them; a projection that holds its
// classes inline is returned unchanged.
func (s *Store) ExpandStoredProjection(ctx context.Context, projected []byte) ([]byte, error) {
	digest, ok := fieldClassSetReference(projected)
	if !ok {
		return nil, errFieldClassSetMissing
	}
	if digest == "" {
		return projected, nil
	}
	if err := s.checkFieldClassSet(ctx, projected); err != nil {
		return nil, err
	}
	var classes string
	if err := s.db.QueryRowContext(ctx, `SELECT classes_json FROM audit_field_class_sets WHERE digest = ?`, digest).Scan(&classes); err != nil {
		return nil, fmt.Errorf("audit: read field class set: %w", err)
	}
	member := fieldClassSetMember(digest)
	if bytes.Count(projected, member) != 1 {
		return nil, errFieldClassSetMissing
	}
	return bytes.Replace(projected, member, append([]byte(`"field_classes":`), classes...), 1), nil
}
