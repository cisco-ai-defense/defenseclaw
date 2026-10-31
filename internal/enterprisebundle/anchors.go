// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package enterprisebundle

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
	"time"
	"unicode/utf8"
)

// AnchorsName is the trust anchor file name (in <etc>/trust/).
const AnchorsName = "bundle-anchors.json"

// AnchorsSchemaVersion is the bundle-anchors.json schema this build reads.
const AnchorsSchemaVersion = 1

// Key statuses. A retired key verifies only the bundle already applied (a
// repair re-verifies it after a rotation); a revoked key verifies nothing.
const (
	KeyActive  = "active"
	KeyRetired = "retired"
	KeyRevoked = "revoked"
)

// MaxAnchorDeviceGroups bounds device_groups.
const MaxAnchorDeviceGroups = 256

// Anchors is bundle-anchors.json, which MDM installs: the tenant, the
// device groups this device belongs to (empty: any), the lowest bundle
// version it accepts and the bundle signing keys. Its presence turns bundle
// mode on.
type Anchors struct {
	SchemaVersion int         `json:"schema_version"`
	TenantID      string      `json:"tenant_id"`
	DeviceGroups  []string    `json:"device_groups"`
	MinVersion    uint64      `json:"min_version"`
	Keys          []AnchorKey `json:"keys"`
}

// AnchorKey is one bundle signing key: its id, algorithm, public key (DER
// SubjectPublicKeyInfo, standard base64), validity and status.
type AnchorKey struct {
	KeyID     string `json:"key_id"`
	Alg       string `json:"alg"`
	PublicKey string `json:"public_key"`
	NotBefore string `json:"not_before"`
	NotAfter  string `json:"not_after"`
	Status    string `json:"status"`

	public    crypto.PublicKey
	notBefore time.Time
	notAfter  time.Time
}

// AnchorsSummary is the anchors_summary member of bundle status: what the
// installed trust anchor file says, without the public keys, so a
// management agent reports it without reading and hashing the file itself.
// SHA256 is the lowercase hex SHA-256 of the file bytes status decoded.
type AnchorsSummary struct {
	SHA256       string             `json:"sha256"`
	TenantID     string             `json:"tenant_id"`
	DeviceGroups []string           `json:"device_groups"`
	MinVersion   uint64             `json:"min_version"`
	Keys         []AnchorKeySummary `json:"keys"`
}

// AnchorKeySummary is one key of AnchorsSummary: never the public key.
type AnchorKeySummary struct {
	KeyID     string `json:"key_id"`
	Alg       string `json:"alg"`
	Status    string `json:"status"`
	NotBefore string `json:"not_before"`
	NotAfter  string `json:"not_after"`
}

// SummarizeAnchors summarizes decoded anchors and the bytes they were
// decoded from (ReadAnchorsFile); nil anchors summarize to nil.
func SummarizeAnchors(a *Anchors, raw []byte) *AnchorsSummary {
	if a == nil {
		return nil
	}
	sum := sha256.Sum256(raw)
	out := &AnchorsSummary{SHA256: hex.EncodeToString(sum[:]), TenantID: a.TenantID,
		DeviceGroups: append([]string{}, a.DeviceGroups...), MinVersion: a.MinVersion, Keys: []AnchorKeySummary{}}
	for _, k := range a.Keys {
		out.Keys = append(out.Keys, AnchorKeySummary{KeyID: k.KeyID, Alg: k.Alg, Status: k.Status, NotBefore: k.NotBefore, NotAfter: k.NotAfter})
	}
	return out
}

// Public returns the parsed public key (set by DecodeAnchors).
func (k *AnchorKey) Public() crypto.PublicKey { return k.public }

// ValidAt reports whether t falls inside the key validity (both ends
// inclusive).
func (k *AnchorKey) ValidAt(t time.Time) bool {
	return !t.Before(k.notBefore) && !t.After(k.notAfter)
}

// Key returns the key with id, or nil.
func (a *Anchors) Key(id string) *AnchorKey {
	for i := range a.Keys {
		if a.Keys[i].KeyID == id {
			return &a.Keys[i]
		}
	}
	return nil
}

// AllowsDeviceGroup reports whether a bundle for group may apply here: the
// anchor lists it, or lists no group.
func (a *Anchors) AllowsDeviceGroup(group string) bool {
	if len(a.DeviceGroups) == 0 {
		return true
	}
	for _, g := range a.DeviceGroups {
		if g == group {
			return true
		}
	}
	return false
}

// PinDeviceGroup pins decoded anchors (and the bytes they were decoded from)
// to the one device group this device is in, for `enterprise bundle anchors
// install --device-group` (the device_groups member names the groups this
// device belongs to). The file may name several groups, the way a tenant-wide
// file does, or none (any); either way it must allow group, so the pin only
// narrows what the file trusts. A file that already names exactly that group
// keeps its bytes. Otherwise the pinned file is the anchors re-encoded with
// device_groups [group] and decoded again, so what is written is what a
// device reads. The group is checked like a device_groups entry.
func PinDeviceGroup(a *Anchors, raw []byte, group string) (*Anchors, []byte, error) {
	if !scopeIDPattern.MatchString(group) {
		return nil, nil, refuse(CodeAnchorInvalid, AnchorsName, "device group: want 1-128 characters of [A-Za-z0-9._-]")
	}
	if !a.AllowsDeviceGroup(group) {
		return nil, nil, refuse(CodeAnchorInvalid, AnchorsName,
			"device group %s is not one of the groups this anchor file lists (%s); a pin only narrows the file", group, strings.Join(a.DeviceGroups, ", "))
	}
	if len(a.DeviceGroups) == 1 {
		return a, raw, nil
	}
	pinned := *a
	pinned.DeviceGroups = []string{group}
	out, err := json.MarshalIndent(&pinned, "", "  ")
	if err != nil {
		return nil, nil, refuse(CodeAnchorInvalid, AnchorsName, "cannot pin the device group: %v", err)
	}
	out = append(out, '\n')
	decoded, err := DecodeAnchors(out)
	if err != nil {
		return nil, nil, err
	}
	return decoded, out, nil
}

// TrustCheck refuses an anchor path a standard user could replace or edit.
type TrustCheck func(path string) error

// LoadAnchors reads the anchor file at path. A missing file is
// anchor_missing; a file or folder above it that fails trust (owner, mode,
// ACL, links; nil skips the check) or that is not a regular file is
// anchor_insecure; a malformed file is anchor_invalid. An anchor_insecure
// refusal caused by an operating system error wraps it: errors.Is(err,
// fs.ErrPermission) tells an account that may not read the file.
func LoadAnchors(path string, trust TrustCheck) (*Anchors, error) {
	anchors, _, err := ReadAnchorsFile(path, trust)
	return anchors, err
}

// ReadAnchorsFile is LoadAnchors that also returns the bytes it decoded
// (nil on any error), so a caller that installs the file writes exactly
// what was checked without reading the source again.
func ReadAnchorsFile(path string, trust TrustCheck) (*Anchors, []byte, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil, refuse(CodeAnchorMissing, AnchorsName, "no trust anchor file; bundle mode is off")
	}
	if err != nil {
		refusal := refuse(CodeAnchorInsecure, AnchorsName, "cannot inspect the trust anchor file: %s", boundedDetail(errors.Unwrap(err).Error()))
		refusal.cause = err
		return nil, nil, refusal
	}
	if !info.Mode().IsRegular() {
		return nil, nil, refuse(CodeAnchorInsecure, AnchorsName, "the trust anchor path is not a regular file")
	}
	if trust != nil {
		if err := trust(path); err != nil {
			refusal := refuse(CodeAnchorInsecure, AnchorsName, "%s", boundedDetail(err.Error()))
			refusal.cause = err
			return nil, nil, refusal
		}
	}
	file, err := os.Open(path)
	if err != nil {
		refusal := refuse(CodeAnchorInsecure, AnchorsName, "cannot open the trust anchor file")
		refusal.cause = err
		return nil, nil, refusal
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, nil, refuse(CodeAnchorInsecure, AnchorsName, "the trust anchor file was replaced while it was read")
	}
	raw, err := io.ReadAll(io.LimitReader(file, MaxAnchorsBytes+1))
	if err != nil {
		return nil, nil, refuse(CodeAnchorInvalid, AnchorsName, "cannot read the trust anchor file")
	}
	anchors, err := DecodeAnchors(raw)
	if err != nil {
		return nil, nil, err
	}
	return anchors, raw, nil
}

// DecodeAnchors decodes bundle-anchors.json strictly (anchor_invalid).
func DecodeAnchors(raw []byte) (*Anchors, error) {
	bad := func(field, format string, args ...any) error {
		if field != "" {
			format = field + ": " + format
		}
		return refuse(CodeAnchorInvalid, AnchorsName, format, args...)
	}
	if len(raw) > MaxAnchorsBytes {
		return nil, bad("", "larger than %d bytes", MaxAnchorsBytes)
	}
	if !utf8.Valid(raw) || bytes.HasPrefix(raw, []byte("\xef\xbb\xbf")) {
		return nil, bad("", "not UTF-8 JSON without a byte-order mark")
	}
	if err := checkJSONKeys(raw, CodeAnchorInvalid, AnchorsName); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var a Anchors
	if err := dec.Decode(&a); err != nil {
		return nil, bad("", "%s", jsonProblem(err))
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, bad("", "data after the anchor object")
	}
	if a.SchemaVersion != AnchorsSchemaVersion {
		return nil, bad("schema_version", "unsupported schema version %d (this build reads %d)", a.SchemaVersion, AnchorsSchemaVersion)
	}
	if !scopeIDPattern.MatchString(a.TenantID) {
		return nil, bad("tenant_id", "want 1-128 characters of [A-Za-z0-9._-]")
	}
	if len(a.DeviceGroups) > MaxAnchorDeviceGroups {
		return nil, bad("device_groups", "more than %d groups", MaxAnchorDeviceGroups)
	}
	groups := map[string]bool{}
	for _, group := range a.DeviceGroups {
		if !scopeIDPattern.MatchString(group) {
			return nil, bad("device_groups", "want 1-128 characters of [A-Za-z0-9._-] per group")
		}
		if groups[group] {
			return nil, bad("device_groups", "%s is listed twice", group)
		}
		groups[group] = true
	}
	if a.MinVersion > MaxVersion {
		return nil, bad("min_version", "above %d", uint64(MaxVersion))
	}
	if len(a.Keys) == 0 || len(a.Keys) > MaxAnchorKeys {
		return nil, bad("keys", "want 1 to %d keys", MaxAnchorKeys)
	}
	ids := map[string]bool{}
	for i := range a.Keys {
		key := &a.Keys[i]
		field := fmt.Sprintf("keys[%d]", i)
		if !ValidKeyID(key.KeyID) {
			return nil, bad(field+".key_id", "want 1-128 characters of [A-Za-z0-9._:-]")
		}
		if ids[key.KeyID] {
			return nil, bad(field+".key_id", "%s is listed twice", key.KeyID)
		}
		ids[key.KeyID] = true
		if key.Alg != AlgEd25519 && key.Alg != AlgECDSAP256SHA256 {
			return nil, bad(field+".alg", "want ed25519 or ecdsa-p256-sha256")
		}
		der, err := base64.StdEncoding.Strict().DecodeString(key.PublicKey)
		if err != nil {
			return nil, bad(field+".public_key", "not standard base64")
		}
		public, alg, err := ParsePublicKey(der)
		if err != nil {
			return nil, bad(field+".public_key", "%s", err)
		}
		if alg != key.Alg {
			return nil, bad(field+".public_key", "the key is not an %s key", key.Alg)
		}
		key.public = public
		if key.notBefore, err = parseUTC(key.NotBefore); err != nil {
			return nil, bad(field+".not_before", "want an RFC 3339 UTC time ending in Z")
		}
		if key.notAfter, err = parseUTC(key.NotAfter); err != nil {
			return nil, bad(field+".not_after", "want an RFC 3339 UTC time ending in Z")
		}
		if !key.notAfter.After(key.notBefore) {
			return nil, bad(field+".not_after", "not after not_before")
		}
		switch key.Status {
		case KeyActive, KeyRetired, KeyRevoked:
		default:
			return nil, bad(field+".status", "want active, retired or revoked")
		}
	}
	return &a, nil
}

func parseUTC(value string) (time.Time, error) {
	if !strings.HasSuffix(value, "Z") {
		return time.Time{}, errors.New("not UTC")
	}
	return time.Parse(time.RFC3339, value)
}
