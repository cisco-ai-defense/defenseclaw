// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/pathidentity"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

type Manifest struct {
	Version int              `json:"version" yaml:"version"`
	Targets []ManifestTarget `json:"targets" yaml:"targets"`
	// Skipped lists rows left out because they were invalid, where the
	// platform isolates a bad row instead of rejecting the whole manifest.
	Skipped []ManifestRowSkip `json:"-" yaml:"-"`
}

// ManifestRowSkip is one manifest row that was left out, by its index in
// the file.
type ManifestRowSkip struct {
	Index  int
	Reason string
}

type ManifestTarget struct {
	User         string `json:"user,omitempty" yaml:"user,omitempty"`
	UserHome     string `json:"user_home,omitempty" yaml:"user_home,omitempty"`
	UID          *int   `json:"uid,omitempty" yaml:"uid,omitempty"`
	GID          *int   `json:"gid,omitempty" yaml:"gid,omitempty"`
	SID          string `json:"sid,omitempty" yaml:"sid,omitempty"`
	Connector    string `json:"connector,omitempty" yaml:"connector,omitempty"`
	DataDir      string `json:"data_dir,omitempty" yaml:"data_dir,omitempty"`
	AgentVersion string `json:"agent_version,omitempty" yaml:"agent_version,omitempty"`
	Enabled      *bool  `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	// Deferred authorizes the Windows Guardian to leave this otherwise-enabled
	// target pending while no exact WTSActive token exists for its manifest SID.
	// The bit lives in the administrator-owned, digest-bound manifest so an
	// ordinary disabled row can never be mistaken for automatic enrollment.
	Deferred bool `json:"deferred,omitempty" yaml:"deferred,omitempty"`
	// HomeInode binds a standalone Unix row to the home directory the
	// enumerator observed. A reused uid or a recreated home gets a new
	// inode, so the row is treated as a new enrollment with no prior
	// repair rights. Zero (absent) on every other platform and profile.
	HomeInode uint64 `json:"home_inode,omitempty" yaml:"home_inode,omitempty"`
}

const enterpriseHookManifestMaxBytes int64 = 4 << 20

func LoadManifest(path string) (Manifest, error) {
	manifest, _, err := LoadManifestWithSHA256(path)
	return manifest, err
}

// LoadManifestWithSHA256 returns the digest of the exact bounded bytes parsed
// from the identity-stable manifest handle. Callers can therefore bind a
// reconcile receipt to the same file generation they actually processed.
func LoadManifestWithSHA256(path string) (Manifest, string, error) {
	return loadManifestWithSHA256(path, validateManifestPlatformTarget)
}

func loadManifestWithSHA256(path string, validateTarget func(int, ManifestTarget) error) (Manifest, string, error) {
	if strings.TrimSpace(path) == "" {
		return Manifest{}, "", fmt.Errorf("enterprise hooks: manifest path is required")
	}
	var data []byte
	err := safefile.RetryPublishedRead(func() error {
		var readErr error
		data, readErr = readManifestStableBytes(path)
		return readErr
	})
	if err != nil {
		return Manifest{}, "", err
	}
	var manifest Manifest
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	decodeErr := decoder.Decode(&manifest)
	if decodeErr == io.EOF {
		return Manifest{}, "", fmt.Errorf("enterprise hooks: manifest %s is empty; refusing to withdraw enrolled hooks", path)
	}
	isolated := false
	if decodeErr != nil && manifestIsolatesBadRows {
		// One malformed row must not stop every user: decode row by row
		// and leave out only the rows that do not parse.
		if rows, ok := decodeManifestRowByRow(data); ok {
			manifest, decodeErr, isolated = rows, nil, true
		}
	}
	if decodeErr != nil {
		return Manifest{}, "", fmt.Errorf("enterprise hooks: parse manifest %s: %w", path, decodeErr)
	}
	if manifest.Targets == nil && len(manifest.Skipped) == 0 {
		return Manifest{}, "", fmt.Errorf("enterprise hooks: manifest %s has no explicit targets; refusing to withdraw enrolled hooks", path)
	}
	if !isolated {
		var trailing any
		if err := decoder.Decode(&trailing); err != io.EOF {
			if err == nil {
				err = fmt.Errorf("multiple YAML documents are not allowed")
			}
			return Manifest{}, "", fmt.Errorf("enterprise hooks: parse manifest %s: %w", path, err)
		}
	}
	if manifest.Version == 0 {
		manifest.Version = 1
	}
	if manifest.Version != 1 {
		return Manifest{}, "", fmt.Errorf("enterprise hooks: manifest version %d is not supported", manifest.Version)
	}
	seen := map[string]int{}
	kept := manifest.Targets[:0:0]
	decodeSkipped := append([]ManifestRowSkip(nil), manifest.Skipped...)
	for i, target := range manifest.Targets {
		index := manifestRowIndex(decodeSkipped, i)
		if err := validateManifestRow(index, target, seen, validateTarget); err != nil {
			if !manifestIsolatesBadRows {
				return Manifest{}, "", err
			}
			manifest.Skipped = append(manifest.Skipped, ManifestRowSkip{Index: index, Reason: err.Error()})
			continue
		}
		kept = append(kept, target)
	}
	if manifestIsolatesBadRows {
		if len(kept) == 0 && len(manifest.Skipped) > 0 {
			// Every row was left out: an unusable manifest must not read
			// as one that withdraws every enrolled user.
			return Manifest{}, "", fmt.Errorf("enterprise hooks: manifest %s has no valid targets (%s); refusing to withdraw enrolled hooks",
				path, manifest.Skipped[0].Reason)
		}
		manifest.Targets = kept
	}
	digest := sha256.Sum256(data)
	return manifest, hex.EncodeToString(digest[:]), nil
}

// readManifestStableBytes repeats the whole checked read after a transient
// name lookup failure. A successful retry must validate its own file identity.
func readManifestStableBytes(path string) ([]byte, error) {
	expected, err := pathidentity.LstatPinned(path)
	if err != nil {
		return nil, fmt.Errorf("enterprise hooks: inspect manifest %s: %w", path, err)
	}
	if !expected.Mode().IsRegular() {
		return nil, fmt.Errorf("enterprise hooks: manifest is not a regular non-link file: %s", path)
	}
	if expected.Size() > enterpriseHookManifestMaxBytes {
		return nil, fmt.Errorf(
			"enterprise hooks: manifest %s exceeds %d-byte limit",
			path,
			enterpriseHookManifestMaxBytes,
		)
	}
	file, err := winpath.OpenReadShared(path)
	if err != nil {
		return nil, fmt.Errorf("enterprise hooks: read manifest %s: %w", path, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("enterprise hooks: inspect manifest %s: %w", path, err)
	}
	if !info.Mode().IsRegular() || !os.SameFile(expected, info) {
		return nil, fmt.Errorf("enterprise hooks: manifest changed identity before open: %s", path)
	}
	if info.Size() > enterpriseHookManifestMaxBytes {
		return nil, fmt.Errorf(
			"enterprise hooks: manifest %s exceeds %d-byte limit",
			path,
			enterpriseHookManifestMaxBytes,
		)
	}
	current, err := os.Lstat(path)
	if err != nil || !current.Mode().IsRegular() || !os.SameFile(info, current) {
		if err != nil {
			return nil, fmt.Errorf("enterprise hooks: re-inspect manifest %s: %w", path, err)
		}
		return nil, fmt.Errorf("enterprise hooks: manifest changed identity before read: %s", path)
	}
	data, err := io.ReadAll(io.LimitReader(file, enterpriseHookManifestMaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("enterprise hooks: read manifest %s: %w", path, err)
	}
	if int64(len(data)) > enterpriseHookManifestMaxBytes {
		return nil, fmt.Errorf(
			"enterprise hooks: manifest %s exceeds %d-byte limit",
			path,
			enterpriseHookManifestMaxBytes,
		)
	}
	// Post-read identity confirmation. The pre-ReadAll Lstat above proves
	// the entry we're about to read is still the same inode we opened, but
	// nothing between there and here reproves it — a swap in the read
	// window would silently give us bytes from a different file. Re-Lstat
	// AFTER ReadAll and require size + inode identity to still match the
	// open handle's Stat. Same pattern as stableManagedArtifactDigestWith in
	// internal/gateway/connector/connector_state.go.
	final, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("enterprise hooks: re-inspect manifest %s after read: %w", path, err)
	}
	if !final.Mode().IsRegular() || !os.SameFile(info, final) || final.Size() != int64(len(data)) {
		return nil, fmt.Errorf("enterprise hooks: manifest changed identity during read: %s", path)
	}
	return data, nil
}

// validateManifestRow checks one row with the caller's platform rule
// (validateTarget) and records an enabled row's key in seen, so a later
// duplicate is refused.
func validateManifestRow(i int, target ManifestTarget, seen map[string]int, validateTarget func(int, ManifestTarget) error) error {
	if target.Deferred && target.Enabled != nil && !*target.Enabled {
		return fmt.Errorf(
			"enterprise hooks: target %d cannot be both disabled and deferred",
			i,
		)
	}
	if target.Enabled != nil && !*target.Enabled {
		return nil
	}
	if strings.TrimSpace(target.User) == "" && strings.TrimSpace(target.UserHome) == "" && strings.TrimSpace(target.SID) == "" {
		return fmt.Errorf("enterprise hooks: target %d requires user, user_home, or sid", i)
	}
	if strings.TrimSpace(target.Connector) == "" {
		return fmt.Errorf("enterprise hooks: target %d requires connector", i)
	}
	if err := validateTarget(i, target); err != nil {
		return err
	}
	key := manifestTargetKey(target)
	if previous, duplicate := seen[key]; duplicate {
		return fmt.Errorf("enterprise hooks: target %d duplicates enabled target %d", i, previous)
	}
	seen[key] = i
	return nil
}

// manifestRowIndex maps a position among the decoded targets back to the
// row's index in the file when rows were already left out while decoding.
// skipped is in file order.
func manifestRowIndex(skipped []ManifestRowSkip, position int) int {
	index := position
	for _, row := range skipped {
		if row.Index <= index {
			index++
		}
	}
	return index
}

// decodeManifestRowByRow parses a manifest whose strict decode failed one
// row at a time, keeping the rows that parse strictly and recording the
// rest. It reports false when the document itself is unusable.
func decodeManifestRowByRow(data []byte) (Manifest, bool) {
	var loose struct {
		Version int         `yaml:"version"`
		Targets []yaml.Node `yaml:"targets"`
	}
	// Only the rows are isolated: an unknown top-level key (a typo such as
	// "targetz") still rejects the document rather than loading it as empty.
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&loose); err != nil {
		return Manifest{}, false
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Manifest{}, false
	}
	manifest := Manifest{Version: loose.Version}
	for i := range loose.Targets {
		encoded, err := yaml.Marshal(&loose.Targets[i])
		if err != nil {
			manifest.Skipped = append(manifest.Skipped, ManifestRowSkip{Index: i, Reason: err.Error()})
			continue
		}
		var target ManifestTarget
		rowDecoder := yaml.NewDecoder(bytes.NewReader(encoded))
		rowDecoder.KnownFields(true)
		if err := rowDecoder.Decode(&target); err != nil {
			manifest.Skipped = append(manifest.Skipped, ManifestRowSkip{
				Index:  i,
				Reason: fmt.Sprintf("enterprise hooks: target %d does not parse: %v", i, err),
			})
			continue
		}
		manifest.Targets = append(manifest.Targets, target)
	}
	return manifest, true
}

func manifestTargetKey(target ManifestTarget) string {
	connectorName := strings.ToLower(strings.TrimSpace(target.Connector))
	if sid := strings.TrimSpace(target.SID); sid != "" {
		return connectorName + "\x00sid\x00" + canonicalManifestTargetSID(sid)
	}
	if userName := strings.TrimSpace(target.User); userName != "" {
		return connectorName + "\x00user\x00" + userName
	}
	return connectorName + "\x00home\x00" + filepath.Clean(strings.TrimSpace(target.UserHome))
}

func (t ManifestTarget) IsEnabled() bool {
	return t.Enabled == nil || *t.Enabled
}

func (t ManifestTarget) IsDeferred() bool {
	return t.Deferred
}
