// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type Manifest struct {
	Version int              `json:"version" yaml:"version"`
	Targets []ManifestTarget `json:"targets" yaml:"targets"`
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
}

const enterpriseHookManifestMaxBytes int64 = 4 << 20

func LoadManifest(path string) (Manifest, error) {
	if strings.TrimSpace(path) == "" {
		return Manifest{}, fmt.Errorf("enterprise hooks: manifest path is required")
	}
	expected, err := os.Lstat(path)
	if err != nil {
		return Manifest{}, fmt.Errorf("enterprise hooks: inspect manifest %s: %w", path, err)
	}
	if expected.Mode()&os.ModeSymlink != 0 || !expected.Mode().IsRegular() {
		return Manifest{}, fmt.Errorf("enterprise hooks: manifest is not a regular non-link file: %s", path)
	}
	if expected.Size() > enterpriseHookManifestMaxBytes {
		return Manifest{}, fmt.Errorf(
			"enterprise hooks: manifest %s exceeds %d-byte limit",
			path,
			enterpriseHookManifestMaxBytes,
		)
	}
	file, err := os.Open(path)
	if err != nil {
		return Manifest{}, fmt.Errorf("enterprise hooks: read manifest %s: %w", path, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return Manifest{}, fmt.Errorf("enterprise hooks: inspect manifest %s: %w", path, err)
	}
	if !info.Mode().IsRegular() || !os.SameFile(expected, info) {
		return Manifest{}, fmt.Errorf("enterprise hooks: manifest changed identity before open: %s", path)
	}
	if info.Size() > enterpriseHookManifestMaxBytes {
		return Manifest{}, fmt.Errorf(
			"enterprise hooks: manifest %s exceeds %d-byte limit",
			path,
			enterpriseHookManifestMaxBytes,
		)
	}
	current, err := os.Lstat(path)
	if err != nil || current.Mode()&os.ModeSymlink != 0 || !current.Mode().IsRegular() || !os.SameFile(info, current) {
		if err != nil {
			return Manifest{}, fmt.Errorf("enterprise hooks: re-inspect manifest %s: %w", path, err)
		}
		return Manifest{}, fmt.Errorf("enterprise hooks: manifest changed identity before read: %s", path)
	}
	data, err := io.ReadAll(io.LimitReader(file, enterpriseHookManifestMaxBytes+1))
	if err != nil {
		return Manifest{}, fmt.Errorf("enterprise hooks: read manifest %s: %w", path, err)
	}
	if int64(len(data)) > enterpriseHookManifestMaxBytes {
		return Manifest{}, fmt.Errorf(
			"enterprise hooks: manifest %s exceeds %d-byte limit",
			path,
			enterpriseHookManifestMaxBytes,
		)
	}
	var manifest Manifest
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	decodeErr := decoder.Decode(&manifest)
	if decodeErr != nil && decodeErr != io.EOF {
		return Manifest{}, fmt.Errorf("enterprise hooks: parse manifest %s: %w", path, decodeErr)
	}
	if decodeErr == nil {
		var trailing any
		if err := decoder.Decode(&trailing); err != io.EOF {
			if err == nil {
				err = fmt.Errorf("multiple YAML documents are not allowed")
			}
			return Manifest{}, fmt.Errorf("enterprise hooks: parse manifest %s: %w", path, err)
		}
	}
	if manifest.Version == 0 {
		manifest.Version = 1
	}
	if manifest.Version != 1 {
		return Manifest{}, fmt.Errorf("enterprise hooks: manifest version %d is not supported", manifest.Version)
	}
	seen := map[string]int{}
	for i, target := range manifest.Targets {
		if target.Enabled != nil && !*target.Enabled {
			continue
		}
		if strings.TrimSpace(target.User) == "" && strings.TrimSpace(target.UserHome) == "" && strings.TrimSpace(target.SID) == "" {
			return Manifest{}, fmt.Errorf("enterprise hooks: target %d requires user, user_home, or sid", i)
		}
		if strings.TrimSpace(target.Connector) == "" {
			return Manifest{}, fmt.Errorf("enterprise hooks: target %d requires connector", i)
		}
		if err := validateManifestPlatformTarget(i, target); err != nil {
			return Manifest{}, err
		}
		key := manifestTargetKey(target)
		if previous, duplicate := seen[key]; duplicate {
			return Manifest{}, fmt.Errorf("enterprise hooks: target %d duplicates enabled target %d", i, previous)
		}
		seen[key] = i
	}
	return manifest, nil
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
