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
	// AgentExecutable is an exact administrator-selected native client image.
	// The guardian never resolves this value through PATH, and protected hosts
	// bind it to a short-lived digest receipt before connector Setup.
	AgentExecutable string `json:"agent_executable,omitempty" yaml:"agent_executable,omitempty"`
	Enabled         *bool  `json:"enabled,omitempty" yaml:"enabled,omitempty"`
}

func LoadManifest(path string) (Manifest, error) {
	if strings.TrimSpace(path) == "" {
		return Manifest{}, fmt.Errorf("enterprise hooks: manifest path is required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, fmt.Errorf("enterprise hooks: read manifest %s: %w", path, err)
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
		if target.AgentExecutable != strings.TrimSpace(target.AgentExecutable) ||
			strings.ContainsAny(target.AgentExecutable, "\x00\r\n") ||
			(target.AgentExecutable != "" && (!filepath.IsAbs(target.AgentExecutable) ||
				filepath.Clean(target.AgentExecutable) != target.AgentExecutable)) {
			return Manifest{}, fmt.Errorf("enterprise hooks: target %d has invalid agent_executable", i)
		}
		if target.AgentExecutable != "" && strings.TrimSpace(target.AgentVersion) == "" {
			return Manifest{}, fmt.Errorf("enterprise hooks: target %d requires agent_version with agent_executable", i)
		}
	}
	return manifest, nil
}

func (t ManifestTarget) IsEnabled() bool {
	return t.Enabled == nil || *t.Enabled
}
