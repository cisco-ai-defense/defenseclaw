// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

const (
	deploymentFileName = "deployment.json"
	pendingFileName    = "pending.json"
	snapshotsDirName   = "snapshots"
	adoptedPrefix      = "adopted-"

	deploymentSchemaVersion = 1
	pendingSchemaVersion    = 1
)

// Install channels.
const (
	ChannelPayload = "payload" // binaries copied from a staged directory
	ChannelPackage = "package" // binaries owned by the deb/rpm/pkg
)

// MacOSPackageID is the receipt identifier of the macOS installer package.
const MacOSPackageID = "com.cisco.defenseclaw.enterprise"

// Deployment is the committed record of what the lifecycle installed. It is
// root-only state in the lifecycle directory and the source of truth for
// ensure, verify and uninstall.
type Deployment struct {
	SchemaVersion  int    `json:"schema_version"`
	Profile        string `json:"profile"`
	Platform       string `json:"platform"`
	ProductVersion string `json:"product_version"`
	Channel        string `json:"channel"`
	InstalledAt    string `json:"installed_at"`
	UpdatedAt      string `json:"updated_at"`
	NoStart        bool   `json:"no_start"`

	ServiceUser           string `json:"service_user"`
	ServiceUID            int    `json:"service_uid"`
	ServiceGID            int    `json:"service_gid"`
	CreatedServiceAccount bool   `json:"created_service_account"`

	ConfigSHA256  string `json:"config_sha256"`
	SecretsSHA256 string `json:"secrets_sha256"`
	// Files maps every file the lifecycle wrote (canonical path) to the
	// SHA-256 of its installed bytes.
	Files map[string]string `json:"files"`
	// CreatedDirs lists directories outside the DefenseClaw tree that the
	// lifecycle created (vendor machine-policy parents). Uninstall removes
	// them only while they are empty.
	CreatedDirs []string `json:"created_dirs"`
	// MachinePolicyConnectors are the connectors whose DefenseClaw hooks the
	// last transaction left in place in vendor machine policy; the runtime
	// descriptor records exactly this set.
	MachinePolicyConnectors []string `json:"machine_policy_connectors"`
	// RulePacks are the rule packs the applied config resolved to, keyed by
	// setting (validatedConfig.RulePacks).
	RulePacks map[string]string `json:"rule_packs,omitempty"`
}

// Pending is the intent record of an in-flight transaction.
type Pending struct {
	SchemaVersion    int      `json:"schema_version"`
	Action           string   `json:"action"`
	StartedAt        string   `json:"started_at"`
	SnapshotDir      string   `json:"snapshot_dir"`
	Phase            string   `json:"phase"`
	PreviouslyActive []string `json:"previously_active"`
	// PreviouslyEnabled lists the units that started at boot before the
	// transaction (the managed units and, for an adoption, the adopted
	// ones); rollback enables them again.
	PreviouslyEnabled []string `json:"previously_enabled,omitempty"`
	// EnabledRecorded is set when PreviouslyEnabled covers every managed
	// unit, so rollback also disables the managed units the transaction
	// enabled. An intent from a service manager that cannot report whether
	// a unit is enabled (launchd, whose failed first install removes its
	// plists instead) leaves it unset, and so does an intent written
	// before the field existed.
	EnabledRecorded bool `json:"enabled_recorded,omitempty"`
}

func (e *Env) deploymentPath() string {
	return filepath.Join(e.P(e.Layout.LifecycleDir), deploymentFileName)
}

func (e *Env) pendingPath() string {
	return filepath.Join(e.P(e.Layout.LifecycleDir), pendingFileName)
}

// loadDeployment returns the committed record, or nil when none exists.
func (e *Env) loadDeployment() (*Deployment, error) {
	data, err := readBounded(e.deploymentPath(), maxInputBytes)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read deployment record: %w", err)
	}
	var record Deployment
	if err := decodeStrict(data, &record); err != nil {
		return nil, fmt.Errorf("parse deployment record: %w", err)
	}
	if record.SchemaVersion != deploymentSchemaVersion {
		return nil, fmt.Errorf("deployment record schema_version %d is not supported", record.SchemaVersion)
	}
	if record.Files == nil {
		record.Files = map[string]string{}
	}
	return &record, nil
}

func (e *Env) saveDeployment(record *Deployment) error {
	record.SchemaVersion = deploymentSchemaVersion
	sort.Strings(record.CreatedDirs)
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	return e.writeFileAtomic(e.deploymentPath(), append(data, '\n'), 0o600, rootOwner())
}

func (e *Env) loadPending() (*Pending, error) {
	data, err := readBounded(e.pendingPath(), maxInputBytes)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read pending transaction: %w", err)
	}
	var pending Pending
	if err := decodeStrict(data, &pending); err != nil {
		return nil, fmt.Errorf("parse pending transaction: %w", err)
	}
	return &pending, nil
}

func (e *Env) savePending(pending *Pending) error {
	pending.SchemaVersion = pendingSchemaVersion
	data, err := json.MarshalIndent(pending, "", "  ")
	if err != nil {
		return err
	}
	return e.writeFileAtomic(e.pendingPath(), append(data, '\n'), 0o600, rootOwner())
}

func (e *Env) clearPending() error {
	return removeFile(e.pendingPath())
}

func decodeStrict(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if decoder.More() {
		return errors.New("trailing data")
	}
	return nil
}

func rootOwner() fileOwner { return fileOwner{UID: 0, GID: 0} }
