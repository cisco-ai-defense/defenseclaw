// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// The keys of the store state ConfigMap (defenseclaw-store-state) the
// gateway leader writes after it migrated the store, and the rollback check
// reads.
const (
	StoreStateSchemaKey  = "schema_version"
	StoreStateBackupKey  = "backup"
	StoreStateVersionKey = "written_by_version"
	StoreStateUpdatedKey = "updated_at"
)

// StoreState is the leader store's schema and the backup it took before the
// last migration.
type StoreState struct {
	SchemaVersion    int    `json:"schema_version"`
	Backup           string `json:"backup,omitempty"`
	WrittenByVersion string `json:"written_by_version,omitempty"`
	UpdatedAt        string `json:"updated_at,omitempty"`
}

// ParseStoreState reads the ConfigMap data; nil data (no ConfigMap yet,
// a fresh install) is a nil state.
func ParseStoreState(data map[string]string) (*StoreState, error) {
	if data == nil {
		return nil, nil
	}
	n, err := strconv.Atoi(strings.TrimSpace(data[StoreStateSchemaKey]))
	if err != nil || n < 1 {
		return nil, fmt.Errorf("store state: %s %q is not a schema version", StoreStateSchemaKey, data[StoreStateSchemaKey])
	}
	return &StoreState{
		SchemaVersion:    n,
		Backup:           data[StoreStateBackupKey],
		WrittenByVersion: data[StoreStateVersionKey],
		UpdatedAt:        data[StoreStateUpdatedKey],
	}, nil
}

// Data is the ConfigMap data of s.
func (s StoreState) Data() map[string]string {
	d := map[string]string{StoreStateSchemaKey: strconv.Itoa(s.SchemaVersion)}
	if s.Backup != "" {
		d[StoreStateBackupKey] = s.Backup
	}
	if s.WrittenByVersion != "" {
		d[StoreStateVersionKey] = s.WrittenByVersion
	}
	if s.UpdatedAt != "" {
		d[StoreStateUpdatedKey] = s.UpdatedAt
	}
	return d
}

// ErrRollbackSchema refuses a rollback (or a downgrade through upgrade) to a
// release whose gateway cannot read the store (E25).
type ErrRollbackSchema struct {
	Store, Target int
	Backup        string
	WrittenBy     string
}

func (e *ErrRollbackSchema) Error() string {
	msg := fmt.Sprintf("refusing the rollback: the leader store is at schema %d (written by %s) and this release reads schema %d",
		e.Store, orDefault(e.WrittenBy, "a newer release"), e.Target)
	if e.Backup != "" {
		return msg + fmt.Sprintf(". To go back anyway, scale the leader to 0, restore the backup %s on the defenseclaw-store volume "+
			"(the store state ConfigMap names it), set %s to %d, then roll back", e.Backup, StoreStateSchemaKey, e.Target)
	}
	return msg + ". No backup is recorded; restore the volume from your own snapshot before rolling back"
}

// CheckRollback refuses a target release that reads an older store schema
// than the store has. A fresh store (nil state) never refuses.
func CheckRollback(targetSchema int, state *StoreState) error {
	if state == nil || state.SchemaVersion <= targetSchema {
		return nil
	}
	return &ErrRollbackSchema{Store: state.SchemaVersion, Target: targetSchema, Backup: state.Backup, WrittenBy: state.WrittenByVersion}
}

// ErrSkew refuses an upgrade that skips a minor release, or one that goes
// backwards (use helm rollback).
var ErrSkew = errors.New("upgrade skew")

// CheckUpgrade allows N-1 -> N and any patch: the target's major.minor is the
// same as the installed one's or the next minor. An unknown installed version
// (no store state yet) is allowed.
func CheckUpgrade(installed, target string) error {
	if installed == "" {
		return nil
	}
	from, err := ParseVersion(installed)
	if err != nil {
		return nil
	}
	to, err := ParseVersion(target)
	if err != nil {
		return fmt.Errorf("%w: target version %q: %v", ErrSkew, target, err)
	}
	switch {
	case to.Compare(from) < 0:
		return fmt.Errorf("%w: %s is older than the installed %s; use helm rollback, which checks the store schema", ErrSkew, target, installed)
	case to.Major != from.Major && (to.Major != from.Major+1 || to.Minor != 0):
		return fmt.Errorf("%w: %s -> %s skips a major release; upgrade one release at a time", ErrSkew, installed, target)
	case to.Major == from.Major && to.Minor > from.Minor+1:
		return fmt.Errorf("%w: %s -> %s skips a minor release; upgrade one minor at a time", ErrSkew, installed, target)
	}
	return nil
}
