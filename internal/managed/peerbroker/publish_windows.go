// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package peerbroker

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"golang.org/x/sys/windows"
)

// publishPipeName writes the published-name record to path (in the machine
// <data dir>\hooks folder): a temp file next to it with the owner-only
// protection plus a BUILTIN\Users read entry, renamed over the old record.
// Only LocalSystem and Administrators can write it; the gateway and users
// read it.
func publishPipeName(path string, names Names, pipe string) error {
	raw, err := names.EncodePublished(Published{Version: ProtocolVersion, Pipe: pipe, PID: windows.GetCurrentProcessId()})
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if info, err := os.Lstat(dir); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("the hooks folder of the data dir is missing")
	}
	tmp, err := os.CreateTemp(dir, ".peer-broker-pipe-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := safefile.ProtectFile(name); err != nil {
		return err
	}
	if err := safefile.GrantUsersRead(name); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// readPublishedPipeName reads and validates the record: a regular file (no
// link) owned by this account, LocalSystem or Administrators with no write
// entry for anyone else, at most MaxMessageBytes, naming a pipe of this
// scope.
func readPublishedPipeName(path string, names Names) (Published, error) {
	if err := safefile.ValidatePrivateFileOwnershipAllowingAdministrators(path); err != nil {
		return Published{}, err
	}
	raw, err := safefile.ReadRegularFileBounded(path, MaxMessageBytes)
	if err != nil {
		return Published{}, err
	}
	return names.DecodePublished(raw)
}

// unpublishPipeName removes the record when it still names pipe.
func unpublishPipeName(path string, names Names, pipe string) {
	if current, err := readPublishedPipeName(path, names); err == nil && current.Pipe == pipe {
		_ = os.Remove(path)
	}
}
