// Copyright 2026 Cisco Systems, Inc.
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const mcpInventoryReady = "mcp-inventory-v1: ready\n"

// PublishMCPInventorySpool invalidates a connector's inventory receipt before
// attempting publication. The receipt lives beside the spool directory, so a
// record that Windows will neither replace nor withdraw cannot remain current.
// Admission keeps using its existing per-record refresh protocol.
func PublishMCPInventorySpool(dir string, publish func() error, setOwnership func(string) error) error {
	path := dir + ".inventory-ready"
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("create MCP inventory receipt directory: %w", err)
	}
	// Truncate in place before doing anything that can fail in the publisher.
	// A crash, a failed write, or a failed final rename leaves no ready receipt.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		// A read-only receipt may still be removable by its parent directory.
		removeErr := os.Remove(path)
		return fmt.Errorf("invalidate MCP inventory receipt: %w", errors.Join(err, removeErr))
	}
	if err := errors.Join(f.Sync(), f.Close()); err != nil {
		return fmt.Errorf("close pending MCP inventory receipt: %w", err)
	}
	if setOwnership != nil {
		if err := setOwnership(path); err != nil {
			return fmt.Errorf("protect MCP inventory receipt: %w", err)
		}
	}
	if err := publish(); err != nil {
		return err
	}
	return writeSpoolBytes(filepath.Dir(path), filepath.Base(path), ".mcp-inventory-*", []byte(mcpInventoryReady), setOwnership)
}

// ReadMCPInventoryPublication requires a trusted, successful publication before
// a Secure Client inventory scan consumes any of a connector's records.
func ReadMCPInventoryPublication(dir string, validate func(string, string) error) error {
	path := dir + ".inventory-ready"
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() != int64(len(mcpInventoryReady)) {
		return fmt.Errorf("MCP inventory publication is incomplete")
	}
	if validate != nil {
		if err := validate(path, filepath.Dir(path)); err != nil {
			return err
		}
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, int64(len(mcpInventoryReady)+1)))
	if err != nil {
		return err
	}
	if string(data) != mcpInventoryReady {
		return fmt.Errorf("MCP inventory publication is incomplete")
	}
	return nil
}
