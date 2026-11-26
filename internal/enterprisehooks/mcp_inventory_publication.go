// Copyright 2026 Cisco Systems, Inc.
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	mcpInventoryReceiptPrefix = "mcp-inventory-v1: "
	mcpInventoryPending       = "mcp-inventory-v1: pending\n"
	mcpInventoryGenerationLen = 16
)

// PublishMCPInventorySpool invalidates a connector's inventory receipt before
// attempting publication. The receipt lives beside the spool directory, so a
// record that Windows will neither replace nor withdraw cannot remain current.
// Admission keeps using its existing per-record refresh protocol.
func PublishMCPInventorySpool(dir string, publish func() error, setOwnership func(string) error) error {
	readyPath := dir + ".inventory-ready"
	pendingPath := dir + ".inventory-pending"
	if err := os.MkdirAll(filepath.Dir(readyPath), 0o750); err != nil {
		return fmt.Errorf("create MCP inventory receipt directory: %w", err)
	}
	if err := writeSpoolBytes(filepath.Dir(pendingPath), filepath.Base(pendingPath), ".mcp-inventory-pending-*", []byte(mcpInventoryPending), setOwnership); err != nil {
		return fmt.Errorf("mark MCP inventory publication pending: %w", err)
	}
	// Truncate in place before doing anything that can fail in the publisher.
	// A crash or failed write leaves the pending marker in place.
	f, err := os.OpenFile(readyPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		// A read-only receipt may still be removable by its parent directory.
		removeErr := os.Remove(readyPath)
		return fmt.Errorf("invalidate MCP inventory receipt: %w", errors.Join(err, removeErr))
	}
	if err := errors.Join(f.Sync(), f.Close()); err != nil {
		return fmt.Errorf("close pending MCP inventory receipt: %w", err)
	}
	if setOwnership != nil {
		if err := setOwnership(readyPath); err != nil {
			return fmt.Errorf("protect MCP inventory receipt: %w", err)
		}
	}
	if err := publish(); err != nil {
		return err
	}
	generation := make([]byte, mcpInventoryGenerationLen)
	if _, err := rand.Read(generation); err != nil {
		return fmt.Errorf("create MCP inventory generation: %w", err)
	}
	receipt := mcpInventoryReceiptPrefix + hex.EncodeToString(generation) + "\n"
	if err := writeSpoolBytes(filepath.Dir(readyPath), filepath.Base(readyPath), ".mcp-inventory-ready-*", []byte(receipt), setOwnership); err != nil {
		return err
	}
	if err := os.Remove(pendingPath); err != nil {
		return fmt.Errorf("complete MCP inventory publication: %w", err)
	}
	return nil
}

// ReadMCPInventoryPublication requires a trusted, successful publication before
// a Secure Client inventory scan consumes any of a connector's records. The
// returned generation lets the caller reject a concurrent republish.
func ReadMCPInventoryPublication(dir string, validate func(string, string) error) (string, error) {
	path := dir + ".inventory-ready"
	if _, err := os.Lstat(dir + ".inventory-pending"); !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("MCP inventory publication is incomplete")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Size() != int64(len(mcpInventoryReceiptPrefix)+hex.EncodedLen(mcpInventoryGenerationLen)+1) {
		return "", fmt.Errorf("MCP inventory publication is incomplete")
	}
	if validate != nil {
		if err := validate(path, filepath.Dir(path)); err != nil {
			return "", err
		}
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, info.Size()+1))
	if err != nil {
		return "", err
	}
	receipt := string(data)
	generation := strings.TrimSuffix(strings.TrimPrefix(receipt, mcpInventoryReceiptPrefix), "\n")
	decoded, decodeErr := hex.DecodeString(generation)
	if !strings.HasPrefix(receipt, mcpInventoryReceiptPrefix) || !strings.HasSuffix(receipt, "\n") || decodeErr != nil || len(decoded) != mcpInventoryGenerationLen {
		return "", fmt.Errorf("MCP inventory publication is incomplete")
	}
	if _, err := os.Lstat(dir + ".inventory-pending"); !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("MCP inventory publication is incomplete")
	}
	return generation, nil
}
