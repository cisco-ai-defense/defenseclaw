// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// AssetQuarantinePlan binds one source tree to its connector-owned quarantine
// destination and immutable SHA-256 identity before any filesystem mutation.
type AssetQuarantinePlan struct {
	TargetType     string
	TargetName     string
	Connector      string
	SourcePath     string
	SourceRoot     string
	QuarantineRoot string
	QuarantinePath string
	ContentHash    string
	OwnershipJSON  string
}

// AssetRestorePlan binds a journalled quarantine copy to an allowed restore
// root. RecordID creates a deterministic, recoverable staging path.
type AssetRestorePlan struct {
	RecordID       string
	TargetType     string
	TargetName     string
	QuarantineRoot string
	QuarantinePath string
	RestorePath    string
	AllowedRoots   []string
	ContentHash    string
}

// NewAssetQuarantinePlan validates containment and captures content/ownership
// before the watcher commits its pending provenance record.
func NewAssetQuarantinePlan(
	quarantineRoot string,
	sourceRoots []string,
	targetType, targetName, connector, sourcePath string,
) (AssetQuarantinePlan, error) {
	typeDir, err := quarantineTypeDir(targetType)
	if err != nil {
		return AssetQuarantinePlan{}, err
	}
	if !safePathSegment(targetName) {
		return AssetQuarantinePlan{}, fmt.Errorf("enforce: invalid quarantine target name")
	}
	connector = strings.TrimSpace(connector)
	if connector != "" && !safePathSegment(connector) {
		return AssetQuarantinePlan{}, fmt.Errorf("enforce: invalid quarantine connector")
	}
	sourcePath, sourceRoot, err := pathWithinRoots(sourcePath, sourceRoots, false)
	if err != nil {
		return AssetQuarantinePlan{}, fmt.Errorf("enforce: quarantine source: %w", err)
	}
	if err := validateExistingAncestors(filepath.Dir(sourcePath)); err != nil {
		return AssetQuarantinePlan{}, fmt.Errorf("enforce: quarantine source ancestry: %w", err)
	}
	if filepath.Base(sourcePath) != targetName {
		return AssetQuarantinePlan{}, fmt.Errorf("enforce: quarantine source identity mismatch")
	}
	quarantineRootInput := strings.TrimSpace(quarantineRoot)
	if quarantineRootInput == "" {
		return AssetQuarantinePlan{}, fmt.Errorf("enforce: invalid quarantine root")
	}
	quarantineRoot, err = filepath.Abs(quarantineRootInput)
	if err != nil {
		return AssetQuarantinePlan{}, fmt.Errorf("enforce: invalid quarantine root")
	}
	quarantineRoot = filepath.Clean(quarantineRoot)
	if pathWithin(sourcePath, quarantineRoot, true) {
		return AssetQuarantinePlan{}, fmt.Errorf("enforce: quarantine source is inside quarantine storage")
	}
	parts := []string{quarantineRoot, typeDir}
	if connector != "" {
		parts = append(parts, connector)
	}
	parts = append(parts, targetName)
	destination := filepath.Join(parts...)
	if !pathWithin(destination, quarantineRoot, false) {
		return AssetQuarantinePlan{}, fmt.Errorf("enforce: quarantine destination escaped storage")
	}
	contentHash, err := AssetContentHash(sourcePath)
	if err != nil {
		return AssetQuarantinePlan{}, err
	}
	ownership, err := assetOwnershipJSON(sourcePath)
	if err != nil {
		return AssetQuarantinePlan{}, err
	}
	return AssetQuarantinePlan{
		TargetType: targetType, TargetName: targetName, Connector: connector,
		SourcePath: sourcePath, SourceRoot: sourceRoot,
		QuarantineRoot: quarantineRoot, QuarantinePath: destination,
		ContentHash: contentHash, OwnershipJSON: ownership,
	}, nil
}

// ExecuteAssetQuarantine performs copy, hash verification, atomic publication,
// source re-verification, then source removal. A verified published copy is
// retained on later failure so the pending durable journal can recover it.
func ExecuteAssetQuarantine(plan AssetQuarantinePlan, recordID string) error {
	if err := validateQuarantinePlan(plan); err != nil {
		return err
	}
	if !safePathSegment(recordID) {
		return fmt.Errorf("enforce: invalid quarantine journal id")
	}
	destinationExists, err := assetPathExists(plan.QuarantinePath)
	if err != nil {
		return err
	}
	if destinationExists {
		if err := requireAssetHash(plan.QuarantinePath, plan.ContentHash); err != nil {
			return fmt.Errorf("enforce: existing quarantine destination: %w", err)
		}
		sourceExists, sourceErr := assetPathExists(plan.SourcePath)
		if sourceErr != nil {
			return sourceErr
		}
		if !sourceExists {
			return nil
		}
		if err := requireAssetHash(plan.SourcePath, plan.ContentHash); err != nil {
			return fmt.Errorf("enforce: source changed during quarantine recovery: %w", err)
		}
		return removeAssetPath(plan.SourcePath, plan.SourceRoot)
	}
	if err := requireAssetHash(plan.SourcePath, plan.ContentHash); err != nil {
		return fmt.Errorf("enforce: source changed before quarantine: %w", err)
	}
	parent := filepath.Dir(plan.QuarantinePath)
	if err := ensureContainedDirectory(parent, plan.QuarantineRoot); err != nil {
		return err
	}
	stage := plan.QuarantinePath + ".pending-" + recordID
	if !pathWithin(stage, plan.QuarantineRoot, false) {
		return fmt.Errorf("enforce: quarantine stage escaped storage")
	}
	if exists, err := assetPathExists(stage); err != nil {
		return err
	} else if exists {
		if err := removeAssetPath(stage, plan.QuarantineRoot); err != nil {
			return fmt.Errorf("enforce: remove stale quarantine stage: %w", err)
		}
	}
	published := false
	defer func() {
		if !published {
			_ = removeAssetPathIfExists(stage, plan.QuarantineRoot)
		}
	}()
	if err := copyAssetPath(plan.SourcePath, stage); err != nil {
		return fmt.Errorf("enforce: copy quarantine stage: %w", err)
	}
	if err := requireAssetHash(stage, plan.ContentHash); err != nil {
		return fmt.Errorf("enforce: verify quarantine stage: %w", err)
	}
	if err := os.Rename(stage, plan.QuarantinePath); err != nil {
		return fmt.Errorf("enforce: publish quarantine destination: %w", err)
	}
	published = true
	if err := requireAssetHash(plan.QuarantinePath, plan.ContentHash); err != nil {
		return fmt.Errorf("enforce: verify quarantine destination: %w", err)
	}
	if err := requireAssetHash(plan.SourcePath, plan.ContentHash); err != nil {
		return fmt.Errorf("enforce: source changed during quarantine: %w", err)
	}
	if err := removeAssetPath(plan.SourcePath, plan.SourceRoot); err != nil {
		return fmt.Errorf("enforce: remove quarantined source: %w", err)
	}
	return nil
}

// ExecuteAssetRestore copies and verifies quarantine content into a staging
// path, atomically publishes it, re-verifies both copies, then removes the
// quarantine copy. It also completes interrupted restores idempotently.
func ExecuteAssetRestore(plan AssetRestorePlan) error {
	normalized, restoreRoot, err := normalizeRestorePlan(plan)
	if err != nil {
		return err
	}
	quarantineExists, err := assetPathExists(normalized.QuarantinePath)
	if err != nil {
		return err
	}
	restoreExists, err := assetPathExists(normalized.RestorePath)
	if err != nil {
		return err
	}
	if restoreExists {
		if err := requireAssetHash(normalized.RestorePath, normalized.ContentHash); err != nil {
			return fmt.Errorf("enforce: restore destination already exists with different content: %w", err)
		}
		if quarantineExists {
			if err := requireAssetHash(normalized.QuarantinePath, normalized.ContentHash); err != nil {
				return fmt.Errorf("enforce: quarantine changed during restore recovery: %w", err)
			}
			if err := removeAssetPath(normalized.QuarantinePath, normalized.QuarantineRoot); err != nil {
				return fmt.Errorf("enforce: finish quarantine removal: %w", err)
			}
		}
		return nil
	}
	if !quarantineExists {
		return fmt.Errorf("enforce: quarantined asset is missing")
	}
	if err := requireAssetHash(normalized.QuarantinePath, normalized.ContentHash); err != nil {
		return fmt.Errorf("enforce: quarantine integrity check: %w", err)
	}
	parent := filepath.Dir(normalized.RestorePath)
	if err := ensureContainedDirectory(parent, restoreRoot); err != nil {
		return err
	}
	stage := filepath.Join(parent, ".defenseclaw-restore-"+normalized.RecordID)
	if !pathWithin(stage, restoreRoot, false) {
		return fmt.Errorf("enforce: restore stage escaped allowed root")
	}
	if exists, err := assetPathExists(stage); err != nil {
		return err
	} else if exists {
		if err := removeAssetPath(stage, restoreRoot); err != nil {
			return fmt.Errorf("enforce: remove stale restore stage: %w", err)
		}
	}
	published := false
	defer func() {
		if !published {
			_ = removeAssetPathIfExists(stage, restoreRoot)
		}
	}()
	if err := copyAssetPath(normalized.QuarantinePath, stage); err != nil {
		return fmt.Errorf("enforce: copy restore stage: %w", err)
	}
	if err := requireAssetHash(stage, normalized.ContentHash); err != nil {
		return fmt.Errorf("enforce: verify restore stage: %w", err)
	}
	if err := os.Rename(stage, normalized.RestorePath); err != nil {
		return fmt.Errorf("enforce: publish restore destination: %w", err)
	}
	published = true
	if err := requireAssetHash(normalized.RestorePath, normalized.ContentHash); err != nil {
		return fmt.Errorf("enforce: verify restore destination: %w", err)
	}
	if err := requireAssetHash(normalized.QuarantinePath, normalized.ContentHash); err != nil {
		return fmt.Errorf("enforce: quarantine changed during restore: %w", err)
	}
	if err := removeAssetPath(normalized.QuarantinePath, normalized.QuarantineRoot); err != nil {
		return fmt.Errorf("enforce: remove restored quarantine copy: %w", err)
	}
	return nil
}

// AssetContentHash returns the deterministic SHA-256 tree identity used by the
// Python quarantine implementation. File type, relative path, permissions,
// and bytes all contribute to the digest.
func AssetContentHash(path string) (string, error) {
	pathInput := strings.TrimSpace(path)
	if pathInput == "" {
		return "", fmt.Errorf("enforce: invalid asset path")
	}
	path, err := filepath.Abs(pathInput)
	if err != nil {
		return "", fmt.Errorf("enforce: invalid asset path")
	}
	path = filepath.Clean(path)
	info, err := safeAssetInfo(path)
	if err != nil {
		return "", err
	}
	digest := sha256.New()
	if info.Mode().IsRegular() {
		writeDigest(digest, []byte("F\x00.\x00"))
		writeDigest(digest, []byte(fmt.Sprintf("%04o\x00", info.Mode().Perm())))
		if err := hashFileInto(digest, path); err != nil {
			return "", err
		}
	} else if info.IsDir() {
		if err := hashAssetDirectory(digest, path, path); err != nil {
			return "", err
		}
	} else {
		return "", fmt.Errorf("enforce: refusing non-regular asset %s", path)
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

// AssetContentHashMatches reports whether an existing safe asset retains the
// recorded SHA-256 identity.
func AssetContentHashMatches(path, expected string) (bool, error) {
	hashValue, err := AssetContentHash(path)
	if err != nil {
		return false, err
	}
	return hashValue == strings.ToLower(strings.TrimSpace(expected)), nil
}

func validateQuarantinePlan(plan AssetQuarantinePlan) error {
	if _, err := quarantineTypeDir(plan.TargetType); err != nil {
		return err
	}
	if !safePathSegment(plan.TargetName) || !safePathSegment(plan.Connector) && plan.Connector != "" {
		return fmt.Errorf("enforce: invalid quarantine identity")
	}
	if !filepath.IsAbs(plan.SourcePath) || !filepath.IsAbs(plan.SourceRoot) ||
		!filepath.IsAbs(plan.QuarantinePath) || !filepath.IsAbs(plan.QuarantineRoot) {
		return fmt.Errorf("enforce: quarantine plan paths must be absolute")
	}
	if !pathWithin(plan.SourcePath, plan.SourceRoot, false) ||
		!pathWithin(plan.QuarantinePath, plan.QuarantineRoot, false) {
		return fmt.Errorf("enforce: quarantine plan escaped an allowed root")
	}
	if filepath.Base(plan.SourcePath) != plan.TargetName ||
		filepath.Base(plan.QuarantinePath) != plan.TargetName {
		return fmt.Errorf("enforce: quarantine plan identity mismatch")
	}
	if err := validateSHA256Hex(plan.ContentHash); err != nil {
		return err
	}
	return nil
}

func normalizeRestorePlan(plan AssetRestorePlan) (AssetRestorePlan, string, error) {
	if _, err := quarantineTypeDir(plan.TargetType); err != nil {
		return AssetRestorePlan{}, "", err
	}
	if !safePathSegment(plan.TargetName) || !safePathSegment(plan.RecordID) {
		return AssetRestorePlan{}, "", fmt.Errorf("enforce: invalid restore identity")
	}
	var err error
	quarantineRootInput := strings.TrimSpace(plan.QuarantineRoot)
	if quarantineRootInput == "" || !filepath.IsAbs(quarantineRootInput) {
		return AssetRestorePlan{}, "", fmt.Errorf("enforce: quarantine root must be absolute")
	}
	plan.QuarantineRoot, err = filepath.Abs(quarantineRootInput)
	if err != nil {
		return AssetRestorePlan{}, "", fmt.Errorf("enforce: invalid quarantine root")
	}
	quarantinePathInput := strings.TrimSpace(plan.QuarantinePath)
	if quarantinePathInput == "" || !filepath.IsAbs(quarantinePathInput) {
		return AssetRestorePlan{}, "", fmt.Errorf("enforce: quarantine path must be absolute")
	}
	plan.QuarantinePath, err = filepath.Abs(quarantinePathInput)
	if err != nil {
		return AssetRestorePlan{}, "", fmt.Errorf("enforce: invalid quarantine path")
	}
	if !pathWithin(plan.QuarantinePath, plan.QuarantineRoot, false) ||
		filepath.Base(plan.QuarantinePath) != plan.TargetName {
		return AssetRestorePlan{}, "", fmt.Errorf("enforce: restore quarantine path escaped storage")
	}
	if err := validateExistingAncestors(filepath.Dir(plan.QuarantinePath)); err != nil {
		return AssetRestorePlan{}, "", fmt.Errorf("enforce: quarantine ancestry: %w", err)
	}
	var restoreRoot string
	plan.RestorePath, restoreRoot, err = pathWithinRoots(plan.RestorePath, plan.AllowedRoots, false)
	if err != nil {
		return AssetRestorePlan{}, "", fmt.Errorf("enforce: restore destination: %w", err)
	}
	if filepath.Base(plan.RestorePath) != plan.TargetName {
		return AssetRestorePlan{}, "", fmt.Errorf("enforce: restore destination identity mismatch")
	}
	if err := validateExistingAncestors(filepath.Dir(plan.RestorePath)); err != nil {
		return AssetRestorePlan{}, "", fmt.Errorf("enforce: restore ancestry: %w", err)
	}
	plan.ContentHash = strings.ToLower(strings.TrimSpace(plan.ContentHash))
	if err := validateSHA256Hex(plan.ContentHash); err != nil {
		return AssetRestorePlan{}, "", err
	}
	return plan, restoreRoot, nil
}

func quarantineTypeDir(targetType string) (string, error) {
	switch strings.TrimSpace(targetType) {
	case "skill":
		return "skills", nil
	case "plugin":
		return "plugins", nil
	default:
		return "", fmt.Errorf("enforce: unsupported quarantine target type %q", targetType)
	}
}

func safePathSegment(value string) bool {
	return value != "" && value == strings.TrimSpace(value) &&
		value != "." && value != ".." && !filepath.IsAbs(value) &&
		!strings.ContainsAny(value, "/\\\x00")
}

func pathWithinRoots(path string, roots []string, allowEqual bool) (string, string, error) {
	pathInput := strings.TrimSpace(path)
	if pathInput == "" || !filepath.IsAbs(pathInput) {
		return "", "", fmt.Errorf("path is not absolute")
	}
	path = filepath.Clean(pathInput)
	for _, root := range roots {
		rootInput := strings.TrimSpace(root)
		if rootInput == "" {
			continue
		}
		if !filepath.IsAbs(rootInput) {
			return "", "", fmt.Errorf("root is not absolute")
		}
		root = filepath.Clean(rootInput)
		if pathWithin(path, root, allowEqual) {
			return path, root, nil
		}
	}
	return "", "", fmt.Errorf("path is outside configured roots")
}

func pathWithin(path, root string, allowEqual bool) bool {
	path = filepath.Clean(path)
	root = filepath.Clean(root)
	relative, err := filepath.Rel(root, path)
	if err != nil || filepath.IsAbs(relative) {
		return false
	}
	if relative == "." {
		return allowEqual
	}
	return relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func safeAssetInfo(path string) (fs.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("enforce: inspect asset %s: %w", path, err)
	}
	if fileInfoIsLinkOrReparse(info) {
		return nil, fmt.Errorf("enforce: refusing linked or reparse-point asset %s", path)
	}
	if !info.IsDir() && !info.Mode().IsRegular() {
		return nil, fmt.Errorf("enforce: refusing non-regular asset %s", path)
	}
	return info, nil
}

func hashAssetDirectory(digest hash.Hash, root, current string) error {
	info, err := safeAssetInfo(current)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("enforce: expected asset directory %s", current)
	}
	relative, err := filepath.Rel(root, current)
	if err != nil || strings.HasPrefix(relative, "..") {
		return fmt.Errorf("enforce: asset tree escaped root")
	}
	writeDigest(digest, []byte("D\x00"))
	writeDigest(digest, []byte(filepath.ToSlash(relative)))
	writeDigest(digest, []byte("\x00"+fmt.Sprintf("%04o\x00", info.Mode().Perm())))
	entries, err := os.ReadDir(current)
	if err != nil {
		return fmt.Errorf("enforce: read asset directory %s: %w", current, err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	var directories []fs.DirEntry
	for _, entry := range entries {
		path := filepath.Join(current, entry.Name())
		childInfo, err := safeAssetInfo(path)
		if err != nil {
			return err
		}
		if childInfo.IsDir() {
			directories = append(directories, entry)
			continue
		}
		relative, err := filepath.Rel(root, path)
		if err != nil || strings.HasPrefix(relative, "..") {
			return fmt.Errorf("enforce: asset file escaped root")
		}
		writeDigest(digest, []byte("F\x00"))
		writeDigest(digest, []byte(filepath.ToSlash(relative)))
		writeDigest(digest, []byte("\x00"+fmt.Sprintf("%04o\x00", childInfo.Mode().Perm())))
		if err := hashFileInto(digest, path); err != nil {
			return err
		}
	}
	for _, entry := range directories {
		if err := hashAssetDirectory(digest, root, filepath.Join(current, entry.Name())); err != nil {
			return err
		}
	}
	return nil
}

func hashFileInto(digest hash.Hash, path string) error {
	identity, err := safeAssetInfo(path)
	if err != nil {
		return err
	}
	handle, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("enforce: open asset file %s: %w", path, err)
	}
	defer handle.Close()
	opened, err := handle.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(identity, opened) {
		return fmt.Errorf("enforce: asset file identity changed before hashing: %s", path)
	}
	buffer := make([]byte, 1024*1024)
	if _, err := io.CopyBuffer(digest, handle, buffer); err != nil {
		return fmt.Errorf("enforce: hash asset file %s: %w", path, err)
	}
	return nil
}

func writeDigest(digest hash.Hash, value []byte) {
	_, _ = digest.Write(value)
}

func assetOwnershipJSON(path string) (string, error) {
	info, err := safeAssetInfo(path)
	if err != nil {
		return "", err
	}
	marker, err := json.Marshal(struct {
		Mode uint32 `json:"mode"`
	}{Mode: uint32(info.Mode().Perm())})
	if err != nil {
		return "", fmt.Errorf("enforce: encode asset ownership: %w", err)
	}
	return string(marker), nil
}

func copyAssetPath(source, destination string) error {
	info, err := safeAssetInfo(source)
	if err != nil {
		return err
	}
	if info.IsDir() {
		if err := os.Mkdir(destination, info.Mode().Perm()); err != nil {
			return err
		}
		entries, err := os.ReadDir(source)
		if err != nil {
			return err
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
		for _, entry := range entries {
			if err := copyAssetPath(
				filepath.Join(source, entry.Name()), filepath.Join(destination, entry.Name()),
			); err != nil {
				return err
			}
		}
		return os.Chmod(destination, info.Mode().Perm())
	}
	sourceFile, err := os.Open(source)
	if err != nil {
		return err
	}
	defer sourceFile.Close()
	opened, err := sourceFile.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return fmt.Errorf("enforce: asset file identity changed before copy: %s", source)
	}
	destinationFile, err := os.OpenFile(
		destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, info.Mode().Perm(),
	)
	if err != nil {
		return err
	}
	copyErr := func() error {
		buffer := make([]byte, 1024*1024)
		if _, err := io.CopyBuffer(destinationFile, sourceFile, buffer); err != nil {
			return err
		}
		if err := destinationFile.Chmod(info.Mode().Perm()); err != nil {
			return err
		}
		return destinationFile.Sync()
	}()
	closeErr := destinationFile.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

func ensureContainedDirectory(path, root string) error {
	if !pathWithin(path, root, true) {
		return fmt.Errorf("enforce: directory escaped allowed root")
	}
	if err := validateExistingAncestors(root); err != nil {
		return err
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("enforce: create contained directory: %w", err)
	}
	return validateContainedAncestors(path, root)
}

func validateExistingAncestors(path string) error {
	current := filepath.Clean(path)
	for {
		info, err := os.Lstat(current)
		if err == nil {
			if fileInfoIsLinkOrReparse(info) {
				return fmt.Errorf("enforce: linked path ancestor %s", current)
			}
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("enforce: inspect path ancestor %s: %w", current, err)
		}
		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
		current = parent
	}
}

func validateContainedAncestors(path, root string) error {
	current := filepath.Clean(path)
	root = filepath.Clean(root)
	for {
		info, err := os.Lstat(current)
		if err != nil {
			return fmt.Errorf("enforce: inspect contained path %s: %w", current, err)
		}
		if fileInfoIsLinkOrReparse(info) {
			return fmt.Errorf("enforce: linked contained path %s", current)
		}
		if current == root {
			return nil
		}
		parent := filepath.Dir(current)
		if parent == current || !pathWithin(parent, root, true) {
			return fmt.Errorf("enforce: contained path escaped root")
		}
		current = parent
	}
}

func requireAssetHash(path, expected string) error {
	actual, err := AssetContentHash(path)
	if err != nil {
		return err
	}
	if actual != strings.ToLower(strings.TrimSpace(expected)) {
		return fmt.Errorf("asset content hash mismatch")
	}
	return nil
}

func validateSHA256Hex(value string) error {
	decoded, err := hex.DecodeString(strings.ToLower(strings.TrimSpace(value)))
	if err != nil || len(decoded) != sha256.Size {
		return fmt.Errorf("enforce: content hash must be SHA-256 hex")
	}
	return nil
}

func assetPathExists(path string) (bool, error) {
	_, err := os.Lstat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, fmt.Errorf("enforce: inspect asset path %s: %w", path, err)
}

func removeAssetPathIfExists(path, root string) error {
	exists, err := assetPathExists(path)
	if err != nil || !exists {
		return err
	}
	return removeAssetPath(path, root)
}

func removeAssetPath(path, root string) error {
	if !pathWithin(path, root, false) {
		return fmt.Errorf("enforce: removal path escaped allowed root")
	}
	if err := validateContainedAncestors(filepath.Dir(path), root); err != nil {
		return fmt.Errorf("enforce: removal ancestry: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.IsDir() && !fileInfoIsLinkOrReparse(info) {
		return os.RemoveAll(path)
	}
	return os.Remove(path)
}
