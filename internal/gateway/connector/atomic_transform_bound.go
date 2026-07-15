// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func validateAtomicTransformBoundLeaf(name string) error {
	if name == "" || name == "." || name == ".." || filepath.Base(name) != name ||
		strings.ContainsAny(name, `/\\`) {
		return fmt.Errorf("invalid compare-and-swap relative artifact name %q", name)
	}
	if runtime.GOOS == "windows" && (strings.Contains(name, ":") ||
		strings.HasSuffix(name, ".") || strings.HasSuffix(name, " ")) {
		return fmt.Errorf("unsafe Windows compare-and-swap artifact name %q", name)
	}
	return nil
}

type atomicTransformBoundDirectory struct {
	path     string
	identity string
	file     *os.File
	guards   []*os.File
}

func bindAtomicTransformDirectory(path string) (*atomicTransformBoundDirectory, error) {
	canonical, err := canonicalAtomicTransformTargetPath(filepath.Join(path, ".bound-leaf"))
	if err != nil {
		return nil, err
	}
	canonical = filepath.Dir(canonical)
	if err := atomicTransformValidateDirectoryCaseSemantics(canonical); err != nil {
		return nil, err
	}
	file, err := openAtomicTransformBoundDirectoryPlatform(canonical)
	if err != nil {
		return nil, err
	}
	identity, err := atomicTransformOpenFileIdentity(file)
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	pathIdentity, err := atomicTransformDirectoryIdentity(canonical)
	if err != nil || pathIdentity != identity {
		_ = file.Close()
		if err == nil {
			err = fmt.Errorf("compare-and-swap directory changed while binding")
		}
		return nil, err
	}
	if err := validateAtomicTransformBoundDirectoryPlatform(file, false); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := validateAtomicTransformBoundDirectoryDurabilityPlatform(file); err != nil {
		_ = file.Close()
		return nil, err
	}
	guards := make([]*os.File, 0, 8)
	if runtime.GOOS == "windows" {
		for ancestor := filepath.Dir(canonical); ; ancestor = filepath.Dir(ancestor) {
			guard, guardErr := openAtomicTransformBoundDirectoryPlatform(ancestor)
			if guardErr != nil {
				for _, opened := range guards {
					_ = opened.Close()
				}
				_ = file.Close()
				return nil, fmt.Errorf("guard compare-and-swap ancestor %s against rename: %w", ancestor, guardErr)
			}
			guards = append(guards, guard)
			next := filepath.Dir(ancestor)
			if next == ancestor {
				break
			}
		}
	}
	return &atomicTransformBoundDirectory{path: canonical, identity: identity, file: file, guards: guards}, nil
}

func (dir *atomicTransformBoundDirectory) validatePrivate() error {
	if err := dir.validate(); err != nil {
		return err
	}
	return validateAtomicTransformBoundDirectoryPlatform(dir.file, true)
}

func (dir *atomicTransformBoundDirectory) Close() error {
	if dir == nil || dir.file == nil {
		return nil
	}
	err := dir.file.Close()
	dir.file = nil
	for _, guard := range dir.guards {
		err = errors.Join(err, guard.Close())
	}
	dir.guards = nil
	return err
}

func (dir *atomicTransformBoundDirectory) validate() error {
	if dir == nil || dir.file == nil {
		return fmt.Errorf("compare-and-swap directory handle is closed")
	}
	identity, err := atomicTransformOpenFileIdentity(dir.file)
	if err != nil || identity != dir.identity {
		if err == nil {
			err = fmt.Errorf("bound compare-and-swap directory changed identity")
		}
		return err
	}
	locatorIdentity, err := atomicTransformDirectoryIdentity(dir.path)
	if err != nil || locatorIdentity != dir.identity {
		if err == nil {
			err = fmt.Errorf("compare-and-swap directory locator no longer names the bound directory")
		}
		return err
	}
	if err := validateAtomicTransformBoundDirectoryPlatform(dir.file, false); err != nil {
		return err
	}
	return validateAtomicTransformBoundDirectoryDurabilityPlatform(dir.file)
}

func atomicTransformBoundStateFromOpen(
	file *os.File, label string, maxBytes int64,
) (atomicTransformArtifactState, error) {
	if _, err := file.Seek(0, 0); err != nil {
		return atomicTransformArtifactState{}, fmt.Errorf("seek bound artifact %s: %w", label, err)
	}
	data, err := readAtomicTransformBytes(file, label, maxBytes)
	if err != nil {
		return atomicTransformArtifactState{}, err
	}
	info, err := file.Stat()
	if err != nil {
		return atomicTransformArtifactState{}, err
	}
	identity, err := atomicTransformOpenFileIdentity(file)
	if err != nil {
		return atomicTransformArtifactState{}, err
	}
	protection, err := atomicTransformProtectionDigest(file)
	if err != nil {
		return atomicTransformArtifactState{}, err
	}
	metadata, err := atomicTransformMetadataPlatform(file)
	if err != nil {
		return atomicTransformArtifactState{}, err
	}
	linkCount, err := atomicTransformBoundLinkCountPlatform(file)
	if err != nil {
		return atomicTransformArtifactState{}, err
	}
	return atomicTransformArtifactState{
		exists: true, data: data, info: info, digest: atomicTransformDigest(data),
		size: int64(len(data)), protectionDigest: protection, identity: identity,
		metadataDigest: metadata.digest, preservedMetadataDigest: metadata.preservedDigest,
		stageOwnedMetadataDigest: metadata.stageOwnedDigest,
		ownerGroupDigest:         metadata.ownerGroupDigest,
		creationTime:             metadata.creationTime, lastWriteTime: metadata.lastWriteTime,
		linkCount: linkCount,
	}, nil
}

func atomicTransformBoundInspect(
	dir *atomicTransformBoundDirectory, name string, maxBytes int64,
) (atomicTransformArtifactState, error) {
	if err := validateAtomicTransformBoundLeaf(name); err != nil {
		return atomicTransformArtifactState{}, err
	}
	if err := dir.validate(); err != nil {
		return atomicTransformArtifactState{}, err
	}
	file, err := openAtomicTransformBoundFilePlatform(dir.file, name, false)
	if errors.Is(err, os.ErrNotExist) {
		return atomicTransformArtifactState{}, nil
	}
	if err != nil {
		return atomicTransformArtifactState{}, err
	}
	defer file.Close()
	return atomicTransformBoundStateFromOpen(file, name, maxBytes)
}

func atomicTransformBoundInspectPrivate(
	dir *atomicTransformBoundDirectory, name string, maxBytes int64,
) (atomicTransformArtifactState, error) {
	if err := validateAtomicTransformBoundLeaf(name); err != nil {
		return atomicTransformArtifactState{}, err
	}
	if err := dir.validatePrivate(); err != nil {
		return atomicTransformArtifactState{}, err
	}
	return atomicTransformBoundInspectFilePrivateValidated(dir, name, maxBytes)
}

// atomicTransformBoundInspectFilePrivate validates privacy on the exact opened
// leaf without requiring its ordinary config parent to be private. It is used
// for harmless CAS markers that live beside user-managed config files.
func atomicTransformBoundInspectFilePrivate(
	dir *atomicTransformBoundDirectory, name string, maxBytes int64,
) (atomicTransformArtifactState, error) {
	if err := validateAtomicTransformBoundLeaf(name); err != nil {
		return atomicTransformArtifactState{}, err
	}
	if err := dir.validate(); err != nil {
		return atomicTransformArtifactState{}, err
	}
	return atomicTransformBoundInspectFilePrivateValidated(dir, name, maxBytes)
}

func atomicTransformBoundInspectFilePrivateValidated(
	dir *atomicTransformBoundDirectory, name string, maxBytes int64,
) (atomicTransformArtifactState, error) {
	file, err := openAtomicTransformBoundFilePlatform(dir.file, name, false)
	if errors.Is(err, os.ErrNotExist) {
		return atomicTransformArtifactState{}, nil
	}
	if err != nil {
		return atomicTransformArtifactState{}, err
	}
	defer file.Close()
	if err := validateAtomicTransformBoundFilePrivatePlatform(file); err != nil {
		return atomicTransformArtifactState{}, err
	}
	return atomicTransformBoundStateFromOpen(file, name, maxBytes)
}

func atomicTransformBoundCreateEmpty(
	dir *atomicTransformBoundDirectory, name string, perm os.FileMode,
) (*os.File, atomicTransformArtifactState, error) {
	if err := validateAtomicTransformBoundLeaf(name); err != nil {
		return nil, atomicTransformArtifactState{}, err
	}
	if err := dir.validate(); err != nil {
		return nil, atomicTransformArtifactState{}, err
	}
	file, err := createAtomicTransformBoundFilePlatform(dir.file, name, perm)
	if err != nil {
		return nil, atomicTransformArtifactState{}, err
	}
	fail := func(cause error) (*os.File, atomicTransformArtifactState, error) {
		deleteErr := deleteAtomicTransformBoundFilePlatform(dir.file, file, name)
		closeErr := file.Close()
		syncErr := syncAtomicTransformBoundDirectoryPlatform(dir.file)
		return nil, atomicTransformArtifactState{}, errors.Join(cause, deleteErr, closeErr, syncErr)
	}
	if err := file.Chmod(perm); err != nil {
		return fail(err)
	}
	if err := validateAtomicTransformBoundFilePrivatePlatform(file); err != nil {
		return fail(fmt.Errorf("validate newly created private compare-and-swap artifact: %w", err))
	}
	if err := file.Sync(); err != nil {
		return fail(err)
	}
	if err := syncAtomicTransformBoundDirectoryPlatform(dir.file); err != nil {
		return fail(err)
	}
	state, err := atomicTransformBoundStateFromOpen(file, name, atomicTransformMaxConfigBytes)
	if err != nil {
		return fail(err)
	}
	return file, state, nil
}

func atomicTransformBoundCreate(
	dir *atomicTransformBoundDirectory, name string, data []byte, perm os.FileMode,
) (atomicTransformArtifactState, error) {
	file, _, err := atomicTransformBoundCreateEmpty(dir, name, perm)
	if err != nil {
		return atomicTransformArtifactState{}, err
	}
	failOpen := func(cause error) (atomicTransformArtifactState, error) {
		deleteErr := deleteAtomicTransformBoundFilePlatform(dir.file, file, name)
		closeErr := file.Close()
		syncErr := syncAtomicTransformBoundDirectoryPlatform(dir.file)
		return atomicTransformArtifactState{}, errors.Join(cause, deleteErr, closeErr, syncErr)
	}
	if written, err := file.Write(data); err != nil {
		return failOpen(err)
	} else if written != len(data) {
		return failOpen(io.ErrShortWrite)
	}
	if err := file.Sync(); err != nil {
		return failOpen(err)
	}
	expected, err := atomicTransformBoundStateFromOpen(file, name, atomicTransformMaxConfigBytes)
	if err != nil {
		return failOpen(err)
	}
	if err := validateAtomicTransformBoundFilePrivatePlatform(file); err != nil {
		return failOpen(err)
	}
	if err := file.Close(); err != nil {
		return atomicTransformArtifactState{}, err
	}
	state, err := atomicTransformBoundInspectFilePrivate(dir, name, atomicTransformMaxConfigBytes)
	if err != nil || !atomicTransformArtifactStatesEqualExact(state, expected) ||
		state.digest != atomicTransformDigest(data) {
		if err == nil {
			err = fmt.Errorf("bound artifact did not persist exactly: %s", name)
		}
		if state.exists && atomicTransformArtifactStatesEqualExact(state, expected) {
			err = errors.Join(err, atomicTransformBoundDeleteExact(dir, name, state))
		}
		return atomicTransformArtifactState{}, err
	}
	return state, nil
}

// atomicTransformBoundPublishBootstrap publishes the first authenticated
// receipt without an unauthenticated durable temporary file. The source is
// created atomically delete-on-close, written and flushed, then hard-linked
// no-replace to its final reserved name. A process exit before link creation
// lets the kernel retire the source; after link creation, closing the source
// retires only the temporary link while the exact complete file remains at the
// final name.
func atomicTransformBoundPublishBootstrap(
	dir *atomicTransformBoundDirectory, tempName, finalName string,
	data []byte, perm os.FileMode, requirePrivateDir bool, progress func(string) error,
) (atomicTransformArtifactState, error) {
	if err := validateAtomicTransformBoundLeaf(tempName); err != nil {
		return atomicTransformArtifactState{}, err
	}
	if err := validateAtomicTransformBoundLeaf(finalName); err != nil {
		return atomicTransformArtifactState{}, err
	}
	validateDir := dir.validate
	if requirePrivateDir {
		validateDir = dir.validatePrivate
	}
	if err := validateDir(); err != nil {
		return atomicTransformArtifactState{}, err
	}
	file, err := createAtomicTransformBoundDeleteOnCloseFilePlatform(dir.file, tempName, perm)
	if err != nil {
		return atomicTransformArtifactState{}, err
	}
	closed := false
	defer func() {
		if !closed {
			_ = file.Close()
		}
	}()
	if err := file.Chmod(perm); err != nil {
		return atomicTransformArtifactState{}, err
	}
	if progress != nil {
		if err := progress("created-delete-on-close"); err != nil {
			return atomicTransformArtifactState{}, err
		}
	}
	prefix := len(data) / 2
	if prefix == 0 && len(data) != 0 {
		prefix = 1
	}
	if written, err := file.Write(data[:prefix]); err != nil {
		return atomicTransformArtifactState{}, err
	} else if written != prefix {
		return atomicTransformArtifactState{}, io.ErrShortWrite
	}
	if progress != nil {
		if err := progress("partially-written"); err != nil {
			return atomicTransformArtifactState{}, err
		}
	}
	if written, err := file.Write(data[prefix:]); err != nil {
		return atomicTransformArtifactState{}, err
	} else if written != len(data)-prefix {
		return atomicTransformArtifactState{}, io.ErrShortWrite
	}
	if err := file.Sync(); err != nil {
		return atomicTransformArtifactState{}, err
	}
	if err := validateAtomicTransformBoundFilePrivatePlatform(file); err != nil {
		return atomicTransformArtifactState{}, err
	}
	if progress != nil {
		if err := progress("complete-and-flushed"); err != nil {
			return atomicTransformArtifactState{}, err
		}
	}
	if links, err := atomicTransformBoundLinkCountPlatform(file); err != nil || links != 1 {
		if err == nil {
			err = fmt.Errorf("bootstrap source has unexpected hard-link count %d", links)
		}
		return atomicTransformArtifactState{}, err
	}
	expected, err := atomicTransformBoundStateFromOpen(file, tempName, atomicTransformMaxIntentBytes)
	if err != nil {
		return atomicTransformArtifactState{}, err
	}
	if err := linkAtomicTransformBoundFilePlatform(dir.file, file, finalName, func() error {
		if progress == nil {
			return nil
		}
		return progress("namespace-linked-before-flush")
	}); err != nil {
		return atomicTransformArtifactState{}, err
	}
	if links, err := atomicTransformBoundLinkCountPlatform(file); err != nil || links != 2 {
		if err == nil {
			err = fmt.Errorf("bootstrap publication has unexpected hard-link count %d", links)
		}
		return atomicTransformArtifactState{}, err
	}
	if progress != nil {
		if err := progress("hard-link-published"); err != nil {
			return atomicTransformArtifactState{}, err
		}
	}
	if err := file.Sync(); err != nil {
		return atomicTransformArtifactState{}, err
	}
	if err := file.Close(); err != nil {
		closed = true
		return atomicTransformArtifactState{}, err
	}
	closed = true
	inspect := atomicTransformBoundInspectFilePrivate
	if requirePrivateDir {
		inspect = atomicTransformBoundInspectPrivate
	}
	published, err := inspect(dir, finalName, atomicTransformMaxIntentBytes)
	if err != nil || !atomicTransformArtifactStatesEqualExact(published, expected) {
		if err == nil {
			err = fmt.Errorf("bootstrap receipt hard link changed identity or bytes")
		}
		return atomicTransformArtifactState{}, err
	}
	temporary, err := inspect(dir, tempName, atomicTransformMaxIntentBytes)
	if err != nil || temporary.exists {
		if err == nil {
			err = fmt.Errorf("delete-on-close bootstrap source link survived publication")
		}
		return atomicTransformArtifactState{}, err
	}
	if progress != nil {
		if err := progress("source-link-retired"); err != nil {
			return atomicTransformArtifactState{}, err
		}
	}
	finalFile, err := openAtomicTransformBoundFilePlatform(dir.file, finalName, false)
	if err != nil {
		return atomicTransformArtifactState{}, err
	}
	links, linkErr := atomicTransformBoundLinkCountPlatform(finalFile)
	closeErr := finalFile.Close()
	if linkErr != nil || closeErr != nil || links != 1 {
		if linkErr == nil && closeErr == nil {
			linkErr = fmt.Errorf("published bootstrap receipt has unexpected hard-link count %d", links)
		}
		return atomicTransformArtifactState{}, errors.Join(linkErr, closeErr)
	}
	return published, nil
}

func atomicTransformBoundRenameNoReplace(
	dir *atomicTransformBoundDirectory,
	sourceName, targetName string,
	expected atomicTransformArtifactState,
) (atomicTransformArtifactState, error) {
	if err := validateAtomicTransformBoundLeaf(sourceName); err != nil {
		return atomicTransformArtifactState{}, err
	}
	if err := validateAtomicTransformBoundLeaf(targetName); err != nil {
		return atomicTransformArtifactState{}, err
	}
	if err := dir.validate(); err != nil {
		return atomicTransformArtifactState{}, err
	}
	source, err := openAtomicTransformBoundFilePlatform(dir.file, sourceName, true)
	if err != nil {
		return atomicTransformArtifactState{}, err
	}
	defer source.Close()
	currentSource, err := atomicTransformBoundStateFromOpen(source, sourceName, atomicTransformMaxConfigBytes)
	if err != nil || !atomicTransformArtifactStatesEqualExact(currentSource, expected) {
		if err == nil {
			err = fmt.Errorf("bound rename source changed identity or metadata: %s", sourceName)
		}
		return atomicTransformArtifactState{}, err
	}
	if err := dir.validate(); err != nil {
		return atomicTransformArtifactState{}, err
	}
	if err := renameAtomicTransformBoundFilePlatform(dir.file, source, targetName, false); err != nil {
		return atomicTransformArtifactState{}, err
	}
	if err := dir.validate(); err != nil {
		return atomicTransformArtifactState{}, fmt.Errorf("bound directory detached during rename: %w", err)
	}
	if err := syncAtomicTransformBoundDirectoryPlatform(dir.file); err != nil {
		return atomicTransformArtifactState{}, err
	}
	published, err := atomicTransformBoundInspect(dir, targetName, atomicTransformMaxConfigBytes)
	if err != nil || !atomicTransformArtifactStatesEqualAfterBoundRename(published, expected) {
		if err == nil {
			err = fmt.Errorf(
				"bound rename target changed identity or metadata: %s (id %s/%s, data %s/%s, protection %s/%s, mode %v/%v, metadata %s/%s, preserved %s/%s, stage-owned %s/%s, creation %d/%d, last-write %d/%d)",
				targetName, expected.identity, published.identity,
				expected.digest, published.digest,
				expected.protectionDigest, published.protectionDigest,
				expected.info.Mode(), published.info.Mode(),
				expected.metadataDigest, published.metadataDigest,
				expected.preservedMetadataDigest, published.preservedMetadataDigest,
				expected.stageOwnedMetadataDigest, published.stageOwnedMetadataDigest,
				expected.creationTime, published.creationTime,
				expected.lastWriteTime, published.lastWriteTime,
			)
		}
		return atomicTransformArtifactState{}, err
	}
	return published, nil
}

func atomicTransformBoundDeleteExact(
	dir *atomicTransformBoundDirectory,
	name string,
	expected atomicTransformArtifactState,
) error {
	if err := validateAtomicTransformBoundLeaf(name); err != nil {
		return err
	}
	if err := dir.validate(); err != nil {
		return err
	}
	file, err := openAtomicTransformBoundFilePlatform(dir.file, name, true)
	if err != nil {
		return err
	}
	closed := false
	defer func() {
		if !closed {
			_ = file.Close()
		}
	}()
	current, err := atomicTransformBoundStateFromOpen(file, name, atomicTransformMaxConfigBytes)
	if err != nil || !atomicTransformArtifactStatesEqualExact(current, expected) {
		if err == nil {
			err = fmt.Errorf("bound delete target changed identity or metadata: %s", name)
		}
		return err
	}
	if err := dir.validate(); err != nil {
		return err
	}
	if err := deleteAtomicTransformBoundFilePlatform(dir.file, file, name); err != nil {
		return err
	}
	if err := dir.validate(); err != nil {
		return fmt.Errorf("bound directory detached during exact deletion: %w", err)
	}
	if err := file.Close(); err != nil {
		return err
	}
	closed = true
	if err := syncAtomicTransformBoundDirectoryPlatform(dir.file); err != nil {
		return err
	}
	after, err := atomicTransformBoundInspect(dir, name, atomicTransformMaxConfigBytes)
	if err != nil {
		return err
	}
	if after.exists {
		return fmt.Errorf("bound artifact name was reoccupied after exact deletion: %s", name)
	}
	return nil
}
