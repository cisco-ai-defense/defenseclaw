// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package redaction

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

func TestCorrelationKeyCreateAndExisting(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	created, err := LoadOrCreateCorrelationKey(dir)
	if err != nil {
		t.Fatalf("create correlation key: %v", err)
	}
	createdMaterial, ok := created.Material()
	if !ok {
		t.Fatal("created key is unavailable")
	}
	if got, want := created.ID(), hashV1KeyID(createdMaterial[:]); got != want {
		t.Fatalf("key ID = %q, want %q", got, want)
	}
	if len(created.ID()) != 12 || created.ID() != strings.ToLower(created.ID()) {
		t.Fatalf("key ID is not 12 lowercase hex characters: %q", created.ID())
	}

	path := filepath.Join(dir, correlationKeyFilename)
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("stat created key: %v", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() != hashV1KeySize {
		t.Fatalf("created key metadata = mode %v size %d", info.Mode(), info.Size())
	}
	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read created key: %v", err)
	}
	if !bytes.Equal(onDisk, createdMaterial[:]) {
		t.Fatal("created key does not match returned value")
	}

	loaded, err := LoadOrCreateCorrelationKey(dir)
	if err != nil {
		t.Fatalf("load existing correlation key: %v", err)
	}
	loadedMaterial, ok := loaded.Material()
	if !ok || loaded.ID() != created.ID() || loadedMaterial != createdMaterial {
		t.Fatal("existing load did not return the created key")
	}
	assertNoCorrelationKeyTemps(t, dir)
}

func TestCorrelationKeyLoadsOwnerOnlyExistingFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	want := fixedTestKey(0x31)
	writeExistingCorrelationKey(t, dir, want[:], 0o400)

	key, err := LoadOrCreateCorrelationKey(dir)
	if err != nil {
		t.Fatalf("load owner-readable key: %v", err)
	}
	got, ok := key.Material()
	if !ok || got != want {
		t.Fatal("loaded key material mismatch")
	}
}

func TestCorrelationKeyRejectsUnsafePermissions(t *testing.T) {
	t.Parallel()
	for _, mode := range []os.FileMode{0o604, 0o620, 0o640, 0o666} {
		mode := mode
		t.Run(fmt.Sprintf("%04o", mode), func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			key := fixedTestKey(byte(mode))
			writeExistingCorrelationKey(t, dir, key[:], mode)
			_, err := LoadOrCreateCorrelationKey(dir)
			if !IsKeyStoreError(err, KeyStoreErrorUnsafePermissions) {
				t.Fatalf("error = %v, want unsafe permissions", err)
			}
		})
	}
}

func TestCorrelationKeyRejectsSymlink(t *testing.T) {
	for _, dangling := range []bool{false, true} {
		dangling := dangling
		t.Run(fmt.Sprintf("dangling_%t", dangling), func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			target := filepath.Join(dir, "target")
			if !dangling {
				key := fixedTestKey(0x42)
				if err := os.WriteFile(target, key[:], 0o600); err != nil {
					t.Fatalf("write symlink target: %v", err)
				}
			}
			if err := os.Symlink(target, filepath.Join(dir, correlationKeyFilename)); err != nil {
				t.Fatalf("create symlink: %v", err)
			}

			_, err := LoadOrCreateCorrelationKey(dir)
			if !IsKeyStoreError(err, KeyStoreErrorUnsafeType) {
				t.Fatalf("error = %v, want unsafe type", err)
			}
		})
	}
}

func TestCorrelationKeyRejectsNonRegularFiles(t *testing.T) {
	t.Parallel()
	t.Run("directory", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		if err := os.Mkdir(filepath.Join(dir, correlationKeyFilename), 0o700); err != nil {
			t.Fatalf("create key directory: %v", err)
		}
		_, err := LoadOrCreateCorrelationKey(dir)
		if !IsKeyStoreError(err, KeyStoreErrorUnsafeType) {
			t.Fatalf("error = %v, want unsafe type", err)
		}
	})

	t.Run("fifo", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		path := filepath.Join(dir, correlationKeyFilename)
		if err := unix.Mkfifo(path, 0o600); err != nil {
			t.Fatalf("create key FIFO: %v", err)
		}
		_, err := LoadOrCreateCorrelationKey(dir)
		if !IsKeyStoreError(err, KeyStoreErrorUnsafeType) {
			t.Fatalf("error = %v, want unsafe type", err)
		}
	})
}

func TestCorrelationKeyRejectsWrongLength(t *testing.T) {
	t.Parallel()
	for _, size := range []int{0, hashV1KeySize - 1, hashV1KeySize + 1, 1024} {
		size := size
		t.Run(fmt.Sprintf("size_%d", size), func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			writeExistingCorrelationKey(t, dir, bytes.Repeat([]byte{0x55}, size), 0o600)
			_, err := LoadOrCreateCorrelationKey(dir)
			if !IsKeyStoreError(err, KeyStoreErrorInvalidLength) {
				t.Fatalf("error = %v, want invalid length", err)
			}
		})
	}
}

func TestCorrelationKeyRevalidatesExistingFileAfterInitialStat(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(string) error
		code   KeyStoreErrorCode
	}{
		{name: "truncate_during_read", code: KeyStoreErrorInvalidLength, mutate: func(path string) error {
			return os.Truncate(path, 0)
		}},
		{name: "append_during_read", code: KeyStoreErrorInvalidLength, mutate: func(path string) error {
			file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
			if err != nil {
				return err
			}
			if _, err = file.Write([]byte{0x7f}); err != nil {
				_ = file.Close()
				return err
			}
			return file.Close()
		}},
		{name: "permissions_change_after_read", code: KeyStoreErrorUnsafePermissions, mutate: func(path string) error {
			return os.Chmod(path, 0o640)
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			key := fixedTestKey(0x29)
			writeExistingCorrelationKey(t, dir, key[:], 0o600)
			path := filepath.Join(dir, correlationKeyFilename)
			hooks := keyStoreHooks{afterExistingValidation: func() error { return test.mutate(path) }}
			_, err := loadOrCreateCorrelationKeyPlatform(dir, bytes.NewReader(nil), hooks)
			if !IsKeyStoreError(err, test.code) {
				t.Fatalf("error = %v, want %s", err, test.code)
			}
		})
	}
}

func TestCorrelationKeyRejectsWrongEffectiveOwner(t *testing.T) {
	t.Parallel()
	stat := unix.Stat_t{
		Mode: unix.S_IFREG | 0o600,
		Uid:  uint32(os.Geteuid() + 1),
		Size: hashV1KeySize,
	}
	if err := validateCorrelationKeyStat(&stat); !IsKeyStoreError(err, KeyStoreErrorUnsafeOwner) {
		t.Fatalf("error = %v, want unsafe owner", err)
	}
}

func TestCorrelationKeyConcurrentCreatorsConverge(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	const creators = 48
	results := make(chan CorrelationKey, creators)
	errorsCh := make(chan error, creators)
	start := make(chan struct{})
	var group sync.WaitGroup
	group.Add(creators)
	for range creators {
		go func() {
			defer group.Done()
			<-start
			key, err := LoadOrCreateCorrelationKey(dir)
			if err != nil {
				errorsCh <- err
				return
			}
			results <- key
		}()
	}
	close(start)
	group.Wait()
	close(results)
	close(errorsCh)
	for err := range errorsCh {
		t.Errorf("concurrent creator: %v", err)
	}
	var winner CorrelationKey
	first := true
	for key := range results {
		if first {
			winner = key
			first = false
			continue
		}
		winnerMaterial, winnerOK := winner.Material()
		keyMaterial, keyOK := key.Material()
		if !winnerOK || !keyOK || winner.ID() != key.ID() || winnerMaterial != keyMaterial {
			t.Fatal("concurrent creators did not converge")
		}
	}
	if first {
		t.Fatal("no concurrent creator returned a key")
	}
	assertNoCorrelationKeyTemps(t, dir)
}

func TestCorrelationKeyInterruptedCreationCleansTemporaryFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	entropy := bytes.NewReader(bytes.Repeat([]byte{0x6a}, hashV1KeySize+keyTempRandomBytes))
	hooks := keyStoreHooks{afterTempSync: func() error { return errors.New("injected interruption") }}

	_, err := loadOrCreateCorrelationKeyPlatform(dir, entropy, hooks)
	if !IsKeyStoreError(err, KeyStoreErrorInstall) {
		t.Fatalf("error = %v, want install failure", err)
	}
	if _, statErr := os.Lstat(filepath.Join(dir, correlationKeyFilename)); !os.IsNotExist(statErr) {
		t.Fatalf("target exists after interruption: %v", statErr)
	}
	assertNoCorrelationKeyTemps(t, dir)
}

func TestCorrelationKeyPostLinkFailureLeavesOneLoadableKey(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	entropy := bytes.NewReader(bytes.Repeat([]byte{0x3c}, hashV1KeySize+keyTempRandomBytes))
	hooks := keyStoreHooks{afterLink: func() error { return errors.New("injected directory sync failure") }}

	_, err := loadOrCreateCorrelationKeyPlatform(dir, entropy, hooks)
	if !IsKeyStoreError(err, KeyStoreErrorSync) {
		t.Fatalf("error = %v, want sync failure", err)
	}
	loaded, err := LoadOrCreateCorrelationKey(dir)
	if err != nil {
		t.Fatalf("load key installed before sync failure: %v", err)
	}
	material, ok := loaded.Material()
	var expected [hashV1KeySize]byte
	for index := range expected {
		expected[index] = 0x3c
	}
	if !ok || material != expected {
		t.Fatal("post-link failure did not leave the installed candidate loadable")
	}
	assertNoCorrelationKeyTemps(t, dir)
}

func TestCorrelationKeyEntropyFailureCreatesNothing(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, err := loadOrCreateCorrelationKeyPlatform(dir, errorReader{}, keyStoreHooks{})
	if !IsKeyStoreError(err, KeyStoreErrorEntropy) {
		t.Fatalf("error = %v, want entropy failure", err)
	}
	entries, readErr := os.ReadDir(dir)
	if readErr != nil {
		t.Fatalf("read data directory: %v", readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("entropy failure left %d files", len(entries))
	}
}

func TestCorrelationKeyReadOnlyDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can bypass directory write permission checks")
	}
	t.Parallel()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("make directory read-only: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	_, err := LoadOrCreateCorrelationKey(dir)
	if !IsKeyStoreError(err, KeyStoreErrorTemporaryFile) {
		t.Fatalf("error = %v, want temporary-file failure", err)
	}
	assertNoCorrelationKeyTemps(t, dir)
}

func TestCorrelationKeyMaterialIsCopySafe(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	key, err := LoadOrCreateCorrelationKey(dir)
	if err != nil {
		t.Fatalf("create correlation key: %v", err)
	}
	first, ok := key.Material()
	if !ok {
		t.Fatal("created key unavailable")
	}
	original := first
	first[0] ^= 0xff
	second, ok := key.Material()
	if !ok || second != original {
		t.Fatal("mutating an accessor copy changed the retained key")
	}

	valueCopy := key
	third, ok := valueCopy.Material()
	if !ok || third != original || valueCopy.ID() != key.ID() {
		t.Fatal("CorrelationKey value copy changed identity or material")
	}
	var zero CorrelationKey
	if material, available := zero.Material(); available || zero.ID() != "" || material != [hashV1KeySize]byte{} {
		t.Fatal("zero-value CorrelationKey must be unavailable")
	}
}

func TestCorrelationKeyErrorsNeverExposePathOrMaterial(t *testing.T) {
	t.Parallel()
	secretPathPart := "operator-secret-path-component"
	dir := filepath.Join(t.TempDir(), secretPathPart)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("create test directory: %v", err)
	}
	material := bytes.Repeat([]byte("Z"), hashV1KeySize)
	writeExistingCorrelationKey(t, dir, material, 0o644)

	_, err := LoadOrCreateCorrelationKey(dir)
	if err == nil {
		t.Fatal("unsafe existing key unexpectedly loaded")
	}
	message := fmt.Sprintf("%+v", err)
	for _, forbidden := range []string{dir, secretPathPart, string(material)} {
		if strings.Contains(message, forbidden) {
			t.Fatalf("safe error exposed forbidden value %q: %q", forbidden, message)
		}
	}
	var typed *KeyStoreError
	if !errors.As(err, &typed) || typed.Code != KeyStoreErrorUnsafePermissions {
		t.Fatalf("error = %v, want typed unsafe-permissions failure", err)
	}
}

func TestCorrelationKeyInvalidDataDirectory(t *testing.T) {
	t.Parallel()
	if _, err := LoadOrCreateCorrelationKey(""); !IsKeyStoreError(err, KeyStoreErrorInvalidDataDir) {
		t.Fatalf("empty data-dir error = %v", err)
	}
	file := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatalf("write non-directory: %v", err)
	}
	if _, err := LoadOrCreateCorrelationKey(file); !IsKeyStoreError(err, KeyStoreErrorInvalidDataDir) {
		t.Fatalf("non-directory error = %v", err)
	}
	symlink := filepath.Join(t.TempDir(), "data-link")
	if err := os.Symlink(t.TempDir(), symlink); err != nil {
		t.Fatalf("create data-dir symlink: %v", err)
	}
	if _, err := LoadOrCreateCorrelationKey(symlink); !IsKeyStoreError(err, KeyStoreErrorInvalidDataDir) {
		t.Fatalf("symlink data-dir error = %v", err)
	}
	if _, err := LoadOrCreateCorrelationKey(filepath.Join(t.TempDir(), "missing")); !IsKeyStoreError(err, KeyStoreErrorUnavailable) {
		t.Fatalf("missing data-dir error = %v", err)
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("injected entropy failure") }

func fixedTestKey(seed byte) [hashV1KeySize]byte {
	var key [hashV1KeySize]byte
	for i := range key {
		key[i] = seed + byte(i)
	}
	return key
}

func writeExistingCorrelationKey(t *testing.T, dir string, material []byte, mode os.FileMode) {
	t.Helper()
	path := filepath.Join(dir, correlationKeyFilename)
	if err := os.WriteFile(path, material, 0o600); err != nil {
		t.Fatalf("write existing key: %v", err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("set existing key mode: %v", err)
	}
}

func assertNoCorrelationKeyTemps(t *testing.T, dir string) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, correlationKeyTempPrefix+"*"))
	if err != nil {
		t.Fatalf("glob temporary keys: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary key files remain: %v", matches)
	}
}
