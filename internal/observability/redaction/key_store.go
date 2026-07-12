// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package redaction

import (
	"crypto/rand"
	"errors"
	"io"
)

const (
	correlationKeyFilename   = "redaction-correlation.key"
	correlationKeyTempPrefix = ".redaction-correlation.key.tmp-"
	keyInstallAttempts       = 128
	keyTempRandomBytes       = 16
)

// KeyStoreErrorCode is a bounded, value-free correlation-key failure identity.
// It is safe to include in health telemetry.
type KeyStoreErrorCode string

const (
	KeyStoreErrorInvalidDataDir    KeyStoreErrorCode = "invalid_data_dir"
	KeyStoreErrorUnavailable       KeyStoreErrorCode = "key_unavailable"
	KeyStoreErrorUnsafeType        KeyStoreErrorCode = "unsafe_key_type"
	KeyStoreErrorUnsafeOwner       KeyStoreErrorCode = "unsafe_key_owner"
	KeyStoreErrorUnsafePermissions KeyStoreErrorCode = "unsafe_key_permissions"
	KeyStoreErrorInvalidLength     KeyStoreErrorCode = "invalid_key_length"
	KeyStoreErrorEntropy           KeyStoreErrorCode = "entropy_unavailable"
	KeyStoreErrorTemporaryFile     KeyStoreErrorCode = "temporary_file_failed"
	KeyStoreErrorSync              KeyStoreErrorCode = "key_sync_failed"
	KeyStoreErrorInstall           KeyStoreErrorCode = "key_install_failed"
	KeyStoreErrorUnsupported       KeyStoreErrorCode = "unsupported_platform"
)

// KeyStoreError deliberately contains no path, key material, operating-system
// error, file metadata, or other operator-controlled value.
type KeyStoreError struct {
	Code KeyStoreErrorCode
}

func (e *KeyStoreError) Error() string {
	return "redaction correlation key failed: " + string(e.Code)
}

// IsKeyStoreError reports whether err is a safe key-store failure with code.
func IsKeyStoreError(err error, code KeyStoreErrorCode) bool {
	var target *KeyStoreError
	return errors.As(err, &target) && target.Code == code
}

func keyStoreError(code KeyStoreErrorCode) error {
	return &KeyStoreError{Code: code}
}

// CorrelationKey is an immutable value copy of the process correlation key.
// Its zero value is unavailable. Material returns another value copy so callers
// cannot mutate a key retained by the loader or another destination projection.
type CorrelationKey struct {
	material [hashV1KeySize]byte
	id       string
}

func newCorrelationKey(material [hashV1KeySize]byte) CorrelationKey {
	return CorrelationKey{material: material, id: hashV1KeyID(material[:])}
}

// ID returns the safe 12-lowercase-hex key identity. It returns an empty string
// for an unavailable zero-value CorrelationKey.
func (k CorrelationKey) ID() string { return k.id }

// Material returns a value copy of the 32-byte key and whether the key is
// available. The caller should keep the copy scoped to the cryptographic call.
func (k CorrelationKey) Material() ([hashV1KeySize]byte, bool) {
	return k.material, k.id != ""
}

// LoadOrCreateCorrelationKey loads the fixed correlation key below dataDir, or
// securely creates it when absent. There is intentionally no path or key-material
// override in this API.
func LoadOrCreateCorrelationKey(dataDir string) (CorrelationKey, error) {
	return loadOrCreateCorrelationKeyPlatform(dataDir, rand.Reader, keyStoreHooks{})
}

// keyStoreHooks exists only to exercise cleanup and failure-closed behavior in
// package tests. Production always supplies the zero value.
type keyStoreHooks struct {
	afterExistingValidation func() error
	afterTempSync           func() error
	afterLink               func() error
}

func runAfterExistingValidation(hooks keyStoreHooks) error {
	if hooks.afterExistingValidation == nil {
		return nil
	}
	return hooks.afterExistingValidation()
}

func runAfterTempSync(hooks keyStoreHooks) error {
	if hooks.afterTempSync == nil {
		return nil
	}
	return hooks.afterTempSync()
}

func runAfterLink(hooks keyStoreHooks) error {
	if hooks.afterLink == nil {
		return nil
	}
	return hooks.afterLink()
}

func writeAll(file interface{ Write([]byte) (int, error) }, data []byte) error {
	for len(data) > 0 {
		written, err := file.Write(data)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}

// Keep io.Reader in the platform boundary so tests can inject a deterministic
// failing reader without mutable package globals.
type keyEntropyReader = io.Reader
