// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

// Package enterprisebundle reads and validates signed policy bundles for the
// standalone enterprise profile: the manifest and its strict decoder, the
// archive and directory readers with their limits, the files[] integrity
// check, secret references and the inline-secret scan, group reachability
// warnings, and the effective policy digest of a bundle per platform.
//
// Everything here is a pure function of its inputs: nothing is written,
// installed or published, and no bundle content ever appears in an error.
// It also holds the trust layer: manifest.sig, the MDM-installed trust
// anchors, the version floor and Verify, which runs every check in order.
package enterprisebundle

import (
	"errors"
	"fmt"
	"strconv"
)

// Code is the stable error code of a refused bundle (spec section 7). The
// receipt, the CLI JSON and the MDM result carry it unchanged.
type Code string

const (
	CodeArchiveInvalid   Code = "archive_invalid"
	CodeDiskFull         Code = "disk_full"
	CodeManifestInvalid  Code = "manifest_invalid"
	CodeFileMissing      Code = "file_missing"
	CodeFileExtra        Code = "file_extra"
	CodeFileHashMismatch Code = "file_hash_mismatch"
	CodeInlineSecret     Code = "inline_secret"
	CodeConfigInvalid    Code = "config_invalid"
	CodeInvalidArguments Code = "invalid_arguments"

	// Trust: the anchor file, the signing key and the signature.
	CodeAnchorMissing    Code = "anchor_missing"
	CodeAnchorInsecure   Code = "anchor_insecure"
	CodeAnchorInvalid    Code = "anchor_invalid"
	CodeKeyUnknown       Code = "key_unknown"
	CodeKeyRevoked       Code = "key_revoked"
	CodeKeyExpired       Code = "key_expired"
	CodeSignatureInvalid Code = "signature_invalid"

	// Scope and order: tenant, target, version floor, product version.
	CodeTenantMismatch  Code = "tenant_mismatch"
	CodeTargetMismatch  Code = "target_mismatch"
	CodeVersionNotNewer Code = "version_not_newer"
	CodeProductTooOld   Code = "product_too_old"

	// Device facts: secret presence, the signed credential values and the
	// effective policy digest.
	CodeSecretRefMissing Code = "secret_ref_missing"
	// CodeSecretRefMismatch: a stored credential is not the value its
	// secret_refs entry signs (value_sha256).
	CodeSecretRefMismatch Code = "secret_ref_mismatch"
	// CodeSecretRefUnbound: a secret_refs entry signs no value_sha256. Bundles
	// signed before 1.0.4 bound credential names only; sign them again with
	// --secret-file.
	CodeSecretRefUnbound Code = "secret_ref_unbound"
	CodeDigestMismatch   Code = "digest_mismatch"

	// Apply and the receipt state machine (spec section 7).
	CodeApplyFailed    Code = "apply_failed"
	CodeCapabilityLoss Code = "capability_loss"
	// CodeRestartDeferred refuses, before anything changes, a bundle whose
	// config change restarts the gateway when the caller asked to defer
	// restarts (apply --defer-restart); retry it in a maintenance window.
	CodeRestartDeferred Code = "restart_deferred"
	CodeNotConfirmed    Code = "not_confirmed"
	CodeInterrupted     Code = "interrupted"
	// CodeSuperseded ends the receipt of an inbox bundle that one run
	// did not apply because the same inbox held a higher version.
	CodeSuperseded     Code = "superseded"
	CodeLifecycleBusy  Code = "lifecycle_busy"
	CodeBundleRequired Code = "bundle_required"
	CodeNotManaged     Code = "not_managed"
	CodeNotAdmin       Code = "not_admin"
	// CodeStateInvalid: bundle-state.json cannot be read. Nothing is
	// applied: an unreadable state must not lower the version floor.
	CodeStateInvalid Code = "state_invalid"

	// CodeNotSupportedSecureClient refuses every bundle verb on a Secure
	// Client computer before anything is read or written.
	CodeNotSupportedSecureClient Code = "not_supported_secure_client"
)

// Limits of the readers and the manifest decoder. A bundle over any of them
// is refused before anything else is looked at.
const (
	MaxCompressedBytes = 4 << 20   // a .dcbundle file
	MaxExpandedBytes   = 16 << 20  // the sum of all file sizes
	MaxEntries         = 512       // files and directories
	MaxManifestBytes   = 256 << 10 // manifest.json
	MaxSignatureBytes  = 16 << 10  // manifest.sig
	MaxAnchorsBytes    = 64 << 10  // bundle-anchors.json
	MaxAnchorKeys      = 32
	MaxPathBytes       = 255
	MaxPathDepth       = 16
	MaxChangeSummary   = 512 // runes
	MaxSecretRefs      = 64
	MaxWarnings        = 256
)

// Error is a refused bundle. Path names the bundle file or manifest field at
// fault; Detail says what is wrong without quoting any content.
type Error struct {
	Code   Code
	Path   string
	Detail string
	// cause is the operating system error behind the refusal, if any, for
	// errors.Is (for example fs.ErrPermission); it is never printed.
	cause error
}

// Unwrap returns the operating system error behind the refusal.
func (e *Error) Unwrap() error { return e.cause }

func (e *Error) Error() string {
	if e.Path == "" {
		return fmt.Sprintf("bundle %s: %s", e.Code, e.Detail)
	}
	return fmt.Sprintf("bundle %s: %s: %s", e.Code, safePath(e.Path), e.Detail)
}

// CodeOf returns the bundle error code of err, or "" when err is not a
// bundle refusal.
func CodeOf(err error) Code {
	var bundleErr *Error
	if errors.As(err, &bundleErr) {
		return bundleErr.Code
	}
	return ""
}

func refuse(code Code, path, format string, args ...any) *Error {
	return &Error{Code: code, Path: path, Detail: fmt.Sprintf(format, args...)}
}

// StageError preserves a storage exhaustion reason when a valid bundle could
// not be copied into the private stage. The receipt and CLI use the same code.
func StageError(err error) *Error {
	code := CodeArchiveInvalid
	if stageDiskFull(err) {
		code = CodeDiskFull
	}
	return &Error{Code: code, Detail: "cannot stage the bundle: " + err.Error(), cause: err}
}

// safePath quotes a path taken from untrusted input when it holds anything
// other than the characters a valid bundle path may hold, and bounds it.
func safePath(path string) string {
	if len(path) > 128 {
		path = path[:128] + "..."
	}
	for i := 0; i < len(path); i++ {
		if !pathByte(path[i]) && path[i] != '[' && path[i] != ']' {
			return strconv.QuoteToASCII(path)
		}
	}
	return path
}
