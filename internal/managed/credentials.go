// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"

	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
)

// ServiceCredentialLimit bounds a protected credential read. API keys are a
// few hundred bytes; anything larger is malformed.
const ServiceCredentialLimit = 16 << 10

// ErrNoServiceCredential reports that the named credential is not
// provisioned. Callers treat it as "remote inspection disabled", never as
// "use some other key".
var ErrNoServiceCredential = errors.New("service credential is not provisioned")

// ErrUnusableServiceCredential reports that the named credential is stored
// but fails a check the gateway's own read applies: the path trust, the
// reader ACL, the size limit, an empty or a multi-line value. The gateway
// cannot use it, so bundle verify and apply count it as missing
// (ServiceCredentialValue), never as unchecked.
var ErrUnusableServiceCredential = errors.New("service credential is stored but unusable")

// unusableCredentialError keeps the text and the chain of the failed check
// and adds ErrUnusableServiceCredential to it.
type unusableCredentialError struct{ err error }

func (e *unusableCredentialError) Error() string { return e.err.Error() }
func (e *unusableCredentialError) Unwrap() []error {
	return []error{ErrUnusableServiceCredential, e.err}
}

// credentialVerdict classifies a failed check of a credential file that
// exists. A failed operating-system call (access denied, a file, owner or
// security descriptor that could not be read) means the caller could not
// decide, and the error is returned as is; any other failure is a verdict on
// the stored file and wraps ErrUnusableServiceCredential.
func credentialVerdict(err error) error {
	var errno syscall.Errno
	if err == nil || errors.Is(err, ErrUnusableServiceCredential) || errors.As(err, &errno) {
		return err
	}
	return &unusableCredentialError{err: err}
}

// ServiceCredentialValue maps the result of a credential read to what
// bundle verify and apply compare with the signed value. Stored and usable
// is the value. Not stored, or stored but unusable
// (ErrUnusableServiceCredential), is nil with no error, so a required
// reference refuses with secret_ref_missing as the gateway would fail to
// read it. Any other error means the caller could not read the store and is
// returned, so verify warns secret_presence_unchecked. A value it does not
// return is cleared.
func ServiceCredentialValue(value []byte, err error) ([]byte, error) {
	if err == nil {
		return value, nil
	}
	clear(value)
	if errors.Is(err, ErrNoServiceCredential) || errors.Is(err, ErrUnusableServiceCredential) {
		return nil, nil
	}
	return nil, err
}

var serviceCredentialNamePattern = lazyregexp.New(`^[a-z0-9][a-z0-9-]{0,62}$`)

// ValidCredentialName reports whether name is a safe credential name. It
// becomes a file name, so path separators and dots are refused.
func ValidCredentialName(name string) bool {
	return serviceCredentialNamePattern.MatchString(name)
}

// CredentialSource says where a credential was read from, for status
// output; it never carries the value.
type CredentialSource string

const (
	CredentialFromSystemd CredentialSource = "systemd_credential"
	CredentialFromFile    CredentialSource = "protected_file"
)

// ResolveServiceCredential reads the named credential of a standalone
// deployment. secretsDir is the layout's administrator-owned secrets
// directory. The value exists only in memory; it is never logged.
func ResolveServiceCredential(name, secretsDir string) ([]byte, CredentialSource, error) {
	if !ValidCredentialName(name) {
		return nil, "", fmt.Errorf("credential name %q is not valid", name)
	}
	return resolvePlatformServiceCredential(name, secretsDir)
}

// readStoredCredential runs the gateway's checks on the credential file at
// path, which exists, then reads it. A check that refuses the file, or a
// value that is too large, empty or not a single line, wraps
// ErrUnusableServiceCredential (credentialVerdict).
func readStoredCredential(name, path string, checks ...func(path string) error) ([]byte, error) {
	for _, check := range checks {
		if err := check(path); err != nil {
			return nil, credentialVerdict(err)
		}
	}
	data, err := readBoundedCredential(path)
	if err != nil {
		return nil, credentialVerdict(fmt.Errorf("credential %s: %w", name, err))
	}
	return data, nil
}

// ReadCredentialSource reads a credential value from path as the gateway
// reads a stored one: at most ServiceCredentialLimit bytes, surrounding
// whitespace trimmed, one non-empty line. bundle sign --secret-file binds
// the value the gateway will read.
func ReadCredentialSource(path string) ([]byte, error) {
	return readBoundedCredential(path)
}

// readBoundedCredential reads at most ServiceCredentialLimit bytes from an
// already-validated file and trims surrounding whitespace.
func readBoundedCredential(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open credential: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, ServiceCredentialLimit+1))
	if err != nil {
		return nil, fmt.Errorf("read credential: %w", err)
	}
	if len(data) > ServiceCredentialLimit {
		return nil, fmt.Errorf("credential exceeds %d bytes", ServiceCredentialLimit)
	}
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, errors.New("credential is empty")
	}
	if bytes.ContainsAny(data, "\x00\r\n") {
		return nil, errors.New("credential must be a single line")
	}
	return data, nil
}
