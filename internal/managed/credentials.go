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
	"regexp"
)

// ServiceCredentialLimit bounds a protected credential read. API keys are a
// few hundred bytes; anything larger is malformed.
const ServiceCredentialLimit = 16 << 10

// ErrNoServiceCredential reports that the named credential is not
// provisioned. Callers treat it as "remote inspection disabled", never as
// "use some other key".
var ErrNoServiceCredential = errors.New("service credential is not provisioned")

var serviceCredentialNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

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
