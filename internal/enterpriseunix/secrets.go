// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// maxSecretBytes bounds a protected credential.
const maxSecretBytes = 16 << 10

// SecretState is the non-secret description of one protected credential.
type SecretState struct {
	Name         string `json:"name"`
	Present      bool   `json:"present"`
	SHA256Prefix string `json:"sha256_prefix,omitempty"`
	ModifiedAt   string `json:"modified_at,omitempty"`
	Mode         string `json:"mode,omitempty"`
}

// listSecrets returns the credential names in the secrets directory and a
// digest over their names and contents, so ensure notices a rotation.
func (e *Env) listSecrets() ([]string, string, error) {
	names, err := e.secretNames()
	if err != nil {
		return nil, "", err
	}
	var digest bytes.Buffer
	for _, name := range names {
		sum, err := sha256File(filepath.Join(e.P(e.Layout.SecretsDir), name))
		if err != nil {
			return nil, "", err
		}
		fmt.Fprintf(&digest, "%s:%s\n", name, sum)
	}
	return names, sha256Bytes(digest.Bytes()), nil
}

// secretNames lists, sorted, the credentials in the secrets directory: the
// regular files with a credential name. No credential is opened; a missing
// directory holds none.
func (e *Env) secretNames() ([]string, error) {
	dir := e.P(e.Layout.SecretsDir)
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var names []string
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, ".") || !config.ValidEnterpriseCredentialName(name) {
			continue
		}
		info, err := os.Lstat(filepath.Join(dir, name))
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}

// SecretValue reads the credential name from the secrets directory with the
// gateway's read checks (managed.StoredCredentialValue) and this host's
// trust check. Bundle verify and apply both use it to compare the value with
// the signed value_sha256, so a stored file the gateway would refuse (empty,
// several lines, too large, readable by other users, untrusted) is missing
// (nil), not present. A store the caller cannot read is an error.
func (e *Env) SecretValue(name string) ([]byte, error) {
	e.fillDefaults()
	return managed.StoredCredentialValue(name, e.P(e.Layout.SecretsDir),
		func(path string) error { return e.Trust(path, TrustAdminFile) })
}

// TrustedSecretSource refuses a --from-file credential that another account
// could have changed: a symlink, a file that group or others can write or
// that another account owns, or one in a folder another account can write.
// The Windows CLI and the MDM wrapper refuse such a file; the Unix CLI read
// it (GAP-0334).
func TrustedSecretSource(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(abs); errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("--from-file %s does not exist", path)
	}
	return trustedInputFile(abs, "--from-file")
}

// ReadSecretValue reads a credential from r, stripping one trailing line
// ending so `echo key |` works.
func ReadSecretValue(r io.Reader) ([]byte, error) {
	data, err := ReadSecretBytes(r)
	if err != nil {
		return nil, err
	}
	return ParseSecretValue(data)
}

// ReadSecretBytes reads what a credential source delivers, at most one byte
// over the credential limit, without checking it (ParseSecretValue does).
func ReadSecretBytes(r io.Reader) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r, maxSecretBytes+1))
}

// ParseSecretValue checks the bytes a credential source delivered and
// strips one trailing line ending.
func ParseSecretValue(data []byte) ([]byte, error) {
	if len(data) > maxSecretBytes {
		return nil, fmt.Errorf("credential exceeds %d bytes", maxSecretBytes)
	}
	data = bytes.TrimSuffix(data, []byte("\n"))
	data = bytes.TrimSuffix(data, []byte("\r"))
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, errors.New("credential is empty")
	}
	if bytes.ContainsAny(data, "\x00\n") {
		return nil, errors.New("credential must be a single line without NUL bytes")
	}
	return data, nil
}

// SecretStatus reports every credential without revealing values.
func (e *Env) SecretStatus() ([]SecretState, error) {
	e.fillDefaults()
	names, _, err := e.listSecrets()
	if err != nil {
		return nil, err
	}
	states := []SecretState{}
	for _, name := range names {
		path := filepath.Join(e.P(e.Layout.SecretsDir), name)
		state := SecretState{Name: name, Present: true}
		if info, err := os.Lstat(path); err == nil {
			state.ModifiedAt = info.ModTime().UTC().Format(time.RFC3339)
			state.Mode = fmt.Sprintf("%04o", info.Mode().Perm())
		}
		if sum, err := sha256File(path); err == nil {
			state.SHA256Prefix = sum[:12]
		}
		states = append(states, state)
	}
	return states, nil
}

// WriteSecret stores one protected credential. On Linux with systemd 247+
// the file is root-only and reaches the gateway through LoadCredential;
// otherwise it is readable by the gateway's group only.
func (e *Env) WriteSecret(ctx context.Context, name string, value []byte) error {
	e.fillDefaults()
	if !config.ValidEnterpriseCredentialName(name) {
		return fmt.Errorf("credential name %q is not valid (lowercase letters, digits and dashes)", name)
	}
	account, ok, err := e.Accounts.Lookup(ctx, e.Layout.ServiceUser)
	if err != nil {
		return err
	}
	// Before the first install there is no service account: the credential
	// is staged root-only, and the install gives the gateway its access
	// (settleSecretModes), so a config that references it installs at once.
	mode, owner, dirMode, dirOwner := os.FileMode(0o600), rootOwner(), os.FileMode(0o700), rootOwner()
	if ok {
		mode, owner, dirMode, dirOwner = e.secretModes(ctx, account)
	}
	if err := e.ensureDir(e.P(e.Layout.SecretsDir), dirMode, dirOwner); err != nil {
		return err
	}
	return e.writeFileAtomic(filepath.Join(e.P(e.Layout.SecretsDir), name), value, mode, owner)
}

// RemoveSecret deletes one protected credential. It refuses one the
// installed config still names: an enabled observability destination (the
// gateway could not start on that config without it) or the LLM judge and AI
// Defense keys (the judge would run without its key, GAP-0674).
func (e *Env) RemoveSecret(name string) error {
	e.fillDefaults()
	if !config.ValidEnterpriseCredentialName(name) {
		return fmt.Errorf("credential name %q is not valid", name)
	}
	if raw, err := readBounded(e.P(e.Layout.ConfigPath), maxInputBytes); err == nil {
		if at := config.InstalledCredentialReference(e.Layout.ConfigPath, raw, e.Layout.DataDir, name); at != "" {
			return fmt.Errorf("the installed config still references credential %s at %s; remove that reference and apply the config first", name, at)
		}
	}
	return removeFile(filepath.Join(e.P(e.Layout.SecretsDir), name))
}

// settleSecretModes gives every stored credential the mode and owner the
// gateway reads it with; one staged before the first install is root-only
// until then.
func (e *Env) settleSecretModes(ctx context.Context, account Account) error {
	names, _, err := e.listSecrets()
	if err != nil {
		return err
	}
	mode, owner, _, _ := e.secretModes(ctx, account)
	for _, name := range names {
		if err := e.fixMetadata(filepath.Join(e.P(e.Layout.SecretsDir), name), mode, owner); err != nil {
			return fmt.Errorf("set the access of credential %s: %w", name, err)
		}
	}
	return nil
}

func (e *Env) secretModes(ctx context.Context, account Account) (os.FileMode, fileOwner, os.FileMode, fileOwner) {
	service := fileOwner{UID: 0, GID: account.GID}
	if e.GOOS == "linux" && e.Services.Version(ctx) >= loadCredentialSystemd {
		return 0o600, rootOwner(), 0o700, rootOwner()
	}
	return 0o640, service, 0o750, service
}
