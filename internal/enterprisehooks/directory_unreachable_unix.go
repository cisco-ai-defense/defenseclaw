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

package enterprisehooks

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// The Active Directory domains whose domain controllers stopped answering
// (macOS).
//
// A bound Mac's Open Directory can keep listing its Active Directory node
// Online through a domain controller outage, and some 20 minutes in it lists
// the accounts with their primary group (Domain Users) still named but
// without their other domain groups. Nothing in that answer says it is
// incomplete, so the accounts moved to the default profile as a verified
// "default" instead of default_lookup_failed (GAP-0092), and since no account
// was listed without its primary group, nothing flushed the caches once the
// domain controller was back (GAP-0095). The root guardian therefore checks
// the domain controllers of the enrolled accounts' Active Directory domains
// itself, about once a minute and every 15 seconds while one is away, and
// writes the domains whose domain controllers stopped answering to
// DirectoryUnreachableFile in the identity spool. The gateway takes the
// lookup of an Active Directory account of such a domain as failed while the
// file is current (DirectoryUnreachableMaxAge), as it does when Open
// Directory lists the node offline. A domain counts only after it answered
// once: a Mac that never reaches its domain controllers' LDAP port (a
// firewall) is not put in an outage for good.

// DirectoryUnreachableFile is the file of the identity spool that lists the
// domains whose domain controllers stopped answering.
const DirectoryUnreachableFile = "directory-unreachable.json"

// DirectoryUnreachableMaxAge is how long the gateway trusts the file after
// the guardian last wrote it: the guardian rewrites it every 15 seconds
// while a domain is away, so an older file is a guardian that stopped.
const DirectoryUnreachableMaxAge = 3 * time.Minute

const (
	directoryUnreachableVersion  = 1
	maxDirectoryUnreachableBytes = 16 << 10
	maxDirectoryUnreachable      = 64
)

type directoryUnreachableDoc struct {
	Version   int       `json:"v"`
	UpdatedAt time.Time `json:"updated_at"`
	Domains   []string  `json:"domains"`
}

// WriteDirectoryUnreachable replaces dir's list of the domains whose domain
// controllers stopped answering with domains, at now; with none it removes
// the file. setOwnership gives the file the guardian authorization
// ownership before it is renamed into place.
func WriteDirectoryUnreachable(dir string, domains []string, now time.Time, setOwnership func(string) error) error {
	if dir == "" {
		return nil
	}
	clean := cleanDirectoryDomains(domains)
	if len(clean) == 0 {
		if err := os.Remove(filepath.Join(dir, DirectoryUnreachableFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	data, err := json.Marshal(directoryUnreachableDoc{Version: directoryUnreachableVersion, UpdatedAt: now.UTC(), Domains: clean})
	if err != nil {
		return err
	}
	return writeSpoolBytes(dir, DirectoryUnreachableFile, ".unreachable-*", data, setOwnership)
}

// ReadDirectoryUnreachable returns the domains dir lists as having no domain
// controller that answers, when the file exists, trust accepts it and it is
// no older than DirectoryUnreachableMaxAge at now; otherwise none.
func ReadDirectoryUnreachable(dir string, trust func(path, label string) error, now time.Time) []string {
	if dir == "" {
		return nil
	}
	path := filepath.Join(dir, DirectoryUnreachableFile)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxDirectoryUnreachableBytes {
		return nil
	}
	if trust != nil && trust(path, "directory reachability record") != nil {
		return nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxDirectoryUnreachableBytes+1))
	if err != nil || len(data) > maxDirectoryUnreachableBytes {
		return nil
	}
	var doc directoryUnreachableDoc
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&doc) != nil || doc.Version != directoryUnreachableVersion {
		return nil
	}
	if age := now.Sub(doc.UpdatedAt); doc.UpdatedAt.IsZero() || age < -time.Minute || age > DirectoryUnreachableMaxAge {
		return nil
	}
	return cleanDirectoryDomains(doc.Domains)
}

// cleanDirectoryDomains keeps the valid DNS domain names, lower case, each
// once and sorted, at most maxDirectoryUnreachable.
func cleanDirectoryDomains(domains []string) []string {
	var out []string
	for _, domain := range domains {
		domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
		if validDirectoryDomain(domain) && !slices.Contains(out, domain) && len(out) < maxDirectoryUnreachable {
			out = append(out, domain)
		}
	}
	slices.Sort(out)
	return out
}
