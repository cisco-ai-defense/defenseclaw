// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

// Package kernel embeds DefenseClaw's fixed kernel control set for Tetragon
// and computes its kernel_policy digest.
//
// The set ships inside the binary and is the only thing that can ever become
// a kernel deny: there are no per-host or per-user control keys. It is kept
// out of policyassets.Files, so it is never seeded into a per-user policy
// directory and never installed as a vendor policy file.
//
// The digest is what an administrator approves. It covers the embedded files
// and the Tetragon schema they are rendered for, and nothing that varies per
// host (uids, pids, paths of homes), so every host running the same build
// reports the same value and the value read in observe mode is the one that
// goes into enterprise.tetragon.enforce_ack. The sensor helper, the gateway's
// effective-digest component and the enterprise lifecycle all call Digest.
package kernel

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

//go:embed linux/*.yaml
var files embed.FS

const (
	// ControlSSHPrivateKeyRead denies agent descendants opens of the user's
	// SSH private keys.
	ControlSSHPrivateKeyRead = "kernel.ssh_private_key_read"
	// ControlPersistenceWrite denies agent descendants write opens of the
	// user's shell startup files and user autostart units.
	ControlPersistenceWrite = "kernel.persistence_write"

	// Schema names the lowest Tetragon release the policies are rendered
	// for. It is part of the digest: rendering for another schema is a
	// different control set.
	Schema = "tetragon-1.7"

	// digestVersion versions the digest's own input format.
	digestVersion = 1

	// AckHexLength is the number of hex characters of the kernel_policy
	// digest an administrator puts in enforce_ack.
	AckHexLength = 12

	// AccessOpen matches any open; AccessWrite only opens for writing.
	AccessOpen  = "open"
	AccessWrite = "write"
)

var ackPattern = regexp.MustCompile(`^sha256:[0-9a-f]{12}$`)

// Control is one enforce-capable kernel control.
type Control struct {
	ID     string `yaml:"id"`
	RuleID string `yaml:"rule_id"`
	Access string `yaml:"access"`
	// Files are home-relative exact names; Dirs are home-relative
	// directories with a trailing slash.
	Files []string `yaml:"files"`
	Dirs  []string `yaml:"dirs"`
	// ExemptBinaries are absolute paths, resolved on the host before use,
	// whose own opens never match the control.
	ExemptBinaries []string `yaml:"exempt_binaries"`
}

// ObserveGroup is one path group of the observe policy.
type ObserveGroup struct {
	Name string `yaml:"name"`
	// Scope is "home" (paths relative to each enrolled home) or "system"
	// (absolute paths).
	Scope  string   `yaml:"scope"`
	Access string   `yaml:"access"`
	Files  []string `yaml:"files"`
	Dirs   []string `yaml:"dirs"`
	// FromControl takes Files and Dirs from the named control.
	FromControl string `yaml:"from_control"`
}

// Observe is the post-only file policy.
type Observe struct {
	Version   int            `yaml:"version"`
	RateLimit string         `yaml:"rate_limit"`
	Groups    []ObserveGroup `yaml:"groups"`
}

// Connect is the post-only tcp_connect policy.
type Connect struct {
	Version             int      `yaml:"version"`
	RateLimit           string   `yaml:"rate_limit"`
	ExcludeDestinations []string `yaml:"exclude_destinations"`
}

// Set is the whole embedded control set.
type Set struct {
	Controls []Control
	Observe  Observe
	Connect  Connect
}

type controlsFile struct {
	Version  int       `yaml:"version"`
	Controls []Control `yaml:"controls"`
}

// Control returns the control with id.
func (s Set) Control(id string) (Control, bool) {
	for _, control := range s.Controls {
		if control.ID == id {
			return control, true
		}
	}
	return Control{}, false
}

type embeddedFile struct {
	name string
	data []byte
}

var (
	loadOnce sync.Once
	loaded   Set
	loadErr  error
	sums     digests
)

type digests struct {
	controls string // hex sha256 of the embedded files
	full     string // hex sha256 of the canonical digest input
}

// embeddedFiles returns the embedded files in name order.
func embeddedFiles() ([]embeddedFile, error) {
	var out []embeddedFile
	err := fs.WalkDir(files, "linux", func(name string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() || path.Ext(name) != ".yaml" {
			return err
		}
		data, err := files.ReadFile(name)
		if err != nil {
			return err
		}
		out = append(out, embeddedFile{name: name, data: data})
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out, err
}

// Load parses and validates the embedded set once.
func Load() (Set, error) {
	loadOnce.Do(func() { loaded, sums, loadErr = load() })
	return loaded, loadErr
}

// MustLoad is Load for callers that run after the package's own tests have
// proven the embedded set valid.
func MustLoad() Set {
	set, err := Load()
	if err != nil {
		panic(err)
	}
	return set
}

func load() (Set, digests, error) {
	embedded, err := embeddedFiles()
	if err != nil {
		return Set{}, digests{}, err
	}
	byName := map[string][]byte{}
	hash := sha256.New()
	for _, file := range embedded {
		byName[path.Base(file.name)] = file.data
		// Length-prefixed, so no two different sets hash the same.
		fmt.Fprintf(hash, "%s\x00%d\x00", file.name, len(file.data))
		hash.Write(file.data)
	}
	var set Set
	var controls controlsFile
	if err := strictYAML(byName["controls.yaml"], &controls); err != nil {
		return Set{}, digests{}, fmt.Errorf("kernel controls: controls.yaml: %w", err)
	}
	set.Controls = controls.Controls
	if err := strictYAML(byName["observe.yaml"], &set.Observe); err != nil {
		return Set{}, digests{}, fmt.Errorf("kernel controls: observe.yaml: %w", err)
	}
	if err := strictYAML(byName["connect.yaml"], &set.Connect); err != nil {
		return Set{}, digests{}, fmt.Errorf("kernel controls: connect.yaml: %w", err)
	}
	if controls.Version != 1 || set.Observe.Version != 1 || set.Connect.Version != 1 {
		return Set{}, digests{}, fmt.Errorf("kernel controls: unsupported file version")
	}
	if err := validate(set); err != nil {
		return Set{}, digests{}, err
	}
	controlsSum := hex.EncodeToString(hash.Sum(nil))
	canonical, err := json.Marshal(map[string]any{
		"v":        digestVersion,
		"controls": controlsSum,
		"schema":   Schema,
	})
	if err != nil {
		return Set{}, digests{}, err
	}
	full := sha256.Sum256(canonical)
	return set, digests{controls: controlsSum, full: hex.EncodeToString(full[:])}, nil
}

func strictYAML(data []byte, out any) error {
	if len(bytes.TrimSpace(data)) == 0 {
		return fmt.Errorf("missing")
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	return decoder.Decode(out)
}

func validate(set Set) error {
	seen := map[string]bool{}
	for _, control := range set.Controls {
		switch control.ID {
		case ControlSSHPrivateKeyRead, ControlPersistenceWrite:
		default:
			return fmt.Errorf("kernel controls: unknown control %q", control.ID)
		}
		if seen[control.ID] {
			return fmt.Errorf("kernel controls: duplicate control %q", control.ID)
		}
		seen[control.ID] = true
		if control.RuleID == "" {
			return fmt.Errorf("kernel controls: %s has no rule_id", control.ID)
		}
		if control.Access != AccessOpen && control.Access != AccessWrite {
			return fmt.Errorf("kernel controls: %s access %q", control.ID, control.Access)
		}
		if len(control.Files)+len(control.Dirs) == 0 {
			return fmt.Errorf("kernel controls: %s names no path", control.ID)
		}
		// The ssh exemption (NoPost for ssh, ssh-keygen, ssh-add) is keyed to
		// exact key names; a directory here would be denied without it.
		if control.ID == ControlSSHPrivateKeyRead && len(control.Dirs) != 0 {
			return fmt.Errorf("kernel controls: %s must name exact files only", control.ID)
		}
		if err := validateRelative(control.ID, control.Files, control.Dirs); err != nil {
			return err
		}
		for _, binary := range control.ExemptBinaries {
			if !path.IsAbs(binary) || path.Clean(binary) != binary {
				return fmt.Errorf("kernel controls: %s exempt binary %q is not a clean absolute path", control.ID, binary)
			}
		}
	}
	if len(seen) != 2 {
		return fmt.Errorf("kernel controls: want exactly the two controls, have %d", len(seen))
	}
	for _, group := range set.Observe.Groups {
		if group.Access != AccessOpen && group.Access != AccessWrite {
			return fmt.Errorf("kernel observe: group %s access %q", group.Name, group.Access)
		}
		if group.FromControl != "" {
			if _, ok := set.Control(group.FromControl); !ok || len(group.Files)+len(group.Dirs) != 0 {
				return fmt.Errorf("kernel observe: group %s from_control %q", group.Name, group.FromControl)
			}
			continue
		}
		switch group.Scope {
		case "home":
			if err := validateRelative("observe "+group.Name, group.Files, group.Dirs); err != nil {
				return err
			}
		case "system":
			for _, p := range append(append([]string{}, group.Files...), group.Dirs...) {
				if !path.IsAbs(p) || path.Clean(p) != strings.TrimSuffix(p, "/") || p == "/" {
					return fmt.Errorf("kernel observe: system path %q is not a clean absolute path", p)
				}
			}
		default:
			return fmt.Errorf("kernel observe: group %s scope %q", group.Name, group.Scope)
		}
	}
	if set.Observe.RateLimit == "" || set.Connect.RateLimit == "" {
		return fmt.Errorf("kernel policies: rate_limit is required")
	}
	return nil
}

func validateRelative(owner string, files, dirs []string) error {
	for _, p := range files {
		if p == "" || path.IsAbs(p) || strings.HasSuffix(p, "/") || path.Clean(p) != p || strings.HasPrefix(p, "..") {
			return fmt.Errorf("kernel controls: %s file %q is not a clean home-relative name", owner, p)
		}
	}
	for _, p := range dirs {
		trimmed := strings.TrimSuffix(p, "/")
		if !strings.HasSuffix(p, "/") || trimmed == "" || path.IsAbs(p) || path.Clean(trimmed) != trimmed || strings.HasPrefix(trimmed, "..") {
			return fmt.Errorf("kernel controls: %s dir %q is not a clean home-relative directory with a trailing slash", owner, p)
		}
	}
	return nil
}

// FullDigest is the whole kernel_policy digest, "sha256:" and 64 hex.
func FullDigest() string {
	MustLoad()
	return "sha256:" + sums.full
}

// Digest is the kernel_policy digest in the form every surface prints and
// compares: "sha256:" and the first AckHexLength hex characters. It is the
// value enforce_ack must equal.
func Digest() string {
	MustLoad()
	return "sha256:" + sums.full[:AckHexLength]
}

// ValidAck reports whether value has the enforce_ack shape. The empty string
// is the unset value and is valid config, but never matches Digest.
func ValidAck(value string) bool {
	return value == "" || ackPattern.MatchString(value)
}

// AckMatches reports whether ack approves this build's control set.
func AckMatches(ack string) bool {
	return ack != "" && ack == Digest()
}
