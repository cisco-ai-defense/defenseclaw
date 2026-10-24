// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package openshell

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// The Docker sandbox bootstrap of OpenShell before 0.1.5 (GAP-0300).
//
// OpenShell's docker driver keeps, per sandbox, the protected bootstrap it
// launches the sandbox with in
// <state>/openshell/docker-sandbox-tokens/<namespace>/<sandbox id>/:
// boundary-bootstrap.json (the in-container side) and
// runtime-descriptor.json (the supervisor's side). It reads both again at
// every start of the stopped container, and decodes them with no unknown
// field. OpenShell 0.1.5 (NVIDIA/OpenShell#3898) replaced their
// outer_fence, which 0.1.1 to 0.1.4 write, with provisioning_evidence: a
// sandbox those releases created cannot start on 0.1.5 ("decode Docker
// sandbox bootstrap for authentication rotation: unknown field
// `outer_fence`"), and neither can a pull that starts it. Nothing in
// OpenShell 0.1.5 rewrites them.
//
// MigrateDockerBootstrap rewrites the two files of such a sandbox to what
// 0.1.5 writes for it: outer_fence out, provisioning_evidence in, computed
// as 0.1.5's docker driver computes it (crates/openshell-driver-docker
// isolation.rs provisioning_evidence), from the generation and the
// docker.container_id claim the file already holds; every other field is
// kept as it is. A 0.1.5 start then replaces the evidence with that of
// the new generation, as for a sandbox 0.1.5 created. It must run only
// once the gateway is 0.1.5 or later: OpenShell before 0.1.5 refuses the
// new field the same way. Remove with the 0.1.5 floor's legacy upgrade
// (LegacyMin), once no supported upgrade starts from 0.1.4 or older.

const (
	dockerSandboxTokensDir    = "docker-sandbox-tokens"
	dockerBoundaryConfigFile  = "boundary-bootstrap.json"
	dockerRuntimeDescriptor   = "runtime-descriptor.json"
	legacyOuterFenceField     = "outer_fence"
	provisioningEvidenceField = "provisioning_evidence"
	dockerContainerIDClaim    = "docker.container_id"
)

// ErrDockerBootstrap is a Docker sandbox bootstrap of an OpenShell before
// 0.1.5 that MigrateDockerBootstrap could not rewrite.
var ErrDockerBootstrap = errors.New("openshell: the Docker sandbox bootstrap of an OpenShell release before 0.1.5 could not be moved to 0.1.5")

// ErrDockerStateUnreadable is a state folder whose Docker sandbox folders
// cannot be listed, so whether it keeps a sandbox is not known. It says
// nothing about the sandbox's own bootstrap (ErrDockerBootstrap).
var ErrDockerStateUnreadable = errors.New("openshell: the Docker sandbox folders of an OpenShell state folder cannot be listed")

// MigrateDockerBootstrap rewrites, for the Docker sandbox whose OpenShell
// id is sandboxID, the bootstrap files an OpenShell before 0.1.5 wrote
// (see above), in every namespace of the state folder stateHome
// (UserStateHome) that keeps the sandbox. It names the files it rewrote,
// and reports whether the folder keeps the sandbox; a sandbox with no such
// folder, or whose files 0.1.5 wrote, has none. A file of the sandbox it
// cannot read, parse or replace is ErrDockerBootstrap, and is left as it
// was. A state folder it cannot list, finding the sandbox in no namespace
// it could, is ErrDockerStateUnreadable.
func MigrateDockerBootstrap(stateHome, sandboxID string) (migrated []string, kept bool, err error) {
	if !plainPathElement(sandboxID) || !filepath.IsAbs(stateHome) {
		return nil, false, fmt.Errorf("%w: no sandbox folder for id %q under %q", ErrDockerBootstrap, sandboxID, stateHome)
	}
	root := filepath.Join(stateHome, "openshell", dockerSandboxTokensDir)
	namespaces, err := os.ReadDir(root)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("%w: %v", ErrDockerStateUnreadable, err)
	}
	var unlisted error
	for _, ns := range namespaces {
		if !ns.IsDir() {
			continue
		}
		dir := filepath.Join(root, ns.Name(), sandboxID)
		fi, err := os.Lstat(dir)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			if unlisted == nil {
				unlisted = fmt.Errorf("%w: %v", ErrDockerStateUnreadable, err)
			}
			continue
		}
		if !fi.IsDir() {
			continue
		}
		kept = true
		for _, name := range []string{dockerRuntimeDescriptor, dockerBoundaryConfigFile} {
			path := filepath.Join(dir, name)
			done, err := migrateDockerBootstrapFile(path)
			if err != nil {
				return migrated, true, fmt.Errorf("%w: %s: %v", ErrDockerBootstrap, path, err)
			}
			if done {
				migrated = append(migrated, path)
			}
		}
	}
	if !kept && unlisted != nil {
		return nil, false, unlisted
	}
	return migrated, kept, nil
}

// plainPathElement reports whether s is one path element of its own.
func plainPathElement(s string) bool {
	return s != "" && s != "." && s != ".." && !strings.ContainsAny(s, `/\`) && filepath.Base(s) == s
}

// migrateDockerBootstrapFile rewrites one bootstrap file that has an
// outer_fence (reporting true); a missing file, or one with none, is left.
func migrateDockerBootstrapFile(path string) (bool, error) {
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !fi.Mode().IsRegular() {
		return false, errors.New("not a regular file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	out, changed, err := MigrateDockerBootstrapJSON(data)
	if err != nil || !changed {
		return false, err
	}
	return true, replaceFileAtomic(path, out, fi.Mode().Perm())
}

// MigrateDockerBootstrapJSON is the rewrite of one bootstrap file (a
// BoundaryConfig or a SandboxRuntimeDescriptor of OpenShell 0.1.1 to 0.1.4),
// reporting whether it had an outer_fence to replace.
func MigrateDockerBootstrapJSON(data []byte) ([]byte, bool, error) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, false, fmt.Errorf("parse: %v", err)
	}
	if _, legacy := doc[legacyOuterFenceField]; !legacy {
		return data, false, nil
	}
	if _, both := doc[provisioningEvidenceField]; both {
		return nil, false, fmt.Errorf("it has both %s and %s", legacyOuterFenceField, provisioningEvidenceField)
	}
	var generation string
	if err := json.Unmarshal(doc["generation"], &generation); err != nil || generation == "" {
		return nil, false, errors.New("it names no generation")
	}
	var claims map[string]string
	if err := json.Unmarshal(doc["resource_claims"], &claims); err != nil || claims[dockerContainerIDClaim] == "" {
		return nil, false, fmt.Errorf("it has no %s resource claim", dockerContainerIDClaim)
	}
	evidence, err := dockerProvisioningEvidence(claims[dockerContainerIDClaim], generation)
	if err != nil {
		return nil, false, err
	}
	delete(doc, legacyOuterFenceField)
	doc[provisioningEvidenceField] = evidence
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(doc); err != nil {
		return nil, false, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), true, nil
}

// dockerProvisioningEvidence is the provisioning_evidence OpenShell 0.1.5's
// docker driver binds to a container and a generation: the SHA-256 of the
// generation's length (8 bytes, big endian), the generation, and the JSON
// of the container's fence (its id, network mode "none", no other
// network), as serde_json writes it.
func dockerProvisioningEvidence(containerID, generation string) (json.RawMessage, error) {
	var native bytes.Buffer
	enc := json.NewEncoder(&native)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(struct {
		ContainerID        string   `json:"container_id"`
		NetworkMode        string   `json:"network_mode"`
		UnexpectedNetworks []string `json:"unexpected_networks"`
	}{containerID, "none", []string{}}); err != nil {
		return nil, err
	}
	h := sha256.New()
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(generation)))
	h.Write(n[:])
	h.Write([]byte(generation))
	h.Write(bytes.TrimSuffix(native.Bytes(), []byte("\n")))
	return json.Marshal(struct {
		Generation     string `json:"generation"`
		EvidenceDigest string `json:"evidence_digest"`
	}{generation, hex.EncodeToString(h.Sum(nil))})
}

// replaceFileAtomic replaces path with data (mode perm) through a file in
// its folder, so a reader sees the old file or the new one, never a part.
func replaceFileAtomic(path string, data []byte, perm fs.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".defenseclaw-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	keep := false
	defer func() {
		if !keep {
			_ = os.Remove(name)
		}
	}()
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	keep = true
	return nil
}
