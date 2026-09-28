// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package ipc

// Windows accept-time peer authentication for the Secure Client GUI IPC.
//
// This file holds the platform-neutral half: the admission policy and
// the listener that applies it. The Windows system calls it needs
// (peer PID, process image, file handle, WinVerifyTrust) are injected
// through windowsPeerResolvers, implemented in peerauth_windows.go.
// Keeping the decision logic free of syscalls lets every build host
// run its tests.

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// secureClientWindowsInstallRelativeDir is the Cisco Secure Client
// install directory relative to a trusted Program Files root. The GUI
// ships under Program Files (x86); both roots are accepted so a native
// 64-bit GUI build is admitted from the same administrator-owned tree.
const secureClientWindowsInstallRelativeDir = `Cisco\Cisco Secure Client`

// windowsPeerProcess is what the kernel reports about the process on
// the other end of an accepted AF_UNIX connection.
type windowsPeerProcess struct {
	// ImagePath is the executable the process was created from, as
	// the kernel recorded it (an NT device path in production).
	ImagePath string
	SessionID uint32
	// CreatedAt is the process creation time. A process created after
	// the connection was accepted cannot be the process that connected.
	CreatedAt time.Time
}

// windowsImageSigner is the leaf certificate WinVerifyTrust validated
// for the primary embedded Authenticode signature of an executable.
type windowsImageSigner struct {
	CommonName       string
	Organizations    []string
	ThumbprintSHA256 string
}

// windowsPeerImage is a peer executable held open for verification.
// Production opens it without write or delete sharing, so the file
// that FinalPath names is the file VerifySigner checks.
type windowsPeerImage interface {
	// FinalPath is the canonical drive-letter path of the open file,
	// with reparse points resolved and no \\?\ prefix.
	FinalPath() string
	// VerifySigner runs WinVerifyTrust on the open file and returns
	// the signer it validated.
	VerifySigner() (windowsImageSigner, error)
	Close() error
}

// windowsPeerResolvers are the operating-system lookups the listener
// needs. Tests substitute fakes; peerauth_windows.go wires the real
// implementations.
type windowsPeerResolvers struct {
	peerPID   func(net.Conn) (uint32, error)
	process   func(pid uint32) (windowsPeerProcess, error)
	openImage func(imagePath string) (windowsPeerImage, error)
	now       func() time.Time
}

func (r windowsPeerResolvers) complete() bool {
	return r.peerPID != nil && r.process != nil && r.openImage != nil && r.now != nil
}

// windowsPeerPolicy is the resolved admission policy: the exact
// executables that may connect and the signers they must carry.
type windowsPeerPolicy struct {
	images  []string
	signers map[string]struct{}
}

// newWindowsPeerPolicy joins every install-relative image with every
// trusted Program Files root. Roots must be absolute drive paths from
// protected machine registration, never the process environment. Any
// empty input or malformed entry is an error: an empty policy would
// admit nothing, and silently starting a server nobody can reach hides
// a misconfiguration.
func newWindowsPeerPolicy(programFilesRoots, relativeImages, signers []string) (windowsPeerPolicy, error) {
	var policy windowsPeerPolicy
	if len(programFilesRoots) == 0 {
		return policy, errors.New("ipc: windows peer auth: no trusted Program Files root")
	}
	if len(relativeImages) == 0 {
		return policy, errors.New("ipc: windows peer auth: no allowed Secure Client image")
	}
	if len(signers) == 0 {
		return policy, errors.New("ipc: windows peer auth: no allowed Authenticode signer")
	}
	seen := make(map[string]struct{})
	for _, root := range programFilesRoots {
		root = strings.TrimRight(root, `\`)
		if !isCanonicalWindowsDrivePath(root) {
			return windowsPeerPolicy{}, fmt.Errorf("ipc: windows peer auth: Program Files root %q is not a canonical drive path", root)
		}
		for _, rel := range relativeImages {
			if err := config.ValidateWindowsSecureClientImage(rel); err != nil {
				return windowsPeerPolicy{}, fmt.Errorf("ipc: windows peer auth: image %q: %w", rel, err)
			}
			full := root + `\` + secureClientWindowsInstallRelativeDir + `\` + rel
			key := strings.ToLower(full)
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			policy.images = append(policy.images, full)
		}
	}
	policy.signers = make(map[string]struct{}, len(signers))
	for _, signer := range signers {
		if err := config.ValidateWindowsSecureClientSigner(signer); err != nil {
			return windowsPeerPolicy{}, fmt.Errorf("ipc: windows peer auth: signer %q: %w", signer, err)
		}
		policy.signers[signer] = struct{}{}
	}
	return policy, nil
}

// allowsImage reports whether finalPath is exactly one of the allowed
// executables. NTFS names are case-insensitive, so the comparison is
// too; anything that is not already canonical is refused rather than
// normalized here, because the production path comes from
// GetFinalPathNameByHandle and a non-canonical value means something
// upstream is wrong.
func (p windowsPeerPolicy) allowsImage(finalPath string) bool {
	if !isCanonicalWindowsDrivePath(finalPath) {
		return false
	}
	for _, image := range p.images {
		if strings.EqualFold(finalPath, image) {
			return true
		}
	}
	return false
}

// signerRejection returns "" when the signer's subject common name is
// allowed and every subject organization it carries is allowed too, so
// a certificate cannot pair an allowed common name with a different
// organization.
func (p windowsPeerPolicy) signerRejection(signer windowsImageSigner) string {
	if signer.CommonName == "" {
		return "peer image signer has no subject common name"
	}
	if _, ok := p.signers[signer.CommonName]; !ok {
		return fmt.Sprintf("peer image signer %q is not allowed", signer.CommonName)
	}
	for _, organization := range signer.Organizations {
		if _, ok := p.signers[organization]; !ok {
			return fmt.Sprintf("peer image signer organization %q is not allowed", organization)
		}
	}
	return ""
}

// isCanonicalWindowsDrivePath accepts `X:\...` with backslash
// separators and no ".", "..", or empty segments, and no characters
// that Win32 would reinterpret.
func isCanonicalWindowsDrivePath(path string) bool {
	if len(path) < 3 || path[1] != ':' || path[2] != '\\' {
		return false
	}
	drive := path[0] | 0x20
	if drive < 'a' || drive > 'z' {
		return false
	}
	rest := path[3:]
	if rest == "" {
		return true
	}
	if strings.ContainsAny(rest, `/:*?"<>|`) {
		return false
	}
	for _, segment := range strings.Split(rest, `\`) {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
		if strings.HasSuffix(segment, ".") || strings.HasSuffix(segment, " ") {
			return false
		}
		if strings.IndexFunc(segment, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
			return false
		}
	}
	return true
}

// windowsPeerIdentity is what an accepted Windows peer was verified as,
// or as much of it as was learned before a rejection.
type windowsPeerIdentity struct {
	PID       uint32
	SessionID uint32
	ImagePath string
	Signer    string
}

// windowsPeerAuthListener admits a connection only when the process on
// the other end is an allowed, Authenticode-verified Secure Client GUI
// executable. Every other peer is closed before gRPC reads a byte, so
// no health, stats, or notification data reaches it.
type windowsPeerAuthListener struct {
	inner     net.Listener
	policy    windowsPeerPolicy
	resolve   windowsPeerResolvers
	logReject func(windowsPeerIdentity, string)
}

func newWindowsPeerAuthListener(
	inner net.Listener,
	policy windowsPeerPolicy,
	resolve windowsPeerResolvers,
	logReject func(windowsPeerIdentity, string),
) (*windowsPeerAuthListener, error) {
	if inner == nil {
		return nil, errors.New("ipc: windows peer auth: nil listener")
	}
	if !resolve.complete() {
		return nil, errors.New("ipc: windows peer auth: incomplete resolver set")
	}
	if len(policy.images) == 0 || len(policy.signers) == 0 {
		return nil, errors.New("ipc: windows peer auth: empty policy")
	}
	return &windowsPeerAuthListener{inner: inner, policy: policy, resolve: resolve, logReject: logReject}, nil
}

func (l *windowsPeerAuthListener) Accept() (net.Conn, error) {
	for {
		c, err := l.inner.Accept()
		if err != nil {
			return nil, err
		}
		acceptedAt := l.resolve.now()
		id, reason := l.authenticate(c, acceptedAt)
		if reason != "" {
			if l.logReject != nil {
				l.logReject(id, reason)
			}
			_ = c.Close()
			continue
		}
		return c, nil
	}
}

// authenticate orders the checks cheapest first, so a peer that is not
// even running an allowed executable never costs a WinVerifyTrust.
func (l *windowsPeerAuthListener) authenticate(c net.Conn, acceptedAt time.Time) (windowsPeerIdentity, string) {
	var id windowsPeerIdentity
	pid, err := l.resolve.peerPID(c)
	if err != nil {
		return id, fmt.Sprintf("peer pid unavailable: %v", err)
	}
	id.PID = pid
	// 0 is the idle process and 4 is System; neither is a user-mode
	// Secure Client GUI.
	if pid <= 4 {
		return id, fmt.Sprintf("peer pid %d is not a user process", pid)
	}
	process, err := l.resolve.process(pid)
	if err != nil {
		return id, fmt.Sprintf("peer process lookup failed: %v", err)
	}
	id.SessionID = process.SessionID
	id.ImagePath = process.ImagePath
	if process.CreatedAt.IsZero() {
		return id, "peer process creation time unavailable"
	}
	if process.CreatedAt.After(acceptedAt) {
		return id, "peer process was created after the connection was accepted"
	}
	image, err := l.resolve.openImage(process.ImagePath)
	if err != nil {
		return id, fmt.Sprintf("peer image unavailable: %v", err)
	}
	defer image.Close()
	finalPath := image.FinalPath()
	id.ImagePath = finalPath
	if !l.policy.allowsImage(finalPath) {
		return id, "peer image is not an allowed Secure Client GUI executable"
	}
	signer, err := image.VerifySigner()
	if err != nil {
		return id, fmt.Sprintf("peer image signature rejected: %v", err)
	}
	id.Signer = signer.CommonName
	if reason := l.policy.signerRejection(signer); reason != "" {
		return id, reason
	}
	return id, ""
}

func (l *windowsPeerAuthListener) Close() error   { return l.inner.Close() }
func (l *windowsPeerAuthListener) Addr() net.Addr { return l.inner.Addr() }
