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
//
// Admission authenticates the executable, not the interactive user.
// Every admitted Secure Client GUI instance receives the same
// machine-wide health, stats and notification stream, as on macOS.
// Scoping records to one session would need the originating session on
// block events, which the gateway does not record today.

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
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
	// CreatedAt is the process creation time. The production resolver
	// reads it before and after the image lookup and refuses a PID
	// whose creation time changed in between; a zero value means that
	// bracket did not run.
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
	peerPID func(net.Conn) (uint32, error)
	process func(pid uint32) (windowsPeerProcess, error)
	// openImage opens one of the policy's allowed drive paths. It is
	// never called with a path reported by, or chosen by, the peer.
	openImage func(drivePath string) (windowsPeerImage, error)
}

func (r windowsPeerResolvers) complete() bool {
	return r.peerPID != nil && r.process != nil && r.openImage != nil
}

// windowsPeerAllowedImage is one executable the policy admits, in the
// two forms the listener compares: the drive-letter path the opened
// file must resolve to, and the NT device path the kernel records as a
// process image name.
type windowsPeerAllowedImage struct {
	drivePath  string
	kernelPath string
}

// windowsPeerPolicy is the resolved admission policy: the exact
// executables that may connect and the signers they must carry.
type windowsPeerPolicy struct {
	images  []windowsPeerAllowedImage
	signers map[string]struct{}
}

// newWindowsPeerPolicy joins every install-relative image with every
// trusted Program Files root. Roots must be absolute drive paths from
// protected machine registration, never the process environment.
// driveDevice maps a drive ("C:") to the NT device it names in the
// service's DOS device namespace, so each allowed executable also has
// the kernel form a process image name is compared against. Any empty
// input or malformed entry is an error: an empty policy would admit
// nothing, and silently starting a server nobody can reach hides a
// misconfiguration.
func newWindowsPeerPolicy(programFilesRoots, relativeImages, signers []string, driveDevice func(drive string) (string, error)) (windowsPeerPolicy, error) {
	var policy windowsPeerPolicy
	if driveDevice == nil {
		return policy, errors.New("ipc: windows peer auth: no drive device resolver")
	}
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
	devices := make(map[string]string)
	for _, root := range programFilesRoots {
		root = strings.TrimRight(root, `\`)
		if !isCanonicalWindowsDrivePath(root) {
			return windowsPeerPolicy{}, fmt.Errorf("ipc: windows peer auth: Program Files root %q is not a canonical drive path", root)
		}
		drive := strings.ToUpper(root[:2])
		device, ok := devices[drive]
		if !ok {
			resolved, err := driveDevice(drive)
			if err != nil {
				return windowsPeerPolicy{}, fmt.Errorf("ipc: windows peer auth: resolve device of %s: %w", drive, err)
			}
			if !isLocalNTDeviceName(resolved) {
				return windowsPeerPolicy{}, fmt.Errorf("ipc: windows peer auth: drive %s maps to %q, not a local NT device", drive, resolved)
			}
			device = resolved
			devices[drive] = device
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
			policy.images = append(policy.images, windowsPeerAllowedImage{
				drivePath:  full,
				kernelPath: device + full[2:],
			})
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
		if strings.EqualFold(finalPath, image.drivePath) {
			return true
		}
	}
	return false
}

// matchKernelImage returns the allowed drive path whose NT form is
// exactly kernelPath (case-insensitively), or false. It is a string
// comparison only: nothing is opened for a process whose image name
// is not already one of the allowed executables.
func (p windowsPeerPolicy) matchKernelImage(kernelPath string) (string, bool) {
	for _, image := range p.images {
		if strings.EqualFold(kernelPath, image.kernelPath) {
			return image.drivePath, true
		}
	}
	return "", false
}

// isLocalNTDeviceName accepts a single-segment NT device name such as
// `\Device\HarddiskVolume3`. Redirector mappings (which carry the
// share after the device name) and \??\ substitutions are refused, so
// the kernel form of an allowed path always names a local volume.
func isLocalNTDeviceName(device string) bool {
	name, ok := strings.CutPrefix(device, `\Device\`)
	if !ok || name == "" {
		return false
	}
	if strings.ContainsAny(name, `\/:*?"<>|`) {
		return false
	}
	if strings.IndexFunc(name, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		return false
	}
	switch strings.ToLower(name) {
	case "mup", "lanmanredirector", "webdavredirector", "rdpdr":
		return false
	}
	return true
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

// Bounds on the accept-time check. Each accepted connection is
// authenticated in its own goroutine, so one slow check cannot stop the
// listener from admitting other peers or from closing.
const (
	// windowsPeerAuthTimeout is how long one peer check may take before
	// its connection is closed. A local image lookup and WinVerifyTrust
	// on the GUI executable finish in well under a second.
	windowsPeerAuthTimeout = 10 * time.Second
	// windowsPeerAuthMaxPending caps concurrent peer checks. When every
	// slot is busy the listener stops pulling connections off the
	// socket backlog until one finishes.
	windowsPeerAuthMaxPending = 8
)

// windowsPeerAuthListener admits a connection only when the process on
// the other end is an allowed, Authenticode-verified Secure Client GUI
// executable. Every other peer is closed before gRPC reads a byte, so
// no health, stats, or notification data reaches it.
type windowsPeerAuthListener struct {
	inner     net.Listener
	policy    windowsPeerPolicy
	resolve   windowsPeerResolvers
	logReject func(windowsPeerIdentity, string)
	timeout   time.Duration

	start     sync.Once
	slots     chan struct{}
	admitted  chan net.Conn
	transient chan error
	closed    chan struct{}
	closeOnce sync.Once
	// loopDone is closed when the accept loop stops; loopErr, written
	// before the close, is the error that stopped it.
	loopDone chan struct{}
	loopErr  error
}

func newWindowsPeerAuthListener(
	inner net.Listener,
	policy windowsPeerPolicy,
	resolve windowsPeerResolvers,
	logReject func(windowsPeerIdentity, string),
) (*windowsPeerAuthListener, error) {
	return newWindowsPeerAuthListenerWithLimits(inner, policy, resolve, logReject,
		windowsPeerAuthTimeout, windowsPeerAuthMaxPending)
}

func newWindowsPeerAuthListenerWithLimits(
	inner net.Listener,
	policy windowsPeerPolicy,
	resolve windowsPeerResolvers,
	logReject func(windowsPeerIdentity, string),
	timeout time.Duration,
	maxPending int,
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
	if timeout <= 0 || maxPending <= 0 {
		return nil, errors.New("ipc: windows peer auth: invalid check limits")
	}
	return &windowsPeerAuthListener{
		inner:     inner,
		policy:    policy,
		resolve:   resolve,
		logReject: logReject,
		timeout:   timeout,
		slots:     make(chan struct{}, maxPending),
		admitted:  make(chan net.Conn),
		transient: make(chan error),
		closed:    make(chan struct{}),
		loopDone:  make(chan struct{}),
	}, nil
}

// Accept returns the next authenticated connection. The accept loop
// starts on the first call.
func (l *windowsPeerAuthListener) Accept() (net.Conn, error) {
	l.start.Do(func() { go l.acceptLoop() })
	select {
	case c := <-l.admitted:
		return c, nil
	case err := <-l.transient:
		return nil, err
	case <-l.closed:
		return nil, net.ErrClosed
	case <-l.loopDone:
		return nil, l.loopErr
	}
}

func (l *windowsPeerAuthListener) acceptLoop() {
	err := l.runAcceptLoop()
	l.loopErr = err
	close(l.loopDone)
}

func (l *windowsPeerAuthListener) runAcceptLoop() error {
	for {
		c, err := l.inner.Accept()
		if err != nil {
			select {
			case <-l.closed:
				return net.ErrClosed
			default:
			}
			// Hand transient errors to the caller, which backs off
			// (grpc.Server does), and keep accepting.
			var temporary interface{ Temporary() bool }
			if errors.As(err, &temporary) && temporary.Temporary() {
				select {
				case l.transient <- err:
					continue
				case <-l.closed:
					return net.ErrClosed
				}
			}
			return err
		}
		select {
		case l.slots <- struct{}{}:
		case <-l.closed:
			_ = c.Close()
			return net.ErrClosed
		}
		go l.admit(c)
	}
}

// admit authenticates one connection and hands it to Accept, or closes
// it. The slot is released only when the check itself returns, so the
// number of in-flight checks stays bounded even after a timeout.
func (l *windowsPeerAuthListener) admit(c net.Conn) {
	defer func() { <-l.slots }()
	var decided atomic.Bool
	timer := time.AfterFunc(l.timeout, func() {
		if decided.CompareAndSwap(false, true) {
			l.reject(windowsPeerIdentity{}, fmt.Sprintf("peer authentication did not finish within %s", l.timeout))
			_ = c.Close()
		}
	})
	id, reason := l.authenticate(c)
	timer.Stop()
	if !decided.CompareAndSwap(false, true) {
		// Timed out: the connection is already closed and logged.
		return
	}
	if reason != "" {
		l.reject(id, reason)
		_ = c.Close()
		return
	}
	select {
	case l.admitted <- c:
	case <-l.closed:
		_ = c.Close()
	}
}

func (l *windowsPeerAuthListener) reject(id windowsPeerIdentity, reason string) {
	if l.logReject != nil {
		l.logReject(id, reason)
	}
}

// authenticate runs the checks in order. The process image name the
// kernel reports must already equal an allowed executable, by string
// comparison, before anything is opened; the file that is then opened
// is the policy's own path, never one supplied by the peer.
func (l *windowsPeerAuthListener) authenticate(c net.Conn) (windowsPeerIdentity, string) {
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
	drivePath, ok := l.policy.matchKernelImage(process.ImagePath)
	if !ok {
		return id, "peer image is not an allowed Secure Client GUI executable"
	}
	image, err := l.resolve.openImage(drivePath)
	if err != nil {
		return id, fmt.Sprintf("peer image unavailable: %v", err)
	}
	defer image.Close()
	finalPath := image.FinalPath()
	id.ImagePath = finalPath
	if !l.policy.allowsImage(finalPath) || !strings.EqualFold(finalPath, drivePath) {
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

// Close stops accepting. Checks still in flight finish on their own
// and close their connections; Close does not wait for them.
func (l *windowsPeerAuthListener) Close() error {
	err := net.ErrClosed
	l.closeOnce.Do(func() {
		close(l.closed)
		err = l.inner.Close()
	})
	return err
}

func (l *windowsPeerAuthListener) Addr() net.Addr { return l.inner.Addr() }
