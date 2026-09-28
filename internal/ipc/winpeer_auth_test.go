// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package ipc

import (
	"errors"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
)

const (
	testProgramFilesX86 = `C:\Program Files (x86)`
	testProgramFiles    = `C:\Program Files`
	testGUIImage        = `C:\Program Files (x86)\Cisco\Cisco Secure Client\UI\csc_ui.exe`
	testCiscoSigner     = "Cisco Systems, Inc."
)

func testWindowsPeerPolicy(t *testing.T) windowsPeerPolicy {
	t.Helper()
	policy, err := newWindowsPeerPolicy(
		[]string{testProgramFilesX86, testProgramFiles},
		[]string{`UI\csc_ui.exe`},
		[]string{testCiscoSigner},
	)
	if err != nil {
		t.Fatalf("newWindowsPeerPolicy: %v", err)
	}
	return policy
}

type fakeWindowsPeerImage struct {
	finalPath string
	signer    windowsImageSigner
	signerErr error

	mu       sync.Mutex
	verified bool
	closed   bool
}

func (f *fakeWindowsPeerImage) FinalPath() string { return f.finalPath }

func (f *fakeWindowsPeerImage) VerifySigner() (windowsImageSigner, error) {
	f.mu.Lock()
	f.verified = true
	f.mu.Unlock()
	return f.signer, f.signerErr
}

func (f *fakeWindowsPeerImage) Close() error {
	f.mu.Lock()
	f.closed = true
	f.mu.Unlock()
	return nil
}

type fakeWindowsPeer struct {
	pid        uint32
	pidErr     error
	process    windowsPeerProcess
	processErr error
	image      *fakeWindowsPeerImage
	imageErr   error
}

var testAcceptedAt = time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)

func genuineWindowsPeer() *fakeWindowsPeer {
	return &fakeWindowsPeer{
		pid: 4242,
		process: windowsPeerProcess{
			ImagePath: `\Device\HarddiskVolume3\Program Files (x86)\Cisco\Cisco Secure Client\UI\csc_ui.exe`,
			SessionID: 1,
			CreatedAt: testAcceptedAt.Add(-time.Hour),
		},
		image: &fakeWindowsPeerImage{
			finalPath: testGUIImage,
			signer: windowsImageSigner{
				CommonName:    testCiscoSigner,
				Organizations: []string{testCiscoSigner},
			},
		},
	}
}

func (f *fakeWindowsPeer) resolvers() windowsPeerResolvers {
	return windowsPeerResolvers{
		peerPID: func(net.Conn) (uint32, error) { return f.pid, f.pidErr },
		process: func(pid uint32) (windowsPeerProcess, error) {
			if pid != f.pid {
				return windowsPeerProcess{}, errors.New("unexpected pid")
			}
			return f.process, f.processErr
		},
		openImage: func(string) (windowsPeerImage, error) {
			if f.imageErr != nil {
				return nil, f.imageErr
			}
			return f.image, nil
		},
		now: func() time.Time { return testAcceptedAt },
	}
}

func authenticateFake(t *testing.T, peer *fakeWindowsPeer) (windowsPeerIdentity, string) {
	t.Helper()
	listener, err := newWindowsPeerAuthListener(stubListener{}, testWindowsPeerPolicy(t), peer.resolvers(), nil)
	if err != nil {
		t.Fatalf("newWindowsPeerAuthListener: %v", err)
	}
	return listener.authenticate(nil, testAcceptedAt)
}

type stubListener struct{}

func (stubListener) Accept() (net.Conn, error) { return nil, errors.New("stub") }
func (stubListener) Close() error              { return nil }
func (stubListener) Addr() net.Addr            { return &net.UnixAddr{Name: "stub", Net: "unix"} }

func TestWindowsPeerAuthAdmitsGenuineSecureClientGUI(t *testing.T) {
	peer := genuineWindowsPeer()
	id, reason := authenticateFake(t, peer)
	if reason != "" {
		t.Fatalf("genuine Secure Client GUI rejected: %s", reason)
	}
	if id.PID != 4242 || id.SessionID != 1 || id.ImagePath != testGUIImage || id.Signer != testCiscoSigner {
		t.Fatalf("identity = %+v", id)
	}
	if !peer.image.verified || !peer.image.closed {
		t.Fatalf("image verified=%v closed=%v, want both", peer.image.verified, peer.image.closed)
	}
}

func TestWindowsPeerAuthAdmitsGUIFromEitherProgramFilesRootCaseInsensitively(t *testing.T) {
	for _, path := range []string{
		`C:\Program Files\Cisco\Cisco Secure Client\UI\csc_ui.exe`,
		`c:\program files (x86)\cisco\cisco secure client\ui\CSC_UI.EXE`,
	} {
		peer := genuineWindowsPeer()
		peer.image.finalPath = path
		if _, reason := authenticateFake(t, peer); reason != "" {
			t.Errorf("%s rejected: %s", path, reason)
		}
	}
}

// TestWindowsPeerAuthRejectsUnauthenticatedPeers covers the peers the
// Windows IPC used to accept: any process of any authenticated user.
func TestWindowsPeerAuthRejectsUnauthenticatedPeers(t *testing.T) {
	cases := []struct {
		name       string
		mutate     func(*fakeWindowsPeer)
		wantReason string
		wantVerify bool
	}{
		{
			name:       "peer pid unavailable",
			mutate:     func(p *fakeWindowsPeer) { p.pidErr = errors.New("ioctl failed") },
			wantReason: "peer pid unavailable",
		},
		{
			name:       "system pid",
			mutate:     func(p *fakeWindowsPeer) { p.pid = 4 },
			wantReason: "not a user process",
		},
		{
			name:       "process lookup failure",
			mutate:     func(p *fakeWindowsPeer) { p.processErr = errors.New("gone") },
			wantReason: "peer process lookup failed",
		},
		{
			name:       "missing creation time",
			mutate:     func(p *fakeWindowsPeer) { p.process.CreatedAt = time.Time{} },
			wantReason: "creation time unavailable",
		},
		{
			name: "process created after accept (reused pid)",
			mutate: func(p *fakeWindowsPeer) {
				p.process.CreatedAt = testAcceptedAt.Add(time.Millisecond)
			},
			wantReason: "created after the connection was accepted",
		},
		{
			name:       "image cannot be opened",
			mutate:     func(p *fakeWindowsPeer) { p.imageErr = errors.New("sharing violation") },
			wantReason: "peer image unavailable",
		},
		{
			name: "arbitrary user tool",
			mutate: func(p *fakeWindowsPeer) {
				p.image.finalPath = `C:\Users\alice\Downloads\tool.exe`
			},
			wantReason: "not an allowed Secure Client GUI executable",
		},
		{
			name: "genuine GUI copied outside Program Files",
			mutate: func(p *fakeWindowsPeer) {
				p.image.finalPath = `C:\Users\alice\AppData\Local\Temp\UI\csc_ui.exe`
			},
			wantReason: "not an allowed Secure Client GUI executable",
		},
		{
			name: "other Cisco binary in the Secure Client tree",
			mutate: func(p *fakeWindowsPeer) {
				p.image.finalPath = `C:\Program Files (x86)\Cisco\Cisco Secure Client\vpnagent.exe`
			},
			wantReason: "not an allowed Secure Client GUI executable",
		},
		{
			name: "GUI name in a sibling directory",
			mutate: func(p *fakeWindowsPeer) {
				p.image.finalPath = `C:\Program Files (x86)\Cisco\Cisco Secure Client\DefenseClaw\UI\csc_ui.exe`
			},
			wantReason: "not an allowed Secure Client GUI executable",
		},
		{
			name: "GUI path under another drive",
			mutate: func(p *fakeWindowsPeer) {
				p.image.finalPath = `D:\Program Files (x86)\Cisco\Cisco Secure Client\UI\csc_ui.exe`
			},
			wantReason: "not an allowed Secure Client GUI executable",
		},
		{
			name: "non-canonical final path",
			mutate: func(p *fakeWindowsPeer) {
				p.image.finalPath = `C:\Program Files (x86)\Cisco\Cisco Secure Client\UI\..\UI\csc_ui.exe`
			},
			wantReason: "not an allowed Secure Client GUI executable",
		},
		{
			name: "unsigned image at the GUI path",
			mutate: func(p *fakeWindowsPeer) {
				p.image.signerErr = errors.New("TRUST_E_NOSIGNATURE")
			},
			wantReason: "signature rejected",
			wantVerify: true,
		},
		{
			name: "trusted non-Cisco signer",
			mutate: func(p *fakeWindowsPeer) {
				p.image.signer = windowsImageSigner{CommonName: "Contoso Ltd", Organizations: []string{"Contoso Ltd"}}
			},
			wantReason: `signer "Contoso Ltd" is not allowed`,
			wantVerify: true,
		},
		{
			name: "Cisco common name with another organization",
			mutate: func(p *fakeWindowsPeer) {
				p.image.signer.Organizations = []string{"Contoso Ltd"}
			},
			wantReason: `organization "Contoso Ltd" is not allowed`,
			wantVerify: true,
		},
		{
			name: "signer without common name",
			mutate: func(p *fakeWindowsPeer) {
				p.image.signer = windowsImageSigner{Organizations: []string{testCiscoSigner}}
			},
			wantReason: "no subject common name",
			wantVerify: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			peer := genuineWindowsPeer()
			tc.mutate(peer)
			_, reason := authenticateFake(t, peer)
			if reason == "" {
				t.Fatal("peer admitted, want rejection")
			}
			if !strings.Contains(reason, tc.wantReason) {
				t.Fatalf("reason = %q, want substring %q", reason, tc.wantReason)
			}
			if peer.image.verified != tc.wantVerify {
				t.Fatalf("WinVerifyTrust ran = %v, want %v (path checks must run first)", peer.image.verified, tc.wantVerify)
			}
			if peer.imageErr == nil && peer.processErr == nil && peer.pidErr == nil &&
				peer.pid > 4 && !peer.process.CreatedAt.IsZero() &&
				!peer.process.CreatedAt.After(testAcceptedAt) && !peer.image.closed {
				t.Fatal("opened image was not closed")
			}
		})
	}
}

// TestWindowsPeerAuthListenerClosesRejectedConnections drives Accept
// end to end: a rejected peer is closed before any byte is served and
// logged, and the next, genuine peer is returned.
func TestWindowsPeerAuthListenerClosesRejectedConnections(t *testing.T) {
	rejectedServer, rejectedClient := net.Pipe()
	acceptedServer, acceptedClient := net.Pipe()
	defer rejectedClient.Close()
	defer acceptedClient.Close()
	inner := &queueListener{conns: []net.Conn{rejectedServer, acceptedServer}}

	genuine := genuineWindowsPeer()
	imposterImage := &fakeWindowsPeerImage{finalPath: `C:\Users\mallory\gui.exe`}
	resolvers := genuine.resolvers()
	resolvers.peerPID = func(c net.Conn) (uint32, error) {
		if c == rejectedServer {
			return 5150, nil
		}
		return genuine.pid, nil
	}
	resolvers.process = func(pid uint32) (windowsPeerProcess, error) {
		if pid == 5150 {
			return windowsPeerProcess{ImagePath: `C:\Users\mallory\gui.exe`, SessionID: 2, CreatedAt: testAcceptedAt.Add(-time.Minute)}, nil
		}
		return genuine.process, nil
	}
	resolvers.openImage = func(path string) (windowsPeerImage, error) {
		if strings.Contains(path, "mallory") {
			return imposterImage, nil
		}
		return genuine.image, nil
	}

	var rejected []windowsPeerIdentity
	listener, err := newWindowsPeerAuthListener(inner, testWindowsPeerPolicy(t), resolvers,
		func(id windowsPeerIdentity, reason string) {
			if !strings.Contains(reason, "not an allowed Secure Client GUI executable") {
				t.Errorf("reject reason = %q", reason)
			}
			rejected = append(rejected, id)
		})
	if err != nil {
		t.Fatal(err)
	}
	got, err := listener.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if got != acceptedServer {
		t.Fatal("Accept returned the rejected connection")
	}
	if len(rejected) != 1 || rejected[0].PID != 5150 || rejected[0].SessionID != 2 {
		t.Fatalf("rejected = %+v", rejected)
	}
	if imposterImage.verified {
		t.Fatal("imposter image reached WinVerifyTrust")
	}
	_ = rejectedClient.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := rejectedClient.Read(make([]byte, 1)); err == nil {
		t.Fatal("rejected connection is still open")
	}
}

type queueListener struct {
	mu    sync.Mutex
	conns []net.Conn
}

func (q *queueListener) Accept() (net.Conn, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.conns) == 0 {
		return nil, net.ErrClosed
	}
	c := q.conns[0]
	q.conns = q.conns[1:]
	return c, nil
}
func (q *queueListener) Close() error   { return nil }
func (q *queueListener) Addr() net.Addr { return &net.UnixAddr{Name: "queue", Net: "unix"} }

func TestNewWindowsPeerPolicyFailsClosed(t *testing.T) {
	roots := []string{testProgramFilesX86}
	images := []string{`UI\csc_ui.exe`}
	signers := []string{testCiscoSigner}
	cases := map[string]struct {
		roots, images, signers []string
	}{
		"no roots":              {nil, images, signers},
		"no images":             {roots, nil, signers},
		"no signers":            {roots, images, nil},
		"relative root":         {[]string{`Program Files (x86)`}, images, signers},
		"unc root":              {[]string{`\\server\share`}, images, signers},
		"traversing image":      {roots, []string{`..\..\Users\Public\gui.exe`}, signers},
		"absolute image":        {roots, []string{`C:\Users\Public\gui.exe`}, signers},
		"forward-slash image":   {roots, []string{`UI/csc_ui.exe`}, signers},
		"padded signer":         {roots, images, []string{" Cisco Systems, Inc."}},
		"empty signer in list":  {roots, images, []string{testCiscoSigner, ""}},
		"empty image in list":   {roots, []string{`UI\csc_ui.exe`, ""}, signers},
		"stream-suffixed image": {roots, []string{`UI\csc_ui.exe:evil`}, signers},
	}
	for name, tc := range cases {
		if _, err := newWindowsPeerPolicy(tc.roots, tc.images, tc.signers); err == nil {
			t.Errorf("%s: newWindowsPeerPolicy accepted an unsafe policy", name)
		}
	}
	if _, err := newWindowsPeerAuthListener(stubListener{}, windowsPeerPolicy{}, genuineWindowsPeer().resolvers(), nil); err == nil {
		t.Error("listener accepted an empty policy")
	}
	incomplete := genuineWindowsPeer().resolvers()
	incomplete.openImage = nil
	if _, err := newWindowsPeerAuthListener(stubListener{}, testWindowsPeerPolicy(t), incomplete, nil); err == nil {
		t.Error("listener accepted an incomplete resolver set")
	}
}

func TestNewWindowsPeerPolicyJoinsRootsAndImages(t *testing.T) {
	policy, err := newWindowsPeerPolicy(
		[]string{testProgramFilesX86, testProgramFiles, `C:\Program Files (x86)\`},
		[]string{`UI\csc_ui.exe`, `UI\CSC_UI.EXE`},
		[]string{testCiscoSigner},
	)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		testGUIImage,
		`C:\Program Files\Cisco\Cisco Secure Client\UI\csc_ui.exe`,
	}
	if strings.Join(policy.images, "|") != strings.Join(want, "|") {
		t.Fatalf("images = %q, want %q", policy.images, want)
	}
}

func TestIsCanonicalWindowsDrivePath(t *testing.T) {
	for _, path := range []string{`C:\`, `C:\Program Files (x86)\Cisco\UI\csc_ui.exe`, `z:\a b\c.exe`} {
		if !isCanonicalWindowsDrivePath(path) {
			t.Errorf("isCanonicalWindowsDrivePath(%q) = false", path)
		}
	}
	for _, path := range []string{
		``, `C:`, `C:relative`, `\\?\C:\x.exe`, `\\server\share\x.exe`, `\Device\HarddiskVolume3\x.exe`,
		`C:/Program Files/x.exe`, `C:\a\..\x.exe`, `C:\a\.\x.exe`, `C:\a\\x.exe`, `C:\x.exe:ads`,
		`C:\x.exe.`, `C:\dir \x.exe`, `1:\x.exe`, "C:\\x\x00.exe",
	} {
		if isCanonicalWindowsDrivePath(path) {
			t.Errorf("isCanonicalWindowsDrivePath(%q) = true", path)
		}
	}
}

func TestCodesignStateLabelReportsWindowsEnforcement(t *testing.T) {
	for _, requireFlags := range []bool{true, false} {
		if got := codesignStateLabel("windows", requireFlags, requireFlags, 0); got != codesignStateEnabled {
			t.Fatalf("windows label = %q, want %q", got, codesignStateEnabled)
		}
	}
}

func TestPeerAuthPolicyLogFieldsKeepsUnixFormatAndReportsWindowsPolicy(t *testing.T) {
	s := &Server{
		allowedTeamIDs:         []string{"T"},
		allowedSigningIDs:      []string{"S"},
		allowedBundleIDs:       []string{"B"},
		requireUnixPeer:        true,
		requireSigningMetadata: true,
		allowedWindowsSigners:  []string{testCiscoSigner},
		allowedWindowsImages:   []string{`UI\csc_ui.exe`},
	}
	want := "team_ids=[T] signing_ids=[S] bundle_ids=[B] require_unix_peer=true require_signing_metadata=true"
	if got := s.peerAuthPolicyLogFields("darwin"); got != want {
		t.Fatalf("darwin fields = %q, want %q", got, want)
	}
	got := s.peerAuthPolicyLogFields("windows")
	for _, fragment := range []string{
		`windows_signers=["Cisco Systems, Inc."]`,
		`windows_images=["UI\\csc_ui.exe"]`,
		"require_unix_peer=true",
		"require_signing_metadata=true",
	} {
		if !strings.Contains(got, fragment) {
			t.Fatalf("windows fields = %q, missing %q", got, fragment)
		}
	}
}

func TestNewServerSeedsWindowsPeerPolicy(t *testing.T) {
	// NewServer only keeps the store for later RPCs; a zero value
	// avoids the platform-specific storage ACL checks.
	store := &audit.Store{}
	newServer := func(managedIPC config.ManagedIPCConfig, mode string) *Server {
		t.Helper()
		managedIPC.SocketPath = filepath.Join(t.TempDir(), "ipc", SocketFileName)
		srv, err := NewServer(ServerOptions{
			Config: &config.Config{DataDir: t.TempDir(), DeploymentMode: mode, Managed: managedIPC},
			Health: gateway.NewSidecarHealth(),
			Store:  store,
			Logf:   func(string, ...any) {},
		})
		if err != nil {
			t.Fatalf("NewServer: %v", err)
		}
		return srv
	}
	for _, mode := range []string{"managed_enterprise", ""} {
		srv := newServer(config.ManagedIPCConfig{}, mode)
		if len(srv.allowedWindowsSigners) != 1 || srv.allowedWindowsSigners[0] != config.SecureClientWindowsSigner {
			t.Fatalf("mode %q: signers = %q", mode, srv.allowedWindowsSigners)
		}
		if len(srv.allowedWindowsImages) != 1 || srv.allowedWindowsImages[0] != config.SecureClientWindowsGUIImage {
			t.Fatalf("mode %q: images = %q", mode, srv.allowedWindowsImages)
		}
	}
	srv := newServer(config.ManagedIPCConfig{
		AllowedWindowsSigners: []string{"Cisco Systems, Inc."},
		AllowedWindowsImages:  []string{`UI\csc_ui_next.exe`},
	}, "managed_enterprise")
	if len(srv.allowedWindowsImages) != 1 || srv.allowedWindowsImages[0] != `UI\csc_ui_next.exe` {
		t.Fatalf("override images = %q", srv.allowedWindowsImages)
	}
}
