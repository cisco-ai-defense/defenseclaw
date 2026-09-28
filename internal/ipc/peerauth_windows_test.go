// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package ipc

import (
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/defenseclaw/defenseclaw/internal/gateway"
	pb "github.com/defenseclaw/defenseclaw/proto/defenseclaw/secureclient/v1"
)

const peerAuthHelperSocketEnv = "DEFENSECLAW_IPC_PEERAUTH_HELPER_SOCKET"

func TestWindowsPeerAuthSyscallConstants(t *testing.T) {
	if sioAFUnixGetPeerPID != 0x58000100 {
		t.Fatalf("SIO_AF_UNIX_GETPEERPID = %#x, want 0x58000100", sioAFUnixGetPeerPID)
	}
	if windows.SystemProcessIdInformation != 0x58 {
		t.Fatalf("SystemProcessIdInformation = %#x, want 0x58", windows.SystemProcessIdInformation)
	}
}

// shortSocketDir keeps AF_UNIX paths under the 108-byte sun_path limit.
func shortSocketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp(os.TempDir(), "dcpa")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func listenTestUnix(t *testing.T) (net.Listener, string) {
	t.Helper()
	path := filepath.Join(shortSocketDir(t), "p.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Skipf("AF_UNIX unavailable: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener, path
}

func TestAFUnixPeerPIDReportsConnectingProcess(t *testing.T) {
	listener, path := listenTestUnix(t)
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := listener.Accept()
		if err == nil {
			accepted <- c
		}
		close(accepted)
	}()
	client, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := <-accepted
	if server == nil {
		t.Fatal("accept failed")
	}
	defer server.Close()
	pid, err := afUnixPeerPID(server)
	if err != nil {
		t.Fatalf("afUnixPeerPID: %v", err)
	}
	if pid != uint32(os.Getpid()) {
		t.Fatalf("peer pid = %d, want %d", pid, os.Getpid())
	}
	if _, err := afUnixPeerPID(&net.TCPConn{}); err == nil {
		t.Fatal("afUnixPeerPID accepted a non-AF_UNIX connection")
	}
}

func selfExecutable(t *testing.T) string {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := filepath.EvalSymlinks(executable)
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}

func TestQueryWindowsPeerProcessResolvesImageWithoutProcessHandle(t *testing.T) {
	process, err := queryWindowsPeerProcess(uint32(os.Getpid()))
	if err != nil {
		t.Fatalf("queryWindowsPeerProcess: %v", err)
	}
	if !strings.HasPrefix(process.ImagePath, `\Device\`) {
		t.Fatalf("image path = %q, want an NT device path", process.ImagePath)
	}
	if process.CreatedAt.IsZero() || process.CreatedAt.After(time.Now()) {
		t.Fatalf("creation time = %v", process.CreatedAt)
	}
	var session uint32
	if err := windows.ProcessIdToSessionId(uint32(os.Getpid()), &session); err == nil && session != process.SessionID {
		t.Fatalf("session = %d, want %d", process.SessionID, session)
	}
	image, err := openWindowsPeerImage(process.ImagePath)
	if err != nil {
		t.Fatalf("openWindowsPeerImage: %v", err)
	}
	defer image.Close()
	if want := selfExecutable(t); !strings.EqualFold(image.FinalPath(), want) {
		t.Fatalf("final path = %q, want %q", image.FinalPath(), want)
	}
	if _, err := queryWindowsPeerProcess(0xfffffff0); err == nil {
		t.Fatal("queryWindowsPeerProcess accepted a pid that is not running")
	}
}

func TestOpenWindowsPeerImageDeniesWritersWhileHeld(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gui.exe")
	if err := os.WriteFile(path, []byte("MZ not a real image"), 0o600); err != nil {
		t.Fatal(err)
	}
	image, err := openWindowsPeerImage(path)
	if err != nil {
		t.Fatalf("openWindowsPeerImage: %v", err)
	}
	defer image.Close()
	if writer, err := os.OpenFile(path, os.O_WRONLY, 0); err == nil {
		_ = writer.Close()
		t.Fatal("held peer image allowed a concurrent writer")
	}
	if err := os.Rename(path, path+".moved"); err == nil {
		t.Fatal("held peer image allowed a rename")
	}
	if _, err := image.VerifySigner(); err == nil {
		t.Fatal("VerifySigner accepted an unsigned file")
	}
}

func TestOpenWindowsPeerImageRejectsDirectoriesAndRelativePaths(t *testing.T) {
	if _, err := openWindowsPeerImage(t.TempDir()); err == nil {
		t.Fatal("openWindowsPeerImage accepted a directory")
	}
	for _, path := range []string{"", `relative\gui.exe`, `\\server\share\gui.exe`, "C:\\gui\x00.exe"} {
		if _, err := openWindowsPeerImage(path); err == nil {
			t.Errorf("openWindowsPeerImage(%q) succeeded", path)
		}
	}
}

func TestVerifySignerRejectsUnsignedGoBinary(t *testing.T) {
	image, err := openWindowsPeerImage(selfExecutable(t))
	if err != nil {
		t.Fatalf("openWindowsPeerImage: %v", err)
	}
	defer image.Close()
	if signer, err := image.VerifySigner(); err == nil {
		t.Fatalf("unsigned test binary verified as %+v", signer)
	}
}

// TestVerifySignerExtractsLeafOfSignedBinary exercises the WinTrust
// provider-data walk on an embedded-signed executable, and checks that
// a trusted signer other than Cisco is still refused by the policy.
func TestVerifySignerExtractsLeafOfSignedBinary(t *testing.T) {
	candidates := []string{
		filepath.Join(os.Getenv("ProgramFiles"), "PowerShell", "7", "pwsh.exe"),
		filepath.Join(os.Getenv("ProgramFiles(x86)"), "Microsoft", "Edge", "Application", "msedge.exe"),
		filepath.Join(os.Getenv("ProgramFiles"), "Git", "cmd", "git.exe"),
		filepath.Join(os.Getenv("ProgramFiles"), "Go", "bin", "go.exe"),
	}
	for _, candidate := range candidates {
		resolved, err := filepath.EvalSymlinks(candidate)
		if err != nil {
			continue
		}
		image, err := openWindowsPeerImage(resolved)
		if err != nil {
			continue
		}
		signer, err := image.VerifySigner()
		_ = image.Close()
		if err != nil {
			continue
		}
		if signer.CommonName == "" || len(signer.ThumbprintSHA256) != 64 {
			t.Fatalf("%s: signer = %+v", resolved, signer)
		}
		policy := testWindowsPeerPolicy(t)
		if signer.CommonName != testCiscoSigner && policy.signerRejection(signer) == "" {
			t.Fatalf("%s: policy admitted non-Cisco signer %q", resolved, signer.CommonName)
		}
		allowOwn, err := newWindowsPeerPolicy([]string{testProgramFiles}, []string{`UI\csc_ui.exe`},
			append([]string{signer.CommonName}, signer.Organizations...))
		if err != nil {
			t.Fatal(err)
		}
		if reason := allowOwn.signerRejection(signer); reason != "" {
			t.Fatalf("%s: policy naming the signer still rejected it: %s", resolved, reason)
		}
		t.Logf("%s signed by %q %q", resolved, signer.CommonName, signer.Organizations)
		return
	}
	t.Skip("no embedded-signed executable available on this host")
}

type recordedReject struct {
	id     windowsPeerIdentity
	reason string
}

type rejectRecorder struct {
	mu      sync.Mutex
	rejects []recordedReject
}

func (r *rejectRecorder) log(id windowsPeerIdentity, reason string) {
	r.mu.Lock()
	r.rejects = append(r.rejects, recordedReject{id, reason})
	r.mu.Unlock()
}

func (r *rejectRecorder) snapshot() []recordedReject {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]recordedReject(nil), r.rejects...)
}

// serveSecureClientAPI serves the real gRPC service on a peer-auth
// listener built with the production resolvers.
func serveSecureClientAPI(t *testing.T, inner net.Listener, policy windowsPeerPolicy, recorder *rejectRecorder) {
	t.Helper()
	listener, err := newWindowsPeerAuthListener(inner, policy, productionWindowsPeerResolvers(), recorder.log)
	if err != nil {
		t.Fatal(err)
	}
	health := gateway.NewSidecarHealth()
	health.SetGateway(gateway.StateRunning, "", nil)
	server := grpc.NewServer()
	pb.RegisterDefenseClawSecureClientServiceServer(server, &service{
		health:     health,
		bcast:      newBroadcast(),
		version:    "peerauth-test",
		nowFn:      time.Now,
		statsPoll:  time.Second,
		healthWait: 10 * time.Millisecond,
	})
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
}

// fetchHealth dials the socket and reads one GetHealth snapshot.
func fetchHealth(socketPath string) (*pb.HealthSnapshot, error) {
	conn, err := grpc.NewClient("passthrough:///defenseclaw-ipc",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "unix", socketPath)
		}))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := pb.NewDefenseClawSecureClientServiceClient(conn).GetHealth(ctx, &pb.GetHealthRequest{})
	if err != nil {
		return nil, err
	}
	return stream.Recv()
}

// TestWindowsPeerAuthHelperProcess is the client half of
// TestWindowsSecureClientListenerRejectsUnsignedClient; it only runs
// when re-executed by that test.
func TestWindowsPeerAuthHelperProcess(t *testing.T) {
	socketPath := os.Getenv(peerAuthHelperSocketEnv)
	if socketPath == "" {
		t.Skip("helper process only")
	}
	snapshot, err := fetchHealth(socketPath)
	if err != nil {
		_, _ = io.WriteString(os.Stdout, "HELPER-REJECTED "+err.Error()+"\n")
		return
	}
	_, _ = io.WriteString(os.Stdout, "HELPER-RECEIVED "+snapshot.GetAvailability().String()+"\n")
}

// TestWindowsSecureClientListenerRejectsSameUserTool is the regression
// for the unauthenticated posture: an ordinary process of the logged-on
// user connects to the socket and receives nothing.
func TestWindowsSecureClientListenerRejectsSameUserTool(t *testing.T) {
	inner, socketPath := listenTestUnix(t)
	recorder := &rejectRecorder{}
	serveSecureClientAPI(t, inner, testWindowsPeerPolicy(t), recorder)

	if snapshot, err := fetchHealth(socketPath); err == nil {
		t.Fatalf("unauthenticated client received health snapshot %v", snapshot)
	}
	rejects := recorder.snapshot()
	if len(rejects) == 0 {
		t.Fatal("no rejection recorded")
	}
	first := rejects[0]
	if first.id.PID != uint32(os.Getpid()) {
		t.Fatalf("rejected pid = %d, want %d", first.id.PID, os.Getpid())
	}
	if !strings.EqualFold(first.id.ImagePath, selfExecutable(t)) {
		t.Fatalf("rejected image = %q, want %q", first.id.ImagePath, selfExecutable(t))
	}
	if !strings.Contains(first.reason, "not an allowed Secure Client GUI executable") {
		t.Fatalf("reason = %q", first.reason)
	}
}

// TestWindowsSecureClientListenerRejectsUnsignedClient places an
// unsigned binary at the Secure Client GUI path inside a scratch
// Program Files root and runs it as the client. The path matches, so
// the rejection comes from the Authenticode check.
func TestWindowsSecureClientListenerRejectsUnsignedClient(t *testing.T) {
	if os.Getenv(peerAuthHelperSocketEnv) != "" {
		t.Skip("running as helper")
	}
	root := shortSocketDir(t)
	guiDir := filepath.Join(root, "Cisco", "Cisco Secure Client", "UI")
	if err := os.MkdirAll(guiDir, 0o700); err != nil {
		t.Fatal(err)
	}
	gui := filepath.Join(guiDir, "csc_ui.exe")
	source, err := os.ReadFile(selfExecutable(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(gui, source, 0o700); err != nil {
		t.Fatal(err)
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := newWindowsPeerPolicy([]string{resolvedRoot}, []string{`UI\csc_ui.exe`}, []string{testCiscoSigner})
	if err != nil {
		t.Fatal(err)
	}

	inner, socketPath := listenTestUnix(t)
	recorder := &rejectRecorder{}
	serveSecureClientAPI(t, inner, policy, recorder)

	command := exec.Command(gui, "-test.run=^TestWindowsPeerAuthHelperProcess$", "-test.count=1")
	command.Env = append(os.Environ(), peerAuthHelperSocketEnv+"="+socketPath)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("helper failed: %v\n%s", err, output)
	}
	if strings.Contains(string(output), "HELPER-RECEIVED") || !strings.Contains(string(output), "HELPER-REJECTED") {
		t.Fatalf("unsigned client at the GUI path was not refused:\n%s", output)
	}
	rejects := recorder.snapshot()
	if len(rejects) == 0 {
		t.Fatal("no rejection recorded")
	}
	first := rejects[0]
	if first.id.PID == uint32(os.Getpid()) || first.id.PID == 0 {
		t.Fatalf("rejected pid = %d, want the helper's pid", first.id.PID)
	}
	if !strings.EqualFold(first.id.ImagePath, filepath.Join(resolvedRoot, "Cisco", "Cisco Secure Client", "UI", "csc_ui.exe")) {
		t.Fatalf("rejected image = %q", first.id.ImagePath)
	}
	if !strings.Contains(first.reason, "signature rejected") {
		t.Fatalf("reason = %q, want an Authenticode rejection", first.reason)
	}
}
