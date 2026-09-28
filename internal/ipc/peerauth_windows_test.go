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
	"github.com/defenseclaw/defenseclaw/internal/winpath"
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

// selfKernelImagePath is the NT form of this test binary's path, built
// the same way the admission policy builds its kernel paths.
func selfKernelImagePath(t *testing.T) string {
	t.Helper()
	self := selfExecutable(t)
	device, err := dosDeviceForDrive(strings.ToUpper(self[:2]))
	if err != nil {
		t.Fatalf("dosDeviceForDrive: %v", err)
	}
	return device + self[2:]
}

func TestQueryWindowsPeerProcessResolvesImageWithoutProcessHandle(t *testing.T) {
	process, err := queryWindowsPeerProcess(uint32(os.Getpid()))
	if err != nil {
		t.Fatalf("queryWindowsPeerProcess: %v", err)
	}
	if !strings.HasPrefix(process.ImagePath, `\Device\`) {
		t.Fatalf("image path = %q, want an NT device path", process.ImagePath)
	}
	// The kernel image name must equal the policy-style NT form of the
	// executable's drive path, or the string pre-check would refuse a
	// genuine GUI.
	if want := selfKernelImagePath(t); !strings.EqualFold(process.ImagePath, want) {
		t.Fatalf("image path = %q, want %q", process.ImagePath, want)
	}
	if process.CreatedAt.IsZero() || process.CreatedAt.After(time.Now()) {
		t.Fatalf("creation time = %v", process.CreatedAt)
	}
	var session uint32
	if err := windows.ProcessIdToSessionId(uint32(os.Getpid()), &session); err == nil && session != process.SessionID {
		t.Fatalf("session = %d, want %d", process.SessionID, session)
	}
	image, err := openWindowsPeerImage(selfExecutable(t))
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

func TestDOSDeviceForDriveMapsSystemDrive(t *testing.T) {
	systemDrive := strings.ToUpper(os.Getenv("SystemDrive"))
	if len(systemDrive) != 2 {
		t.Skipf("SystemDrive = %q", systemDrive)
	}
	device, err := dosDeviceForDrive(systemDrive)
	if err != nil {
		t.Fatalf("dosDeviceForDrive(%s): %v", systemDrive, err)
	}
	if !isLocalNTDeviceName(device) {
		t.Fatalf("system drive maps to %q, want a local NT device", device)
	}
	for _, drive := range []string{"", "C", `C:\`, "CC"} {
		if got, err := dosDeviceForDrive(drive); err == nil {
			t.Errorf("dosDeviceForDrive(%q) = %q, want an error", drive, got)
		}
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
	for _, path := range []string{
		"", `relative\gui.exe`, `\\server\share\gui.exe`, "C:\\gui\x00.exe",
		`\Device\Mup\server\share\gui.exe`, `\Device\HarddiskVolume1\gui.exe`,
		`\\?\GLOBALROOT\Device\Mup\server\share\gui.exe`, `\\?\C:\gui.exe`,
	} {
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

// embeddedSignedExecutable returns an executable on this host whose
// embedded Authenticode signature WinVerifyTrust accepts, and the
// signer it validated.
func embeddedSignedExecutable(t *testing.T) (string, windowsImageSigner, bool) {
	t.Helper()
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
		return resolved, signer, true
	}
	return "", windowsImageSigner{}, false
}

// TestVerifySignerExtractsLeafOfSignedBinary exercises the WinTrust
// provider-data walk on an embedded-signed executable, and checks that
// a trusted signer other than Cisco is still refused by the policy.
func TestVerifySignerExtractsLeafOfSignedBinary(t *testing.T) {
	resolved, signer, ok := embeddedSignedExecutable(t)
	if !ok {
		t.Skip("no embedded-signed executable available on this host")
	}
	if signer.CommonName == "" || len(signer.ThumbprintSHA256) != 64 {
		t.Fatalf("%s: signer = %+v", resolved, signer)
	}
	policy := testWindowsPeerPolicy(t)
	if signer.CommonName != testCiscoSigner && policy.signerRejection(signer) == "" {
		t.Fatalf("%s: policy admitted non-Cisco signer %q", resolved, signer.CommonName)
	}
	allowOwn, err := newWindowsPeerPolicy([]string{testProgramFiles}, []string{`UI\csc_ui.exe`},
		append([]string{signer.CommonName}, signer.Organizations...), testDriveDevice)
	if err != nil {
		t.Fatal(err)
	}
	if reason := allowOwn.signerRejection(signer); reason != "" {
		t.Fatalf("%s: policy naming the signer still rejected it: %s", resolved, reason)
	}
	t.Logf("%s signed by %q %q", resolved, signer.CommonName, signer.Organizations)
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
	// Refused on the kernel image name, before anything was opened.
	if want := selfKernelImagePath(t); !strings.EqualFold(first.id.ImagePath, want) {
		t.Fatalf("rejected image = %q, want %q", first.id.ImagePath, want)
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
	// Resolve the scratch root to its long, canonical form first and
	// launch the client from there, so the kernel records the same
	// image name the policy expects.
	resolvedRoot, err := filepath.EvalSymlinks(shortSocketDir(t))
	if err != nil {
		t.Fatal(err)
	}
	guiDir := filepath.Join(resolvedRoot, "Cisco", "Cisco Secure Client", "UI")
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
	policy, err := newWindowsPeerPolicy([]string{resolvedRoot}, []string{`UI\csc_ui.exe`}, []string{testCiscoSigner}, dosDeviceForDrive)
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

func copyTestFile(t *testing.T, source, destination string) {
	t.Helper()
	data, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, data, 0o700); err != nil {
		t.Fatal(err)
	}
}

// TestWindowsSecureClientListenerRejectsLookAlikeRoot is the live
// regression for the look-alike image path. The policy root holds a
// correctly signed executable at the GUI path, standing in for the
// genuine GUI. The client is this unsigned test binary at the same
// relative path under a sibling directory whose name differs by one
// U+017F (LATIN SMALL LETTER LONG S). Unicode folding equates the two
// directory names and NTFS does not. The client must be refused on its
// image name, before the gateway opens and verifies the signed file.
func TestWindowsSecureClientListenerRejectsLookAlikeRoot(t *testing.T) {
	if os.Getenv(peerAuthHelperSocketEnv) != "" {
		t.Skip("running as helper")
	}
	signed, signer, ok := embeddedSignedExecutable(t)
	if !ok {
		t.Skip("no embedded-signed executable available on this host")
	}
	scratch, err := filepath.EvalSymlinks(shortSocketDir(t))
	if err != nil {
		t.Fatal(err)
	}
	genuineRoot := filepath.Join(scratch, "Files")
	lookAlikeRoot := filepath.Join(scratch, "File\u017f")
	relative := filepath.Join("Cisco", "Cisco Secure Client", "UI", "csc_ui.exe")
	copyTestFile(t, signed, filepath.Join(genuineRoot, relative))
	lookAlikeGUI := filepath.Join(lookAlikeRoot, relative)
	copyTestFile(t, selfExecutable(t), lookAlikeGUI)
	genuineInfo, err := os.Stat(genuineRoot)
	if err != nil {
		t.Fatal(err)
	}
	lookAlikeInfo, err := os.Stat(lookAlikeRoot)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(genuineInfo, lookAlikeInfo) {
		t.Skip("this volume folds U+017F, so the look-alike directory is the same directory")
	}
	if !strings.EqualFold(genuineRoot, lookAlikeRoot) {
		t.Fatal("premise: Unicode folding no longer equates the two roots")
	}

	policy, err := newWindowsPeerPolicy([]string{genuineRoot}, []string{`UI\csc_ui.exe`},
		append([]string{signer.CommonName}, signer.Organizations...), dosDeviceForDrive)
	if err != nil {
		t.Fatal(err)
	}
	// Premise: the signed stand-in passes every check that runs after
	// the image-name match, so only that match can refuse the client.
	image, err := openWindowsPeerImage(filepath.Join(genuineRoot, relative))
	if err != nil {
		t.Fatal(err)
	}
	stand, err := image.VerifySigner()
	finalPath := image.FinalPath()
	_ = image.Close()
	if err != nil || policy.signerRejection(stand) != "" || !policy.allowsImage(finalPath) {
		t.Fatalf("premise: signed stand-in %s not accepted (signer %+v, err %v)", finalPath, stand, err)
	}

	inner, socketPath := listenTestUnix(t)
	recorder := &rejectRecorder{}
	serveSecureClientAPI(t, inner, policy, recorder)

	command := exec.Command(lookAlikeGUI, "-test.run=^TestWindowsPeerAuthHelperProcess$", "-test.count=1")
	command.Env = append(os.Environ(), peerAuthHelperSocketEnv+"="+socketPath)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("helper failed: %v\n%s", err, output)
	}
	if strings.Contains(string(output), "HELPER-RECEIVED") || !strings.Contains(string(output), "HELPER-REJECTED") {
		t.Fatalf("client under the look-alike root was not refused:\n%s", output)
	}
	rejects := recorder.snapshot()
	if len(rejects) == 0 {
		t.Fatal("no rejection recorded")
	}
	first := rejects[0]
	if first.id.PID == uint32(os.Getpid()) || first.id.PID == 0 {
		t.Fatalf("rejected pid = %d, want the helper's pid", first.id.PID)
	}
	if !strings.Contains(first.reason, "not an allowed Secure Client GUI executable") {
		t.Fatalf("reason = %q, want an image-name rejection", first.reason)
	}
	// Refused on the kernel image name: the reported path is still the
	// look-alike NT path, not a file the gateway opened.
	if !strings.HasPrefix(first.id.ImagePath, `\Device\`) || !strings.Contains(first.id.ImagePath, "File\u017f") {
		t.Fatalf("rejected image = %q, want the look-alike NT path", first.id.ImagePath)
	}
}

// TestValidateWindowsSocketPathRefusesLookAlikeTrustedRoot checks the
// socket-path anchor with the same comparison: an ASCII case variant of
// the trusted managed IPC directory is accepted, and a Unicode-fold
// look-alike of it is refused.
func TestValidateWindowsSocketPathRefusesLookAlikeTrustedRoot(t *testing.T) {
	if allowUnsafeSocketOverrideForTest {
		t.Fatal("socket override test hook is set")
	}
	programFiles, err := winpath.TrustedProgramFiles()
	if err != nil || programFiles == "" {
		t.Skipf("trusted Program Files root unavailable: %v", err)
	}
	trustedParent := filepath.Clean(filepath.Join(programFiles, windowsManagedIPCRelativeDir))
	if filepath.Base(trustedParent) != "ipc" {
		t.Fatalf("trusted parent %q does not end in ipc", trustedParent)
	}
	prefix := filepath.Dir(trustedParent)
	for _, parent := range []string{trustedParent, filepath.Join(strings.ToUpper(prefix), "ipc"), filepath.Join(strings.ToLower(prefix), "ipc")} {
		if err := validateWindowsSocketPathOverride(filepath.Join(parent, SocketFileName)); err != nil {
			t.Errorf("%s: %v", parent, err)
		}
	}
	variants := unicodeFoldVariants(t, prefix)
	if len(variants) == 0 {
		t.Fatalf("no fold variants of %q", prefix)
	}
	for _, variant := range variants {
		if err := validateWindowsSocketPathOverride(filepath.Join(variant, "ipc", SocketFileName)); err == nil {
			t.Errorf("look-alike parent %q accepted", variant)
		}
	}
}
