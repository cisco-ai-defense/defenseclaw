// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package plane

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// R108-COWORK-3: the Linux source pins a client image with the rest of the
// exec, through /proc/<pid>/exe, and the event carries its digest once the
// worker has read it, after the process exits and to a gateway that cannot
// read the session's home. A file put over the install path afterwards is
// not read as the image that ran.
func TestLinuxSourceHashesTheRunningClientImage(t *testing.T) {
	useHasher(t, newImageHasher())
	sleep, err := os.ReadFile("/bin/sleep")
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(sleep)
	image := filepath.Join(t.TempDir(), ".local/share/claude/versions/2.1.317")
	pid := startImage(t, image, sleep)

	source := &linuxSource{buffer: NewBuffer()}
	source.pushProcess(KindExec, pid, time.Now(), false)
	if event := <-source.buffer.Events(); event.ImageSHA256 != "" || event.ImageVersion != "2.1.317" {
		t.Fatalf("first exec image identity = %q %q, want the version and no digest yet", event.ImageSHA256, event.ImageVersion)
	}
	clientImages.idle()
	source.pushProcess(KindExec, pid, time.Now(), false)
	if event := <-source.buffer.Events(); event.ImageSHA256 != hex.EncodeToString(want[:]) || event.ImageVersion != "2.1.317" {
		t.Fatalf("exec image identity = %q %q", event.ImageSHA256, event.ImageVersion)
	}

	if err := os.Remove(image); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(image, []byte("replacement"), 0o700); err != nil {
		t.Fatal(err)
	}
	// /proc/<pid>/exe still names the running (unlinked) image; the unlink
	// changed its key, so it is read once more, and never the replacement.
	source.pushProcess(KindExec, pid, time.Now(), false)
	<-source.buffer.Events()
	clientImages.idle()
	source.pushProcess(KindExec, pid, time.Now(), false)
	if event := <-source.buffer.Events(); event.ImageSHA256 != hex.EncodeToString(want[:]) {
		t.Fatalf("replaced path read as the running image: %q", event.ImageSHA256)
	}

	// An image outside a release layout is not read.
	source.pushProcess(KindExec, startImage(t, filepath.Join(t.TempDir(), "claude"), sleep), time.Now(), false)
	if event := <-source.buffer.Events(); event.ImageSHA256 != "" || event.ImageVersion != "" {
		t.Fatalf("image outside a release layout = %q %q", event.ImageSHA256, event.ImageVersion)
	}
}

// cowork-1-0-8 VERIFY-rows-3-8: a fork is delivered as an exec that still
// carries its parent's command line; when it execs while it is read, the
// command line and the image must not be paired across the two programs. The
// child here execs between the image pin and the command-line read, and
// between that read and the re-check.
func TestForkThatExecsMidReadIsNotPairedWithItsParentImage(t *testing.T) {
	for _, stage := range []string{"pinned", "described"} {
		t.Run(stage, func(t *testing.T) {
			useHasher(t, newImageHasher())
			shell, err := os.ReadFile("/bin/sh")
			if err != nil {
				t.Fatal(err)
			}
			image := filepath.Join(t.TempDir(), ".local/share/claude/versions/2.1.317")
			if err := os.MkdirAll(filepath.Dir(image), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(image, shell, 0o700); err != nil {
				t.Fatal(err)
			}
			var stdin io.WriteCloser
			process := startWrittenImage(t, func() *exec.Cmd {
				process := exec.Command(image, "-c", "read line; exec /bin/sleep 30", "@modelcontextprotocol/server-filesystem")
				if stdin, err = process.StdinPipe(); err != nil {
					t.Fatal(err)
				}
				return process
			})
			t.Cleanup(func() {
				_ = process.Process.Kill()
				_ = process.Wait()
			})
			pid := process.Process.Pid
			source := &linuxSource{buffer: NewBuffer()}
			// The parent image's digest is cached, so a mispairing would
			// carry it.
			source.pushProcess(KindExec, pid, time.Now(), false)
			<-source.buffer.Events()
			clientImages.idle()

			fired := false
			procSnapshotHook = func(at string) {
				if at != stage || fired {
					return
				}
				fired = true
				_, _ = stdin.Write([]byte("go\n"))
				for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
					if path, _, _ := procImage(pid); path != image {
						return
					}
				}
				t.Error("the child did not exec")
			}
			t.Cleanup(func() { procSnapshotHook = nil })
			source.pushProcess(KindExec, pid, time.Now(), false)
			event := <-source.buffer.Events()
			if !fired || event.ImageSHA256 != "" || event.ImageVersion != "" ||
				strings.Contains(event.Cmdline, "modelcontextprotocol") || !strings.Contains(event.Cmdline, "sleep 30") {
				t.Fatalf("exec read across a child exec = %+v", event)
			}
		})
	}
}

// cowork-1-0-8 VERIFY-row3-r2: a fork of the client that runs a quick tool
// command and exits while it is read carries the client's command line but
// can no longer be identified; that copy is not classified (its parent's
// exec carries the same command line, with the identity). An exec event of a
// layout image that exits mid-read is that program's own and keeps its
// command line, unidentified (REVIEW-4), and so does any other process.
func TestClientForkThatExitsMidReadKeepsNoCommandLine(t *testing.T) {
	useHasher(t, newImageHasher())
	shell, err := os.ReadFile("/bin/sh")
	if err != nil {
		t.Fatal(err)
	}
	image := filepath.Join(t.TempDir(), ".local/share/claude/versions/2.1.317")
	if err := os.MkdirAll(filepath.Dir(image), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(image, shell, 0o700); err != nil {
		t.Fatal(err)
	}
	run := func(path string, fromFork bool) Event {
		t.Helper()
		process := startWrittenImage(t, func() *exec.Cmd {
			process := exec.Command(path, "-c", "sleep 30; :", "@modelcontextprotocol/server-filesystem")
			// Its own process group, so the shell's sleep child is killed with it.
			process.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			return process
		})
		killGroup := func() {
			_ = syscall.Kill(-process.Process.Pid, syscall.SIGKILL)
			_ = process.Wait()
		}
		t.Cleanup(killGroup)
		pid := process.Process.Pid
		for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
			if raw, _ := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cmdline")); len(raw) > 0 {
				break
			}
		}
		procSnapshotHook = func(at string) {
			if at == "described" {
				killGroup()
			}
		}
		defer func() { procSnapshotHook = nil }()
		source := &linuxSource{buffer: NewBuffer()}
		source.pushProcess(KindExec, pid, time.Now(), fromFork)
		event := <-source.buffer.Events()
		if event.PID != pid || event.PPID != os.Getpid() || event.ImageVersion != "" || event.ImageSHA256 != "" {
			t.Fatalf("vanished process = %+v, want its lineage facts and no identity", event)
		}
		return event
	}
	if event := run(image, true); event.Cmdline != "" {
		t.Fatalf("vanished client fork kept the client's command line: %q", event.Cmdline)
	}
	if event := run(image, false); !strings.Contains(event.Cmdline, "@modelcontextprotocol/server-filesystem") {
		t.Fatalf("vanished layout exec lost its own command line: %q", event.Cmdline)
	}
	other := filepath.Join(t.TempDir(), "tool")
	if err := os.WriteFile(other, shell, 0o700); err != nil {
		t.Fatal(err)
	}
	if event := run(other, true); !strings.Contains(event.Cmdline, "@modelcontextprotocol/server-filesystem") {
		t.Fatalf("vanished non-layout process lost its command line: %q", event.Cmdline)
	}
}

// Installed client images under the watched homes are hashed before their
// first exec, so that exec (and its first fork) is already identified.
func TestInstalledClientImagesArePrewarmed(t *testing.T) {
	useHasher(t, newImageHasher())
	sleep, err := os.ReadFile("/bin/sleep")
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	image := filepath.Join(home, ".local/share/claude/versions/2.1.317")
	if err := os.MkdirAll(filepath.Dir(image), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(image, sleep, 0o700); err != nil {
		t.Fatal(err)
	}
	prewarmClientImages([]string{filepath.Dir(home) + "/*"})
	clientImages.idle()
	want := sha256.Sum256(sleep)
	source := &linuxSource{buffer: NewBuffer()}
	process := startWrittenImage(t, func() *exec.Cmd { return exec.Command(image, "30") })
	t.Cleanup(func() {
		_ = process.Process.Kill()
		_ = process.Wait()
	})
	source.pushProcess(KindExec, process.Process.Pid, time.Now(), false)
	if event := <-source.buffer.Events(); event.ImageSHA256 != hex.EncodeToString(want[:]) {
		t.Fatalf("first exec of a prewarmed image = %q", event.ImageSHA256)
	}
}

// R108-COWORK-3 review 1: a slow image read never holds up the cn_proc
// reader: the exec is delivered at once, and so is the next one.
func TestSlowClientImageReadDoesNotStopExecDelivery(t *testing.T) {
	hasher := newImageHasher()
	release := make(chan struct{})
	hasher.hash = func(*os.File, int64, time.Time) (string, error) {
		<-release
		return "slow", nil
	}
	useHasher(t, hasher)
	sleep, err := os.ReadFile("/bin/sleep")
	if err != nil {
		t.Fatal(err)
	}
	client := startImage(t, filepath.Join(t.TempDir(), ".local/share/claude/versions/2.1.317"), sleep)
	other := startImage(t, filepath.Join(t.TempDir(), "tool"), sleep)
	source := &linuxSource{buffer: NewBuffer()}
	done := make(chan struct{})
	go func() {
		source.pushProcess(KindExec, client, time.Now(), false)
		source.pushProcess(KindExec, other, time.Now(), false)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("exec delivery waited on the image read")
	}
	for _, pid := range []int{client, other} {
		if event := <-source.buffer.Events(); event.PID != pid || event.ImageSHA256 != "" {
			t.Fatalf("delivered %+v, want pid %d without a digest", event, pid)
		}
	}
	close(release)
	hasher.idle()
	source.pushProcess(KindExec, client, time.Now(), false)
	if event := <-source.buffer.Events(); event.ImageSHA256 != "slow" {
		t.Fatalf("digest after the read = %q", event.ImageSHA256)
	}
}

// A digest is cached only when the file is unchanged after it was read.
func TestClientImageDigestIsDroppedWhenTheFileChangesDuringTheRead(t *testing.T) {
	hasher := newImageHasher()
	path := filepath.Join(t.TempDir(), "image")
	if err := os.WriteFile(path, []byte("release image fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	hasher.hash = func(file *os.File, size int64, deadline time.Time) (string, error) {
		if err := os.WriteFile(path, []byte("written during the read"), 0o600); err != nil {
			t.Error(err)
		}
		return hashImage(file, size, deadline)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := statImageKey(file)
	hasher.digestOf(file, key, "")
	hasher.idle()
	if len(hasher.digest) != 0 {
		t.Fatal("a digest of a file written during the read was cached")
	}
}

// R108-COWORK-3 review 1: an overflowed cn_proc socket (ENOBUFS) is loss to
// count and report; the reader keeps reading.
func TestProcessConnectorOverflowIsReportedNotTheEnd(t *testing.T) {
	message := make([]byte, nlMsgHdrLen+cnMsgHdrLen+procEventHdr+8)
	binary.LittleEndian.PutUint32(message[0:], uint32(len(message)))
	binary.LittleEndian.PutUint16(message[4:], unix.NLMSG_DONE)
	body := message[nlMsgHdrLen+cnMsgHdrLen:]
	binary.LittleEndian.PutUint32(body[0:], procEventExec)
	binary.LittleEndian.PutUint32(body[procEventHdr:], 4242)
	reads := []error{unix.ENOBUFS, nil, unix.EBADF}
	source := &linuxSource{buffer: NewBuffer(), procFD: 99}
	source.recv = func(_ int, buffer []byte) (int, error) {
		err := reads[0]
		reads = reads[1:]
		if err != nil {
			return 0, err
		}
		return copy(buffer, message), nil
	}
	source.readProcessConnector(context.Background())
	select {
	case event := <-source.buffer.Events():
		if event.Kind != KindExec || event.PID != 4242 {
			t.Fatalf("decoded %+v after the overflow", event)
		}
	default:
		t.Fatal("the reader stopped at the overflow")
	}
	if got := source.procOverflows.Load(); got != 1 {
		t.Fatalf("overflows = %d, want 1", got)
	}
	if limits := strings.Join(source.Coverage().Limitations, "; "); !strings.Contains(limits, "ENOBUFS") {
		t.Fatalf("coverage limitations = %q, want the overflow", limits)
	}
}

func TestClaudeImageVersionFromInstallLayout(t *testing.T) {
	root := t.TempDir()
	npm := filepath.Join(root, "lib/node_modules/@anthropic-ai/claude-code")
	if err := os.MkdirAll(filepath.Join(npm, "bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(npm, "package.json"), []byte(`{"name":"@anthropic-ai/claude-code","version":"2.1.317"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]string{
		"/sessions/cwk-v1/.local/share/claude/versions/2.1.317": "2.1.317",
		"/opt/homebrew/Caskroom/claude-code/2.1.317/claude":     "2.1.317",
		filepath.Join(npm, "bin/claude.exe"):                    "2.1.317",
		"/opt/tools/2.1.317":                                    "",
		"/sessions/cwk-v1/.local/share/claude/versions/latest":  "",
		"/usr/local/bin/claude":                                 "",
		"relative/claude/versions/2.1.317":                      "",
	} {
		if got := claudeImageVersion(path); got != want {
			t.Errorf("claudeImageVersion(%q) = %q, want %q", path, got, want)
		}
	}
}

// REVIEW-2: prewarm reads a bounded number of entries per home, follows no
// link below the home, and opens nothing while digests are off.
func TestPrewarmIsBoundedAndFollowsNoLinks(t *testing.T) {
	useHasher(t, newImageHasher())
	homes := t.TempDir()
	makeVersions := func(home string, count int) string {
		versions := filepath.Join(homes, home, ".local/share/claude/versions")
		if err := os.MkdirAll(versions, 0o700); err != nil {
			t.Fatal(err)
		}
		for i := range count {
			if err := os.WriteFile(filepath.Join(versions, fmt.Sprintf("1.0.%d", i)), []byte("image"), 0o700); err != nil {
				t.Fatal(err)
			}
		}
		return versions
	}
	many := makeVersions("many", maxPrewarmEntries+8)
	if err := os.Symlink(filepath.Join(many, "1.0.0"), filepath.Join(many, "9.9.9")); err != nil {
		t.Fatal(err)
	}
	if got := prewarmClientImages([]string{filepath.Join(homes, "many")}); got > maxPrewarmEntries || got == 0 {
		t.Fatalf("opened %d images in one cycle, want 1..%d", got, maxPrewarmEntries)
	}
	if err := os.MkdirAll(filepath.Join(homes, "linked-local"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(homes, "many", ".local"), filepath.Join(homes, "linked-local", ".local")); err != nil {
		t.Fatal(err)
	}
	versions := filepath.Join(homes, "linked-versions", ".local/share/claude")
	if err := os.MkdirAll(versions, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(many, filepath.Join(versions, "versions")); err != nil {
		t.Fatal(err)
	}
	only := makeVersions("link-entry", 0)
	if err := os.Symlink(filepath.Join(many, "1.0.0"), filepath.Join(only, "2.1.317")); err != nil {
		t.Fatal(err)
	}
	for _, home := range []string{"linked-local", "linked-versions", "link-entry"} {
		if got := prewarmClientImages([]string{filepath.Join(homes, home)}); got != 0 {
			t.Errorf("%s: opened %d images through a link", home, got)
		}
	}
	clientImages.off.Store(true)
	if got := prewarmClientImages([]string{filepath.Join(homes, "many")}); got != 0 {
		t.Fatalf("opened %d images with digests off", got)
	}
}

func useHasher(t *testing.T, hasher *imageHasher) {
	t.Helper()
	previous := clientImages
	clientImages = hasher
	t.Cleanup(func() { clientImages = previous })
}

func startImage(t *testing.T, path string, data []byte) int {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o700); err != nil {
		t.Fatal(err)
	}
	process := startWrittenImage(t, func() *exec.Cmd { return exec.Command(path, "30") })
	t.Cleanup(func() {
		_ = process.Process.Kill()
		_ = process.Wait()
	})
	return process.Process.Pid
}

// startWrittenImage starts the command newCmd builds for an image the test
// has just written. A fork in a parallel test that lands while the write
// descriptor of the image is open keeps a copy of it until that child execs,
// and an exec of the image fails with ETXTBSY meanwhile (golang/go#22315).
// The image bytes are final once written, so a fresh command for the same
// image starts the same program; any other error still fails the test.
func startWrittenImage(t *testing.T, newCmd func() *exec.Cmd) *exec.Cmd {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		process := newCmd()
		err := process.Start()
		if err == nil {
			return process
		}
		if !errors.Is(err, syscall.ETXTBSY) || time.Now().After(deadline) {
			t.Fatal(err)
		}
	}
}
