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
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// R108-COWORK-3: the Linux source pins a client image with the rest of the
// exec, through /proc/<pid>/exe, and the event carries its digest once the
// worker has read it, after the process exits and to a gateway that cannot
// read the session's home. A file put over the install path afterwards is
// not read as the image that ran.
func TestLinuxSourceHashesTheRunningClientImage(t *testing.T) {
	useHasher(t, newImageHasher())
	sleep, err := os.ReadFile(testenv.NativeSleep(t))
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(sleep)
	image := filepath.Join(t.TempDir(), ".local/share/claude/versions/2.1.317")
	pid := startImage(t, image, sleep)

	source := &linuxSource{buffer: NewBuffer()}
	first := time.Now()
	source.pushProcess(KindExec, pid, first, false)
	if event := <-source.buffer.Events(); event.ImageSHA256 != "" || event.ImageVersion != "2.1.317" ||
		event.ImageDigestState != DigestPending {
		t.Fatalf("first exec image identity = %q %q %q, want the version and the digest pending",
			event.ImageSHA256, event.ImageVersion, event.ImageDigestState)
	}
	clientImages.idle()
	// cowork-1-0-8 GAP-0067: the digest of that exec follows once it is read.
	if event := <-source.buffer.Events(); event.Kind != KindImageDigest || event.PID != pid || !event.At.Equal(first) ||
		event.ImageVersion != "2.1.317" || event.ImageSHA256 != hex.EncodeToString(want[:]) ||
		event.ImageDigestState != DigestRead {
		t.Fatalf("digest of the first exec = %+v", event)
	}
	source.pushProcess(KindExec, pid, time.Now(), false)
	if event := <-source.buffer.Events(); event.ImageSHA256 != hex.EncodeToString(want[:]) || event.ImageVersion != "2.1.317" ||
		event.ImageDigestState != DigestRead {
		t.Fatalf("exec image identity = %q %q %q", event.ImageSHA256, event.ImageVersion, event.ImageDigestState)
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
	if event := <-source.buffer.Events(); event.Kind != KindImageDigest || event.ImageSHA256 != hex.EncodeToString(want[:]) {
		t.Fatalf("digest of the unlinked image = %+v", event)
	}
	source.pushProcess(KindExec, pid, time.Now(), false)
	if event := <-source.buffer.Events(); event.ImageSHA256 != hex.EncodeToString(want[:]) {
		t.Fatalf("replaced path read as the running image: %q", event.ImageSHA256)
	}

	// An image outside a release layout is not read.
	source.pushProcess(KindExec, startImage(t, filepath.Join(t.TempDir(), "claude"), sleep), time.Now(), false)
	if event := <-source.buffer.Events(); event.ImageSHA256 != "" || event.ImageVersion != "" || event.ImageDigestState != "" {
		t.Fatalf("image outside a release layout = %q %q %q", event.ImageSHA256, event.ImageVersion, event.ImageDigestState)
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
			if event := <-source.buffer.Events(); event.Kind != KindImageDigest {
				t.Fatalf("after the parent image's read = %+v, want its digest", event)
			}

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
	sleep, err := os.ReadFile(testenv.NativeSleep(t))
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
	sleep, err := os.ReadFile(testenv.NativeSleep(t))
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
	if event := <-source.buffer.Events(); event.Kind != KindImageDigest || event.PID != client || event.ImageSHA256 != "slow" {
		t.Fatalf("digest of the delivered exec = %+v", event)
	}
	source.pushProcess(KindExec, client, time.Now(), false)
	if event := <-source.buffer.Events(); event.ImageSHA256 != "slow" {
		t.Fatalf("digest after the read = %q", event.ImageSHA256)
	}
}

// cowork-1-0-8 GAP-0067: an exec event says whether its image digest is in
// it, follows it, or is not coming, so the host plane waits only for one
// that is coming. Every waiter of a queued image hears once how its read
// ended.
func TestImageDigestStates(t *testing.T) {
	hasher := newImageHasher()
	started, release := make(chan struct{}, 8), make(chan struct{})
	hasher.hash = func(*os.File, int64, time.Time) (string, error) {
		started <- struct{}{}
		<-release
		return "sum", nil
	}
	released := false
	defer func() {
		if !released {
			close(release)
		}
		hasher.idle()
	}()
	dir := t.TempDir()
	var mu sync.Mutex
	var heard []string
	follow := func(tag string) func(string, bool) {
		return func(sum string, read bool) {
			mu.Lock()
			defer mu.Unlock()
			heard = append(heard, fmt.Sprintf("%s:%s:%t", tag, sum, read))
		}
	}
	state := func(name, account string, then func(string, bool)) DigestState {
		t.Helper()
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); err != nil {
			if err := os.WriteFile(path, []byte(name), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		key, ok := statImageKey(file)
		if !ok {
			t.Skip("no image key on this volume")
		}
		_, got := hasher.digestOf(file, key, account, then)
		return got
	}
	for _, step := range []struct {
		what, image, account string
		then                 func(string, bool)
		want                 DigestState
	}{
		{"queued now", "a", "uid:1", follow("a1"), DigestPending},
		{"already queued: waits for the same read", "a", "uid:1", follow("a2"), DigestPending},
		{"nobody to deliver a later digest to", "a", "uid:1", nil, DigestFailed},
		{"the account's slot holds another image", "b", "uid:1", follow("b"), DigestFailed},
	} {
		if got := state(step.image, step.account, step.then); got != step.want {
			t.Fatalf("%s: %q, want %q", step.what, got, step.want)
		}
	}
	<-started // the worker reads a; the queue has room for maxClientImageJobs more
	for i := range maxClientImageJobs {
		if got := state(fmt.Sprintf("q%d", i), fmt.Sprintf("uid:%d", 10+i), follow("q")); got != DigestPending {
			t.Fatalf("queue slot %d: %q", i, got)
		}
	}
	if got := state("full", "uid:99", follow("full")); got != DigestFailed {
		t.Fatalf("queue full: %q, want failed", got)
	}
	hasher.mu.Lock()
	waiting := hasher.waiting
	hasher.waiting = maxDigestWaiters
	hasher.mu.Unlock()
	if got := state("a", "uid:1", follow("a3")); got != DigestFailed {
		t.Fatalf("waiters full: %q, want failed", got)
	}
	hasher.mu.Lock()
	hasher.waiting = waiting
	hasher.mu.Unlock()
	close(release)
	released = true
	hasher.idle()
	mu.Lock()
	got := strings.Join(heard, " ")
	mu.Unlock()
	if !strings.HasPrefix(got, "a1:sum:true a2:sum:true ") || strings.Count(got, "q:sum:true") != maxClientImageJobs ||
		strings.Contains(got, "a3") || strings.Contains(got, "full") || strings.Contains(got, "b:") {
		t.Fatalf("waiters heard %q", got)
	}
	if got := state("a", "uid:1", follow("a4")); got != DigestRead {
		t.Fatalf("cached: %q, want read", got)
	}
	hasher.off.Store(true)
	if got := state("c", "uid:2", follow("c")); got != DigestFailed {
		t.Fatalf("hashing off: %q, want failed", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if strings.Contains(strings.Join(heard, " "), "a4") || strings.Contains(strings.Join(heard, " "), "c:") {
		t.Fatalf("a digest that is in or not coming was followed up: %q", heard)
	}
}

// The digest of an exec never goes out before the exec's own event, however
// fast its read ends, and nothing goes out of a closed source.
func TestImageDigestFollowsItsExec(t *testing.T) {
	at := time.Unix(1_760_000_000, 7)
	var pushed []Event
	early := newDigestDelivery(func(event Event) { pushed = append(pushed, event) }, 42, at)
	early.version = "2.1.317"
	early.follow("sum", true)
	if len(pushed) != 0 {
		t.Fatalf("digest pushed before its exec: %+v", pushed)
	}
	early.execSent()
	late := newDigestDelivery(func(event Event) { pushed = append(pushed, event) }, 43, at)
	late.version = "2.1.317"
	late.execSent()
	late.follow("ignored", false)
	if len(pushed) != 2 || pushed[0].Kind != KindImageDigest || pushed[0].PID != 42 || !pushed[0].At.Equal(at) ||
		pushed[0].ImageVersion != "2.1.317" || pushed[0].ImageSHA256 != "sum" || pushed[0].ImageDigestState != DigestRead ||
		pushed[1].PID != 43 || pushed[1].ImageSHA256 != "" || pushed[1].ImageDigestState != DigestFailed {
		t.Fatalf("pushed %+v", pushed)
	}
	closed := &linuxSource{buffer: NewBuffer(), closed: true}
	closed.pushUnlessClosed(Event{Kind: KindImageDigest, PID: 44})
	select {
	case event := <-closed.buffer.Events():
		t.Fatalf("closed source delivered %+v", event)
	default:
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
	var heard []string
	if _, state := hasher.digestOf(file, key, "", func(sum string, read bool) {
		heard = append(heard, fmt.Sprintf("%q %t", sum, read))
	}); state != DigestPending {
		t.Fatalf("state %q, want pending", state)
	}
	hasher.idle()
	if len(hasher.digest) != 0 {
		t.Fatal("a digest of a file written during the read was cached")
	}
	if len(heard) != 1 || heard[0] != `"" false` {
		t.Fatalf("the waiter heard %v, want one failed read", heard)
	}
}

// cowork-1-0-8 GAP-0067: a fork event is flagged, and its digest is never
// followed up (the exec has an event of its own), so it takes no waiter.
func TestForkEventIsFlaggedAndNotFollowedUp(t *testing.T) {
	useHasher(t, newImageHasher())
	sleep, err := os.ReadFile(testenv.NativeSleep(t))
	if err != nil {
		t.Fatal(err)
	}
	pid := startImage(t, filepath.Join(t.TempDir(), ".local/share/claude/versions/2.1.317"), sleep)
	source := &linuxSource{buffer: NewBuffer()}
	source.pushProcess(KindExec, pid, time.Now(), true)
	if event := <-source.buffer.Events(); !event.Fork || event.ImageVersion != "2.1.317" ||
		event.ImageDigestState != DigestFailed {
		t.Fatalf("fork event = %+v, want flagged, the version, no digest coming", event)
	}
	clientImages.idle()
	select {
	case event := <-source.buffer.Events():
		t.Fatalf("a fork was followed up: %+v", event)
	default:
	}
	source.pushProcess(KindExec, pid, time.Now(), false)
	if event := <-source.buffer.Events(); event.Fork || event.ImageDigestState != DigestRead {
		t.Fatalf("exec event = %+v, want unflagged with the digest the fork's read cached", event)
	}
}

// A read that fails tells its waiters so: the host plane records the held
// client at once instead of at the end of its hold.
func TestFailedClientImageReadIsFollowedUp(t *testing.T) {
	hasher := newImageHasher()
	hasher.hash = func(*os.File, int64, time.Time) (string, error) { return "", errImageDeadline }
	path := filepath.Join(t.TempDir(), "image")
	if err := os.WriteFile(path, []byte("release image fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := statImageKey(file)
	var heard []string
	if _, state := hasher.digestOf(file, key, "", func(sum string, read bool) {
		heard = append(heard, fmt.Sprintf("%q %t", sum, read))
	}); state != DigestPending {
		t.Fatalf("state %q, want pending", state)
	}
	hasher.idle()
	if len(heard) != 1 || heard[0] != `"" false` || len(hasher.digest) != 0 || hasher.waiting != 0 {
		t.Fatalf("heard %v, cached %d, waiting %d; want one failed read and nothing left", heard, len(hasher.digest), hasher.waiting)
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

// cowork-1-0-8 GAP-0071: an event the source's own buffer drops after the
// kernel delivered it is named in the coverage, as an ENOBUFS loss is, for
// the native source and for the Tetragon stream (its buffer and its native
// process half's).
func TestBufferDropsAreReportedInCoverage(t *testing.T) {
	fill := func(buffer *Buffer) {
		for index := 0; index <= eventBuffer; index++ {
			buffer.Push(Event{Kind: KindFileRead, PID: index})
		}
	}
	native := &linuxSource{buffer: NewBuffer()}
	if limits := strings.Join(native.Coverage().Limitations, "; "); strings.Contains(limits, "dropped") {
		t.Fatalf("limitations before any drop = %q", limits)
	}
	fill(native.buffer)
	if limits := strings.Join(native.Coverage().Limitations, "; "); !strings.Contains(limits, "1 events were dropped from the sensor's event buffer") {
		t.Fatalf("native limitations = %q, want the buffer drop", limits)
	}
	stream := NewTetragonSource(nil, TetragonOptions{Mode: "consume"}).(*tetragonSource)
	half := &linuxSource{buffer: NewBuffer()}
	files := &linuxSource{buffer: NewBuffer()}
	stream.proc = halfSource{linuxSource: half, cancel: func() {}}
	stream.files = halfSource{linuxSource: files, cancel: func() {}}
	fill(stream.buffer)
	fill(half.buffer)
	fill(files.buffer)
	if limits := strings.Join(stream.Coverage().Limitations, "; "); !strings.Contains(limits, "3 events were dropped from the sensor's event buffer") {
		t.Fatalf("Tetragon limitations = %q, want the stream's, the process half's and the file half's drops", limits)
	}
	// A half that stops keeps its drops: TestTetragonSourceFallsBackInStreamAndRecovers
	// (cn_proc at a Tetragon reconnect) and
	// TestTetragonSourceHandsTheFileHalfOverAndTakesItBack (fanotify at the hand-off).
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
