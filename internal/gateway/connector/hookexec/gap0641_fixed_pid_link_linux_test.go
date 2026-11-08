package hookexec

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestGAP0641FixedPIDProcCWDOrdinaryNoAnswer(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux proc path")
	}
	root := t.TempDir()
	home := filepath.Join(root, "home")
	protected := filepath.Join(home, ".defenseclaw", "cache", "entry")
	project := filepath.Join(root, "project")
	runner := filepath.Join(root, "runner", "child")
	for _, dir := range []string{filepath.Dir(protected), project, runner} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(protected, []byte("protected"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "runner", "status"), []byte("ordinary"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(protected, filepath.Join(project, "status")); err != nil {
		t.Fatal(err)
	}
	pidPath := fmt.Sprintf("/proc/%d/cwd", os.Getpid())
	if err := os.Symlink(pidPath, filepath.Join(project, "jump")); err != nil {
		t.Fatal(err)
	}
	t.Chdir(runner)
	for _, path := range []string{pidPath + "/../status", filepath.Join(project, "jump") + "/../status"} {
		data, err := exec.Command("cat", path).Output()
		if err != nil || string(data) != "ordinary" {
			t.Fatalf("child read %q = %q, %v", path, data, err)
		}
		if !ordinaryNoAnswerPayloadInHome(gap0641Payload(runner, "cat "+path), home) {
			t.Errorf("ordinary shell %q was classified protected", path)
		}
		readPayload := fmt.Sprintf("{\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Read\",\"cwd\":%q,\"tool_input\":{\"file_path\":%q}}", runner, path)
		if !ordinaryNoAnswerPayloadInHome([]byte(readPayload), home) {
			t.Errorf("ordinary Read %q was classified protected", path)
		}
	}
	if ordinaryNoAnswerPayloadInHome(gap0641Payload(runner, "cat "+filepath.Join(project, "status")), home) {
		t.Error("direct protected link was classified ordinary")
	}
}

func TestGAP0641FixedPIDProcFDOrdinaryNoAnswer(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux proc path")
	}
	root := t.TempDir()
	home := filepath.Join(root, "home")
	protected := filepath.Join(home, ".defenseclaw", "cache", "entry")
	project := filepath.Join(root, "project")
	ordinaryDir := filepath.Join(root, "ordinary", "child")
	for _, dir := range []string{filepath.Dir(protected), project, ordinaryDir} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(protected, []byte("protected"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "ordinary", "status"), []byte("ordinary"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ordinaryDir, "status"), []byte("ordinary"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(protected, filepath.Join(project, "status")); err != nil {
		t.Fatal(err)
	}
	dir, err := os.Open(ordinaryDir)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	fdPath := fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), dir.Fd())
	if err := os.Symlink(fdPath, filepath.Join(project, "jump")); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{fdPath + "/status", fdPath + "/../status", filepath.Join(project, "jump") + "/../status"} {
		data, err := exec.Command("cat", path).Output()
		if err != nil || string(data) != "ordinary" {
			t.Fatalf("child read %q = %q, %v", path, data, err)
		}
		if !ordinaryNoAnswerPayloadInHome(gap0641Payload(project, "cat "+path), home) {
			t.Errorf("ordinary shell %q was classified protected", path)
		}
		readPayload := fmt.Sprintf("{\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Read\",\"cwd\":%q,\"tool_input\":{\"file_path\":%q}}", project, path)
		if !ordinaryNoAnswerPayloadInHome([]byte(readPayload), home) {
			t.Errorf("ordinary Read %q was classified protected", path)
		}
	}
	if ordinaryNoAnswerPayloadInHome(gap0641Payload(project, "cat "+filepath.Join(project, "status")), home) {
		t.Error("direct protected link was classified ordinary")
	}
	if err := os.Remove(filepath.Join(root, "ordinary", "status")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(protected, filepath.Join(root, "ordinary", "status")); err != nil {
		t.Fatal(err)
	}
	protectedViaFD := fdPath + "/../status"
	if data, err := exec.Command("cat", protectedViaFD).Output(); err != nil || string(data) != "protected" {
		t.Fatalf("child protected read %q = %q, %v", protectedViaFD, data, err)
	}
	if ordinaryNoAnswerPayloadInHome(gap0641Payload(project, "cat "+protectedViaFD), home) {
		t.Error("protected fixed-PID fd path was classified ordinary")
	}
}

func TestGAP0641FixedPIDProcFDOSSDeadlineAllows(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux proc path")
	}
	shortAnswerBudget(t, 300*time.Millisecond)
	addr := hungGateway(t)
	dir := filepath.Join(t.TempDir(), "ordinary", "child")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "status"), []byte("ordinary"), 0600); err != nil {
		t.Fatal(err)
	}
	openDir, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer openDir.Close()
	path := fmt.Sprintf("/proc/%d/fd/%d/status", os.Getpid(), openDir.Fd())
	if data, err := exec.Command("cat", path).Output(); err != nil || string(data) != "ordinary" {
		t.Fatalf("child read %q = %q, %v", path, data, err)
	}
	result, _ := runAgainstGateway(t, "claudecode", addr, func(opts *Options) {
		opts.FailMode = "open"
		opts.OutageFailModeNow = func() string { return "open" }
		opts.Stdin = strings.NewReader(string(gap0641Payload(dir, "cat "+path)))
	})
	if nativeOutageBlocked(result) {
		t.Errorf("ordinary fixed-PID descriptor was blocked at OSS deadline: code=%d stdout=%q stderr=%q", result.code, result.stdout, result.stderr)
	}
}

func TestGAP0641FixedPIDProcFDManagedOutageAllows(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux proc path")
	}
	shortAnswerBudget(t, 550*time.Millisecond)
	fastRestartRetries(t)
	dir := filepath.Join(t.TempDir(), "ordinary", "child")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "status"), []byte("ordinary"), 0600); err != nil {
		t.Fatal(err)
	}
	openDir, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer openDir.Close()
	path := fmt.Sprintf("/proc/%d/fd/%d/status", os.Getpid(), openDir.Fd())
	if data, err := exec.Command("cat", path).Output(); err != nil || string(data) != "ordinary" {
		t.Fatalf("child read %q = %q, %v", path, data, err)
	}
	rt := &stubRT{onRequest: func(rt *stubRT, req *http.Request) (*http.Response, error) {
		if rt.requests == 1 {
			return nil, fakeStoppedSCM()
		}
		<-req.Context().Done()
		return nil, req.Context().Err()
	}}
	result := run(t, "codex", rt, func(opts *Options) {
		managedCodex(opts)
		opts.FailMode = "open"
		opts.ExplainUnenrolledAccount = true
		opts.StartedAt = time.Now()
		opts.FailureLogHome = userLogHome(opts.Home)
		opts.Stdin = strings.NewReader(fmt.Sprintf(`{"hook_event_name":"PreToolUse","tool_name":"exec_command","cwd":%q,"tool_input":{"cmd":%q}}`, dir, "cat "+path))
	})
	if blocked(result) {
		t.Errorf("ordinary fixed-PID descriptor was blocked in managed admin-open outage: code=%d stdout=%q stderr=%q", result.code, result.stdout, result.stderr)
	}
}

// The shared reader proves this call ordinary (the payload test above), but the
// restart-window scan (GAP-0518) does not step through a dot-dot component, and
// the open tier needs both: the call stays closed at the deadline, as on the
// release base.
func TestGAP0641FixedPIDProcCWDOSSDeadlineStaysClosedWithoutBothScans(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux proc path")
	}
	shortAnswerBudget(t, 300*time.Millisecond)
	addr := hungGateway(t)
	root := t.TempDir()
	runner := filepath.Join(root, "runner", "child")
	if err := os.MkdirAll(runner, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "runner", "status"), []byte("ordinary"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(runner)
	path := fmt.Sprintf("/proc/%d/cwd/../status", os.Getpid())
	if data, err := exec.Command("cat", path).Output(); err != nil || string(data) != "ordinary" {
		t.Fatalf("child read %q = %q, %v", path, data, err)
	}
	result, _ := runAgainstGateway(t, "claudecode", addr, func(opts *Options) {
		opts.FailMode = "open"
		opts.OutageFailModeNow = func() string { return "open" }
		opts.Stdin = strings.NewReader(string(gap0641Payload(runner, "cat "+path)))
	})
	if !nativeOutageBlocked(result) {
		t.Errorf("fixed-PID cwd with a dot-dot step was allowed at OSS deadline: code=%d stdout=%q stderr=%q", result.code, result.stdout, result.stderr)
	}
}

func TestGAP0641FixedPIDProcCWDManagedOutageAllows(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux proc path")
	}
	shortAnswerBudget(t, 550*time.Millisecond)
	fastRestartRetries(t)
	root := t.TempDir()
	runner := filepath.Join(root, "runner", "child")
	if err := os.MkdirAll(runner, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "runner", "status"), []byte("ordinary"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(runner)
	path := fmt.Sprintf("/proc/%d/cwd/../status", os.Getpid())
	if data, err := exec.Command("cat", path).Output(); err != nil || string(data) != "ordinary" {
		t.Fatalf("child read %q = %q, %v", path, data, err)
	}
	rt := &stubRT{onRequest: func(rt *stubRT, req *http.Request) (*http.Response, error) {
		if rt.requests == 1 {
			return nil, fakeStoppedSCM()
		}
		<-req.Context().Done()
		return nil, req.Context().Err()
	}}
	result := run(t, "codex", rt, func(opts *Options) {
		managedCodex(opts)
		opts.FailMode = "open"
		opts.ExplainUnenrolledAccount = true
		opts.StartedAt = time.Now()
		opts.FailureLogHome = userLogHome(opts.Home)
		opts.Stdin = strings.NewReader(fmt.Sprintf(`{"hook_event_name":"PreToolUse","tool_name":"exec_command","cwd":%q,"tool_input":{"cmd":%q}}`, runner, "cat "+path))
	})
	if blocked(result) {
		t.Errorf("ordinary fixed-PID cwd was blocked in managed admin-open outage: code=%d stdout=%q stderr=%q", result.code, result.stdout, result.stderr)
	}
}

func TestGAP0641ExternalFixedPIDProcFDPolicy(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux proc path")
	}
	dir := filepath.Join(t.TempDir(), "ordinary", "child")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "status"), []byte("ordinary"), 0600); err != nil {
		t.Fatal(err)
	}
	openDir, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer openDir.Close()
	holder := exec.Command("sleep", "10")
	holder.ExtraFiles = []*os.File{openDir}
	if err := holder.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = holder.Process.Kill()
		_ = holder.Wait()
	})
	path := fmt.Sprintf("/proc/%d/fd/3/status", holder.Process.Pid)
	if data, err := exec.Command("cat", path).Output(); err != nil || string(data) != "ordinary" {
		t.Fatalf("agent child read %q = %q, %v", path, data, err)
	}
	t.Run("oss", func(t *testing.T) {
		shortAnswerBudget(t, 300*time.Millisecond)
		addr := hungGateway(t)
		result, _ := runAgainstGateway(t, "claudecode", addr, func(opts *Options) {
			opts.FailMode = "open"
			opts.OutageFailModeNow = func() string { return "open" }
			opts.Stdin = strings.NewReader(string(gap0641Payload(dir, "cat "+path)))
		})
		if nativeOutageBlocked(result) {
			t.Errorf("external-PID ordinary descriptor blocked at OSS deadline: code=%d", result.code)
		}
	})
	t.Run("managed", func(t *testing.T) {
		shortAnswerBudget(t, 550*time.Millisecond)
		fastRestartRetries(t)
		rt := &stubRT{onRequest: func(rt *stubRT, req *http.Request) (*http.Response, error) {
			if rt.requests == 1 {
				return nil, fakeStoppedSCM()
			}
			<-req.Context().Done()
			return nil, req.Context().Err()
		}}
		result := run(t, "codex", rt, func(opts *Options) {
			managedCodex(opts)
			opts.FailMode = "open"
			opts.ExplainUnenrolledAccount = true
			opts.StartedAt = time.Now()
			opts.FailureLogHome = userLogHome(opts.Home)
			opts.Stdin = strings.NewReader(fmt.Sprintf(`{"hook_event_name":"PreToolUse","tool_name":"exec_command","cwd":%q,"tool_input":{"cmd":%q}}`, dir, "cat "+path))
		})
		if blocked(result) {
			t.Errorf("external-PID ordinary descriptor blocked in managed admin-open outage: code=%d", result.code)
		}
	})
}
