// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestRelaunchHelperGuard plays a relaunched guard: it answers every request.
func TestRelaunchHelperGuard(t *testing.T) {
	if os.Getenv("DC_ACP_RELAUNCH_HELPER") != "1" {
		return
	}
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Text()
		id := line[strings.Index(line, `"id":`)+5 : strings.Index(line, `,"method"`)]
		fmt.Printf(`{"jsonrpc":"2.0","id":%s,"result":{"sessionId":"relaunched"}}`+"\n", id)
	}
	os.Exit(0)
}

// A guard that ended its session for a central change stays for Zed's next
// thread: it answers with the reason until setup ran again, then starts the
// guard the entry names now. Zed showed "Incoming transport closed" on
// session/new until Retry (GAP-0906).
func TestSessionEndedGuardServesTheNextThread(t *testing.T) {
	editorIn, editorWriter := io.Pipe()
	outReader, out := io.Pipe()
	setUpAgain := make(chan bool, 1)
	setUpAgain <- false
	relaunch := func() (*exec.Cmd, bool) {
		if !<-setUpAgain {
			setUpAgain <- true
			return nil, false
		}
		self, err := os.Executable()
		if err != nil {
			t.Error(err)
			return nil, false
		}
		command := exec.Command(self, "-test.run=TestRelaunchHelperGuard")
		command.Env = append(os.Environ(), "DC_ACP_RELAUNCH_HELPER=1")
		return command, true
	}
	done := make(chan error, 1)
	initialize := []byte(`{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":1}}`)
	go func() {
		done <- serveAfterSessionEnd(editorIn, out, initialize, "profile moved", relaunch)
		_ = out.Close()
	}()
	answers := bufio.NewScanner(outReader)
	for id, want := range map[int]string{1: `"message":"profile moved"`, 2: `"sessionId":"relaunched"`} {
		if _, err := fmt.Fprintf(editorWriter, `{"jsonrpc":"2.0","id":%d,"method":"session/new","params":{}}`+"\n", id); err != nil {
			t.Fatal(err)
		}
		if !answers.Scan() || !strings.Contains(answers.Text(), want) || !strings.Contains(answers.Text(), fmt.Sprintf(`"id":%d`, id)) {
			t.Fatalf("thread %d: answer %q, want %s", id, answers.Text(), want)
		}
	}
	_ = editorWriter.Close()
	if err := <-done; err != nil {
		t.Fatalf("serve: %v", err)
	}

	// The proxy reads the editor until detach, and the guard the rest; the
	// editor's initialize request is kept for the relaunched guard.
	stdinReader, stdinWriter := io.Pipe()
	input := newEditorInput(stdinReader)
	go func() {
		_, _ = io.WriteString(stdinWriter, string(initialize)+"\n")
		_, _ = io.WriteString(stdinWriter, `{"jsonrpc":"2.0","id":3,"method":"session/new"}`+"\n")
		_ = stdinWriter.Close()
	}()
	proxyView := bufio.NewReader(input)
	if line, err := proxyView.ReadString('\n'); err != nil || !strings.Contains(line, `"initialize"`) {
		t.Fatalf("proxy read %q, %v", line, err)
	}
	input.detach()
	if _, err := proxyView.ReadString('\n'); err == nil {
		t.Fatal("the proxy kept reading after detach")
	}
	rest, err := io.ReadAll(input.rest())
	if err != nil || string(input.initializeRequest()) != string(initialize) ||
		(len(rest) > 0 && !strings.Contains(string(rest), `"id":3`)) {
		t.Fatalf("rest %q, initialize %q, err %v", rest, input.initializeRequest(), err)
	}

	// Only this guard executable, with other arguments, is started.
	dir := t.TempDir()
	settings, lock := filepath.Join(dir, "settings.json"), filepath.Join(dir, "lock.json")
	guard := filepath.Join(dir, "defenseclaw-acp")
	previous := guardExecutable
	t.Cleanup(func() { guardExecutable = previous })
	guardExecutable = func() (string, error) { return guard, nil }
	if err := os.WriteFile(lock, []byte(fmt.Sprintf(`{"client":{"config_path":%q}}`, settings)), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		command string
		args    []string
		ok      bool
	}{
		{guard, []string{"--mode", "action"}, true},
		{guard, []string{"--mode", "observe"}, false},
		{filepath.Join(dir, "other"), []string{"--mode", "action"}, false},
	} {
		entry := fmt.Sprintf(`{"agent_servers":{"DefenseClaw · Hermes":{"command":%q,"args":["%s"]}}}`, test.command, strings.Join(test.args, `","`))
		if err := os.WriteFile(settings, []byte(entry), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, ok := relaunchCommand(lock, "hermes", []string{"--mode", "observe"}); ok != test.ok {
			t.Fatalf("relaunch of %s %v = %v, want %v", test.command, test.args, ok, test.ok)
		}
	}
}
