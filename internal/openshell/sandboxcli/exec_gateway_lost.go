// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package sandboxcli

import (
	"bytes"
	"context"
	"io"
	"strings"
	"sync"
)

// gatewayLostFilter is the standard-error writer of a `sandbox exec` that
// streams the OpenShell command's output. The command's own lines pass
// through at once; the OpenShell command's connect failure when its gateway
// is not answering (a block that opens "Error: × transport error" and goes on
// with "├─▶ tcp connect error" and "╰─▶ Connection refused (os error 111)")
// is held back, so the person reads DefenseClaw's account of it and not the
// transport trace (rel-1-0-6 GAP-0340, the GAP-0186 class).
type gatewayLostFilter struct {
	next    io.Writer
	mu      sync.Mutex
	partial bytes.Buffer
	holding bool
	held    bytes.Buffer
}

func newGatewayLostFilter(next io.Writer) *gatewayLostFilter { return &gatewayLostFilter{next: next} }

func (f *gatewayLostFilter) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.partial.Write(p)
	for {
		line, err := f.partial.ReadString('\n')
		if err != nil {
			f.partial.WriteString(line) // not a whole line yet
			return len(p), nil
		}
		if werr := f.line(line); werr != nil {
			return len(p), werr
		}
	}
}

// line routes one whole line.
func (f *gatewayLostFilter) line(line string) error {
	text := strings.TrimSpace(line)
	switch {
	case !f.holding && strings.HasPrefix(text, "Error:") && strings.Contains(text, "transport error"):
		f.holding = true
		f.held.WriteString(line)
		return nil
	case f.holding && (text == "" || gatewayTraceLine(text)):
		f.held.WriteString(line)
		return nil
	}
	f.holding = false
	_, err := io.WriteString(f.next, line)
	return err
}

// gatewayTraceLine is a continuation of the OpenShell command's error trace.
func gatewayTraceLine(text string) bool {
	return strings.HasPrefix(text, "├") || strings.HasPrefix(text, "╰") || strings.HasPrefix(text, "│") ||
		strings.HasPrefix(text, "tcp connect error") || strings.HasPrefix(text, "Connection refused")
}

// finish ends the stream. It reports whether the OpenShell gateway was not
// answering (a held connect failure of a command that failed); anything else
// held, or left in a last unfinished line, is written as it came.
func (f *gatewayLostFilter) finish(code int) (gatewayLost bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.partial.Len() > 0 {
		_ = f.line(f.partial.String())
		f.partial.Reset()
	}
	if f.held.Len() == 0 {
		return false
	}
	if code != 0 {
		return true
	}
	_, _ = f.next.Write(f.held.Bytes())
	return false
}

// gatewayLostExecText says that a `sandbox exec` could not reach the OpenShell
// gateway: what happened, where the sandbox stands, and what to do.
func (a *App) gatewayLostExecText(ctx context.Context, sandbox string) string {
	text := "the OpenShell gateway of your sandboxes is not answering (it was stopped or is restarting), so the command did not run in " +
		sandbox + "; " + sandbox + " itself is not changed. Wait a few seconds and run the command again; `" + CommandName +
		" doctor` shows whether the gateway is back"
	facts := a.managedFacts(ctx)
	if a.ManagedHost() || onManagedHost() || a.managedSeen != nil {
		text += ". On this computer your organization's sandbox service starts it again. " + accountOutageContact(facts.RequestAccess)
	}
	return text
}
