// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxcli"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// accountStatusAPI is the account's sandbox daemon as a restarted one reports
// itself: a status that names the install reason, nothing settled about the
// account's profile.
type accountStatusAPI struct {
	sandboxcli.API
	status sandboxapi.Status
}

func (a accountStatusAPI) Status(context.Context) (*sandboxapi.Status, error) {
	st := a.status
	return &st, nil
}

// accountPolicyOf asks the real policy/explain route for the caller's view of
// a new run of connectorName, as sandboxrelay.UnixClient.Explain does: the
// request has no connector header, a refusal is an error and a 2xx answer is
// the ManagedExplain.
func accountPolicyOf(f *sandboxFixture, connectorName string) func(context.Context, string) (*sandboxapi.ManagedExplain, error) {
	return func(_ context.Context, harness string) (*sandboxapi.ManagedExplain, error) {
		rec := f.do(sbxAlice, http.MethodPost, sandboxrelay.PathPolicyExplain,
			sandboxrelay.ExplainRequest{V: sandboxrelay.WireVersion, Connector: harness, Harness: harness}, nil)
		if rec.Code < 200 || rec.Code > 299 {
			return nil, fmt.Errorf("policy/explain for %q: %d %s", harness, rec.Code, strings.TrimSpace(rec.Body.String()))
		}
		var view sandboxapi.ManagedExplain
		if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
			return nil, err
		}
		return &view, nil
	}
}

// `sandbox status` and `sandbox activity -f` name the profile's refusal for an
// account whose profile denies sandboxes while the daemon's own status names
// the install reason, through the managed gateway's real policy/explain route
// (GAP-2059). The gateway refuses a policy view that names no connector, so
// the view of these commands is the one of the configured primary connector.
func TestSandboxStatusNamesTheProfileRefusalThroughTheRealExplainRoute(t *testing.T) {
	no := false
	f := newSandboxFixture(t, config.EnterpriseEnrollmentConfig{}, nil)
	f.cfg.Guardrail.Profiles["no-sandbox"] = config.GuardrailProfile{Description: "No sandboxes", Mode: "action",
		Sandbox: &config.OpenShellAdminConfig{Allowed: &no}}
	f.cfg.Guardrail.ProfileAssignments = append([]config.ProfileAssignment{
		{Profile: "no-sandbox", Match: config.ProfileMatch{Groups: []string{"dc-sbx-nosandbox"}}},
	}, f.cfg.Guardrail.ProfileAssignments...)
	f.publishFirstGeneration()
	f.setGroups(sbxAlice, "dc-sbx-nosandbox")

	// The gateway's own answer to a view that names no connector.
	rec := f.do(sbxAlice, http.MethodPost, sandboxrelay.PathPolicyExplain,
		sandboxrelay.ExplainRequest{V: sandboxrelay.WireVersion}, nil)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), managedHookReasonConnectorUnknown) {
		t.Fatalf("explain without a connector: %d %s, want 403 %s", rec.Code, rec.Body.String(), managedHookReasonConnectorUnknown)
	}
	// And for the primary connector it says the profile denies sandboxes.
	view, err := accountPolicyOf(f, "claudecode")(context.Background(), "claudecode")
	if err != nil || view.Allowed {
		t.Fatalf("explain for claudecode = %+v, %v; want a view that refuses sandboxes", view, err)
	}

	newApp := func(primary string) (*sandboxcli.App, *bytes.Buffer) {
		cfg := &config.Config{DataDir: t.TempDir()}
		cfg.OpenShell.Enabled = true
		cfg.Guardrail.Connector = primary
		out := &bytes.Buffer{}
		return &sandboxcli.App{
			Cfg: cfg, GOOS: "linux",
			IO: sandboxcli.IO{In: strings.NewReader(""), Out: out, Err: &bytes.Buffer{}},
			API: accountStatusAPI{status: sandboxapi.Status{Enabled: true, Managed: &sandboxapi.ManagedStatus{
				Allowed: true, RequestAccess: "it@example.com",
				Unavailable: "OpenShell 0.1.3 runs no DefenseClaw sandbox: OpenShell 0.1.6 or later is required"}}},
			ManagedAccountPolicy: accountPolicyOf(f, primary),
		}, out
	}
	reasonOf := func(t *testing.T, out *bytes.Buffer) string {
		t.Helper()
		var got struct {
			Reason string `json:"reason"`
		}
		if err := json.Unmarshal(out.Bytes(), &got); err != nil {
			t.Fatalf("status --json: %v\n%s", err, out.String())
		}
		return got.Reason
	}
	const profile, install = "allow sandboxes for your account", "runs no DefenseClaw sandbox"

	t.Run("status", func(t *testing.T) {
		app, out := newApp("claudecode")
		if err := app.Status(context.Background(), "", sandboxcli.OutputJSON); err != nil {
			t.Fatal(err)
		}
		if reason := reasonOf(t, out); !strings.Contains(reason, profile) || strings.Contains(reason, install) {
			t.Errorf("status --json reason = %q, want the profile's refusal", reason)
		}
	})
	t.Run("activity -f", func(t *testing.T) {
		app, _ := newApp("claudecode")
		var off *sandboxcli.DisabledError
		if err := app.Activity(context.Background(), sandboxcli.ActivityOptions{Follow: true, Output: sandboxcli.OutputJSON}); !errors.As(err, &off) ||
			!strings.Contains(off.Message, profile) || strings.Contains(off.Message, install) {
			t.Errorf("activity -f = %v, want a refusal that names the profile", err)
		}
	})
	t.Run("no connector configured", func(t *testing.T) {
		// Nothing to ask a view for: the daemon's status stands.
		app, out := newApp("")
		if err := app.Status(context.Background(), "", sandboxcli.OutputJSON); err != nil {
			t.Fatal(err)
		}
		if reason := reasonOf(t, out); !strings.Contains(reason, install) {
			t.Errorf("status --json reason = %q, want the daemon's install reason", reason)
		}
	})
}
