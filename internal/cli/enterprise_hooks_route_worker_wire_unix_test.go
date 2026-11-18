//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// routeWorkerHelperEnv makes TestRouteOnlyWorkerHelperProcess the real
// worker (enterpriseHookWorkerMain reads and decodes the request the guardian
// encoded), with the installer and verifier replaced by a record of the
// route-only render that reached it.
const routeWorkerHelperEnv = "DEFENSECLAW_TEST_ROUTE_WORKER_HELPER"

func TestRouteOnlyWorkerHelperProcess(t *testing.T) {
	if os.Getenv(routeWorkerHelperEnv) == "" {
		return
	}
	record := func(_ context.Context, opts enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
		if opts.RouteOnly == nil {
			return enterprisehooks.InstallResult{}, errors.New("no route-only render reached the worker")
		}
		if err := os.WriteFile(filepath.Join(opts.UserHome, "route-"+opts.ConnectorName), []byte(routeFacts(opts.RouteOnly)), 0o600); err != nil {
			return enterprisehooks.InstallResult{}, err
		}
		return enterprisehooks.InstallResult{
			Connector:                  opts.ConnectorName,
			UserHome:                   opts.UserHome,
			HookContractLockUpdatedAt:  "2026-09-26T00:00:00Z",
			HookContractEntryUpdatedAt: "2026-09-26T00:00:01Z",
		}, nil
	}
	enterpriseHookWorkerInstaller, enterpriseHookWorkerVerifier = record, record
	os.Exit(enterpriseHookWorkerMain(context.Background(), os.Stdin, os.Stdout, os.Stderr))
}

func routeFacts(r *connector.RouteOnlySetup) string {
	return fmt.Sprintf("base=%s token=%s bedrock=%t signing=%t custody=%t unavailable=%q",
		r.BaseURL, r.Token, r.Bedrock, r.GatewaySigning, r.Custody, r.Unavailable)
}

// Managed Linux with enrollment and routing route_only [claudecode, codex]:
// the guardian puts each target's route-only render in the worker request it
// JSON-encodes. The func field GAP-1133 round 3 added to RouteOnlySetup
// (HeldElsewhere) failed that encode, so every routed target was "not
// protected: json: unsupported type: func() bool" (guardian_target_failed).
// The whole pass, with the real worker launch: every target is protected
// and the render reaches the worker whole (rel-1-0-10:GAP-1311).
func TestStandaloneRouteOnlyTargetsCrossTheWorkerBoundary(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the helper worker runs as the invoking user; root cannot be a target")
	}
	uid, gid := os.Getuid(), os.Getgid()
	resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}, transient: map[string]bool{}}
	f := newStandaloneFixture(t, resolver)
	origExe, origArgs, origEnv := enterpriseHookWorkerExecutable, enterpriseHookWorkerArgs, enterpriseHookWorkerExtraEnv
	origToken, origRouteLog := enterpriseHookRouteToken, enterpriseHookRouteOnlyLog
	t.Cleanup(func() {
		enterpriseHookWorkerExecutable, enterpriseHookWorkerArgs, enterpriseHookWorkerExtraEnv = origExe, origArgs, origEnv
		enterpriseHookRouteToken, enterpriseHookRouteOnlyLog = origToken, origRouteLog
	})
	enterpriseHookWorkerRunner = runEnterpriseHookWorker // the fixture restores its own
	enterpriseHookWorkerExecutable = os.Executable
	enterpriseHookWorkerArgs = []string{"-test.run=^TestRouteOnlyWorkerHelperProcess$"}
	enterpriseHookWorkerExtraEnv = []string{routeWorkerHelperEnv + "=1"}
	enterpriseHookRouteOnlyLog = io.Discard
	enterpriseHookRouteToken = func(_, connectorName, identity string, _ bool) (string, error) {
		return "dcr1-route-" + connectorName + "-" + identity, nil
	}
	cfg.Enterprise.Enrollment.Mode = "auto"
	cfg.Routing.Enabled = true
	cfg.Routing.RouteOnly = config.RoutingRouteOnlyConfig{
		Connectors: []string{"claudecode", "codex"},
		Upstreams: map[string]config.RoutingUpstreamConfig{
			"claudecode": {BaseURL: "https://api.anthropic.com", API: config.RoutingAPIMessages},
			"codex":      {BaseURL: "https://api.openai.com/v1", API: config.RoutingAPIResponses},
		},
	}
	home := f.home(t, "alice", 0o700)
	resolver.accounts["alice"] = unixidentity.Account{Name: "alice", UID: uid, GID: gid, Home: home, Shell: "/bin/bash"}
	f.writeManifest(t,
		enterprisehooks.ManifestTarget{User: "alice", Connector: "claudecode"},
		enterprisehooks.ManifestTarget{User: "alice", Connector: "codex"},
	)

	run, err := runEnterpriseHookReconcileOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	requireLedgerOrStateTrust(t, run.StateErr)
	if run.Failures != 0 || len(run.Rows) != 2 {
		t.Fatalf("routed targets failed (guardian_target_failed): failures=%d rows=%+v", run.Failures, run.Rows)
	}
	for _, row := range run.Rows {
		if !row.OK || row.Pending || row.Error != "" {
			t.Fatalf("routed target %s is not protected: %+v", row.Connector, row)
		}
	}
	apiAddr := "127.0.0.1:" + strconv.Itoa(cfg.Gateway.APIPort)
	for _, name := range []string{"claudecode", "codex"} {
		want := gateway.ManagedRouteOnlySetup(cfg, name, apiAddr, "dcr1-route-"+name+"-"+strconv.Itoa(uid))
		if want == nil {
			t.Fatalf("the guardian renders no route for %s", name)
		}
		got, err := os.ReadFile(filepath.Join(home, "route-"+name))
		if err != nil {
			t.Fatalf("the %s route-only render did not reach the worker: %v", name, err)
		}
		if string(got) != routeFacts(want) {
			t.Fatalf("%s render in the worker = %s, want %s", name, got, routeFacts(want))
		}
	}
}

// Every type the guardian and its worker exchange as JSON encodes: no field
// of a kind encoding/json refuses (func, chan, complex, unsafe pointer, a map
// key it cannot write) without json:"-", in any struct reachable from the
// request or the response. A new runtime-only field fails here, not on a
// managed host (rel-1-0-10:GAP-1311).
func TestEnterpriseHookWorkerWireTypesEncode(t *testing.T) {
	for _, typ := range []reflect.Type{
		reflect.TypeOf(enterpriseHookWorkerRequest{}),
		reflect.TypeOf(enterpriseHookWorkerResponse{}),
	} {
		if bad := jsonUnencodableFields(typ, typ.Name(), map[reflect.Type]bool{}); len(bad) > 0 {
			t.Errorf("%s holds fields encoding/json cannot encode; tag them json:\"-\" or keep them off the wire: %v", typ.Name(), bad)
		}
	}
}

var (
	jsonMarshalerType = reflect.TypeOf((*json.Marshaler)(nil)).Elem()
	textMarshalerType = reflect.TypeOf((*encoding.TextMarshaler)(nil)).Elem()
)

// jsonUnencodableFields returns the field paths under typ that json.Marshal
// refuses whatever their value. A type with its own MarshalJSON is taken as
// it is; an interface is checked only at run time by encoding/json.
func jsonUnencodableFields(typ reflect.Type, path string, seen map[reflect.Type]bool) []string {
	if typ.Implements(jsonMarshalerType) || reflect.PointerTo(typ).Implements(jsonMarshalerType) {
		return nil
	}
	switch typ.Kind() {
	case reflect.Func, reflect.Chan, reflect.Complex64, reflect.Complex128, reflect.UnsafePointer:
		return []string{path + " (" + typ.String() + ")"}
	case reflect.Pointer, reflect.Slice, reflect.Array:
		return jsonUnencodableFields(typ.Elem(), path, seen)
	case reflect.Map:
		var bad []string
		key := typ.Key()
		if key.Kind() != reflect.String && !(key.Kind() >= reflect.Int && key.Kind() <= reflect.Uintptr) &&
			!key.Implements(textMarshalerType) {
			bad = append(bad, path+" (map key "+key.String()+")")
		}
		return append(bad, jsonUnencodableFields(typ.Elem(), path+"[]", seen)...)
	case reflect.Struct:
		if seen[typ] {
			return nil
		}
		seen[typ] = true
		var bad []string
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			if (!field.IsExported() && !field.Anonymous) || field.Tag.Get("json") == "-" {
				continue
			}
			bad = append(bad, jsonUnencodableFields(field.Type, path+"."+field.Name, seen)...)
		}
		return bad
	}
	return nil
}
