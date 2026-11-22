// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"context"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// GAP-0056: every error path of stopController leaves the controller at its
// old replica count (or says loudly that it could not), never stopped with
// the DefenseClaw policies still in place.
func TestGAP0056StopControllerErrorPathsRestoreTheReplicas(t *testing.T) {
	oldTimeout, oldPoll := ControllerStopTimeout, pollEvery
	ControllerStopTimeout, pollEvery = 50*time.Millisecond, 5*time.Millisecond
	defer func() { ControllerStopTimeout, pollEvery = oldTimeout, oldPoll }()

	const dep = "defenseclaw-controller"
	setup := func() (ChartPlan, *fakeAPI, *fakeKube, ActorRef) {
		plan := testPlan()
		plan.ControllerDeployment = dep
		api, kube := newFakeAPI(), newFakeKube()
		ours := ActorRef{"eng-web", "a1"}
		api.egress[ours] = &EgressPolicy{Actor: ours, Hostnames: []string{plan.ActorHost}}
		kube.replicas[plan.Namespace+"/"+dep] = 2
		return plan, api, kube, ours
	}
	check := func(t *testing.T, plan ChartPlan, api *fakeAPI, kube *fakeKube, ours ActorRef, err error) {
		t.Helper()
		if err == nil {
			t.Fatal("the uninstall went on")
		}
		if got := kube.replicas[plan.Namespace+"/"+dep]; got != 2 {
			t.Fatalf("controller left at %d replicas (scales %v): %v", got, kube.scales, err)
		}
		if api.egress[ours] == nil {
			t.Fatal("a policy was removed although the controller could not be stopped")
		}
	}

	t.Run("the scale call fails after it took effect", func(t *testing.T) {
		plan, api, kube, ours := setup()
		kube.scaleErr = func(i int, _ int32) (bool, error) {
			if i == 0 {
				return true, errors.New("connection reset after the patch")
			}
			return false, nil
		}
		_, err := PreDelete(context.Background(), plan, api, kube)
		check(t, plan, api, kube, ours, err)
	})
	t.Run("the pod count cannot be read", func(t *testing.T) {
		plan, api, kube, ours := setup()
		kube.podsErr = errors.New("forbidden: pods")
		_, err := PreDelete(context.Background(), plan, api, kube)
		check(t, plan, api, kube, ours, err)
		if !strings.Contains(err.Error(), "count the pods") {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("the hook is cancelled while it waits", func(t *testing.T) {
		plan, api, kube, ours := setup()
		ctx, cancel := context.WithCancel(context.Background())
		kube.pods = func(string) int32 { cancel(); return 1 } // a pod is still terminating
		_, err := PreDelete(ctx, plan, api, kube)
		check(t, plan, api, kube, ours, err)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("pods do not go within the timeout", func(t *testing.T) {
		plan, api, kube, ours := setup()
		kube.pods = func(string) int32 { return 1 }
		_, err := PreDelete(context.Background(), plan, api, kube)
		check(t, plan, api, kube, ours, err)
	})
	t.Run("the scale-back fails too: the error says so and how to fix it", func(t *testing.T) {
		plan, api, kube, _ := setup()
		kube.podsErr = errors.New("forbidden: pods")
		kube.scaleErr = func(i int, _ int32) (bool, error) {
			if i == 1 {
				return false, errors.New("apiserver down")
			}
			return false, nil
		}
		_, err := PreDelete(context.Background(), plan, api, kube)
		if err == nil || !strings.Contains(err.Error(), "could not be scaled back to 2") ||
			!strings.Contains(err.Error(), "kubectl -n "+plan.Namespace+" scale deployment/"+dep+" --replicas=2") {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("a sweep that cannot list keeps the controller and says it was restored", func(t *testing.T) {
		plan, api, kube, ours := setup()
		api.listErr = errors.New("PermissionDenied")
		r, err := PreDelete(context.Background(), plan, api, kube)
		check(t, plan, api, kube, ours, err)
		if !strings.Contains(strings.Join(r.Notes, "\n"), "scaled "+dep+" back to 2") {
			t.Fatalf("notes %v", r.Notes)
		}
	})
}

// GAP-0056 (P4 part): the pod count includes terminating pods, which
// status.replicas leaves out, and asks for the Deployment's own selector.
func TestDeploymentPodsCountsTerminatingPods(t *testing.T) {
	var podQuery string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/deployments/defenseclaw-controller"):
			_, _ = w.Write([]byte(`{"spec":{"selector":{"matchLabels":{"app.kubernetes.io/name":"defenseclaw","app.kubernetes.io/component":"controller"}}},"status":{"replicas":0}}`))
		case strings.HasSuffix(r.URL.Path, "/pods"):
			podQuery = r.URL.Query().Get("labelSelector")
			_, _ = w.Write([]byte(`{"items":[{"metadata":{"deletionTimestamp":"2026-11-13T00:00:00Z"},"status":{"phase":"Running"}},{"status":{"phase":"Succeeded"}}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	dir := t.TempDir()
	tok := filepath.Join(dir, "token")
	if err := os.WriteFile(tok, []byte("t"), 0o600); err != nil {
		t.Fatal(err)
	}
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	k, err := NewKube(srv.URL, tok, ca)
	if err != nil {
		t.Fatal(err)
	}
	n, err := k.DeploymentPods(context.Background(), "defenseclaw-system", "defenseclaw-controller")
	if err != nil || n != 1 {
		t.Fatalf("pods = %d, %v; want the terminating pod counted", n, err)
	}
	if podQuery != "app.kubernetes.io/component=controller,app.kubernetes.io/name=defenseclaw" {
		t.Fatalf("label selector %q", podQuery)
	}
}
