// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
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

// GAP-0609: a failed hook keeps its Job and Error pod (hook-succeeded), so
// the pre-delete hook deletes the chart's other hook Jobs, by name in the
// release namespace, with background propagation so their pods go too.
func TestPreDeleteDeletesLeftoverHookJobs(t *testing.T) {
	var deletes []string
	var bodies []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "/apis/batch/v1/") {
			deletes = append(deletes, r.URL.Path)
			b, _ := io.ReadAll(r.Body)
			bodies = append(bodies, string(b))
			if strings.HasSuffix(r.URL.Path, "/defenseclaw-pre-upgrade") {
				_, _ = w.Write([]byte(`{"kind":"Status","status":"Success"}`))
				return
			}
		}
		http.NotFound(w, r)
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
	plan := testPlan()
	plan.CredentialProvider.Grant = false
	r, err := PreDelete(context.Background(), plan, newFakeAPI(), k)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{}
	for _, n := range []string{"defenseclaw-chain-key", "defenseclaw-relay-session", "defenseclaw-pre-upgrade", "defenseclaw-pre-rollback", "defenseclaw-bootstrap"} {
		want["/apis/batch/v1/namespaces/defenseclaw-system/jobs/"+n] = true
	}
	for _, p := range deletes {
		if !want[p] {
			t.Errorf("deleted %s, which is not a leftover hook Job of the release namespace", p)
		}
		delete(want, p)
	}
	if len(want) > 0 {
		t.Errorf("hook Jobs not deleted: %v (deleted %v)", want, deletes)
	}
	for _, b := range bodies {
		if !strings.Contains(b, `"propagationPolicy":"Background"`) {
			t.Errorf("a Job delete without background propagation leaves its pods: %s", b)
		}
	}
	notes := strings.Join(r.Notes, "\n")
	if !strings.Contains(notes, "deleted the hook Job(s) defenseclaw-pre-upgrade and their pods") {
		t.Errorf("notes do not name the deleted Job: %s", notes)
	}
}

// GAP-0609 (2): the kept access-policy grants come with the exact commands a
// global owner runs, for the global policy and each writable atespace.
func TestPurgeStepsGiveTheExactGrantCommands(t *testing.T) {
	steps := strings.Join(PurgeSteps(testPlan()), "\n")
	for _, w := range []string{
		"kubectl ate get access-policy --global -o yaml > global.yaml",
		"kubectl ate update access-policy --global -f global.yaml",
		"kubectl ate get access-policy -a eng-web -o yaml > eng-web.yaml",
		"kubectl ate update access-policy -a eng-web -f eng-web.yaml",
		"kubectl ate update access-policy -a data-team -f data-team.yaml",
	} {
		if !strings.Contains(steps, w) {
			t.Errorf("purge steps lack %q:\n%s", w, steps)
		}
	}
}

// GAP-0611: a Job that cannot be deleted (403 here, 500 for another) is a
// note with the kubectl command; the other Jobs are still deleted and the
// uninstall succeeds.
func TestPreDeleteKeepsGoingWhenAHookJobCannotBeDeleted(t *testing.T) {
	var deletes []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "/apis/batch/v1/") {
			deletes = append(deletes, r.URL.Path)
			switch {
			case strings.HasSuffix(r.URL.Path, "/defenseclaw-pre-rollback"):
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"kind":"Status","status":"Failure","reason":"Forbidden","code":403}`))
				return
			case strings.HasSuffix(r.URL.Path, "/defenseclaw-chain-key"):
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`{"kind":"Status","status":"Failure","code":500}`))
				return
			case strings.HasSuffix(r.URL.Path, "/defenseclaw-pre-upgrade"):
				_, _ = w.Write([]byte(`{"kind":"Status","status":"Success"}`))
				return
			}
		}
		http.NotFound(w, r)
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
	plan := testPlan()
	plan.CredentialProvider.Grant = false
	r, err := PreDelete(context.Background(), plan, newFakeAPI(), k)
	if err != nil {
		t.Fatalf("a hook Job that cannot be deleted stopped the uninstall: %v", err)
	}
	if len(deletes) != len(LeftoverHookJobs) {
		t.Errorf("deletes %v: every leftover hook Job must still be tried", deletes)
	}
	notes := strings.Join(r.Notes, "\n")
	for _, w := range []string{
		"kubectl -n defenseclaw-system delete job defenseclaw-pre-rollback",
		"kubectl -n defenseclaw-system delete job defenseclaw-chain-key",
		"deleted the hook Job(s) defenseclaw-pre-upgrade and their pods",
	} {
		if !strings.Contains(notes, w) {
			t.Errorf("notes lack %q:\n%s", w, notes)
		}
	}
}

// GAP-0909: UpdateConfigMap is a full PUT, so it carries the labels it read
// as well as the annotations; a grant write must not wipe the labels other
// tools put on the policy ConfigMap.
func TestUpdateConfigMapKeepsLabelsAndAnnotations(t *testing.T) {
	var put map[string]any
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			_, _ = w.Write([]byte(`{"metadata":{"name":"p","namespace":"ns","resourceVersion":"7","labels":{"app.kubernetes.io/managed-by":"helm","team":"sec"},"annotations":{"note":"kept"}},"data":{"k":"v"}}`))
		case http.MethodPut:
			if err := json.NewDecoder(r.Body).Decode(&put); err != nil {
				t.Error(err)
			}
			_, _ = w.Write([]byte(`{}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	tok := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tok, []byte("t"), 0o600); err != nil {
		t.Fatal(err)
	}
	k, err := NewKube(srv.URL, tok, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
	if err != nil {
		t.Fatal(err)
	}
	cm, err := k.GetConfigMap(context.Background(), "ns", "p")
	if err != nil || cm == nil {
		t.Fatalf("get: %v %v", cm, err)
	}
	cm.Data["k"] = "w"
	if err := k.UpdateConfigMap(context.Background(), cm); err != nil {
		t.Fatal(err)
	}
	meta, _ := put["metadata"].(map[string]any)
	labels, _ := meta["labels"].(map[string]any)
	if labels["app.kubernetes.io/managed-by"] != "helm" || labels["team"] != "sec" || len(labels) != 2 {
		t.Errorf("the PUT dropped the labels: %v", meta)
	}
	if ann, _ := meta["annotations"].(map[string]any); ann["note"] != "kept" {
		t.Errorf("the PUT dropped the annotations: %v", meta)
	}
}
