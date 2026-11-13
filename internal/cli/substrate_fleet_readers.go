// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package cli

// The verify readers that need more than one kubectl get (GAP-0200,
// GAP-0209): the snapshot bucket through the object store's own CLI, the
// access policies through ate-api-server as the gateway's ServiceAccount,
// and the actor listener's routes through a port-forward. Every check
// they feed reports only what they read; a reader that cannot read says
// why in the check.

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/fleet"
	"github.com/defenseclaw/defenseclaw/internal/substrate/setup"
)

// kubectlArgs puts the kubeconfig and context flags in front of args.
func kubectlArgs(f *substrateClusterFlags, args ...string) []string {
	var pre []string
	if f.kubeconfig != "" {
		pre = append(pre, "--kubeconfig", f.kubeconfig)
	}
	if f.kubeContext != "" {
		pre = append(pre, "--context", f.kubeContext)
	}
	return append(pre, args...)
}

// substratePortForward forwards a free local port to port of target (for
// example svc/defenseclaw-actor) in namespace and returns the local
// address and a stop function; tests replace it. A port-forward reaches
// the pod directly, so it works where a NetworkPolicy admits only
// Substrate's egress gateway.
var substratePortForward = func(ctx context.Context, f *substrateClusterFlags, namespace, target string, port int) (string, func(), error) {
	pctx, cancel := context.WithCancel(ctx)
	cmd := exec.CommandContext(pctx, "kubectl", kubectlArgs(f, "port-forward", "--address", "127.0.0.1", "-n", namespace,
		target, ":"+strconv.Itoa(port))...)
	var errb strings.Builder
	cmd.Stderr = &errb
	out, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return "", nil, err
	}
	if err := cmd.Start(); err != nil {
		cancel()
		if errors.Is(err, exec.ErrNotFound) {
			return "", nil, errors.New("kubectl is not installed or not on PATH")
		}
		return "", nil, err
	}
	stop := func() {
		cancel()
		_ = cmd.Wait()
	}
	addr := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(out)
		for sc.Scan() {
			// "Forwarding from 127.0.0.1:41234 -> 8080"
			if rest, ok := strings.CutPrefix(sc.Text(), "Forwarding from 127.0.0.1:"); ok {
				if p, _, ok := strings.Cut(rest, " "); ok {
					select {
					case addr <- "127.0.0.1:" + p:
					default:
					}
				}
			}
		}
		_, _ = io.Copy(io.Discard, out)
		close(addr)
	}()
	select {
	case a, ok := <-addr:
		if ok {
			return a, stop, nil
		}
	case <-pctx.Done():
	}
	stop()
	msg := strings.TrimSpace(errb.String())
	if msg == "" {
		msg = "kubectl port-forward did not start"
	}
	return "", nil, errors.New(firstLineOf(msg))
}

// --- the actor listener's routes (GAP-0209) ---------------------------------

// substrateActorProbeClient asks the actor listener for one path; tests
// replace it.
var substrateActorProbeClient = &http.Client{
	Timeout:       5 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// readActorRoutes asks the actor Service for every fleet.ActorListenerProbes
// path, without an actor token, and keeps the ones that answer with
// anything but 404: the actor listener refuses every other path before
// any handler runs.
func readActorRoutes(ctx context.Context, f *substrateClusterFlags, o *fleet.Observed, actorService string) {
	svc, port := "defenseclaw-actor", 80
	if h := actorService; h != "" {
		if host, p, err := net.SplitHostPort(h); err == nil {
			h = host
			if n, err := strconv.Atoi(p); err == nil {
				port = n
			}
		}
		svc, _, _ = strings.Cut(h, ".")
	}
	addr, stop, err := substratePortForward(ctx, f, f.namespace, "svc/"+svc, port)
	if err != nil {
		o.ActorRoutesNote = "no port-forward to the " + svc + " Service: " + err.Error()
		return
	}
	defer stop()
	served := []string{}
	for _, path := range fleet.ActorListenerProbes {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+path, nil)
		if err != nil {
			continue
		}
		// The path is sent as written, never cleaned.
		req.URL.Opaque = path
		resp, err := substrateActorProbeClient.Do(req)
		if err != nil {
			o.ActorRoutesNote = "the " + svc + " Service did not answer: " + firstLineOf(err.Error())
			return
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			served = append(served, path)
		}
	}
	o.ActorRoutes = served
}

// --- the access policies (GAP-0209) -----------------------------------------

// substrateAccessPolicies connects to ate-api-server as the gateway's
// ServiceAccount; tests replace it. The caller closes the result.
var substrateAccessPolicies = func(ctx context.Context, f *substrateClusterFlags, api apiTarget) (accessPolicyReader, error) {
	dir, err := os.MkdirTemp("", "dc-verify-")
	if err != nil {
		return nil, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	// A short token of the gateway ServiceAccount, for the API server's
	// audience: it reads what the gateway itself can read.
	tok, err := substrateKubectl(ctx, f, "create", "token", "defenseclaw-gateway", "-n", f.namespace,
		"--audience", api.serverName, "--duration", "10m")
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("no token for the gateway ServiceAccount: %w", err)
	}
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte(strings.TrimSpace(string(tok))), 0o600); err != nil {
		cleanup()
		return nil, err
	}
	// The trust bundle of the servicedns signer that issues ate-api-server's
	// serving certificate (what the gateway pod mounts).
	bundles, err := kubeGetList(ctx, f, "get", "clustertrustbundles")
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("cannot read the cluster trust bundles: %w", err)
	}
	var pem strings.Builder
	for _, b := range bundles {
		if b.Spec.SignerName == servicednsSigner {
			pem.WriteString(b.Spec.TrustBundle)
			pem.WriteString("\n")
		}
	}
	if pem.Len() == 0 {
		cleanup()
		return nil, fmt.Errorf("no trust bundle of %s", servicednsSigner)
	}
	caFile := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caFile, []byte(pem.String()), 0o600); err != nil {
		cleanup()
		return nil, err
	}
	local, stop, err := substratePortForward(ctx, f, api.namespace, "svc/"+api.service, api.port)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("no port-forward to the API server: %w", err)
	}
	c, err := ateapi.New(ateapi.Options{Address: api.address, ServerName: api.serverName, CAFile: caFile,
		Auth: ateapi.AuthServiceAccount, TokenFile: tokenFile, ReadQPS: -1, WriteQPS: -1,
		ContextDialer: func(ctx context.Context, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", local)
		}})
	if err != nil {
		stop()
		cleanup()
		return nil, err
	}
	return &apiPolicyReader{API: setup.API{Client: c}, done: func() { stop(); cleanup() }}, nil
}

const servicednsSigner = "servicedns.podcert.ate.dev/identity"

// accessPolicyReader reads one access policy ("" is the global one); nil
// with no error when there is none.
type accessPolicyReader interface {
	GetAccessPolicy(ctx context.Context, atespace string) (*setup.AccessPolicy, error)
	Close() error
}

type apiPolicyReader struct {
	setup.API
	done func()
}

func (r *apiPolicyReader) Close() error {
	err := r.API.Close()
	r.done()
	return err
}

// apiTarget is ate-api-server as the config names it.
type apiTarget struct {
	address, serverName, namespace, service string
	port                                    int
}

// substrateAPITarget reads substrate.api.address and server_name (the
// defaults are ate-api-server's Service in the Substrate namespace).
func substrateAPITarget(address, serverName, substrateNS string) (apiTarget, error) {
	if substrateNS == "" {
		substrateNS = "ate-system"
	}
	if address == "" {
		address = "api." + substrateNS + ".svc:443"
	}
	host, p, err := net.SplitHostPort(address)
	if err != nil {
		return apiTarget{}, fmt.Errorf("substrate.api.address %q: %w", address, err)
	}
	port, err := strconv.Atoi(p)
	if err != nil {
		return apiTarget{}, fmt.Errorf("substrate.api.address %q: bad port", address)
	}
	parts := strings.Split(strings.TrimSuffix(host, ".cluster.local"), ".")
	if len(parts) != 3 || parts[2] != "svc" {
		return apiTarget{}, fmt.Errorf("substrate.api.address %q is not a Service of this cluster", address)
	}
	if serverName == "" {
		serverName = strings.TrimSuffix(host, ".cluster.local")
	}
	return apiTarget{address: address, serverName: serverName, namespace: parts[1], service: parts[0], port: port}, nil
}

// readAccessPolicies fills the grants DefenseClaw needs (the chart's plan)
// and the access policies ate-api-server holds for them.
func readAccessPolicies(ctx context.Context, f *substrateClusterFlags, o *fleet.Observed, launcher []string, api apiTarget, apiErr error) {
	o.LauncherAtespaces = launcher
	o.WritableAtespaces = append([]string{}, launcher...)
	for _, a := range f.managedAtespaces {
		if a = strings.TrimSpace(a); a != "" && !slices.Contains(o.WritableAtespaces, a) {
			o.WritableAtespaces = append(o.WritableAtespaces, a)
		}
	}
	slices.Sort(o.WritableAtespaces)
	o.Editors, o.GlobalViewers = setup.ChartEditors(f.namespace), setup.ChartGlobalViewers(f.namespace)
	if apiErr != nil {
		o.PoliciesNote = apiErr.Error()
		return
	}
	r, err := substrateAccessPolicies(ctx, f, api)
	if err != nil {
		o.PoliciesNote = firstLineOf(err.Error())
		return
	}
	defer r.Close()
	read := func(atespace string) (*setup.AccessPolicy, bool) {
		p, err := r.GetAccessPolicy(ctx, atespace)
		if err != nil {
			what := "the global access policy"
			if atespace != "" {
				what = "the access policy of " + atespace
			}
			o.PoliciesNote = what + ": " + policyErrWords(err)
			return nil, false
		}
		return p, true
	}
	global, ok := read("")
	if !ok {
		return
	}
	per := map[string]*setup.AccessPolicy{}
	for _, a := range o.WritableAtespaces {
		p, ok := read(a)
		if !ok {
			return
		}
		if p != nil {
			per[a] = p
		}
	}
	o.GlobalPolicy, o.AtespacePolicies, o.PoliciesReadable = global, per, true
}

func policyErrWords(err error) string {
	if ateapi.IsAuth(err) {
		return "the gateway's ServiceAccount may not read it (" + firstLineOf(err.Error()) + "); it needs the global viewer grant"
	}
	return firstLineOf(err.Error())
}

// --- the snapshot bucket (GAP-0200) -----------------------------------------

// substrateCloudCLI runs the object store's CLI (aws or gcloud) with the
// administrator's own credentials; tests replace it.
var substrateCloudCLI = func(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var out, errb strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return nil, fmt.Errorf("the %s CLI is not installed or not on PATH", name)
		}
		msg := strings.TrimSpace(errb.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, errors.New(firstLineOf(msg))
	}
	return []byte(out.String()), nil
}

// readSnapshotBucket reads the bucket of storage.snapshotLocation: its
// encryption, public access, lifecycle expiry and region.
func readSnapshotBucket(ctx context.Context, f *substrateClusterFlags, o *fleet.Observed, location string) {
	u, err := url.Parse(strings.TrimSpace(location))
	if location == "" || err != nil || u.Host == "" || (u.Scheme != "s3" && u.Scheme != "gs") {
		return
	}
	b := &fleet.Bucket{Location: u.Scheme + "://" + u.Host}
	o.Bucket = b
	if nodes, err := kubeGetList(ctx, f, "get", "nodes", "-l", "topology.kubernetes.io/region"); err == nil && len(nodes) > 0 {
		b.ClusterRegion = nodes[0].Metadata.Labels["topology.kubernetes.io/region"]
	}
	prefix := strings.TrimPrefix(u.Path, "/")
	if u.Scheme == "s3" {
		readS3Bucket(ctx, b, u.Host, prefix)
	} else {
		readGCSBucket(ctx, b, u.Host, prefix)
	}
}

func s3api(ctx context.Context, args ...string) ([]byte, error) {
	return substrateCloudCLI(ctx, "aws", append(append([]string{"s3api"}, args...), "--output", "json")...)
}

func errHas(err error, words ...string) bool {
	for _, w := range words {
		if strings.Contains(err.Error(), w) {
			return true
		}
	}
	return false
}

func readS3Bucket(ctx context.Context, b *fleet.Bucket, bucket, prefix string) {
	raw, err := s3api(ctx, "get-bucket-location", "--bucket", bucket)
	if err != nil {
		if errHas(err, "NoSuchBucket") {
			b.Missing = true
			return
		}
		b.Err = err.Error()
		return
	}
	var loc struct {
		LocationConstraint *string `json:"LocationConstraint"`
	}
	_ = json.Unmarshal(raw, &loc)
	b.Region = "us-east-1" // a null constraint is us-east-1
	if loc.LocationConstraint != nil && *loc.LocationConstraint != "" {
		b.Region = *loc.LocationConstraint
	}

	switch raw, err := s3api(ctx, "get-bucket-encryption", "--bucket", bucket); {
	case err == nil:
		var enc struct {
			Config struct {
				Rules []json.RawMessage `json:"Rules"`
			} `json:"ServerSideEncryptionConfiguration"`
		}
		if json.Unmarshal(raw, &enc) == nil {
			v := len(enc.Config.Rules) > 0
			b.Encrypted = &v
		}
	case errHas(err, "ServerSideEncryptionConfigurationNotFound"):
		v := false
		b.Encrypted = &v
	}

	b.PublicAccessBlocked = readS3PublicAccess(ctx, bucket)

	switch raw, err := s3api(ctx, "get-bucket-lifecycle-configuration", "--bucket", bucket); {
	case err == nil:
		var lc struct {
			Rules []struct {
				Status string `json:"Status"`
				Prefix string `json:"Prefix"`
				Filter *struct {
					Prefix *string `json:"Prefix"`
				} `json:"Filter"`
				Expiration *struct {
					Days int `json:"Days"`
				} `json:"Expiration"`
			} `json:"Rules"`
		}
		if json.Unmarshal(raw, &lc) == nil {
			days := 0
			for _, r := range lc.Rules {
				p := r.Prefix
				if r.Filter != nil && r.Filter.Prefix != nil {
					p = *r.Filter.Prefix
				}
				if r.Status != "Enabled" || r.Expiration == nil || r.Expiration.Days <= 0 || !strings.HasPrefix(prefix, p) {
					continue
				}
				if days == 0 || r.Expiration.Days < days {
					days = r.Expiration.Days
				}
			}
			b.RetentionDays = &days
		}
	case errHas(err, "NoSuchLifecycleConfiguration"):
		days := 0
		b.RetentionDays = &days
	}
}

// readS3PublicAccess: all four block settings on the bucket, or else on
// the account.
func readS3PublicAccess(ctx context.Context, bucket string) *bool {
	type pab struct {
		C map[string]bool `json:"PublicAccessBlockConfiguration"`
	}
	all := func(raw []byte) *bool {
		var p pab
		if json.Unmarshal(raw, &p) != nil {
			return nil
		}
		v := len(p.C) == 4
		for _, on := range p.C {
			v = v && on
		}
		return &v
	}
	raw, err := s3api(ctx, "get-public-access-block", "--bucket", bucket)
	switch {
	case err == nil:
		if v := all(raw); v == nil || *v {
			return v
		}
	case !errHas(err, "NoSuchPublicAccessBlockConfiguration"):
		return nil
	}
	// Not blocked on the bucket: the account's setting may still block it.
	id, err := substrateCloudCLI(ctx, "aws", "sts", "get-caller-identity", "--query", "Account", "--output", "text")
	if err != nil {
		return nil
	}
	raw, err = substrateCloudCLI(ctx, "aws", "s3control", "get-public-access-block", "--account-id",
		strings.TrimSpace(string(id)), "--output", "json")
	switch {
	case err == nil:
		return all(raw)
	case errHas(err, "NoSuchPublicAccessBlockConfiguration"):
		v := false
		return &v
	}
	return nil
}

func readGCSBucket(ctx context.Context, b *fleet.Bucket, bucket, prefix string) {
	raw, err := substrateCloudCLI(ctx, "gcloud", "storage", "buckets", "describe", "gs://"+bucket, "--format=json")
	if err != nil {
		if errHas(err, "404", "not found", "NotFound") {
			b.Missing = true
			return
		}
		b.Err = err.Error()
		return
	}
	var d struct {
		Location               string `json:"location"`
		PublicAccessPrevention string `json:"public_access_prevention"`
		Lifecycle              *struct {
			Rule []struct {
				Action struct {
					Type string `json:"type"`
				} `json:"action"`
				Condition struct {
					Age           int      `json:"age"`
					MatchesPrefix []string `json:"matchesPrefix"`
				} `json:"condition"`
			} `json:"rule"`
		} `json:"lifecycle_config"`
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		b.Err = "gcloud answered something this version does not read"
		return
	}
	// Cloud Storage encrypts every object at rest.
	enc := true
	b.Encrypted = &enc
	b.Region = strings.ToLower(d.Location)
	switch d.PublicAccessPrevention {
	case "enforced":
		v := true
		b.PublicAccessBlocked = &v
	default:
		// "inherited": the organization policy decides, which this
		// reader does not read.
		b.Notes = append(b.Notes, "public access prevention is not enforced on the bucket (inherited), and verify does "+
			"not read the organization policy")
	}
	days := 0
	if d.Lifecycle != nil {
		for _, r := range d.Lifecycle.Rule {
			if r.Action.Type != "Delete" || r.Condition.Age <= 0 {
				continue
			}
			if len(r.Condition.MatchesPrefix) > 0 && !slices.ContainsFunc(r.Condition.MatchesPrefix, func(p string) bool {
				return strings.HasPrefix(prefix, p)
			}) {
				continue
			}
			if days == 0 || r.Condition.Age < days {
				days = r.Condition.Age
			}
		}
	}
	b.RetentionDays = &days
}
