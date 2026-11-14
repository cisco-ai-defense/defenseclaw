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

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/defenseclaw/defenseclaw/internal/substrate/fleet"
	"github.com/defenseclaw/defenseclaw/internal/substrate/setup"
)

// verifyChecks runs verify against the fakes and returns check id -> check.
func verifyChecks(t *testing.T, install string, extra ...string) map[string]fleet.Check {
	t.Helper()
	f := &substrateClusterFlags{installFile: writeInstall(t, install), namespace: "defenseclaw-system",
		substrateNS: "ate-system", timeout: 10 * time.Second}
	if len(extra) > 0 {
		f.managedAtespaces = extra
	}
	o, r, err := collectFleet(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]fleet.Check{}
	for _, c := range fleet.BuildVerify(o, r.ProductVersion, r.Now).Checks {
		out[c.ID] = c
	}
	return out
}

func wantCheck(t *testing.T, c fleet.Check, status, contains string) {
	t.Helper()
	if c.Status != status || !strings.Contains(c.Message, contains) {
		t.Errorf("%s = %s %q, want %s containing %q", c.ID, c.Status, c.Message, status, contains)
	}
}

// awsAnswers replaces some aws answers of the healthy fake: a value
// starting with "ERR " is an error with that text.
func awsAnswers(t *testing.T, over map[string]string) {
	t.Helper()
	prev := substrateCloudCLI
	substrateCloudCLI = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		key := strings.Join(args[:2], " ")
		if v, ok := over[key]; ok {
			if msg, isErr := strings.CutPrefix(v, "ERR "); isErr {
				return nil, errors.New(msg)
			}
			return []byte(v), nil
		}
		return prev(ctx, name, args...)
	}
	t.Cleanup(func() { substrateCloudCLI = prev })
}

func TestVerifyReadsTheSnapshotBucket(t *testing.T) {
	t.Run("s3 healthy", func(t *testing.T) {
		fakeKubectl(t, nil)
		wantCheck(t, verifyChecks(t, fleetInstallOK)[fleet.CheckBucket], fleet.Pass, "s3://dc-snapshots-e1 is encrypted, private, expiring")
	})
	t.Run("s3 public, unencrypted, no lifecycle, other region", func(t *testing.T) {
		fakeKubectl(t, nil)
		awsAnswers(t, map[string]string{
			"s3api get-bucket-location":                `{"LocationConstraint":"eu-west-1"}`,
			"s3api get-bucket-encryption":              "ERR An error occurred (ServerSideEncryptionConfigurationNotFoundError)",
			"s3api get-public-access-block":            "ERR An error occurred (NoSuchPublicAccessBlockConfiguration)",
			"sts get-caller-identity":                  "123456789012",
			"s3control get-public-access-block":        "ERR An error occurred (NoSuchPublicAccessBlockConfiguration)",
			"s3api get-bucket-lifecycle-configuration": "ERR An error occurred (NoSuchLifecycleConfiguration)",
		})
		c := verifyChecks(t, fleetInstallOK)[fleet.CheckBucket]
		for _, part := range []string{"not encrypted", "public access is not blocked", "stay forever", "in eu-west-1 while the cluster is in us-east-1"} {
			wantCheck(t, c, fleet.Fail, part)
		}
	})
	t.Run("s3 blocked on the account, lifecycle on another prefix", func(t *testing.T) {
		fakeKubectl(t, nil)
		awsAnswers(t, map[string]string{
			"s3api get-public-access-block":            "ERR An error occurred (NoSuchPublicAccessBlockConfiguration)",
			"sts get-caller-identity":                  "123456789012",
			"s3control get-public-access-block":        fakeS3Healthy["get-public-access-block"],
			"s3api get-bucket-lifecycle-configuration": `{"Rules":[{"Status":"Enabled","Filter":{"Prefix":"logs/"},"Expiration":{"Days":7}}]}`,
		})
		c := verifyChecks(t, fleetInstallOK)[fleet.CheckBucket]
		wantCheck(t, c, fleet.Warn, "stay forever")
		if strings.Contains(c.Message, "public") {
			t.Errorf("the account block counts: %q", c.Message)
		}
	})
	t.Run("s3 access denied is a warning that says so", func(t *testing.T) {
		fakeKubectl(t, nil)
		awsAnswers(t, map[string]string{"s3api get-bucket-location": "ERR aws: [ERROR]: An error occurred (AccessDenied) when calling the GetBucketLocation operation: User: arn:aws:sts::123456789012:assumed-role/admin-role/i-0abc is not authorized"})
		c := verifyChecks(t, fleetInstallOK)[fleet.CheckBucket]
		wantCheck(t, c, fleet.Warn, "could not be read from here (AccessDenied on GetBucketLocation for your AWS identity)")
		if strings.Contains(c.Message, "arn:") || strings.Contains(c.Message, "123456789012") {
			t.Errorf("the message names the caller: %q", c.Message)
		}
	})
	t.Run("a missing bucket fails", func(t *testing.T) {
		fakeKubectl(t, nil)
		awsAnswers(t, map[string]string{"s3api get-bucket-location": "ERR An error occurred (NoSuchBucket)"})
		wantCheck(t, verifyChecks(t, fleetInstallOK)[fleet.CheckBucket], fleet.Fail, "does not exist")
	})
	t.Run("no object-store location skips", func(t *testing.T) {
		fakeKubectl(t, nil)
		install := strings.Replace(fleetInstallOK, "storage.snapshotLocation: s3://dc-snapshots-e1/snapshots/\n", "", 1)
		wantCheck(t, verifyChecks(t, install)[fleet.CheckBucket], fleet.Skip, "names no object-storage snapshot location")
	})
	t.Run("gcs", func(t *testing.T) {
		fakeKubectl(t, nil)
		prev := substrateCloudCLI
		answer := `{"location":"US-EAST1","public_access_prevention":"enforced","lifecycle_config":{"rule":[{"action":{"type":"Delete"},"condition":{"age":14,"matchesPrefix":["snapshots/"]}}]}}`
		substrateCloudCLI = func(_ context.Context, name string, args ...string) ([]byte, error) {
			if name != "gcloud" || args[3] != "gs://dc-snap" {
				return nil, errors.New("unexpected " + name)
			}
			return []byte(answer), nil
		}
		t.Cleanup(func() { substrateCloudCLI = prev })
		install := strings.Replace(fleetInstallOK, "s3://dc-snapshots-e1/snapshots/", "gs://dc-snap/snapshots/", 1)
		// The fake node is in us-east-1, the bucket in us-east1: a region warning.
		wantCheck(t, verifyChecks(t, install)[fleet.CheckBucket], fleet.Warn, "in us-east1 while the cluster is in us-east-1")
		answer = strings.Replace(answer, `"enforced"`, `"inherited"`, 1)
		wantCheck(t, verifyChecks(t, install)[fleet.CheckBucket], fleet.Warn, "not enforced on the bucket (inherited)")
	})
}

func TestVerifyReadsTheAccessPolicies(t *testing.T) {
	t.Run("grants in place", func(t *testing.T) {
		fakeKubectl(t, nil)
		wantCheck(t, verifyChecks(t, fleetInstallOK)[fleet.CheckGrants], fleet.Pass, "no managed atespaces were named")
	})
	t.Run("a managed atespace without the editor grant fails", func(t *testing.T) {
		fakeKubectl(t, nil)
		wantCheck(t, verifyChecks(t, fleetInstallOK, "data-team")[fleet.CheckGrants], fleet.Fail, "managed atespace data-team")
	})
	t.Run("someone else edits a launcher atespace", func(t *testing.T) {
		fakeKubectl(t, nil)
		p := fleetHealthyPolicies("defenseclaw-system", "eng-web")
		p["eng-web"].Bindings = append(p["eng-web"].Bindings, setup.Binding{Role: setup.RoleEditor, Members: []string{"user:mallory"}})
		substrateClusterAPI = func(context.Context, *substrateClusterFlags, apiTarget) (clusterAPIReader, error) {
			return fakePolicyReader(p), nil
		}
		wantCheck(t, verifyChecks(t, fleetInstallOK)[fleet.CheckGrants], fleet.Fail, "1 other editor or owner")
	})
	t.Run("the gateway may not read them", func(t *testing.T) {
		fakeKubectl(t, nil)
		substrateClusterAPI = func(context.Context, *substrateClusterFlags, apiTarget) (clusterAPIReader, error) {
			return deniedReader{}, nil
		}
		wantCheck(t, verifyChecks(t, fleetInstallOK)[fleet.CheckGrants], fleet.Warn, "it needs the global viewer grant")
	})
	t.Run("no token or no port-forward is a warning with the reason", func(t *testing.T) {
		fakeKubectl(t, nil)
		substrateClusterAPI = func(context.Context, *substrateClusterFlags, apiTarget) (clusterAPIReader, error) {
			return nil, errors.New("no token for the gateway ServiceAccount: serviceaccounts \"defenseclaw-gateway\" is forbidden")
		}
		wantCheck(t, verifyChecks(t, fleetInstallOK)[fleet.CheckGrants], fleet.Warn, "no token for the gateway ServiceAccount")
	})
}

type deniedReader struct{}

func (deniedReader) GetAccessPolicy(context.Context, string) (*setup.AccessPolicy, error) {
	return nil, status.Error(codes.PermissionDenied, "not a viewer")
}
func (deniedReader) Actors(context.Context) ([]fleetActor, error) {
	return nil, status.Error(codes.PermissionDenied, "not a viewer")
}
func (deniedReader) Templates(context.Context) (int, error) {
	return 0, status.Error(codes.PermissionDenied, "not a viewer")
}
func (deniedReader) Close() error { return nil }

func TestVerifyProbesTheActorListener(t *testing.T) {
	t.Run("only actor routes", func(t *testing.T) {
		fakeKubectl(t, nil)
		wantCheck(t, verifyChecks(t, fleetInstallOK)[fleet.CheckActorRoutes], fleet.Pass, "only actor routes (8 of")
	})
	t.Run("an admin route on the actor listener fails", func(t *testing.T) {
		fakeKubectl(t, nil)
		leaky := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if fleet.ActorRouteAllowed(r.RequestURI) || r.RequestURI == "/api/v1/substrate/actors" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		t.Cleanup(leaky.Close)
		substratePortForward = func(context.Context, *substrateClusterFlags, string, string, int) (string, func(), error) {
			return strings.TrimPrefix(leaky.URL, "http://"), func() {}, nil
		}
		wantCheck(t, verifyChecks(t, fleetInstallOK)[fleet.CheckActorRoutes], fleet.Fail, "/api/v1/substrate/actors")
	})
	t.Run("no port-forward is a warning with the reason", func(t *testing.T) {
		fakeKubectl(t, nil)
		substratePortForward = func(context.Context, *substrateClusterFlags, string, string, int) (string, func(), error) {
			return "", nil, errors.New(`pods "x" is forbidden: cannot create resource "pods/portforward"`)
		}
		wantCheck(t, verifyChecks(t, fleetInstallOK)[fleet.CheckActorRoutes], fleet.Warn, "pods/portforward")
	})
}

func TestSubstrateAPITarget(t *testing.T) {
	a, err := substrateAPITarget("", "", "ate-system")
	if err != nil || a.namespace != "ate-system" || a.service != "api" || a.port != 443 || a.serverName != "api.ate-system.svc" {
		t.Fatalf("default = %+v, %v", a, err)
	}
	a, err = substrateAPITarget("api.sub.svc.cluster.local:8443", "", "")
	if err != nil || a.namespace != "sub" || a.port != 8443 || a.serverName != "api.sub.svc" {
		t.Fatalf("fqdn = %+v, %v", a, err)
	}
	if _, err := substrateAPITarget("api.example.com:443", "", ""); err == nil {
		t.Error("a host outside the cluster must not be port-forwarded")
	}
}

func TestCloudErrWordsNamesNoIdentity(t *testing.T) {
	got := cloudErrWords(errors.New("ERROR: (gcloud.storage.buckets.describe) HTTPError 403: ops@proj-1.iam.gserviceaccount.com does not have storage.buckets.get access"))
	if strings.Contains(got, "@") || !strings.Contains(got, "[identity]") || !strings.Contains(got, "HTTPError 403") {
		t.Errorf("gcloud words = %q", got)
	}
}
