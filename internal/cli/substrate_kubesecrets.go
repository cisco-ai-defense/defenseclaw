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
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway"
)

// kubeSecrets writes single keys of Kubernetes Secrets through the API
// server with the gateway's ServiceAccount token (the secrets admin API,
// `secrets set --mine`). It never logs or returns a value.
//
// The chart's defenseclaw-gateway-secrets Role grants create, get and patch
// on Secrets only in the namespaces substrate.secrets names (get and patch
// by name where the Secret name has no {person}). RBAC cannot select by
// label, so the ownership is checked here: an existing Secret is changed
// only when it carries the managed-by label this writer puts on the Secrets
// it creates, and the patch names the resourceVersion that check read, so a
// Secret relabelled in between is not written either (substrate-1 GAP-0183).
type kubeSecrets struct {
	server    string
	tokenFile string
	http      *http.Client
}

// kubeManagedByLabel and kubeManagedBy mark the Secrets this writer created.
const (
	kubeManagedByLabel = "app.kubernetes.io/managed-by"
	kubeManagedBy      = "defenseclaw"
)

// kubeSecret is the part of a Secret the writer reads.
type kubeSecret struct {
	Metadata struct {
		ResourceVersion string            `json:"resourceVersion"`
		Labels          map[string]string `json:"labels"`
	} `json:"metadata"`
	Data map[string]string `json:"data"`
}

var kubeNameRE = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$`)
var kubeKeyRE = regexp.MustCompile(`^[-._a-zA-Z0-9]{1,253}$`)

func (k *kubeSecrets) do(ctx context.Context, method, ns, name, ctype string, body []byte) (int, []byte, error) {
	if !kubeNameRE.MatchString(ns) || !kubeNameRE.MatchString(name) {
		return 0, nil, fmt.Errorf("secret %s/%s is not a Kubernetes name", ns, name)
	}
	u := k.server + "/api/v1/namespaces/" + url.PathEscape(ns) + "/secrets"
	if method != http.MethodPost {
		u += "/" + url.PathEscape(name)
	}
	tok, err := os.ReadFile(k.tokenFile)
	if err != nil {
		return 0, nil, fmt.Errorf("kube token: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(tok)))
	req.Header.Set("Accept", "application/json")
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	resp, err := k.http.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, raw, nil
}

// get reads the Secret; found is false when it does not exist.
func (k *kubeSecrets) get(ctx context.Context, ns, name string) (found bool, s kubeSecret, err error) {
	code, raw, err := k.do(ctx, http.MethodGet, ns, name, "", nil)
	switch {
	case err != nil:
		return false, s, err
	case code == http.StatusNotFound:
		return false, s, nil
	case code != http.StatusOK:
		return false, s, fmt.Errorf("get secret %s/%s: HTTP %d", ns, name, code)
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		return false, s, fmt.Errorf("get secret %s/%s: unreadable answer", ns, name)
	}
	return true, s, nil
}

// owned refuses a Secret DefenseClaw did not create.
func owned(ns, name string, s kubeSecret) error {
	if s.Metadata.Labels[kubeManagedByLabel] != kubeManagedBy {
		return fmt.Errorf("secret %s/%s: %w", ns, name, gateway.ErrSubstrateSecretNotOwned)
	}
	return nil
}

// patch merges data into the Secret at the resourceVersion the ownership
// check read (a conflict is an error, never a blind write).
func (k *kubeSecrets) patch(ctx context.Context, ns, name, rv string, data map[string]any) (int, error) {
	body, _ := json.Marshal(map[string]any{"metadata": map[string]any{"resourceVersion": rv}, "data": data})
	code, _, err := k.do(ctx, http.MethodPatch, ns, name, "application/merge-patch+json", body)
	return code, err
}

func (k *kubeSecrets) Exists(ctx context.Context, ns, name, key string) (bool, error) {
	found, s, err := k.get(ctx, ns, name)
	return found && s.Data[key] != "", err
}

func (k *kubeSecrets) Set(ctx context.Context, ns, name, key string, value []byte) error {
	if !kubeKeyRE.MatchString(key) {
		return fmt.Errorf("secret key %q is not valid", key)
	}
	enc := base64.StdEncoding.EncodeToString(value)
	found, s, err := k.get(ctx, ns, name)
	if err != nil {
		return err
	}
	var code int
	if found {
		if err := owned(ns, name, s); err != nil {
			return err
		}
		code, err = k.patch(ctx, ns, name, s.Metadata.ResourceVersion, map[string]any{key: enc})
	} else {
		obj, _ := json.Marshal(map[string]any{
			"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
			"metadata": map[string]any{"name": name, "namespace": ns,
				"labels": map[string]string{kubeManagedByLabel: kubeManagedBy}},
			"data": map[string]string{key: enc},
		})
		code, _, err = k.do(ctx, http.MethodPost, ns, name, "application/json", obj)
	}
	if err != nil {
		return err
	}
	if code/100 != 2 {
		return fmt.Errorf("write secret %s/%s: HTTP %d", ns, name, code)
	}
	return nil
}

func (k *kubeSecrets) Remove(ctx context.Context, ns, name, key string) error {
	found, s, err := k.get(ctx, ns, name)
	if err != nil || !found {
		return err
	}
	if err := owned(ns, name, s); err != nil {
		return err
	}
	code, err := k.patch(ctx, ns, name, s.Metadata.ResourceVersion, map[string]any{key: nil})
	if err != nil {
		return err
	}
	if code/100 != 2 && code != http.StatusNotFound {
		return fmt.Errorf("remove from secret %s/%s: HTTP %d", ns, name, code)
	}
	return nil
}
