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
)

// kubeSecrets writes single keys of Kubernetes Secrets through the API
// server with the gateway's ServiceAccount token (the secrets admin API,
// `secrets set --mine`). It never logs or returns a value. The chart grants
// get/create/patch on Secrets only in the namespaces substrate.secrets
// names.
type kubeSecrets struct {
	server    string
	tokenFile string
	http      *http.Client
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

func (k *kubeSecrets) Exists(ctx context.Context, ns, name, key string) (bool, error) {
	code, raw, err := k.do(ctx, http.MethodGet, ns, name, "", nil)
	switch {
	case err != nil:
		return false, err
	case code == http.StatusNotFound:
		return false, nil
	case code != http.StatusOK:
		return false, fmt.Errorf("get secret %s/%s: HTTP %d", ns, name, code)
	}
	var s struct {
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		return false, fmt.Errorf("get secret %s/%s: unreadable answer", ns, name)
	}
	return s.Data[key] != "", nil
}

func (k *kubeSecrets) Set(ctx context.Context, ns, name, key string, value []byte) error {
	if !kubeKeyRE.MatchString(key) {
		return fmt.Errorf("secret key %q is not valid", key)
	}
	enc := base64.StdEncoding.EncodeToString(value)
	patch, _ := json.Marshal(map[string]any{"data": map[string]string{key: enc}})
	code, _, err := k.do(ctx, http.MethodPatch, ns, name, "application/merge-patch+json", patch)
	if err != nil {
		return err
	}
	if code == http.StatusNotFound {
		obj, _ := json.Marshal(map[string]any{
			"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
			"metadata": map[string]any{"name": name, "namespace": ns,
				"labels": map[string]string{"app.kubernetes.io/managed-by": "defenseclaw"}},
			"data": map[string]string{key: enc},
		})
		code, _, err = k.do(ctx, http.MethodPost, ns, name, "application/json", obj)
		if err != nil {
			return err
		}
	}
	if code/100 != 2 {
		return fmt.Errorf("write secret %s/%s: HTTP %d", ns, name, code)
	}
	return nil
}

func (k *kubeSecrets) Remove(ctx context.Context, ns, name, key string) error {
	patch, _ := json.Marshal(map[string]any{"data": map[string]any{key: nil}})
	code, _, err := k.do(ctx, http.MethodPatch, ns, name, "application/merge-patch+json", patch)
	if err != nil {
		return err
	}
	if code/100 != 2 && code != http.StatusNotFound {
		return fmt.Errorf("remove from secret %s/%s: HTTP %d", ns, name, code)
	}
	return nil
}
