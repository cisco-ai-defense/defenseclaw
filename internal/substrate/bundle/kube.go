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

package bundle

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ConfigMap is the part of a Kubernetes ConfigMap this package uses.
type ConfigMap struct {
	Name            string
	ResourceVersion string
	Data            map[string]string
	BinaryData      map[string][]byte
}

// ErrConflict is a write whose resource version is no longer current.
var ErrConflict = errors.New("bundle: the ConfigMap changed under this write")

// ConfigMaps reads and writes ConfigMaps of one namespace. Get returns nil,
// nil for a missing ConfigMap; Update fails with ErrConflict when the
// resource version is stale, Create when the ConfigMap exists.
type ConfigMaps interface {
	Get(ctx context.Context, name string) (*ConfigMap, error)
	Create(ctx context.Context, cm *ConfigMap) error
	Update(ctx context.Context, cm *ConfigMap) error
}

// MemoryConfigMaps is an in-process ConfigMaps (tests, dry runs).
type MemoryConfigMaps struct {
	mu sync.Mutex
	m  map[string]*ConfigMap
	rv int
}

// NewMemoryConfigMaps returns an empty MemoryConfigMaps.
func NewMemoryConfigMaps() *MemoryConfigMaps { return &MemoryConfigMaps{m: map[string]*ConfigMap{}} }

func cloneCM(cm *ConfigMap) *ConfigMap {
	out := &ConfigMap{Name: cm.Name, ResourceVersion: cm.ResourceVersion, Data: maps.Clone(cm.Data), BinaryData: map[string][]byte{}}
	for k, v := range cm.BinaryData {
		out.BinaryData[k] = bytes.Clone(v)
	}
	return out
}

func (m *MemoryConfigMaps) Get(_ context.Context, name string) (*ConfigMap, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cm, ok := m.m[name]
	if !ok {
		return nil, nil
	}
	return cloneCM(cm), nil
}

func (m *MemoryConfigMaps) Create(_ context.Context, cm *ConfigMap) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.m[cm.Name]; ok {
		return ErrConflict
	}
	m.rv++
	c := cloneCM(cm)
	c.ResourceVersion = strconv.Itoa(m.rv)
	m.m[cm.Name] = c
	return nil
}

func (m *MemoryConfigMaps) Update(_ context.Context, cm *ConfigMap) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.m[cm.Name]
	if !ok || cur.ResourceVersion != cm.ResourceVersion {
		return ErrConflict
	}
	m.rv++
	c := cloneCM(cm)
	c.ResourceVersion = strconv.Itoa(m.rv)
	m.m[cm.Name] = c
	return nil
}

// Put sets a ConfigMap as another writer would (tests: GitOps, tamper).
func (m *MemoryConfigMaps) Put(cm *ConfigMap) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rv++
	c := cloneCM(cm)
	c.ResourceVersion = strconv.Itoa(m.rv)
	m.m[cm.Name] = c
}

// InClusterDir is where the kubelet projects a pod's API token and CA.
const InClusterDir = "/var/run/secrets/kubernetes.io/serviceaccount"

// Kube is a ConfigMaps over the Kubernetes REST API (no client-go). It
// rereads the bearer token on every request.
type Kube struct {
	base, namespace, tokenFile string
	http                       *http.Client
}

// NewInClusterKube builds a client from the pod's projected token and CA.
func NewInClusterKube(namespace string) (*Kube, error) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, errors.New("not in a Kubernetes pod: KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT are unset (pass --kube-api, --kube-token-file and --kube-ca)")
	}
	return NewKube("https://"+net.JoinHostPort(host, port), namespace, filepath.Join(InClusterDir, "token"), filepath.Join(InClusterDir, "ca.crt"))
}

// NewKube builds a client for the API server base with a token file and a
// CA bundle file.
func NewKube(base, namespace, tokenFile, caFile string) (*Kube, error) {
	if namespace == "" {
		return nil, errors.New("no namespace: pass --namespace or set POD_NAMESPACE")
	}
	ca, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("kubernetes CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, errors.New("kubernetes CA: no certificate")
	}
	return &Kube{base: strings.TrimRight(base, "/"), namespace: namespace, tokenFile: tokenFile, http: &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
	}}, nil
}

type cmObject struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Name            string            `json:"name"`
		Namespace       string            `json:"namespace"`
		ResourceVersion string            `json:"resourceVersion,omitempty"`
		Labels          map[string]string `json:"labels,omitempty"`
	} `json:"metadata"`
	Data       map[string]string `json:"data,omitempty"`
	BinaryData map[string][]byte `json:"binaryData,omitempty"`
}

type statusError struct {
	code int
	msg  string
}

func (e *statusError) Error() string { return fmt.Sprintf("kubernetes API %d: %s", e.code, e.msg) }

func (k *Kube) do(ctx context.Context, method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, k.base+path, rd)
	if err != nil {
		return err
	}
	token, err := os.ReadFile(k.tokenFile)
	if err != nil {
		return fmt.Errorf("kubernetes token: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := k.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		var st struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(data, &st)
		return &statusError{code: resp.StatusCode, msg: st.Message}
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

func (k *Kube) path(name string) string {
	p := "/api/v1/namespaces/" + url.PathEscape(k.namespace) + "/configmaps"
	if name != "" {
		p += "/" + url.PathEscape(name)
	}
	return p
}

func (k *Kube) Get(ctx context.Context, name string) (*ConfigMap, error) {
	var obj cmObject
	if err := k.do(ctx, http.MethodGet, k.path(name), nil, &obj); err != nil {
		var se *statusError
		if errors.As(err, &se) && se.code == http.StatusNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &ConfigMap{Name: name, ResourceVersion: obj.Metadata.ResourceVersion, Data: obj.Data, BinaryData: obj.BinaryData}, nil
}

func (k *Kube) object(cm *ConfigMap) cmObject {
	obj := cmObject{APIVersion: "v1", Kind: "ConfigMap", Data: cm.Data, BinaryData: cm.BinaryData}
	obj.Metadata.Name, obj.Metadata.Namespace, obj.Metadata.ResourceVersion = cm.Name, k.namespace, cm.ResourceVersion
	obj.Metadata.Labels = map[string]string{"app.kubernetes.io/part-of": "defenseclaw", "app.kubernetes.io/component": "bundles"}
	return obj
}

func conflict(err error) error {
	var se *statusError
	if errors.As(err, &se) && se.code == http.StatusConflict {
		return ErrConflict
	}
	return err
}

func (k *Kube) Create(ctx context.Context, cm *ConfigMap) error {
	return conflict(k.do(ctx, http.MethodPost, k.path(""), k.object(cm), nil))
}

func (k *Kube) Update(ctx context.Context, cm *ConfigMap) error {
	return conflict(k.do(ctx, http.MethodPut, k.path(cm.Name), k.object(cm), nil))
}
