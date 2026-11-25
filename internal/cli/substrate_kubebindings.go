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
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/defenseclaw/defenseclaw/internal/substrate/secretbind"
)

// kubeBindingsKey is the ConfigMap key of the binding store.
const kubeBindingsKey = "bindings.json"

// kubeBindings is the secretbind.Backend over one ConfigMap the chart
// creates (defenseclaw-secret-bindings in the release namespace). The
// gateway's Role allows only get and update on that one name, so the
// writer never creates it: a missing ConfigMap is secretbind.ErrNoStore,
// which the doctor reports as a chart from before the store. An update
// sends the object it read back with only the key changed, so the chart's
// labels and annotations stay and Helm keeps owning the object.
type kubeBindings struct {
	k        *kubeSecrets
	ns, name string
}

func (b kubeBindings) read(ctx context.Context) (map[string]any, error) {
	code, raw, err := b.k.doResource(ctx, http.MethodGet, "configmaps", b.ns, b.name, "", nil)
	switch {
	case err != nil:
		return nil, err
	case code == http.StatusNotFound:
		return nil, secretbind.ErrNoStore
	case code != http.StatusOK:
		return nil, fmt.Errorf("get configmap %s/%s: HTTP %d", b.ns, b.name, code)
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, fmt.Errorf("get configmap %s/%s: unreadable answer", b.ns, b.name)
	}
	return obj, nil
}

func objVersion(obj map[string]any) string {
	md, _ := obj["metadata"].(map[string]any)
	v, _ := md["resourceVersion"].(string)
	return v
}

func (b kubeBindings) Get(ctx context.Context) ([]byte, string, bool, error) {
	obj, err := b.read(ctx)
	if err != nil {
		return nil, "", false, err
	}
	data, _ := obj["data"].(map[string]any)
	v, found := data[kubeBindingsKey].(string)
	return []byte(v), objVersion(obj), found, nil
}

func (b kubeBindings) Put(ctx context.Context, raw []byte, version string) error {
	obj, err := b.read(ctx)
	if err != nil {
		return err
	}
	if version == "" || objVersion(obj) != version {
		return secretbind.ErrConflict
	}
	data, _ := obj["data"].(map[string]any)
	if data == nil {
		data = map[string]any{}
	}
	data[kubeBindingsKey] = string(raw)
	obj["data"] = data
	body, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	code, _, err := b.k.doResource(ctx, http.MethodPut, "configmaps", b.ns, b.name, "application/json", body)
	switch {
	case err != nil:
		return err
	case code == http.StatusConflict:
		return secretbind.ErrConflict
	case code != http.StatusOK:
		return fmt.Errorf("update configmap %s/%s: HTTP %d", b.ns, b.name, code)
	}
	return nil
}
