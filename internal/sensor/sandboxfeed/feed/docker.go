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

package feed

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/sensor/sandboxfeed"
)

// dockerReplyLimit bounds one Docker Engine answer (an inspect is 10-30 KB).
const dockerReplyLimit = 4 << 20

// DockerInspector reads container labels from the Docker Engine API on its
// unix socket: GET /containers/{id}/json and GET /containers/json filtered by
// the sandbox id label. Read only; nothing else is asked.
type DockerInspector struct {
	// Socket is the Engine socket (sandboxfeed.DefaultDockerSocket when
	// empty).
	Socket string

	once   sync.Once
	client *http.Client
}

func (d *DockerInspector) http() *http.Client {
	d.once.Do(func() {
		socket := d.Socket
		if socket == "" {
			socket = sandboxfeed.DefaultDockerSocket
		}
		d.client = &http.Client{Transport: &http.Transport{
			Proxy: nil,
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var dialer net.Dialer
				return dialer.DialContext(ctx, "unix", socket)
			},
			MaxIdleConns: 2, DisableCompression: true,
		}}
	})
	return d.client
}

// Inspect reads one container. id is a container id or unique prefix (the
// caller checked it is hex).
func (d *DockerInspector) Inspect(ctx context.Context, id string) (ContainerLabels, error) {
	var reply struct {
		ID     string `json:"Id"`
		Config struct {
			Labels map[string]string `json:"Labels"`
		} `json:"Config"`
	}
	if err := d.get(ctx, "/containers/"+url.PathEscape(id)+"/json", &reply); err != nil {
		return ContainerLabels{}, err
	}
	return ContainerLabels{ID: reply.ID, Labels: reply.Config.Labels}, nil
}

// Sandbox lists the containers of one OpenShell sandbox.
func (d *DockerInspector) Sandbox(ctx context.Context, sandboxID string) ([]ContainerLabels, error) {
	filters, err := json.Marshal(map[string][]string{"label": {LabelSandboxID + "=" + sandboxID}})
	if err != nil {
		return nil, err
	}
	var reply []struct {
		ID     string            `json:"Id"`
		Labels map[string]string `json:"Labels"`
	}
	if err := d.get(ctx, "/containers/json?all=1&filters="+url.QueryEscape(string(filters)), &reply); err != nil {
		return nil, err
	}
	out := make([]ContainerLabels, 0, len(reply))
	for _, c := range reply {
		out = append(out, ContainerLabels{ID: c.ID, Labels: c.Labels})
	}
	return out, nil
}

func (d *DockerInspector) get(ctx context.Context, path string, into any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker"+path, nil)
	if err != nil {
		return err
	}
	response, err := d.http().Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	body := io.LimitReader(response.Body, dockerReplyLimit)
	switch {
	case response.StatusCode == http.StatusNotFound:
		_, _ = io.Copy(io.Discard, body)
		return ErrNoSuchContainer
	case response.StatusCode != http.StatusOK:
		_, _ = io.Copy(io.Discard, body)
		return fmt.Errorf("sandbox feed: docker answered %s for %s", response.Status, path)
	}
	return json.NewDecoder(body).Decode(into)
}

// Ping asks the Engine whether it is up (GET /_ping).
func (d *DockerInspector) Ping(ctx context.Context) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/_ping", nil)
	if err != nil {
		return err
	}
	response, err := d.http().Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1024))
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("docker answered %s", response.Status)
	}
	return nil
}
