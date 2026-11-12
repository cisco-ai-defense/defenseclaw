// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// InClusterDir is where the kubelet projects a pod's Kubernetes API token
// and CA.
const InClusterDir = "/var/run/secrets/kubernetes.io/serviceaccount"

// Kube is a small Kubernetes REST client for the hook steps: a few calls do
// not need client-go. It rereads the projected token on every request.
type Kube struct {
	base      string
	tokenFile string
	http      *http.Client
}

// NewInClusterKube builds a client from the pod's projected token and CA
// in dir and KUBERNETES_SERVICE_HOST/PORT.
func NewInClusterKube(dir string) (*Kube, error) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, errors.New("not in a Kubernetes pod: KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT are unset")
	}
	ca, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if err != nil {
		return nil, err
	}
	return NewKube("https://"+net.JoinHostPort(host, port), filepath.Join(dir, "token"), ca)
}

// NewKube builds a client for base with a bearer token file and CA bundle.
func NewKube(base, tokenFile string, caPEM []byte) (*Kube, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("kubernetes CA: no certificate")
	}
	return &Kube{
		base:      strings.TrimRight(base, "/"),
		tokenFile: tokenFile,
		http: &http.Client{
			Timeout:   30 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
		},
	}, nil
}

// apiError is a non-2xx Kubernetes API answer.
type apiError struct {
	Code    int
	Message string
}

func (e *apiError) Error() string { return fmt.Sprintf("kubernetes API %d: %s", e.Code, e.Message) }

func isNotFound(err error) bool {
	var ae *apiError
	return errors.As(err, &ae) && ae.Code == http.StatusNotFound
}

func (k *Kube) do(ctx context.Context, method, path, contentType string, body, out any) error {
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
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
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
		return &apiError{Code: resp.StatusCode, Message: st.Message}
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

type configMapObject struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Name            string `json:"name"`
		Namespace       string `json:"namespace"`
		ResourceVersion string `json:"resourceVersion,omitempty"`
	} `json:"metadata"`
	Data map[string]string `json:"data,omitempty"`
}

func cmPath(namespace, name string) string {
	return "/api/v1/namespaces/" + url.PathEscape(namespace) + "/configmaps/" + url.PathEscape(name)
}

// GetConfigMap implements KubeAPI.
func (k *Kube) GetConfigMap(ctx context.Context, namespace, name string) (*ConfigMap, error) {
	var obj configMapObject
	if err := k.do(ctx, http.MethodGet, cmPath(namespace, name), "", nil, &obj); err != nil {
		if isNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return &ConfigMap{Namespace: namespace, Name: name, ResourceVersion: obj.Metadata.ResourceVersion, Data: obj.Data}, nil
}

// UpdateConfigMap implements KubeAPI. The resource version is the
// precondition, so a concurrent edit fails instead of being overwritten.
func (k *Kube) UpdateConfigMap(ctx context.Context, cm *ConfigMap) error {
	obj := configMapObject{APIVersion: "v1", Kind: "ConfigMap", Data: cm.Data}
	obj.Metadata.Name, obj.Metadata.Namespace, obj.Metadata.ResourceVersion = cm.Name, cm.Namespace, cm.ResourceVersion
	return k.do(ctx, http.MethodPut, cmPath(cm.Namespace, cm.Name), "application/json", obj, nil)
}

// RestartDeployment implements KubeAPI the way kubectl rollout restart does.
func (k *Kube) RestartDeployment(ctx context.Context, namespace, name string) error {
	patch := map[string]any{"spec": map[string]any{"template": map[string]any{"metadata": map[string]any{
		"annotations": map[string]string{"kubectl.kubernetes.io/restartedAt": time.Now().UTC().Format(time.RFC3339)},
	}}}}
	return k.do(ctx, http.MethodPatch, deployPath(namespace, name), "application/strategic-merge-patch+json", patch, nil)
}

// DeleteSecret implements KubeAPI.
func (k *Kube) DeleteSecret(ctx context.Context, namespace, name string) error {
	path := "/api/v1/namespaces/" + url.PathEscape(namespace) + "/secrets/" + url.PathEscape(name)
	if err := k.do(ctx, http.MethodDelete, path, "", nil, nil); err != nil && !isNotFound(err) {
		return err
	}
	return nil
}

func deployPath(namespace, name string) string {
	return "/apis/apps/v1/namespaces/" + url.PathEscape(namespace) + "/deployments/" + url.PathEscape(name)
}

// ScaleDeployment implements KubeAPI through the scale subresource.
func (k *Kube) ScaleDeployment(ctx context.Context, namespace, name string, replicas int32) (int32, bool, error) {
	var cur struct {
		Spec struct {
			Replicas int32 `json:"replicas"`
		} `json:"spec"`
	}
	if err := k.do(ctx, http.MethodGet, deployPath(namespace, name)+"/scale", "", nil, &cur); err != nil {
		if isNotFound(err) {
			return 0, false, nil
		}
		return 0, false, err
	}
	patch := map[string]any{"spec": map[string]any{"replicas": replicas}}
	if err := k.do(ctx, http.MethodPatch, deployPath(namespace, name)+"/scale", "application/merge-patch+json", patch, nil); err != nil {
		return cur.Spec.Replicas, true, err
	}
	return cur.Spec.Replicas, true, nil
}

// DeploymentPods implements KubeAPI.
func (k *Kube) DeploymentPods(ctx context.Context, namespace, name string) (int32, error) {
	var d struct {
		Status struct {
			Replicas int32 `json:"replicas"`
		} `json:"status"`
	}
	if err := k.do(ctx, http.MethodGet, deployPath(namespace, name), "", nil, &d); err != nil {
		if isNotFound(err) {
			return 0, nil
		}
		return 0, err
	}
	return d.Status.Replicas, nil
}
