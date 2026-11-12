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
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

// The admin listener's certificate for names outside the cluster (chart
// admin.tlsSecretName, for a LoadBalancer): laptops do not trust the
// in-cluster serving certificate for an external name (GAP-0086).
var substrateAdminTLSFlags struct {
	cert, key string
}

func init() {
	f := serveCmd.Flags()
	f.StringVar(&substrateAdminTLSFlags.cert, "admin-tls-cert", "", "admin listener certificate (PEM) for external names; default the serving bundle")
	f.StringVar(&substrateAdminTLSFlags.key, "admin-tls-key", "", "key of --admin-tls-cert")
}

// substrateAdminTLS is the admin listener's TLS: the serving config, or a
// key pair re-read when its files change (a Secret rotation).
func substrateAdminTLS(serving *tls.Config) (*tls.Config, error) {
	cert, key := substrateAdminTLSFlags.cert, substrateAdminTLSFlags.key
	if cert == "" && key == "" {
		return serving, nil
	}
	if cert == "" || key == "" {
		return nil, errors.New("--admin-tls-cert and --admin-tls-key go together")
	}
	r := &reloadingKeyPair{cert: cert, key: key}
	if _, err := r.get(); err != nil {
		return nil, err
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return r.get() }}, nil
}

type reloadingKeyPair struct {
	cert, key string

	mu   sync.Mutex
	mod  time.Time
	pair *tls.Certificate
}

func (r *reloadingKeyPair) get() (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	fi, err := os.Stat(r.cert)
	if err != nil {
		if r.pair != nil {
			return r.pair, nil // keep serving the last good pair
		}
		return nil, fmt.Errorf("admin TLS certificate: %w", err)
	}
	if r.pair != nil && fi.ModTime().Equal(r.mod) {
		return r.pair, nil
	}
	pair, err := tls.LoadX509KeyPair(r.cert, r.key)
	if err != nil {
		if r.pair != nil {
			return r.pair, nil
		}
		return nil, fmt.Errorf("admin TLS key pair: %w", err)
	}
	r.pair, r.mod = &pair, fi.ModTime()
	return r.pair, nil
}
