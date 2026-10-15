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

package mqtt

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"os"
)

// buildTLSConfig constructs the broker TLS settings from the configured CA
// and client certificate. Certificate verification cannot be disabled in
// production mode.
func buildTLSConfig() (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if skip := os.Getenv("DCLAW_TLS_SKIP_VERIFY"); skip == "true" || skip == "1" {
		if isProductionMode() {
			log.Printf("[mqtt] WARNING: DCLAW_TLS_SKIP_VERIFY ignored in production mode — certificate verification enforced")
		} else {
			cfg.InsecureSkipVerify = true
		}
	}
	if caPath := os.Getenv("DCLAW_TLS_CA_CERT"); caPath != "" {
		caCert, err := os.ReadFile(caPath)
		if err != nil {
			return nil, fmt.Errorf("read CA cert %s: %w", caPath, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA cert from %s", caPath)
		}
		cfg.RootCAs = pool
	}
	certPath := os.Getenv("DCLAW_TLS_CLIENT_CERT")
	keyPath := os.Getenv("DCLAW_TLS_CLIENT_KEY")
	if certPath != "" && keyPath != "" {
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, fmt.Errorf("load client cert/key (%s, %s): %w", certPath, keyPath, err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	return cfg, nil
}
