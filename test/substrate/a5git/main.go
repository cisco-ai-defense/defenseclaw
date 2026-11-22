// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// a5git is the git remote of the A5 E8 cell: git smart HTTP (git
// http-backend) that takes a push only with the Basic credential in
// GIT_AUTH_FILE, so a push from an actor succeeds only when Substrate egress
// swapped the kit's placeholder for the real credential. It serves https
// with the pod's servicedns certificate when TLS_BUNDLE is set, and http.
package main

import (
	"crypto/subtle"
	"crypto/tls"
	"encoding/pem"
	"log"
	"net/http"
	"net/http/cgi"
	"os"
	"strings"
)

func main() {
	root := envOr("GIT_PROJECT_ROOT", "/srv/git")
	backend := envOr("GIT_HTTP_BACKEND", "/usr/libexec/git-core/git-http-backend")
	want, _ := os.ReadFile(os.Getenv("GIT_AUTH_FILE"))
	h := &cgi.Handler{Path: backend, Env: []string{"GIT_PROJECT_ROOT=" + root, "GIT_HTTP_EXPORT_ALL=1", "REMOTE_USER=a5"}}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Basic ")
		ok := len(want) > 0 && subtle.ConstantTimeCompare([]byte(got), []byte(strings.TrimSpace(string(want)))) == 1
		kind := "none"
		switch {
		case ok:
			kind = "real"
		case got != "":
			kind = "other"
		}
		log.Printf("%s %s %s auth=%s", r.Method, r.URL.Path, r.URL.RawQuery, kind)
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="a5git"`)
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(w, r)
	})
	if b := os.Getenv("TLS_BUNDLE"); b != "" {
		go func() {
			cert, err := loadBundle(b)
			if err != nil {
				log.Fatalf("tls bundle: %v", err)
			}
			srv := &http.Server{Addr: ":8443", Handler: handler, TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}}}
			log.Fatal(srv.ListenAndServeTLS("", ""))
		}()
	}
	log.Fatal(http.ListenAndServe(":8080", handler))
}

// loadBundle reads a PEM credential bundle (key and certificate chain).
func loadBundle(path string) (tls.Certificate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return tls.Certificate{}, err
	}
	var certs, key []byte
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			break
		}
		if strings.Contains(blk.Type, "PRIVATE KEY") {
			key = pem.EncodeToMemory(blk)
		} else {
			certs = append(certs, pem.EncodeToMemory(blk)...)
		}
	}
	return tls.X509KeyPair(certs, key)
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
