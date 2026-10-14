// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package enterprisebundle

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"time"
)

// WriteArchive writes b as a .dcbundle (tar inside gzip): manifest.json,
// manifest.sig, then every file in path order, each a regular 0644 file
// owned by uid 0 with a fixed time, and no gzip name or time, so the same
// bundle always gives the same bytes. ReadArchive reads it back.
func WriteArchive(w io.Writer, b *Bundle) error {
	gz, err := gzip.NewWriterLevel(w, gzip.BestCompression)
	if err != nil {
		return err
	}
	tw := tar.NewWriter(gz)
	put := func(name string, data []byte) error {
		hdr := &tar.Header{
			Typeflag: tar.TypeReg,
			Name:     name,
			Mode:     0o644,
			Size:     int64(len(data)),
			ModTime:  time.Unix(0, 0).UTC(),
			Format:   tar.FormatUSTAR,
		}
		if len(name) > 100 {
			hdr.Format = tar.FormatPAX
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		_, err := tw.Write(data)
		return err
	}
	if b.Manifest != nil {
		if err := put(ManifestName, b.Manifest); err != nil {
			return err
		}
	}
	if b.Signature != nil {
		if err := put(SignatureName, b.Signature); err != nil {
			return err
		}
	}
	for _, name := range b.Paths() {
		if err := put(name, b.Files[name]); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}
