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

package image

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

const maxExportedHosts = 1 << 20

// exportedHosts is the /etc/hosts entry in the container export OpenShell
// uses to make the VM disk. Docker's build stage can carry different bytes.
type exportedHosts struct {
	present  bool
	typeflag byte
	data     []byte
	link     string
}

func (h exportedHosts) initializedByGuest() bool {
	return !h.present || (h.typeflag == tar.TypeReg && len(h.data) == 0)
}

func parseExportedHosts(r io.Reader) (exportedHosts, error) {
	var result exportedHosts
	tr := tar.NewReader(r)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return result, nil
		}
		if err != nil {
			return result, fmt.Errorf("read exported image: %w", err)
		}
		name := strings.TrimPrefix(h.Name, "./")
		if name != "etc/hosts" {
			continue
		}
		if result.present {
			return result, errors.New("exported image has more than one /etc/hosts entry")
		}
		result.present = true
		result.typeflag = h.Typeflag
		switch h.Typeflag {
		case tar.TypeReg, tar.TypeRegA:
			if h.Size < 0 || h.Size > maxExportedHosts {
				return result, errors.New("exported image /etc/hosts is too large to check")
			}
			result.typeflag = tar.TypeReg
			result.data, err = io.ReadAll(io.LimitReader(tr, maxExportedHosts+1))
			if err != nil {
				return result, fmt.Errorf("read exported image /etc/hosts: %w", err)
			}
		case tar.TypeSymlink:
			if len(h.Linkname) == 0 || len(h.Linkname) > 4096 || strings.ContainsRune(h.Linkname, 0) {
				return result, errors.New("exported image /etc/hosts has an invalid link")
			}
			result.link = h.Linkname
		default:
			return result, errors.New("exported image /etc/hosts is not a regular file or symbolic link")
		}
	}
}

// exportHosts reads the same container export that OpenShell makes for the
// local VM root disk. The stream is parsed as it arrives, without retaining
// the image tar, and the temporary container is removed before return.
func (b *Builder) exportHosts(ctx context.Context, tag string) (hosts exportedHosts, err error) {
	id, err := output(ctx, b.Docker, nil, "create", tag)
	if err != nil {
		return hosts, fmt.Errorf("create export container for %s: %w", tag, err)
	}
	if len(id) != 64 {
		return hosts, fmt.Errorf("docker returned an invalid export container ID for %s", tag)
	}
	for _, ch := range id {
		if ch < '0' || (ch > '9' && ch < 'a') || ch > 'f' {
			return hosts, fmt.Errorf("docker returned an invalid export container ID for %s", tag)
		}
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if _, removeErr := output(cleanup, b.Docker, nil, "rm", "-f", id); removeErr != nil {
			err = errors.Join(err, fmt.Errorf("remove export container for %s: %w", tag, removeErr))
		}
	}()
	pr, pw := io.Pipe()
	finished := make(chan error, 1)
	go func() {
		exportErr := b.Docker.Run(ctx, nil, pw, io.Discard, "export", id)
		_ = pw.CloseWithError(exportErr)
		finished <- exportErr
	}()
	hosts, err = parseExportedHosts(pr)
	if err == nil {
		_, err = io.Copy(io.Discard, pr)
	}
	_ = pr.CloseWithError(err)
	exportErr := <-finished
	if exportErr != nil {
		err = errors.Join(err, fmt.Errorf("export image %s: %w", tag, exportErr))
	}
	return hosts, err
}

// verifyExportedResolver checks a nonempty exported hosts file against the
// completed image's libc and NSS configuration with build networking off.
// Missing and empty regular files use OpenShell guest initialization.
func (b *Builder) verifyExportedResolver(ctx context.Context, c *Context) (err error) {
	hosts, err := b.exportHosts(ctx, c.Tag)
	if err != nil {
		return fmt.Errorf("MicroVM image %s localhost check: %w", c.Tag, err)
	}
	if hosts.initializedByGuest() {
		return nil
	}
	var layer bytes.Buffer
	tw := tar.NewWriter(&layer)
	h := &tar.Header{Name: "etc/hosts", Mode: 0o644, Typeflag: hosts.typeflag, Linkname: hosts.link}
	if hosts.typeflag == tar.TypeReg {
		h.Size = int64(len(hosts.data))
	}
	if err := tw.WriteHeader(h); err != nil {
		return err
	}
	if hosts.typeflag == tar.TypeReg {
		if _, err := tw.Write(hosts.data); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	nonce, err := randomHex(4)
	if err != nil {
		return err
	}
	checkTag := c.Tag + "-resolver-" + nonce
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if _, removeErr := output(cleanup, b.Docker, nil, "image", "rm", "-f", checkTag); removeErr != nil && err == nil {
			err = fmt.Errorf("remove temporary resolver image: %w", removeErr)
		}
	}()
	file := microVMResolverToolStage() + "FROM " + c.Tag + " AS dc-complete\nADD hosts.tar /\n" + microVMResolverStep(c.Spec.BaseImage)
	files := []ContextFile{{Name: "Dockerfile", Mode: 0o644, Data: []byte(file)},
		{Name: "hosts.tar", Mode: 0o644, Data: layer.Bytes()},
		{Name: "localhost-resolver.c", Mode: 0o644, Data: microVMResolverSource}}
	if err := buildImage(ctx, b.Docker, files, nil, checkTag, b.Log); err != nil {
		return fmt.Errorf("MicroVM image %s localhost check: %w", c.Tag, err)
	}
	return nil
}
