// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package setuppayload

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// payloadBindingDomain separates this digest from every other SHA-256 the
// build computes, and versions its layout.
const payloadBindingDomain = "defenseclaw-setup-payload-binding/v2"

// PayloadIdentity is the trailer manifest identity a payload binding
// covers besides the file digests. The lifecycle acts on these values (the
// version decides upgrade, compliant or downgrade refusal and is recorded
// for later checks), so they are bound to the image like the bytes are.
type PayloadIdentity struct {
	DistributionFlavor string
	Version            string
	SourceCommit       string
}

// PayloadBinding returns the hex SHA-256 that binds a standalone Setup image
// to the payload it was built with: the distribution flavor, the release
// version and source commit the trailer manifest records, and the SHA-256
// of every payload file, in byte order of the file names. The identity
// values are quoted, so no value can run into the next line.
//
// packaging/windows/standalone/build-setup.sh computes it from the payload
// directory and the values it hands the assembler (windows-repro-manifest
// payload-binding) and links it into the outer Setup image. At run time the
// Setup computes it again from the manifest of the trailer it read and
// refuses a payload that does not match, so the payload and the identity it
// acts on are the ones its own image was built for, whatever file it read
// the trailer from.
//
// files maps a payload file name to its hex SHA-256 (either case).
func PayloadBinding(identity PayloadIdentity, files map[string]string) string {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	digest := sha256.New()
	fmt.Fprintf(digest, "%s\nflavor=%s\nversion=%s\nsource_commit=%s\n", payloadBindingDomain,
		strconv.Quote(identity.DistributionFlavor), strconv.Quote(identity.Version), strconv.Quote(identity.SourceCommit))
	for _, name := range names {
		fmt.Fprintf(digest, "%s %s\n", strings.ToLower(files[name]), name)
	}
	return hex.EncodeToString(digest.Sum(nil))
}
