// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"slices"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// credentialPathReadsWhole is the size up to which the secret-read chain's
// private record is kept whole (thinCredentialPathReads): a call that reads
// a few credentials files keeps every read. A variable so the differential
// tests can thin every record (0) or none.
var credentialPathReadsWhole = 16

// thinCredentialPathReads drops, of the call's private record, every read
// that no check of the chain can tell from the reads it keeps
// (substrate-1:GAP-0674). A recursive search of a deep tree finds hundreds
// of credentials files with paths thousands of bytes long, and the facts of
// the call stay alive behind every check that follows the resolve, until the
// verdict is written: on a Windows replay of 2,048 such calls the records of
// the calls waiting for their checks held about 116 MB.
//
// The record is read only by credentialFileContentRead,
// exactSecretReadChainDigest, credentialFileReadProofDigest,
// hasUnplacedRelativePath, the projection's HasCredentialPathReads and the
// placement (PlaceCredentialPathReads); TestGAP0674ThinReadsCensus keeps it
// so. Each asks whether the record has a read, a read that is no fixture, a
// file-unknown marker, a read the hook places, and whether the identities of
// its reads (secretReadPathIdentity) are all exact and all one, and which one.
// Those answers stay the same when a read is dropped whose identity is one a
// kept read already has, and when two different identities or one that is
// not exact are already kept: no later read can make the reads all exact and
// all one again. chainDistinctCredentialReads marks, in order, the reads that
// add such an answer, for the reads the secret-read digest counts and for
// all reads that are no fixture, both for a call proven to keep its folder
// and for one that is not (a relative read is then not exact), so the marks
// do not depend on which facts read the record. Markers, reads the hook
// places later (CredentialReadPlaceable) and the first other read without a
// resolved path (hasUnplacedRelativePath) are always kept. TestGAP0674ThinReadsDifferential* compare
// every answer and the hook's verdict and audit rows with the whole record.
func thinCredentialPathReads(facts actionfacts.Facts) {
	facts.ThinCredentialPathReads(credentialPathReadsWhole, chainDistinctCredentialReads)
}

// chainDistinctCredentialReads marks the reads thinCredentialPathReads keeps.
func chainDistinctCredentialReads(reads []actionfacts.PathFact) []bool {
	keep := make([]bool, len(reads))
	unplaced := false
	for i, read := range reads {
		// A file-unknown marker, and a read the hook places under the folder
		// it reports (placeSecretReadPaths), whose identity is made later.
		keep[i] = read.Value == "" || read.CredentialReadPlaceable()
		if !keep[i] && !unplaced && !read.Absolute && read.Resolved == "" {
			// hasUnplacedRelativePath: one read it counts that no placement
			// changes (a Windows spelling on a Windows host is one).
			keep[i], unplaced = true, true
		}
	}
	// The identity sets: of the reads credentialFileReadProofDigest counts
	// (no fixture) and of those exactSecretReadChainDigest counts (also a
	// read of a sensitive path), each for a call proven to keep its folder
	// and for one that is not.
	var proof, proofUnproven, secret, secretUnproven chainIdentitySet
	for i, read := range reads {
		if read.Value == "" || read.CredentialReadPlaceable() {
			continue
		}
		if proof.settled() && proofUnproven.settled() && secret.settled() && secretUnproven.settled() {
			break
		}
		value := semanticPathValue(read)
		if credentialFileFixturePath(value) {
			continue
		}
		identity, exact := exactPathIdentity(read)
		// secretReadPathIdentity: a relative read of a call not proven to keep
		// its folder is not exact.
		unprovenExact := exact && read.Absolute
		kept := proof.add(identity, exact)
		kept = proofUnproven.add(identity, unprovenExact) || kept
		if read.Access == actionfacts.PathAccessRead && matchesAnySensitivePathCandidate(value) {
			kept = secret.add(identity, exact) || kept
			kept = secretUnproven.add(identity, unprovenExact) || kept
		}
		keep[i] = keep[i] || kept
	}
	return keep
}

// chainIdentitySet is what the chain's checks know of a set of reads: one
// that is not exact, or the first two different exact identities. Past that
// no read changes their answer.
type chainIdentitySet struct {
	inexact bool
	ids     [2]string
	n       int
}

func (s *chainIdentitySet) settled() bool { return s.inexact || s.n == len(s.ids) }

// add reports whether a read of identity tells the set something new.
func (s *chainIdentitySet) add(identity string, exact bool) bool {
	switch {
	case s.settled():
		return false
	case !exact:
		s.inexact = true
		return true
	case slices.Contains(s.ids[:s.n], identity):
		return false
	}
	s.ids[s.n] = identity
	s.n++
	return true
}
