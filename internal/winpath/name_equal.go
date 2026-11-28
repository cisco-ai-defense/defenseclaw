// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package winpath

// EqualNames reports whether a and b are the same Windows name or path
// spelling to the file system: case-insensitive the way NTFS compares names,
// through the system's uppercase table (CompareStringOrdinal with case
// ignored on Windows), not through Unicode case folding. strings.EqualFold
// folds more than NTFS does: the Kelvin sign U+212A folds to k, so two
// distinct NTFS names, one a folder anyone can create, compare equal
// (rel-1-0-10:GAP-2211, GAP-2221). Off Windows each rune is compared by its
// simple uppercase mapping, which the NTFS uppercase table follows. It is a
// name comparison only: a check whose answer decides what a path is must
// also compare file identity where the files exist (pathidentity.Same).
func EqualNames(a, b string) bool { return equalNames(a, b) }
