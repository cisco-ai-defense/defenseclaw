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

import Darwin
import CryptoKit
import Foundation

/// Lexical preflight and narrowly-scoped failure cleanup for the bundled
/// fresh installer. Kept independent of AppState so the filesystem boundary
/// has a native fault-injection test harness.
enum RuntimeInstallFilesystem {
    struct PathIdentity: Codable, Equatable {
        var device: UInt64
        var inode: UInt64
    }

    struct ActivationTarget: Codable, Equatable {
        var stagedPath: String
        var destinationPath: String
        var stagedIdentity: PathIdentity
        var stagedParentPath: String
        var stagedParentIdentity: PathIdentity
        var stagedLeaf: String
        var destinationParentPath: String
        var destinationParentIdentity: PathIdentity
        var destinationLeaf: String
    }

    struct ActivationReceipt: Equatable {
        var targets: [ActivationTarget]
        var journal: ActivationJournalHandle?
    }

    struct ActivationJournalHandle: Equatable {
        var path: String
        var identity: PathIdentity
    }

    enum ActivationBoundary: Equatable {
        case afterPublish
        case afterDestinationVerification
        case beforeStagedParentSync
        case beforeDestinationParentSync
    }

    private struct ActivationJournal: Codable {
        var schemaVersion: Int
        var targets: [ActivationTarget]
    }

    struct DirectoryReservation: Equatable {
        var path: String
        var identity: PathIdentity
        var created: Bool
    }

    enum ActivationError: LocalizedError {
        case missingOrChangedStage(String)
        case destinationAppeared(String)
        case parentChanged(String)
        case atomicMoveFailed(String, Int32)
        case sourceDigestMismatch(String)
        case invalidSourceTransform(String)
        case invalidActivationJournal(String)
        case rollbackPreservedConcurrentState([String])

        var errorDescription: String? {
            switch self {
            case let .missingOrChangedStage(path):
                return "Fresh-install staging changed before activation: \(path)"
            case let .destinationAppeared(path):
                return "A runtime destination appeared during staging: \(path)"
            case let .parentChanged(path):
                return "A runtime parent directory changed during activation: \(path)"
            case let .atomicMoveFailed(path, code):
                return "No-replace activation failed for \(path) (errno \(code))"
            case let .sourceDigestMismatch(path):
                return "Authenticated runtime source changed before installation: \(path)"
            case let .invalidSourceTransform(path):
                return "Protected runtime source transform is incomplete: \(path)"
            case let .invalidActivationJournal(path):
                return "Fresh-install activation journal is invalid or unsafe: \(path)"
            case let .rollbackPreservedConcurrentState(paths):
                return "Activation stopped and preserved concurrent state at: \(paths.joined(separator: ", "))"
            }
        }
    }

    /// First marker for existing runtime state. An empty, real data directory
    /// is not an installation; any contents, symlink, special file, unreadable
    /// directory, CLI/gateway path, or source-root marker fails closed.
    static func existingManagedRuntimeMarker(home: String) -> String? {
        let dataHome = home + "/.defenseclaw"
        if lexicalPathExists(dataHome), !isLexicallyEmptyDirectory(dataHome) {
            return dataHome
        }
        let markers = [
            home + "/.local/bin/defenseclaw",
            home + "/.local/bin/defenseclaw-gateway",
            home + "/.local/bin/.defenseclaw-source-root",
        ]
        return markers.first(where: lexicalPathExists)
    }

    /// First marker beneath the installation selected by InstallationContext.
    /// The process-wide CLI/gateway paths are checked separately by
    /// `existingManagedRuntimeMarker(home:)`; this covers a custom
    /// DEFENSECLAW_HOME and an independently selected DEFENSECLAW_VENV without
    /// following a final-component symlink.
    static func existingSelectedRuntimeMarker(dataHome: String, venvDir: String) -> String? {
        if lexicalPathExists(dataHome), !isLexicallyEmptyDirectory(dataHome) {
            return dataHome
        }
        let defaultVenv = dataHome + "/.venv"
        if venvDir != defaultVenv, lexicalPathExists(venvDir) {
            return venvDir
        }
        return nil
    }

    static func lexicalPathExists(_ path: String) -> Bool {
        var metadata = stat()
        return path.withCString { pointer in
            lstat(pointer, &metadata) == 0
        }
    }

    static func pathIdentity(_ path: String) -> PathIdentity? {
        var metadata = stat()
        guard path.withCString({ pointer in lstat(pointer, &metadata) }) == 0 else {
            return nil
        }
        return PathIdentity(
            device: UInt64(metadata.st_dev),
            inode: UInt64(metadata.st_ino)
        )
    }

    /// Create a staged symbolic link beneath a pinned real parent. symlinkat(2)
    /// is no-replace by definition; the entry identity is captured immediately
    /// and sampled again after readlinkat(2), so a same-name replacement can
    /// neither redirect creation nor become an accepted activation candidate.
    static func createOwnedSymbolicLink(
        _ path: String,
        target: String,
        expectedParentIdentity: PathIdentity,
        afterCreate: (() throws -> Void)? = nil
    ) throws -> PathIdentity {
        let parts = splitPath(path)
        let pinned = try pinDirectory(
            parts.parent,
            expected: expectedParentIdentity
        )
        defer { close(pinned.descriptor) }
        let created = target.withCString { targetPointer in
            parts.leaf.withCString { leafPointer in
                symlinkat(targetPointer, pinned.descriptor, leafPointer)
            }
        }
        guard created == 0 else {
            if errno == EEXIST {
                throw ActivationError.destinationAppeared(path)
            }
            throw ActivationError.atomicMoveFailed(path, errno)
        }
        guard let ownedIdentity = entryIdentity(pinned.descriptor, parts.leaf) else {
            throw ActivationError.missingOrChangedStage(path)
        }
        do { try afterCreate?() } catch {
            _ = removeOwnedEntry(
                pinned.descriptor,
                leaf: parts.leaf,
                identity: ownedIdentity
            )
            throw error
        }
        guard symbolicLinkTarget(pinned.descriptor, parts.leaf) == target,
              entryIdentity(pinned.descriptor, parts.leaf) == ownedIdentity,
              parentPathStillPinned(parts.parent, expectedParentIdentity)
        else {
            _ = removeOwnedEntry(
                pinned.descriptor,
                leaf: parts.leaf,
                identity: ownedIdentity
            )
            throw ActivationError.missingOrChangedStage(path)
        }
        return ownedIdentity
    }

    /// Copy a verified regular file into a private sibling and publish it with
    /// renameatx_np(RENAME_EXCL). For a protected source, `stripPrefix` and
    /// `decodeXORByte` must be supplied together: `expectedSourceSHA256`
    /// authenticates the complete encoded source while the destination receives
    /// only the decoded payload. The destination can never replace an existing
    /// tool, and a parent-directory swap is detected before publication.
    static func installRegularFileNoReplace(
        source: String,
        destination: String,
        expectedParentIdentity: PathIdentity,
        mode: mode_t,
        stripPrefix: Data? = nil,
        decodeXORByte: UInt8? = nil,
        expectedSourceSHA256: String? = nil,
        afterSourceOpen: (() throws -> Void)? = nil,
        beforeActivate: (() throws -> Void)? = nil,
        afterPublish: (() throws -> Void)? = nil,
        beforeParentSync: (() throws -> Void)? = nil
    ) throws -> PathIdentity {
        guard (stripPrefix == nil) == (decodeXORByte == nil) else {
            throw ActivationError.invalidSourceTransform(source)
        }
        let parts = splitPath(destination)
        let pinned = try pinDirectory(parts.parent, expected: expectedParentIdentity)
        defer { close(pinned.descriptor) }

        let sourceDescriptor = open(source, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard sourceDescriptor >= 0 else {
            throw ActivationError.missingOrChangedStage(source)
        }
        defer { close(sourceDescriptor) }
        var sourceMetadata = stat()
        guard fstat(sourceDescriptor, &sourceMetadata) == 0,
              sourceMetadata.st_mode & S_IFMT == S_IFREG else {
            throw ActivationError.missingOrChangedStage(source)
        }
        try afterSourceOpen?()

        let stagedLeaf = ".\(parts.leaf).install-\(UUID().uuidString)"
        let stagedDescriptor = stagedLeaf.withCString { pointer in
            openat(
                pinned.descriptor,
                pointer,
                O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                mode_t(0o600)
            )
        }
        guard stagedDescriptor >= 0,
              let stagedIdentity = descriptorIdentity(stagedDescriptor) else {
            if stagedDescriptor >= 0 { close(stagedDescriptor) }
            throw ActivationError.destinationAppeared(destination)
        }
        defer { close(stagedDescriptor) }

        var published = false
        do {
            let reader = FileHandle(fileDescriptor: sourceDescriptor, closeOnDealloc: false)
            let writer = FileHandle(fileDescriptor: stagedDescriptor, closeOnDealloc: false)
            var sourceHasher = SHA256()
            if let stripPrefix {
                guard let observed = try reader.read(upToCount: stripPrefix.count),
                      observed == stripPrefix,
                      sourceMetadata.st_size > off_t(stripPrefix.count) else {
                    throw ActivationError.missingOrChangedStage(source)
                }
                sourceHasher.update(data: observed)
            }
            while var chunk = try reader.read(upToCount: 1024 * 1024), !chunk.isEmpty {
                // Hash before decoding so the manifest binds the exact protected
                // bytes shipped in RuntimePayload, including the envelope prefix.
                sourceHasher.update(data: chunk)
                if let decodeXORByte {
                    chunk.withUnsafeMutableBytes { bytes in
                        for index in bytes.indices {
                            bytes[index] ^= decodeXORByte
                        }
                    }
                }
                try writer.write(contentsOf: chunk)
            }
            if let expectedSourceSHA256 {
                let observedSourceSHA256 = sourceHasher.finalize().map {
                    String(format: "%02x", $0)
                }.joined()
                guard observedSourceSHA256 == expectedSourceSHA256.lowercased() else {
                    throw ActivationError.sourceDigestMismatch(source)
                }
            }
            guard fchmod(stagedDescriptor, mode) == 0,
                  fsync(stagedDescriptor) == 0 else {
                throw ActivationError.atomicMoveFailed(destination, errno)
            }
            try beforeActivate?()
            guard parentPathStillPinned(parts.parent, expectedParentIdentity),
                  entryIdentity(pinned.descriptor, stagedLeaf) == stagedIdentity else {
                throw ActivationError.parentChanged(parts.parent)
            }
            if renameAtNoReplace(
                pinned.descriptor,
                stagedLeaf,
                pinned.descriptor,
                parts.leaf
            ) != 0 {
                let code = errno
                if code == EEXIST || code == ENOTEMPTY {
                    throw ActivationError.destinationAppeared(destination)
                }
                throw ActivationError.atomicMoveFailed(destination, code)
            }
            // renameatx_np succeeded: take rollback custody before any
            // verification hook, identity sampling, or durability operation
            // that can fail. stagedDescriptor remains open across the move,
            // so verification is bound to the published inode rather than a
            // same-name replacement.
            published = true
            try afterPublish?()
            guard descriptorIdentity(stagedDescriptor) == stagedIdentity,
                  entryIdentity(pinned.descriptor, parts.leaf) == stagedIdentity,
                  parentPathStillPinned(parts.parent, expectedParentIdentity) else {
                throw ActivationError.missingOrChangedStage(destination)
            }
            try beforeParentSync?()
            guard fsync(pinned.descriptor) == 0 else {
                throw ActivationError.atomicMoveFailed(destination, errno)
            }
            return stagedIdentity
        } catch {
            let cleanupLeaf = published ? parts.leaf : stagedLeaf
            let cleaned = removeOwnedEntry(
                pinned.descriptor,
                leaf: cleanupLeaf,
                identity: stagedIdentity
            )
            // Persist either the withdrawal or the restored/concurrent state
            // before reporting the failed publication to the caller.
            let cleanupSynced = fsync(pinned.descriptor) == 0
            if published && (!cleaned || !cleanupSynced) {
                throw ActivationError.rollbackPreservedConcurrentState([destination])
            }
            throw error
        }
    }

    static func isRealDirectory(_ path: String) -> Bool {
        var metadata = stat()
        guard path.withCString({ pointer in lstat(pointer, &metadata) }) == 0 else {
            return false
        }
        return metadata.st_mode & S_IFMT == S_IFDIR
    }

    /// Remove only the fixed staging tree created by this install attempt.
    /// If the data-home did not exist before the attempt, rmdir(2) may remove
    /// it afterwards—but only while it is still an empty real directory.
    /// Concurrent or pre-existing contents are therefore never removed.
    static func cleanupFailedFreshInstall(
        stagingDir: String,
        stagingIdentity: PathIdentity,
        dataHome: String,
        removeDataHomeIfEmpty: Bool
    ) {
        _ = cleanupOwnedPath(stagingDir, identity: stagingIdentity)
        // Keep an empty real data-home even when this attempt created it.
        // Empty parents are accepted on retry, and retaining the directory
        // avoids a conditional-rmdir race against a same-name replacement.
        _ = dataHome
        _ = removeDataHomeIfEmpty
    }

    /// Allocate a staging directory with mkdirat beneath a pinned real parent
    /// and capture its inode immediately. Failure cleanup may remove only this
    /// identity; a same-name replacement is preserved.
    static func createOwnedDirectory(_ path: String) throws -> PathIdentity {
        let parts = splitPath(path)
        guard let parentIdentity = pathIdentity(parts.parent),
              let pinned = try? pinDirectory(parts.parent, expected: parentIdentity)
        else { throw ActivationError.parentChanged(parts.parent) }
        defer { close(pinned.descriptor) }
        let created = parts.leaf.withCString { pointer in
            mkdirat(pinned.descriptor, pointer, mode_t(0o700))
        }
        guard created == 0 else {
            throw ActivationError.destinationAppeared(path)
        }
        let descriptor = parts.leaf.withCString { pointer in
            openat(
                pinned.descriptor,
                pointer,
                O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
            )
        }
        guard descriptor >= 0, let identity = descriptorIdentity(descriptor) else {
            if descriptor >= 0 { close(descriptor) }
            throw ActivationError.missingOrChangedStage(path)
        }
        close(descriptor)
        guard entryIdentity(pinned.descriptor, parts.leaf) == identity else {
            throw ActivationError.missingOrChangedStage(path)
        }
        return identity
    }

    /// Resolve and, when absent, create a directory chain beneath a pinned
    /// real root. Every hop uses openat/mkdirat with O_NOFOLLOW, so a symlinked
    /// `.local`, `.defenseclaw`, or intermediate `bin` can never redirect a
    /// fresh install outside the selected home.
    static func ensureRealDirectoryTree(
        root: String,
        components: [String]
    ) throws -> [DirectoryReservation] {
        guard isRealDirectory(root), let rootIdentity = pathIdentity(root) else {
            throw ActivationError.parentChanged(root)
        }
        var current = try pinDirectory(root, expected: rootIdentity)
        var currentPath = root
        var reservations: [DirectoryReservation] = []
        defer { close(current.descriptor) }

        for component in components {
            guard !component.isEmpty,
                  component != ".",
                  component != "..",
                  !component.contains("/") else {
                throw ActivationError.parentChanged(currentPath)
            }
            var metadata = stat()
            var created = false
            var status = component.withCString { pointer in
                fstatat(current.descriptor, pointer, &metadata, AT_SYMLINK_NOFOLLOW)
            }
            if status != 0 && errno == ENOENT {
                status = component.withCString { pointer in
                    mkdirat(current.descriptor, pointer, mode_t(0o700))
                }
                guard status == 0 else {
                    throw ActivationError.destinationAppeared(
                        URL(fileURLWithPath: currentPath).appendingPathComponent(component).path
                    )
                }
                created = true
                status = component.withCString { pointer in
                    fstatat(current.descriptor, pointer, &metadata, AT_SYMLINK_NOFOLLOW)
                }
            }
            guard status == 0, metadata.st_mode & S_IFMT == S_IFDIR else {
                throw ActivationError.parentChanged(
                    URL(fileURLWithPath: currentPath).appendingPathComponent(component).path
                )
            }
            let identity = PathIdentity(
                device: UInt64(metadata.st_dev),
                inode: UInt64(metadata.st_ino)
            )
            let nextDescriptor = component.withCString { pointer in
                openat(
                    current.descriptor,
                    pointer,
                    O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
                )
            }
            guard nextDescriptor >= 0, descriptorIdentity(nextDescriptor) == identity else {
                if nextDescriptor >= 0 { close(nextDescriptor) }
                throw ActivationError.parentChanged(currentPath)
            }
            let nextPath = URL(fileURLWithPath: currentPath)
                .appendingPathComponent(component).path
            guard pathIdentity(nextPath) == identity else {
                close(nextDescriptor)
                throw ActivationError.parentChanged(nextPath)
            }
            close(current.descriptor)
            current = PinnedDirectory(descriptor: nextDescriptor, identity: identity)
            currentPath = nextPath
            reservations.append(
                DirectoryReservation(path: nextPath, identity: identity, created: created)
            )
        }
        return reservations
    }

    /// Ensure an arbitrary absolute InstallationContext path through the same
    /// pinned openat/mkdirat walk used for the standard per-user layout.
    /// Standardization is required up front so the journal and activation
    /// receipt bind one exact lexical path rather than an alias containing
    /// `.` or `..` components.
    static func ensureRealDirectoryPath(_ path: String) throws -> PathIdentity {
        let standardized = URL(fileURLWithPath: path, isDirectory: true)
            .standardizedFileURL.path
        guard path.hasPrefix("/"), path == standardized else {
            throw ActivationError.parentChanged(path)
        }
        if path == "/" {
            guard isRealDirectory(path), let identity = pathIdentity(path) else {
                throw ActivationError.parentChanged(path)
            }
            return identity
        }
        var components = URL(fileURLWithPath: path, isDirectory: true).pathComponents
        guard components.first == "/" else {
            throw ActivationError.parentChanged(path)
        }
        components.removeFirst()
        let reservations = try ensureRealDirectoryTree(root: "/", components: components)
        guard let reservation = reservations.last, reservation.path == path else {
            throw ActivationError.parentChanged(path)
        }
        return reservation.identity
    }

    /// Capture every staged inode and re-check every canonical target before
    /// activation. The subsequent renamex_np(RENAME_EXCL) calls repeat the
    /// absence guarantee atomically, so this read-only check is diagnostic and
    /// not the security boundary.
    static func prepareActivationTargets(
        _ pairs: [(staged: String, destination: String)]
    ) throws -> [ActivationTarget] {
        var targets: [ActivationTarget] = []
        for pair in pairs {
            let stagedParts = splitPath(pair.staged)
            let destinationParts = splitPath(pair.destination)
            guard isRealDirectory(stagedParts.parent),
                  let stagedParentIdentity = pathIdentity(stagedParts.parent)
            else {
                throw ActivationError.parentChanged(stagedParts.parent)
            }
            guard isRealDirectory(destinationParts.parent),
                  let destinationParentIdentity = pathIdentity(destinationParts.parent)
            else {
                throw ActivationError.parentChanged(destinationParts.parent)
            }
            guard let identity = pathIdentity(pair.staged) else {
                throw ActivationError.missingOrChangedStage(pair.staged)
            }
            guard !lexicalPathExists(pair.destination) else {
                throw ActivationError.destinationAppeared(pair.destination)
            }
            targets.append(
                ActivationTarget(
                    stagedPath: pair.staged,
                    destinationPath: pair.destination,
                    stagedIdentity: identity,
                    stagedParentPath: stagedParts.parent,
                    stagedParentIdentity: stagedParentIdentity,
                    stagedLeaf: stagedParts.leaf,
                    destinationParentPath: destinationParts.parent,
                    destinationParentIdentity: destinationParentIdentity,
                    destinationLeaf: destinationParts.leaf
                )
            )
        }
        return targets
    }

    /// Durably record the complete activation plan before the first canonical
    /// rename. The fixed journal is created no-replace, written through a
    /// pinned real parent, and fsynced with that parent before it authorizes
    /// any multi-target mutation.
    static func prepareActivationJournal(
        _ targets: [ActivationTarget],
        path: String
    ) throws -> ActivationJournalHandle {
        guard !targets.isEmpty else {
            throw ActivationError.invalidActivationJournal(path)
        }
        let journal = ActivationJournal(schemaVersion: 1, targets: targets)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        guard let payload = try? encoder.encode(journal),
              !payload.isEmpty,
              payload.count <= 256 * 1024 else {
            throw ActivationError.invalidActivationJournal(path)
        }
        let parts = splitPath(path)
        guard let parentIdentity = pathIdentity(parts.parent) else {
            throw ActivationError.parentChanged(parts.parent)
        }
        let pinned = try pinDirectory(parts.parent, expected: parentIdentity)
        defer { close(pinned.descriptor) }
        let descriptor = parts.leaf.withCString { pointer in
            openat(
                pinned.descriptor,
                pointer,
                O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                mode_t(0o600)
            )
        }
        guard descriptor >= 0, let identity = descriptorIdentity(descriptor) else {
            if descriptor >= 0 { close(descriptor) }
            throw ActivationError.destinationAppeared(path)
        }
        var writeSucceeded = false
        payload.withUnsafeBytes { rawBuffer in
            guard let baseAddress = rawBuffer.baseAddress else { return }
            var offset = 0
            while offset < rawBuffer.count {
                let count = Darwin.write(
                    descriptor,
                    baseAddress.advanced(by: offset),
                    rawBuffer.count - offset
                )
                if count <= 0 { return }
                offset += count
            }
            writeSucceeded = fsync(descriptor) == 0
        }
        close(descriptor)
        guard writeSucceeded,
              entryIdentity(pinned.descriptor, parts.leaf) == identity,
              parentPathStillPinned(parts.parent, parentIdentity),
              fsync(pinned.descriptor) == 0 else {
            _ = removeOwnedEntry(
                pinned.descriptor,
                leaf: parts.leaf,
                identity: identity
            )
            throw ActivationError.atomicMoveFailed(path, errno)
        }
        return ActivationJournalHandle(path: path, identity: identity)
    }

    /// Publish a complete fresh runtime with kernel-enforced no-replace moves.
    /// If a later target appears, already-published installer-owned inodes are
    /// withdrawn. A path whose inode changed is treated as concurrent state and
    /// is preserved rather than deleted.
    static func activateNoReplace(
        _ targets: [ActivationTarget],
        journalPath: String? = nil,
        beforeActivating: ((Int) throws -> Void)? = nil,
        atBoundary: ((Int, ActivationBoundary) throws -> Void)? = nil
    ) throws -> ActivationReceipt {
        let pinned = try pinParents(for: targets)
        defer { pinned.values.forEach { close($0.descriptor) } }
        let journal = try journalPath.map {
            try prepareActivationJournal(targets, path: $0)
        }
        var activated: [ActivationTarget] = []
        do {
            for (index, target) in targets.enumerated() {
                do {
                    try beforeActivating?(index)
                    guard parentPathStillPinned(
                            target.stagedParentPath,
                            target.stagedParentIdentity
                          ),
                          parentPathStillPinned(
                            target.destinationParentPath,
                            target.destinationParentIdentity
                          )
                    else {
                        throw ActivationError.parentChanged(target.destinationParentPath)
                    }
                    guard let stagedParent = pinned[target.stagedParentPath],
                          let destinationParent = pinned[target.destinationParentPath]
                    else {
                        throw ActivationError.parentChanged(target.destinationParentPath)
                    }
                    guard entryIdentity(stagedParent.descriptor, target.stagedLeaf)
                            == target.stagedIdentity,
                          let custodyDescriptor = openEntryForCustody(
                            stagedParent.descriptor,
                            target.stagedLeaf,
                            expected: target.stagedIdentity
                          ) else {
                        throw ActivationError.missingOrChangedStage(target.stagedPath)
                    }
                    defer { close(custodyDescriptor) }
                    if renameAtNoReplace(
                        stagedParent.descriptor,
                        target.stagedLeaf,
                        destinationParent.descriptor,
                        target.destinationLeaf
                    ) != 0 {
                        let code = errno
                        if code == EEXIST || code == ENOTEMPTY {
                            throw ActivationError.destinationAppeared(target.destinationPath)
                        }
                        throw ActivationError.atomicMoveFailed(target.destinationPath, code)
                    }
                    // The kernel has published this inode. Record custody
                    // immediately; every later throwable boundary must include
                    // it in rollback, even if path verification or fsync fails.
                    activated.append(target)
                    try atBoundary?(index, .afterPublish)
                    guard descriptorIdentity(custodyDescriptor) == target.stagedIdentity,
                          entryIdentity(destinationParent.descriptor, target.destinationLeaf)
                            == target.stagedIdentity else {
                        throw ActivationError.missingOrChangedStage(target.destinationPath)
                    }
                    try atBoundary?(index, .afterDestinationVerification)
                    try atBoundary?(index, .beforeStagedParentSync)
                    guard fsync(stagedParent.descriptor) == 0 else {
                        throw ActivationError.atomicMoveFailed(target.destinationPath, errno)
                    }
                    if stagedParent.descriptor != destinationParent.descriptor {
                        try atBoundary?(index, .beforeDestinationParentSync)
                        guard fsync(destinationParent.descriptor) == 0 else {
                            throw ActivationError.atomicMoveFailed(target.destinationPath, errno)
                        }
                    }
                }
            }
        } catch {
            var preserved = rollbackOwnedDestinations(activated, pinned: pinned)
            if preserved.isEmpty, let journal,
               !cleanupOwnedPath(journal.path, identity: journal.identity) {
                preserved.append(journal.path)
            }
            if !preserved.isEmpty {
                throw ActivationError.rollbackPreservedConcurrentState(preserved)
            }
            throw error
        }
        return ActivationReceipt(targets: activated, journal: journal)
    }

    @discardableResult
    static func rollbackActivation(_ receipt: ActivationReceipt) -> [String] {
        guard let pinned = try? pinParents(for: receipt.targets) else {
            return receipt.targets.map(\.destinationPath)
        }
        defer { pinned.values.forEach { close($0.descriptor) } }
        let preserved = rollbackOwnedDestinations(receipt.targets, pinned: pinned)
        if preserved.isEmpty, let journal = receipt.journal,
           !cleanupOwnedPath(journal.path, identity: journal.identity) {
            return [journal.path]
        }
        return preserved
    }

    /// Remove the durable journal only after every fresh-process health check
    /// has passed. Until this succeeds, the next attempt treats the activation
    /// as uncommitted and rolls back only the journal-bound inode identities.
    static func commitActivation(_ receipt: ActivationReceipt) throws {
        guard let journal = receipt.journal else { return }
        guard cleanupOwnedPath(
            journal.path,
            identity: journal.identity,
            requirePresent: true
        ) else {
            throw ActivationError.invalidActivationJournal(journal.path)
        }
    }

    /// Recover a process death between no-replace activation moves. Journal
    /// paths are accepted only for the exact three fresh-install targets and
    /// UUID-shaped private stage names beneath their expected real parents.
    /// Concurrent replacements are reported and preserved.
    static func recoverFreshInstallActivation(
        journalPath: String,
        dataHome: String,
        binDir: String,
        venvDir: String? = nil
    ) throws -> [String] {
        guard lexicalPathExists(journalPath) else { return [] }
        let journalParts = splitPath(journalPath)
        guard journalParts.parent == dataHome else {
            throw ActivationError.invalidActivationJournal(journalPath)
        }
        let descriptor = open(journalPath, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else {
            throw ActivationError.invalidActivationJournal(journalPath)
        }
        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0,
              metadata.st_mode & S_IFMT == S_IFREG,
              metadata.st_uid == geteuid(),
              metadata.st_mode & mode_t(0o077) == 0,
              metadata.st_size > 0,
              metadata.st_size <= 256 * 1024,
              let journalIdentity = descriptorIdentity(descriptor) else {
            close(descriptor)
            throw ActivationError.invalidActivationJournal(journalPath)
        }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        guard let payload = try? handle.readToEnd(),
              let journal = try? JSONDecoder().decode(ActivationJournal.self, from: payload),
              journal.schemaVersion == 1,
              validateFreshInstallJournalTargets(
                journal.targets,
                dataHome: dataHome,
                venvDir: venvDir ?? dataHome + "/.venv",
                binDir: binDir
              ) else {
            try? handle.close()
            throw ActivationError.invalidActivationJournal(journalPath)
        }
        try? handle.close()
        let pinned = try pinParents(for: journal.targets)
        defer { pinned.values.forEach { close($0.descriptor) } }
        var preserved = rollbackOwnedDestinations(journal.targets, pinned: pinned)
        preserved.append(contentsOf: cleanupPreparedActivation(journal.targets))
        let ownedRemains = journal.targets.contains { target in
            pathIdentity(target.stagedPath) == target.stagedIdentity
                || pathIdentity(target.destinationPath) == target.stagedIdentity
        }
        guard !ownedRemains else {
            throw ActivationError.rollbackPreservedConcurrentState(
                Array(Set(preserved + journal.targets.map(\.destinationPath))).sorted()
            )
        }
        guard cleanupOwnedPath(journalPath, identity: journalIdentity) else {
            throw ActivationError.invalidActivationJournal(journalPath)
        }
        return Array(Set(preserved)).sorted()
    }

    /// Clean stages that never activated, but only while their captured inode
    /// is still at the installer-owned staging name.
    @discardableResult
    static func cleanupPreparedActivation(_ targets: [ActivationTarget]) -> [String] {
        guard let pinned = try? pinParents(for: targets) else {
            return targets.map(\.stagedPath)
        }
        defer { pinned.values.forEach { close($0.descriptor) } }
        var preserved: [String] = []
        for target in targets.reversed() {
            guard let parent = pinned[target.stagedParentPath] else {
                preserved.append(target.stagedPath)
                continue
            }
            if entryIdentity(parent.descriptor, target.stagedLeaf) == nil {
                continue
            }
            if !removeOwnedEntry(
                parent.descriptor,
                leaf: target.stagedLeaf,
                identity: target.stagedIdentity
            ) {
                preserved.append(target.stagedPath)
            }
        }
        for parent in pinned.values where fsync(parent.descriptor) != 0 {
            preserved.append("activation parent fsync failed")
        }
        return preserved
    }

    @discardableResult
    static func cleanupOwnedPath(
        _ path: String,
        identity: PathIdentity,
        requirePresent: Bool = false,
        afterSwap: (() throws -> Void)? = nil,
        beforePlaceholderRetire: (() throws -> Void)? = nil,
        afterQuarantine: (() throws -> Void)? = nil,
        afterRecursiveRootOpen: (() throws -> Void)? = nil,
        restorationSwap: ((Int32, String, String) -> Int32)? = nil
    ) -> Bool {
        let parts = splitPath(path)
        guard let parentIdentity = pathIdentity(parts.parent),
              let pinned = try? pinDirectory(parts.parent, expected: parentIdentity)
        else { return false }
        defer { close(pinned.descriptor) }
        let removed = removeOwnedEntry(
            pinned.descriptor,
            leaf: parts.leaf,
            identity: identity,
            requirePresent: requirePresent,
            afterSwap: afterSwap,
            beforePlaceholderRetire: beforePlaceholderRetire,
            afterQuarantine: afterQuarantine,
            afterRecursiveRootOpen: afterRecursiveRootOpen,
            restorationSwap: restorationSwap
        )
        // A failed cleanup may still have performed a safety-critical restore
        // from a private quarantine to the canonical name. Sync that restore
        // as well; short-circuiting on `removed == false` would lose its
        // durability boundary.
        let synced = fsync(pinned.descriptor) == 0
        return removed && synced
    }

    private struct PinnedDirectory {
        var descriptor: Int32
        var identity: PathIdentity
    }

    private static func splitPath(_ path: String) -> (parent: String, leaf: String) {
        let url = URL(fileURLWithPath: path)
        return (url.deletingLastPathComponent().path, url.lastPathComponent)
    }

    private static func validateFreshInstallJournalTargets(
        _ targets: [ActivationTarget],
        dataHome: String,
        venvDir: String,
        binDir: String
    ) -> Bool {
        let venv = splitPath(venvDir)
        let expected: [(destination: String, stageParent: String, stagePrefix: String)] = [
            (venvDir, venv.parent, venv.leaf + ".staging-"),
            (binDir + "/defenseclaw-gateway", binDir, "defenseclaw-gateway.install-"),
            (binDir + "/defenseclaw", binDir, "defenseclaw.install-"),
        ]
        guard targets.count == expected.count,
              !venv.leaf.isEmpty,
              venvDir == URL(fileURLWithPath: venvDir).standardizedFileURL.path
        else { return false }
        for (target, rule) in zip(targets, expected) {
            let staged = splitPath(target.stagedPath)
            let destination = splitPath(target.destinationPath)
            let suffix = String(staged.leaf.dropFirst(rule.stagePrefix.count))
            guard target.destinationPath == rule.destination,
                  target.stagedParentPath == rule.stageParent,
                  target.stagedLeaf == staged.leaf,
                  staged.parent == rule.stageParent,
                  staged.leaf.hasPrefix(rule.stagePrefix),
                  UUID(uuidString: suffix) != nil,
                  target.destinationParentPath == destination.parent,
                  target.destinationLeaf == destination.leaf,
                  target.stagedIdentity.device != 0,
                  target.stagedIdentity.inode != 0 else {
                return false
            }
        }
        return true
    }

    private static func pinDirectory(
        _ path: String,
        expected: PathIdentity
    ) throws -> PinnedDirectory {
        let descriptor = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw ActivationError.parentChanged(path) }
        guard descriptorIdentity(descriptor) == expected,
              pathIdentity(path) == expected else {
            close(descriptor)
            throw ActivationError.parentChanged(path)
        }
        return PinnedDirectory(descriptor: descriptor, identity: expected)
    }

    private static func pinParents(
        for targets: [ActivationTarget]
    ) throws -> [String: PinnedDirectory] {
        var expected: [String: PathIdentity] = [:]
        for target in targets {
            for pair in [
                (target.stagedParentPath, target.stagedParentIdentity),
                (target.destinationParentPath, target.destinationParentIdentity),
            ] {
                if let prior = expected[pair.0], prior != pair.1 {
                    throw ActivationError.parentChanged(pair.0)
                }
                expected[pair.0] = pair.1
            }
        }
        var pinned: [String: PinnedDirectory] = [:]
        do {
            for (path, identity) in expected {
                pinned[path] = try pinDirectory(path, expected: identity)
            }
        } catch {
            pinned.values.forEach { close($0.descriptor) }
            throw error
        }
        return pinned
    }

    private static func descriptorIdentity(_ descriptor: Int32) -> PathIdentity? {
        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0 else { return nil }
        return PathIdentity(device: UInt64(metadata.st_dev), inode: UInt64(metadata.st_ino))
    }

    private static func entryIdentity(_ parent: Int32, _ leaf: String) -> PathIdentity? {
        var metadata = stat()
        let status = leaf.withCString { pointer in
            fstatat(parent, pointer, &metadata, AT_SYMLINK_NOFOLLOW)
        }
        guard status == 0 else { return nil }
        return PathIdentity(device: UInt64(metadata.st_dev), inode: UInt64(metadata.st_ino))
    }

    /// Hold the exact directory entry across rename and post-publication
    /// verification. O_SYMLINK makes a final symlink itself the opened object;
    /// because `leaf` is resolved relative to an already-pinned parent, no
    /// attacker-controlled ancestor or link target is traversed.
    private static func openEntryForCustody(
        _ parent: Int32,
        _ leaf: String,
        expected: PathIdentity
    ) -> Int32? {
        let descriptor = leaf.withCString { pointer in
            openat(parent, pointer, O_EVTONLY | O_SYMLINK | O_CLOEXEC)
        }
        guard descriptor >= 0, descriptorIdentity(descriptor) == expected else {
            if descriptor >= 0 { close(descriptor) }
            return nil
        }
        return descriptor
    }

    private static func symbolicLinkTarget(_ parent: Int32, _ leaf: String) -> String? {
        var buffer = [CChar](repeating: 0, count: Int(PATH_MAX) + 1)
        let count = buffer.withUnsafeMutableBufferPointer { bytes in
            leaf.withCString { pointer in
                readlinkat(parent, pointer, bytes.baseAddress, bytes.count - 1)
            }
        }
        guard count >= 0 else { return nil }
        return String(
            bytes: buffer.prefix(Int(count)).map { UInt8(bitPattern: $0) },
            encoding: .utf8
        )
    }

    private static func parentPathStillPinned(
        _ path: String,
        _ expected: PathIdentity
    ) -> Bool {
        pathIdentity(path) == expected
    }

    private static func renameAtNoReplace(
        _ sourceParent: Int32,
        _ sourceLeaf: String,
        _ destinationParent: Int32,
        _ destinationLeaf: String
    ) -> Int32 {
        sourceLeaf.withCString { sourcePointer in
            destinationLeaf.withCString { destinationPointer in
                renameatx_np(
                    sourceParent,
                    sourcePointer,
                    destinationParent,
                    destinationPointer,
                    UInt32(RENAME_EXCL)
                )
            }
        }
    }

    private static func rollbackOwnedDestinations(
        _ targets: [ActivationTarget],
        pinned: [String: PinnedDirectory]
    ) -> [String] {
        var preserved: [String] = []
        for target in targets.reversed() {
            guard let parent = pinned[target.destinationParentPath] else {
                preserved.append(target.destinationPath)
                continue
            }
            if entryIdentity(parent.descriptor, target.destinationLeaf) == nil {
                continue
            }
            if !removeOwnedEntry(
                parent.descriptor,
                leaf: target.destinationLeaf,
                identity: target.stagedIdentity
            ) {
                preserved.append(target.destinationPath)
            }
        }
        for parent in pinned.values where fsync(parent.descriptor) != 0 {
            preserved.append("activation parent fsync failed")
        }
        return preserved
    }

    /// Atomically swap a candidate with an installer-owned placeholder. The
    /// canonical leaf therefore never becomes absent while ownership is being
    /// checked. If the candidate is a concurrent replacement, one more swap
    /// restores it without a create-at-the-empty-name race.
    private static func removeOwnedEntry(
        _ parent: Int32,
        leaf: String,
        identity: PathIdentity,
        requirePresent: Bool = false,
        afterSwap: (() throws -> Void)? = nil,
        beforePlaceholderRetire: (() throws -> Void)? = nil,
        afterQuarantine: (() throws -> Void)? = nil,
        afterRecursiveRootOpen: (() throws -> Void)? = nil,
        restorationSwap: ((Int32, String, String) -> Int32)? = nil
    ) -> Bool {
        guard entryIdentity(parent, leaf) != nil else { return !requirePresent }
        guard let custodyDescriptor = openEntryForCustody(
            parent,
            leaf,
            expected: identity
        ) else { return false }
        defer { close(custodyDescriptor) }
        let restoreSwap = restorationSwap ?? { descriptor, first, second in
            swapEntries(descriptor, first, second)
        }
        let placeholder = ".defenseclaw-cleanup-" + UUID().uuidString
        let placeholderDescriptor = placeholder.withCString { pointer in
            openat(
                parent,
                pointer,
                O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                mode_t(0o600)
            )
        }
        guard placeholderDescriptor >= 0,
              let placeholderIdentity = descriptorIdentity(placeholderDescriptor)
        else {
            if placeholderDescriptor >= 0 { close(placeholderDescriptor) }
            return false
        }
        close(placeholderDescriptor)
        let swapped = leaf.withCString { leafPointer in
            placeholder.withCString { placeholderPointer in
                renameatx_np(
                    parent,
                    leafPointer,
                    parent,
                    placeholderPointer,
                    UInt32(RENAME_SWAP)
                )
            }
        }
        guard swapped == 0 else {
            _ = placeholder.withCString { unlinkat(parent, $0, 0) }
            return false
        }
        do { try afterSwap?() } catch {
            restoreCanonicalAfterCleanupSwap(
                parent,
                leaf: leaf,
                displacedLeaf: placeholder,
                ownedIdentity: identity,
                placeholderIdentity: placeholderIdentity,
                custodyDescriptor: custodyDescriptor,
                restorationSwap: restoreSwap
            )
            return false
        }

        guard descriptorIdentity(custodyDescriptor) == identity,
              entryIdentity(parent, placeholder) == identity,
              entryIdentity(parent, leaf) == placeholderIdentity else {
            restoreCanonicalAfterCleanupSwap(
                parent,
                leaf: leaf,
                displacedLeaf: placeholder,
                ownedIdentity: identity,
                placeholderIdentity: placeholderIdentity,
                custodyDescriptor: custodyDescriptor,
                restorationSwap: restoreSwap
            )
            return false
        }

        // Restore the installer-owned candidate to its canonical name before
        // retiring the synthetic placeholder. Thus every placeholder unlink
        // failure leaves the real candidate—not the placeholder—canonical.
        guard restoreSwap(parent, leaf, placeholder) == 0,
              descriptorIdentity(custodyDescriptor) == identity,
              entryIdentity(parent, leaf) == identity,
              entryIdentity(parent, placeholder) == placeholderIdentity else {
            restoreCanonicalAfterCleanupSwap(
                parent,
                leaf: leaf,
                displacedLeaf: placeholder,
                ownedIdentity: identity,
                placeholderIdentity: placeholderIdentity,
                custodyDescriptor: custodyDescriptor,
                restorationSwap: restoreSwap
            )
            return false
        }
        do { try beforePlaceholderRetire?() } catch {
            _ = retirePrivatePlaceholder(
                parent,
                leaf: placeholder,
                identity: placeholderIdentity
            )
            return false
        }
        guard retirePrivatePlaceholder(
            parent,
            leaf: placeholder,
            identity: placeholderIdentity
        ) else {
            return false
        }

        // With the placeholder gone privately and the held inode restored at
        // the public name, move the candidate to the same unguessable private
        // slot. A failure before removal restores it no-replace; a concurrent
        // canonical replacement is always preserved.
        guard descriptorIdentity(custodyDescriptor) == identity,
              entryIdentity(parent, leaf) == identity else { return false }
        guard renameAtNoReplace(parent, leaf, parent, placeholder) == 0 else {
            return false
        }
        guard descriptorIdentity(custodyDescriptor) == identity,
              entryIdentity(parent, placeholder) == identity else {
            restoreQuarantinedEntry(parent, leaf: leaf, quarantine: placeholder)
            return false
        }
        do { try afterQuarantine?() } catch {
            restoreQuarantinedEntry(parent, leaf: leaf, quarantine: placeholder)
            return false
        }
        let candidateRemoved = removeOpenedEntryRecursively(
            parent,
            leaf: placeholder,
            identity: identity,
            custodyDescriptor: custodyDescriptor,
            afterDirectoryOpen: afterRecursiveRootOpen
        )
        guard candidateRemoved else {
            restoreQuarantinedEntry(parent, leaf: leaf, quarantine: placeholder)
            return false
        }
        return true
    }

    /// Best-effort resolution for every failure after the first exchange. It
    /// prefers the displaced candidate at the canonical name, never replaces a
    /// concurrent canonical object, and never intentionally leaves the
    /// installer-created placeholder canonical.
    private static func restoreCanonicalAfterCleanupSwap(
        _ parent: Int32,
        leaf: String,
        displacedLeaf: String,
        ownedIdentity: PathIdentity,
        placeholderIdentity: PathIdentity,
        custodyDescriptor: Int32,
        restorationSwap: (Int32, String, String) -> Int32
    ) {
        var canonicalIdentity = entryIdentity(parent, leaf)
        var displacedIdentity = entryIdentity(parent, displacedLeaf)
        if canonicalIdentity == placeholderIdentity, displacedIdentity != nil {
            if restorationSwap(parent, leaf, displacedLeaf) == 0 {
                _ = retirePrivatePlaceholder(
                    parent,
                    leaf: displacedLeaf,
                    identity: placeholderIdentity
                )
                return
            }
            // The placeholder or displaced entry may have changed between
            // sampling and the failed exchange. Reconcile the new state; in
            // particular, an absent canonical name can still be restored with
            // a no-replace move from the private slot.
            canonicalIdentity = entryIdentity(parent, leaf)
            displacedIdentity = entryIdentity(parent, displacedLeaf)
        }
        if canonicalIdentity == nil, displacedIdentity != nil {
            _ = renameAtNoReplace(parent, displacedLeaf, parent, leaf)
            return
        }
        if canonicalIdentity == placeholderIdentity, displacedIdentity != nil {
            if restorationSwap(parent, leaf, displacedLeaf) == 0 {
                _ = retirePrivatePlaceholder(
                    parent,
                    leaf: displacedLeaf,
                    identity: placeholderIdentity
                )
                return
            }
            // A repeated exchange failure must not make the synthetic
            // placeholder the permanent public entry. Move it to a second
            // private slot, then restore the displaced candidate no-replace.
            restoreDisplacedCandidateWithoutExchange(
                parent,
                leaf: leaf,
                displacedLeaf: displacedLeaf,
                placeholderIdentity: placeholderIdentity
            )
            return
        }
        if let canonicalIdentity,
           canonicalIdentity != placeholderIdentity,
           displacedIdentity == placeholderIdentity {
            _ = retirePrivatePlaceholder(
                parent,
                leaf: displacedLeaf,
                identity: placeholderIdentity
            )
            return
        }
        // A concurrent canonical entry is already the state that must be
        // preserved. Remove only the privately displaced installer inode; an
        // unrecognized displaced entry remains visibly quarantined.
        if let canonicalIdentity,
           canonicalIdentity != placeholderIdentity,
           displacedIdentity == ownedIdentity,
           descriptorIdentity(custodyDescriptor) == ownedIdentity {
            _ = removeOpenedEntryRecursively(
                parent,
                leaf: displacedLeaf,
                identity: ownedIdentity,
                custodyDescriptor: custodyDescriptor
            )
        }
    }

    /// Remove directory contents only through an inode-checked descriptor.
    /// The final directory unlink is non-recursive and succeeds only while the
    /// original, now-empty directory is still bound to `leaf`. If another
    /// process rebinds that private name, traversal stays on the held inode and
    /// the replacement (especially a non-empty directory) is never recursed.
    private static func removeOpenedEntryRecursively(
        _ parent: Int32,
        leaf: String,
        identity: PathIdentity,
        custodyDescriptor: Int32,
        afterDirectoryOpen: (() throws -> Void)? = nil
    ) -> Bool {
        guard descriptorIdentity(custodyDescriptor) == identity,
              entryIdentity(parent, leaf) == identity else { return false }
        var metadata = stat()
        guard fstat(custodyDescriptor, &metadata) == 0 else { return false }

        if metadata.st_mode & S_IFMT != S_IFDIR {
            guard afterDirectoryOpen == nil,
                  descriptorIdentity(custodyDescriptor) == identity,
                  entryIdentity(parent, leaf) == identity else { return false }
            return leaf.withCString { unlinkat(parent, $0, 0) == 0 }
        }

        let directoryDescriptor = leaf.withCString { pointer in
            openat(
                parent,
                pointer,
                O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
            )
        }
        guard directoryDescriptor >= 0,
              descriptorIdentity(directoryDescriptor) == identity else {
            if directoryDescriptor >= 0 { close(directoryDescriptor) }
            return false
        }
        defer { close(directoryDescriptor) }
        do { try afterDirectoryOpen?() } catch { return false }

        guard removeDirectoryContents(
                directoryDescriptor,
                expectedIdentity: identity
              ),
              descriptorIdentity(directoryDescriptor) == identity,
              descriptorIdentity(custodyDescriptor) == identity,
              entryIdentity(parent, leaf) == identity else { return false }

        // This is intentionally non-recursive. A same-name replacement with
        // contents makes AT_REMOVEDIR fail instead of deleting those contents.
        return leaf.withCString { unlinkat(parent, $0, AT_REMOVEDIR) == 0 }
    }

    /// Depth-first traversal rooted at an already-open directory. Every child
    /// directory is opened with O_NOFOLLOW and checked against the inode first
    /// observed through its pinned parent before recursion. Entries that are
    /// replaced during traversal make cleanup fail closed.
    private static func removeDirectoryContents(
        _ directory: Int32,
        expectedIdentity: PathIdentity
    ) -> Bool {
        guard descriptorIdentity(directory) == expectedIdentity,
              let entries = directoryEntryNames(directory) else { return false }

        for leaf in entries {
            guard let identity = entryIdentity(directory, leaf) else {
                // A concurrently removed child needs no further cleanup.
                continue
            }
            guard let custodyDescriptor = openEntryForCustody(
                    directory,
                    leaf,
                    expected: identity
                  ) else { return false }
            let removed = removeDirectoryEntry(
                directory,
                leaf: leaf,
                identity: identity,
                custodyDescriptor: custodyDescriptor
            )
            close(custodyDescriptor)
            guard removed else { return false }
        }
        return descriptorIdentity(directory) == expectedIdentity
    }

    private static func removeDirectoryEntry(
        _ directory: Int32,
        leaf: String,
        identity: PathIdentity,
        custodyDescriptor: Int32
    ) -> Bool {
        var metadata = stat()
        guard fstat(custodyDescriptor, &metadata) == 0 else { return false }

        if metadata.st_mode & S_IFMT == S_IFDIR {
            let childDirectory = leaf.withCString { pointer in
                openat(
                    directory,
                    pointer,
                    O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
                )
            }
            guard childDirectory >= 0,
                  descriptorIdentity(childDirectory) == identity else {
                if childDirectory >= 0 { close(childDirectory) }
                return false
            }
            let contentsRemoved = removeDirectoryContents(
                childDirectory,
                expectedIdentity: identity
            )
            let childStillHeld = descriptorIdentity(childDirectory) == identity
            close(childDirectory)
            guard contentsRemoved,
                  childStillHeld,
                  descriptorIdentity(custodyDescriptor) == identity,
                  entryIdentity(directory, leaf) == identity else { return false }
            // Non-recursive removal cannot consume the contents of a rebound
            // directory; a non-empty replacement makes this fail closed.
            return leaf.withCString { unlinkat(directory, $0, AT_REMOVEDIR) == 0 }
        }

        guard descriptorIdentity(custodyDescriptor) == identity,
              entryIdentity(directory, leaf) == identity else { return false }
        return leaf.withCString { unlinkat(directory, $0, 0) == 0 }
    }

    private static func directoryEntryNames(_ directory: Int32) -> [String]? {
        let scanDescriptor = dup(directory)
        guard scanDescriptor >= 0 else { return nil }
        guard let stream = fdopendir(scanDescriptor) else {
            close(scanDescriptor)
            return nil
        }
        defer { closedir(stream) }

        var entries: [String] = []
        errno = 0
        while let entry = readdir(stream) {
            var nameBytes = entry.pointee.d_name
            let name = withUnsafeBytes(of: &nameBytes) { bytes -> String in
                let end = bytes.firstIndex(of: 0) ?? bytes.endIndex
                return String(decoding: bytes[..<end], as: UTF8.self)
            }
            if name != "." && name != ".." {
                entries.append(name)
            }
            errno = 0
        }
        return errno == 0 ? entries : nil
    }

    private static func retirePrivatePlaceholder(
        _ parent: Int32,
        leaf: String,
        identity: PathIdentity
    ) -> Bool {
        guard entryIdentity(parent, leaf) == identity else { return false }
        return leaf.withCString { unlinkat(parent, $0, 0) == 0 }
    }

    private static func restoreDisplacedCandidateWithoutExchange(
        _ parent: Int32,
        leaf: String,
        displacedLeaf: String,
        placeholderIdentity: PathIdentity
    ) {
        guard entryIdentity(parent, leaf) == placeholderIdentity,
              entryIdentity(parent, displacedLeaf) != nil else { return }
        let retiredPlaceholder = ".defenseclaw-retired-placeholder-" + UUID().uuidString
        guard renameAtNoReplace(parent, leaf, parent, retiredPlaceholder) == 0 else {
            return
        }
        if renameAtNoReplace(parent, displacedLeaf, parent, leaf) == 0 {
            _ = retirePrivatePlaceholder(
                parent,
                leaf: retiredPlaceholder,
                identity: placeholderIdentity
            )
            return
        }
        // If a concurrent entry claimed the canonical name, preserve it and
        // leave the displaced candidate private. Otherwise retry restoration
        // once before putting the placeholder back as the final visible,
        // fail-closed state for an unrecoverable filesystem error.
        if entryIdentity(parent, leaf) != nil {
            _ = retirePrivatePlaceholder(
                parent,
                leaf: retiredPlaceholder,
                identity: placeholderIdentity
            )
            return
        }
        if renameAtNoReplace(parent, displacedLeaf, parent, leaf) == 0 {
            _ = retirePrivatePlaceholder(
                parent,
                leaf: retiredPlaceholder,
                identity: placeholderIdentity
            )
            return
        }
        _ = renameAtNoReplace(parent, retiredPlaceholder, parent, leaf)
    }

    private static func restoreQuarantinedEntry(
        _ parent: Int32,
        leaf: String,
        quarantine: String
    ) {
        guard entryIdentity(parent, quarantine) != nil,
              entryIdentity(parent, leaf) == nil else { return }
        _ = renameAtNoReplace(parent, quarantine, parent, leaf)
    }

    private static func swapEntries(_ parent: Int32, _ first: String, _ second: String) -> Int32 {
        first.withCString { firstPointer in
            second.withCString { secondPointer in
                renameatx_np(
                    parent,
                    firstPointer,
                    parent,
                    secondPointer,
                    UInt32(RENAME_SWAP)
                )
            }
        }
    }

    private static func isLexicallyEmptyDirectory(_ path: String) -> Bool {
        var metadata = stat()
        guard path.withCString({ pointer in lstat(pointer, &metadata) }) == 0 else {
            return false
        }
        guard metadata.st_mode & S_IFMT == S_IFDIR else { return false }
        guard let contents = try? FileManager.default.contentsOfDirectory(atPath: path) else {
            return false
        }
        return contents.isEmpty
    }
}
