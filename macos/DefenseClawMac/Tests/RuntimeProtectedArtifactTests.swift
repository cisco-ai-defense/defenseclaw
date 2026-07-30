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

import CryptoKit
import Foundation

@main
struct RuntimeProtectedArtifactTests {
    static func main() throws {
        try decodesProtectedWheel()
        try rejectsInvalidEnvelope()
        try rejectsEmptyPayload()
        try rejectsChecksumDrift()
        validatesVersionBoundFilename()
        validatesProtectedArtifactSizeLimit()
        print("RuntimeProtectedArtifactTests passed")
    }

    private static func decodesProtectedWheel() throws {
        let fixture = try Fixture(payload: Data([0x50, 0x4b, 0x03, 0x04, 0x01, 0x02]))
        defer { fixture.cleanup() }

        try RuntimePayload.decodeProtectedArtifact(
            from: fixture.source,
            to: fixture.destination,
            expectedEncodedSHA256: fixture.encodedSHA256
        )

        expect(
            try Data(contentsOf: fixture.destination) == fixture.payload,
            "protected wheel bytes decode exactly"
        )
        let attributes = try FileManager.default.attributesOfItem(atPath: fixture.destination.path)
        let permissions = (attributes[.posixPermissions] as? NSNumber)?.intValue
        expect(permissions == 0o600, "decoded wheel is owner-readable and owner-writable only")
    }

    private static func rejectsInvalidEnvelope() throws {
        let fixture = try Fixture(payload: Data([0x50, 0x4b]))
        defer { fixture.cleanup() }
        try Data(
            repeating: 0x78,
            count: RuntimePayload.protectedArtifactMagic.count + 1
        ).write(to: fixture.source)

        expectThrows(.invalidEnvelope, "invalid protected header is rejected") {
            try RuntimePayload.decodeProtectedArtifact(
                from: fixture.source,
                to: fixture.destination,
                expectedEncodedSHA256: RuntimePayload.sha256(of: fixture.source) ?? ""
            )
        }
        expect(!FileManager.default.fileExists(atPath: fixture.destination.path), "failed output is removed")
    }

    private static func rejectsEmptyPayload() throws {
        let fixture = try Fixture(payload: Data([0x50]))
        defer { fixture.cleanup() }
        try RuntimePayload.protectedArtifactMagic.write(to: fixture.source)

        expectThrows(.emptyPayload, "empty protected payload is rejected") {
            try RuntimePayload.decodeProtectedArtifact(
                from: fixture.source,
                to: fixture.destination,
                expectedEncodedSHA256: RuntimePayload.sha256(of: fixture.source) ?? ""
            )
        }
    }

    private static func rejectsChecksumDrift() throws {
        let fixture = try Fixture(payload: Data([0x50, 0x4b, 0x03, 0x04]))
        defer { fixture.cleanup() }

        expectThrows(.checksumMismatch, "encoded checksum is revalidated during decode") {
            try RuntimePayload.decodeProtectedArtifact(
                from: fixture.source,
                to: fixture.destination,
                expectedEncodedSHA256: String(repeating: "0", count: 64)
            )
        }
        expect(!FileManager.default.fileExists(atPath: fixture.destination.path), "checksum failure removes output")
    }

    private static func validatesVersionBoundFilename() {
        expect(
            RuntimePayload.expectedProtectedWheelFilename(version: "0.8.6")
                == "defenseclaw-0.8.6-2-py3-none-any.dcwheel",
            "schema-2 protected wheel name is version-bound"
        )
    }

    private static func validatesProtectedArtifactSizeLimit() {
        let minimum = Int64(RuntimePayload.protectedArtifactMagic.count + 1)
        expect(
            RuntimePayload.protectedArtifactSizeIsAllowed(minimum),
            "a nonempty protected payload is allowed"
        )
        expect(
            !RuntimePayload.protectedArtifactSizeIsAllowed(0),
            "an undersized protected artifact is rejected"
        )
        expect(
            !RuntimePayload.protectedArtifactSizeIsAllowed(
                RuntimePayload.maximumProtectedArtifactBytes + 1
            ),
            "oversized protected payload is rejected before decoding"
        )
    }

    private static func expectThrows(
        _ expected: ProtectedArtifactError,
        _ message: String,
        operation: () throws -> Void
    ) {
        do {
            try operation()
            fail(message)
        } catch let error as ProtectedArtifactError {
            expect(error == expected, message)
        } catch {
            fail("\(message): unexpected error \(error)")
        }
    }

    private static func expect(_ condition: @autoclosure () throws -> Bool, _ message: String) {
        do {
            guard try condition() else { fail(message) }
        } catch {
            fail("\(message): \(error)")
        }
    }

    private static func fail(_ message: String) -> Never {
        fputs("FAILED: \(message)\n", stderr)
        exit(1)
    }

    private struct Fixture {
        let directory: URL
        let source: URL
        let destination: URL
        let payload: Data
        let encodedSHA256: String

        init(payload: Data) throws {
            self.payload = payload
            directory = FileManager.default.temporaryDirectory.appendingPathComponent(
                "DefenseClaw-protected-artifact-tests-\(UUID().uuidString)",
                isDirectory: true
            )
            source = directory.appendingPathComponent("runtime.dcwheel")
            destination = directory.appendingPathComponent("runtime.whl")
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)

            var encodedPayload = payload
            encodedPayload.withUnsafeMutableBytes { bytes in
                for index in bytes.indices {
                    bytes[index] ^= RuntimePayload.protectedArtifactXORByte
                }
            }
            var artifact = RuntimePayload.protectedArtifactMagic
            artifact.append(encodedPayload)
            try artifact.write(to: source)
            encodedSHA256 = SHA256.hash(data: artifact)
                .map { String(format: "%02x", $0) }
                .joined()
        }

        func cleanup() {
            try? FileManager.default.removeItem(at: directory)
        }
    }
}
