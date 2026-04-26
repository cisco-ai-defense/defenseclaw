import Foundation
import CryptoKit

/// Ed25519 device identity for gateway challenge-response authentication.
/// Mirrors the Go implementation in internal/gateway/device.go.
public struct DeviceIdentity: Sendable {
    public let privateKey: Curve25519.Signing.PrivateKey
    public let publicKey: Curve25519.Signing.PublicKey
    public let deviceID: String

    /// Load existing keypair from disk or generate a new one.
    public static func loadOrCreate(keyFile: String? = nil) throws -> DeviceIdentity {
        let path = keyFile ?? defaultKeyPath()

        if let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
           let identity = try? parse(pemData: data) {
            return identity
        }

        // Generate new keypair
        let privKey = Curve25519.Signing.PrivateKey()
        let pubKey = privKey.publicKey

        // Write PEM to disk
        let dir = (path as NSString).deletingLastPathComponent
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)

        let seed = privKey.rawRepresentation
        let pemString = "-----BEGIN ED25519 PRIVATE KEY-----\n" +
            seed.base64EncodedString(options: [.lineLength64Characters]) +
            "\n-----END ED25519 PRIVATE KEY-----\n"
        try pemString.write(toFile: path, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path)

        return DeviceIdentity(
            privateKey: privKey,
            publicKey: pubKey,
            deviceID: fingerprint(pubKey)
        )
    }

    /// Build the device block for connect params (v3 protocol).
    public func connectDevice(
        clientID: String, clientMode: String, role: String, scopes: [String],
        token: String, nonce: String, platform: String
    ) -> [String: Any] {
        let signedAt = Int64(Date().timeIntervalSince1970 * 1000)
        let signature = signChallenge(
            clientID: clientID, clientMode: clientMode, role: role,
            scopes: scopes, token: token, nonce: nonce,
            platform: platform, signedAtMs: signedAt
        )
        return [
            "id": deviceID,
            "publicKey": publicKeyBase64URL(),
            "signature": signature,
            "signedAt": signedAt,
            "nonce": nonce,
        ]
    }

    // MARK: - Private

    private static func defaultKeyPath() -> String {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        return "\(home)/.defenseclaw/device.key"
    }

    private static func parse(pemData: Data) throws -> DeviceIdentity {
        guard let pemString = String(data: pemData, encoding: .utf8) else {
            throw DeviceIdentityError.invalidPEM
        }
        // Extract base64 content between PEM headers
        let lines = pemString.components(separatedBy: "\n")
            .filter { !$0.hasPrefix("-----") && !$0.isEmpty }
        let base64String = lines.joined()
        guard let seedData = Data(base64Encoded: base64String), seedData.count == 32 else {
            throw DeviceIdentityError.invalidSeed
        }
        let privKey = try Curve25519.Signing.PrivateKey(rawRepresentation: seedData)
        let pubKey = privKey.publicKey
        return DeviceIdentity(
            privateKey: privKey,
            publicKey: pubKey,
            deviceID: fingerprint(pubKey)
        )
    }

    private static func fingerprint(_ pubKey: Curve25519.Signing.PublicKey) -> String {
        let hash = SHA256.hash(data: pubKey.rawRepresentation)
        return hash.map { String(format: "%02x", $0) }.joined()
    }

    private func publicKeyBase64URL() -> String {
        publicKey.rawRepresentation.base64URLEncodedString()
    }

    /// Sign the v3 challenge payload — must match Go's SignChallenge exactly.
    private func signChallenge(
        clientID: String, clientMode: String, role: String, scopes: [String],
        token: String, nonce: String, platform: String, signedAtMs: Int64
    ) -> String {
        let scopeStr = scopes.joined(separator: ",")
        let payload = [
            "v3",
            deviceID,
            clientID,
            clientMode,
            role,
            scopeStr,
            "\(signedAtMs)",
            token,
            nonce,
            platform.lowercased().trimmingCharacters(in: .whitespaces),
            "", // deviceFamily (empty)
        ].joined(separator: "|")

        guard let sig = try? privateKey.signature(for: Data(payload.utf8)) else {
            return ""
        }
        return Data(sig).base64URLEncodedString()
    }
}

public enum DeviceIdentityError: Error, LocalizedError {
    case invalidPEM, invalidSeed
    public var errorDescription: String? {
        switch self {
        case .invalidPEM: return "Invalid PEM in device key file"
        case .invalidSeed: return "Invalid Ed25519 seed length"
        }
    }
}

// MARK: - Base64URL encoding (no padding, URL-safe alphabet)

extension Data {
    func base64URLEncodedString() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
