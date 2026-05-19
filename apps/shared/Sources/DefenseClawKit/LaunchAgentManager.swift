import Foundation

public struct LaunchAgentManager: Sendable {
    public static let label = "com.defenseclaw.sidecar"

    private let plistPath: String
    private let sidecarBinary: String

    public init(sidecarBinary: String = "defenseclaw-gateway") {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        self.plistPath = "\(home)/Library/LaunchAgents/\(Self.label).plist"
        self.sidecarBinary = sidecarBinary
    }

    public func plistContent() -> [String: Any] {
        [
            "Label": Self.label,
            "ProgramArguments": [sidecarBinary, "start", "--foreground"],
            "RunAtLoad": true,
            "KeepAlive": true,
            "StandardOutPath": "\(NSHomeDirectory())/.defenseclaw/sidecar.stdout.log",
            "StandardErrorPath": "\(NSHomeDirectory())/.defenseclaw/sidecar.stderr.log",
            "EnvironmentVariables": [
                "PATH": "/usr/local/bin:/usr/bin:/bin:\(NSHomeDirectory())/.local/bin"
            ]
        ]
    }

    public func install() throws {
        let plist = plistContent()
        let data = try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
        let url = URL(fileURLWithPath: plistPath)
        let dir = url.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        try data.write(to: url, options: .atomic)
    }

    public func load() throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        process.arguments = ["load", plistPath]
        try process.run()
        process.waitUntilExit()
    }

    public func unload() throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        process.arguments = ["unload", plistPath]
        try process.run()
        process.waitUntilExit()
    }

    public func uninstall() throws {
        try? unload()
        try FileManager.default.removeItem(atPath: plistPath)
    }

    public var isInstalled: Bool {
        FileManager.default.fileExists(atPath: plistPath)
    }

    public var isRunning: Bool {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        process.arguments = ["list", Self.label]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = Pipe()
        do {
            try process.run()
            process.waitUntilExit()
            return process.terminationStatus == 0
        } catch { return false }
    }
}
