// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "DefenseClawApp",
    platforms: [.macOS(.v14)],
    dependencies: [
        .package(path: "../shared"),
    ],
    targets: [
        .executableTarget(
            name: "DefenseClaw",
            dependencies: [.product(name: "DefenseClawKit", package: "shared")],
            path: "DefenseClaw"
        ),
    ]
)
