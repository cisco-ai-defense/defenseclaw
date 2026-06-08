// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "DefenseClawKit",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "DefenseClawKit", targets: ["DefenseClawKit"]),
    ],
    dependencies: [
        .package(url: "https://github.com/jpsim/Yams.git", from: "5.1.0"),
    ],
    targets: [
        .target(
            name: "DefenseClawKit",
            dependencies: ["Yams"],
            exclude: ["API-PROTOCOL.md"]
        ),
        .testTarget(
            name: "DefenseClawKitTests",
            dependencies: ["DefenseClawKit"]
        ),
    ]
)
