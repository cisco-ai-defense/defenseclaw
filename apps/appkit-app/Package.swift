// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "DefenseClawAppKit",
    platforms: [.macOS(.v14)],
    dependencies: [
        .package(path: "../shared"),
    ],
    targets: [
        .executableTarget(
            name: "DefenseClawAppKit",
            dependencies: [.product(name: "DefenseClawKit", package: "shared")],
            path: "DefenseClawAppKit"
        ),
    ]
)
