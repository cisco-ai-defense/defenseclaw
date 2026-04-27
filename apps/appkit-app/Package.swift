// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "DefenseClawAppKit",
    platforms: [.macOS(.v14)],
    dependencies: [
        .package(path: "../shared"),
        .package(url: "https://github.com/jpsim/Yams.git", from: "5.1.0"),
    ],
    targets: [
        .executableTarget(
            name: "DefenseClawAppKit",
            dependencies: [
                .product(name: "DefenseClawKit", package: "shared"),
                "Yams",
            ],
            path: "DefenseClawAppKit"
        ),
        .testTarget(
            name: "DefenseClawAppKitTests",
            dependencies: ["DefenseClawAppKit"],
            path: "Tests/DefenseClawAppKitTests"
        ),
    ]
)
