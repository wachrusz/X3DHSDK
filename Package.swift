// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "X3DHSDK",
    platforms: [
        .iOS(.v14),
        .macOS(.v11)
    ],
    products: [
        .library(
            name: "X3DHSDK",
            targets: ["X3DHSDK"]
        ),
    ],
    targets: [
        .target(
            name: "X3DHSDK",
            path: "Sources/X3DHSDK"
        ),
        .testTarget(
            name: "X3DHSDKTests",
            dependencies: ["X3DHSDK"],
            path: "Tests/X3DHSDKTests"
        )
    ]
)

