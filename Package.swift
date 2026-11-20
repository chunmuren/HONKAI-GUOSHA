// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "BgsSecure",
    platforms: [.iOS(.v15), .macOS(.v12)],
    products: [
        .library(name: "BgsSecure", targets: ["BgsSecure"]),
    ],
    targets: [
        .target(name: "BgsSecure"),
        .testTarget(name: "BgsSecureTests", dependencies: ["BgsSecure"]),
    ]
)
