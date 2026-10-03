// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "NTLMac",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "NTLMacCore", targets: ["NTLMacCore"]),
        .executable(name: "ntlmac-nmh", targets: ["ntlmac-nmh"]),
    ],
    targets: [
        .target(name: "NTLMacCore"),
        .executableTarget(name: "ntlmac-nmh", dependencies: ["NTLMacCore"]),
        .testTarget(name: "NTLMacCoreTests", dependencies: ["NTLMacCore"]),
    ]
)
