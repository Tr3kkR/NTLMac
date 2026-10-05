// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "NTLMac",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "NTLMacCore", targets: ["NTLMacCore"]),
        .executable(name: "ntlmac-nmh", targets: ["ntlmac-nmh"]),
        .executable(name: "NTLMacAgent", targets: ["NTLMacAgent"]),
    ],
    targets: [
        .target(name: "CKerberos", linkerSettings: [.linkedFramework("Kerberos")]),
        .target(name: "NTLMacCore", dependencies: ["CKerberos"]),
        .executableTarget(name: "ntlmac-nmh", dependencies: ["NTLMacCore"]),
        .executableTarget(name: "NTLMacAgent", dependencies: ["NTLMacCore"]),
        .testTarget(name: "NTLMacCoreTests", dependencies: ["NTLMacCore"]),
    ]
)
