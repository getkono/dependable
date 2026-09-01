// swift-tools-version:5.10
import PackageDescription

// Everything below is why this file is never read as text. The dependency list is
// assembled at build time: one entry comes from a literal, one from a loop over a
// value defined elsewhere, and one only exists on Apple platforms. A regex over
// this file does not return a short list, it returns a wrong one.
let extraPackages = ["swift-log": "1.5.0"]

var dependencies: [Package.Dependency] = [
    .package(url: "https://github.com/apple/swift-nio.git", from: "2.65.0"),
]

for (name, version) in extraPackages {
    dependencies.append(
        .package(url: "https://github.com/apple/\(name).git", from: Version(stringLiteral: version))
    )
}

#if canImport(Darwin)
dependencies.append(.package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"))
#endif

let package = Package(
    name: "SampleApp",
    products: [.library(name: "SampleApp", targets: ["SampleApp"])],
    dependencies: dependencies,
    targets: [.target(name: "SampleApp")]
)
