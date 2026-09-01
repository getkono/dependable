// A second subproject, for the same reason: the notice has to stay silent for
// every module of a correctly configured build, not just for the first.
dependencies {
    implementation(libs.kotlin.stdlib)
    testImplementation(libs.bundles.testing)
}
