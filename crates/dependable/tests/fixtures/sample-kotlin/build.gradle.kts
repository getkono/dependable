// A build script, kept beside the catalog so the fixture exercises the case where
// the catalog is present and the script therefore needs no notice.
plugins {
    alias(libs.plugins.kotlin.jvm)
}

dependencies {
    implementation(libs.kotlin.stdlib)
    implementation(libs.okhttp)
    testImplementation(libs.bundles.testing)
}
