// A subproject. It has no `gradle/` directory of its own — a Gradle catalog is
// build-root scoped, so this reads the one at the root. Declaring it unread would
// tell the user to put these dependencies in a catalog that already holds them.
dependencies {
    implementation(project(":core"))
    implementation(libs.okhttp)
}
