plugins {
    id("java")
}

repositories {
    mavenCentral()
}

dependencies {
    compileOnly("net.portswigger.burp.extensions:montoya-api:2026.7")

    // The API is compile-only for the extension (Burp provides it at runtime), but tests that touch
    // Burp-facing classes still need it on their classpath to load them.
    testCompileOnly("net.portswigger.burp.extensions:montoya-api:2026.7")
    testRuntimeOnly("net.portswigger.burp.extensions:montoya-api:2026.7")

    testImplementation(platform("org.junit:junit-bom:5.11.3"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.withType<JavaCompile>().configureEach {
    options.encoding = "UTF-8"
    // Java 21 bytecode, cross-compiled from whatever JDK (>= 21) is running Gradle. A `toolchain`
    // block would be stricter, but it hard-fails when no JDK of exactly that version is installed
    // -- including when only a JRE is present, which is the common case on build machines.
    options.release = 21
}

tasks.test {
    useJUnitPlatform()
    testLogging {
        events("passed", "failed", "skipped")
    }
    // Points RealCaptureValidationTest at a fixture file exported from Burp. Without it that test
    // skips, so the suite still runs on a machine that has never seen the target.
    System.getProperty("oracleforms.fixtures")?.let {
        systemProperty("oracleforms.fixtures", it)
    }
}

tasks.named<Jar>("jar") {
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    from(configurations.runtimeClasspath.get().filter { it.isDirectory })
    from(configurations.runtimeClasspath.get().filterNot { it.isDirectory }.map { zipTree(it) })
}
