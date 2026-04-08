plugins {
    kotlin("jvm") version "2.3.10"
    kotlin("plugin.spring") version "2.3.10"
    kotlin("plugin.power-assert") version "2.3.20"
    id("org.springframework.boot") version "4.0.2"
    id("io.spring.dependency-management") version "1.1.7"
    id("gg.jte.gradle") version("3.2.3")
}

kotlin {
    jvmToolchain(25)
}

jte {
    generate()
    binaryStaticContent = true
    jteExtension("gg.jte.models.generator.ModelExtension") {
        property("language", "Kotlin")
    }
}

dependencies {
    implementation("org.springframework.boot:spring-boot-starter-webmvc")
    implementation("org.springframework.boot:spring-boot-starter-security-oauth2-authorization-server")
    implementation("org.springaicommunity:mcp-authorization-server:0.1.2")
    implementation("gg.jte:jte-spring-boot-starter-4:3.2.3")
    implementation("gg.jte:jte-runtime:3.2.3")

    runtimeOnly("org.webjars:webjars-locator-lite:1.1.0")
    runtimeOnly("org.webjars.npm:tailwindcss__browser:4.1.18")

    compileOnly("gg.jte:jte-kotlin:3.2.3")

    jteGenerate("gg.jte:jte-models:3.2.3")

    runtimeOnly(kotlin("reflect"))

    testImplementation("org.springframework.boot:spring-boot-starter-test")

    testRuntimeOnly("org.springframework.boot:spring-boot-devtools")
}

tasks.withType<Test> {
    useJUnitPlatform()

    testLogging {
        showStandardStreams = true
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
        events(org.gradle.api.tasks.testing.logging.TestLogEvent.STARTED, org.gradle.api.tasks.testing.logging.TestLogEvent.PASSED, org.gradle.api.tasks.testing.logging.TestLogEvent.SKIPPED, org.gradle.api.tasks.testing.logging.TestLogEvent.FAILED)
    }
}

tasks.named<org.springframework.boot.gradle.tasks.run.BootRun>("bootTestRun") {
    systemProperty("spring.profiles.active", "testrun")
}
