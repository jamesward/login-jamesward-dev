plugins {
    kotlin("jvm") version "2.3.20"
    kotlin("plugin.spring") version "2.3.20"
    kotlin("plugin.power-assert") version "2.3.20"
    id("org.springframework.boot") version "4.0.6"
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
    runtimeOnly(kotlin("reflect"))

    implementation("org.springframework.boot:spring-boot-starter-webmvc")
    implementation("org.springframework.boot:spring-boot-starter-security-oauth2-authorization-server")
    // need a way to customize the SecurityFilterChain
//    implementation("org.springaicommunity:mcp-authorization-server-spring-boot:0.1.5")
    implementation("org.springaicommunity:mcp-authorization-server:0.1.5")

    implementation("gg.jte:jte-spring-boot-starter-4:3.2.3")
    implementation("gg.jte:jte-runtime:3.2.3")
    compileOnly("gg.jte:jte-kotlin:3.2.3")
    jteGenerate("gg.jte:jte-models:3.2.3")

    runtimeOnly("org.webjars:webjars-locator-lite:1.1.3")
    runtimeOnly("org.webjars.npm:tailwindcss__browser:4.2.1")

    testRuntimeOnly("org.springframework.boot:spring-boot-devtools")
}
