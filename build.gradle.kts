plugins {
    kotlin("jvm") version "2.4.20"
}

group = "com.hekeki.eckstein"
version = "0.1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

kotlin {
    jvmToolchain(25)
}

dependencies {
    testImplementation(platform("org.junit:junit-bom:5.11.4"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")

    testImplementation("org.mindrot:jbcrypt:0.4")
    testImplementation("org.bouncycastle:bcprov-jdk18on:1.85.2")
}

tasks.withType<Test> {
    useJUnitPlatform()
}

