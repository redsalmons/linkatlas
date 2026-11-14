import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

// Release signing material lives in android/keystore.properties (gitignored):
//   storeFile=..., storePassword=..., keyAlias=..., keyPassword=...
val keystoreProperties = Properties()
rootProject.file("keystore.properties").takeIf { it.exists() }
    ?.inputStream()?.use { keystoreProperties.load(it) }

val appVersionName = "1.0.0"

android {
    namespace = "com.redsalmons.linkatlas"
    setProperty("archivesBaseName", "linkatlas-v$appVersionName")
    compileSdk = 36
    ndkVersion = "28.2.13676358"
    sourceSets.getByName("main").assets.srcDir("../../third_party/geoip/data")

    defaultConfig {
        applicationId = "com.redsalmons.linkatlas"
        minSdk = 26
        targetSdk = 36
        versionCode = 3
        versionName = appVersionName
        val lookupUrl = providers.gradleProperty("lookupBaseUrl").getOrElse("")
            .replace("\\", "\\\\").replace("\"", "\\\"")
        buildConfigField("String", "LOOKUP_BASE_URL", "\"$lookupUrl\"")
        buildConfigField("long", "PLAY_CLOUD_PROJECT", "${providers.gradleProperty("playCloudProject").orNull?.toLongOrNull() ?: 0}L")
        buildConfigField("boolean", "LOOKUP_DEVELOPMENT", providers.gradleProperty("lookupDevelopment").getOrElse("false").toBoolean().toString())
        buildConfigField("boolean", "LOOKUP_REAL_BILLING", providers.gradleProperty("lookupRealBilling").getOrElse("false").toBoolean().toString())
        ndk { abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64") }
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }
    signingConfigs {
        maybeCreate("release").apply {
            val store = keystoreProperties.getProperty("storeFile")
            if (store != null) {
                storeFile = rootProject.file(store)
                storePassword = keystoreProperties.getProperty("storePassword")
                keyAlias = keystoreProperties.getProperty("keyAlias")
                keyPassword = keystoreProperties.getProperty("keyPassword")
            }
        }
    }
    buildTypes {
        getByName("debug") {
            // Dev environment; override with -PlookupBaseUrl=...
            if (providers.gradleProperty("lookupBaseUrl").orNull == null) {
                buildConfigField("String", "LOOKUP_BASE_URL", "\"https://testapp.freedomsalmon.com\"")
            }
            if (providers.gradleProperty("lookupDevelopment").orNull == null) {
                buildConfigField("boolean", "LOOKUP_DEVELOPMENT", "true")
            }
        }
        getByName("release") {
            buildConfigField("boolean", "LOOKUP_DEVELOPMENT", "false")
            if (providers.gradleProperty("lookupBaseUrl").orNull == null) {
                buildConfigField("String", "LOOKUP_BASE_URL", "\"https://app.freedomsalmon.com\"")
            }
            if (signingConfigs.getByName("release").storeFile != null) {
                signingConfig = signingConfigs.getByName("release")
            }
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2024.10.01")
    implementation(composeBom)
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.7")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-core")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-play-services:1.8.1")
    implementation("com.google.android.play:integrity:1.4.0")
    implementation("com.android.billingclient:billing-ktx:8.0.0")
    implementation("org.maplibre.gl:android-sdk:13.7.1")
    debugImplementation("androidx.compose.ui:ui-tooling")
}
