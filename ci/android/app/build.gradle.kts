plugins {
  id("com.android.application")
}

android {
  namespace = "dev.getifs.androidharness"
  compileSdk = 34

  defaultConfig {
    applicationId = "dev.getifs.androidharness"
    minSdk = 24
    targetSdk = 34
    versionCode = 1
    versionName = "1.0"
    testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    // cargo-ndk builds only the emulator ABI into src/main/jniLibs.
    ndk { abiFilters += "x86_64" }
  }
}

dependencies {
  androidTestImplementation("androidx.test.ext:junit:1.2.1")
  androidTestImplementation("androidx.test:runner:1.6.2")
}
