# WebHack Toolkit — Android Source Project

An Android app starter for basic, non-invasive website security checks on websites you own or are authorized to assess.

## Features
- Android-native UI
- HTTPS-only target input
- TLS connection and certificate summary
- Basic security response-header checks
- Cookie attribute checks
- Limited redirect inspection
- DNS lookup summary
- Server / technology hints from response headers
- Local scan history
- Share report as JSON

## Build an APK
1. Install Android Studio and JDK 17.
2. Open this folder in Android Studio.
3. Wait for Gradle sync to complete.
4. Choose **Build > Build Bundle(s) / APK(s) > Build APK(s)**.
5. Android Studio will show the APK location.

This package contains source code, not a prebuilt APK. A Gradle wrapper is not included. The project has not been built or device-tested in this environment.

## Notes
- Use only on sites you own or have explicit permission to assess.
- This is a basic diagnostic check, not a full penetration test.
- Network results depend on DNS, server behavior, and the device's network.
- No exploit attempts, brute force, credential testing, stealth, or bypass functions are included.

## Package name
- Namespace / application ID: `com.forgelab.webhacktoolkit`
