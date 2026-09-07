# Требования публичного релиза 2026 — спасённые результаты исследования (2026-09-07)

> Агент research:release-2026 дважды упал до формирования итогового ответа. Ниже — результаты его веб-поисков (сводки поисковой системы + первые источники), без правок. Синтез и чеклисты — в `../release-audit-2026-09.md` §6.6. Проверять критичные даты/цены по первоисточникам перед действиями.

## 1. Azure Trusted Signing individual developers availability 2026 requirements countries price

Based on the search results, here's what I found about Azure Trusted Signing (now called Azure Artifact Signing) for individual developers in 2026:
## Availability for Individual Developers
Individual developers must be located in the United States or Canada for Public Trust certificates. This is a significant geographic restriction compared to organizations, which have broader availability.
## Geographic Availability
Public Trust certificates are available to organizations in the United States, Canada, the European Union, the United Kingdom, Australia, New Zealand, Japan, South Korea, Singapore, Switzerland, Norway, and Israel. However, individual developers are restricted to just the US and Canada.
## Pricing
The service costs $9.99 per month for up to 5,000 signatures with one certificate profile, or $99.99 per month for up to 100,000 signatures with 10 certificate profiles.
## Rebranding
It's worth noting that Azure Trusted Signing was renamed Azure Artifact Signing in 2026, so you may see both names used interchangeably in current documentation.
## Additional Context
The service enables Windows developers to deploy applications without them being blocked or interrupted by pop-up warnings, and uses certificates that are renewed daily and valid for only 24 hours.

Источники:
- [Code signing Windows apps may be easier and more secure with new Azure Artifact service](https://www.devclass.com/security/2026/01/14/code-signing-windows-apps-may-be-easier-and-more-secure-with-new-azure-artifact-service/4079554)
- [Fighting through Setting up Microsoft Trusted Signing - Rick Strahl's Weblog](https://weblog.west-wind.com/posts/2025/Jul/20/Fighting-through-Setting-up-Microsoft-Trusted-Signing)
- [Can't create a new Trusted Signing Individual identity because my country is not available - Microsoft Q&A](https://learn.microsoft.com/en-nz/answers/questions/5810735/cant-create-a-new-trusted-signing-individual-ident)
- [Trusted Signing is now open for individual developers to sign up in Public Preview! | Microsoft Community Hub](https://techcommunity.microsoft.com/blog/microsoft-security-blog/trusted-signing-is-now-open-for-individual-developers-to-sign-up-in-public-previ/4273554)
- [Quickstart: Set up Artifact Signing | Microsoft Learn](https://learn.microsoft.com/en-us/azure/artifact-signing/quickstart)

## 2. SignPath Foundation open source code signing free requirements 2026

Based on the search results, here's what I found about SignPath Foundation's open source code signing program:
## Overview
SignPath Foundation is a nonprofit organization that provides free code signing for qualifying open-source projects through a partnership with SignPath.io, an enterprise code signing platform.
## What You Get
SignPath Foundation offers free code signing for qualifying open-source projects, providing OV-level certificate signing through a managed pipeline. An OV-level code signing certificate is provided for your project, with the private key stored on SignPath Foundation's HSM.
## Key Requirements
To be eligible, open source projects must meet these conditions:
- The project must use an OSI-approved Open Source license without commercial dual-licensing for all components
- The project must not contain malware or potentially unwanted programs
- The project must be actively maintained
- The project must already be released in the form that should be signed
- Must be an open-source project with a publicly available codebase
## Application Process
SignPath Foundation reviews the application and verifies the project meets eligibility criteria, with applications typically taking a few days to a few weeks to process.

Источники:
- [SignPath Software Integrity Platform - The free Code Signing & Software Integrity solution for Open Source Projects](https://signpath.io/solutions/open-source-community)
- [Code signing options for Windows app developers - Windows apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/code-signing-options)
- [Applying for the SignPath Foundation: Free Code Signing for OSS (Part 1: Application)](https://zenn.dev/shm_7ec/articles/signpath-oss-code-signing?locale=en)
- [SignPath Foundation conditions for Open Source projects](https://signpath.org/terms.html)
- [SignPath Foundation](https://signpath.org/)

## 3. Google Play target API level requirement 2026 Android 16 API 36 deadline

Here are the key findings from the web search:
## Google Play Target API Level Requirement for 2026
Starting August 31, 2026, new apps and app updates must target Android 16 (API level 36) or higher to be submitted to Google Play, except for Wear OS and Android Automotive OS apps, which must target Android 15 (API level 35) or higher, and Android TV and Android XR apps, which must target Android 14 (API level 34) or higher.
Existing apps must target Android 15 (API level 35) or higher to remain available to new users on devices running Android OS higher than your app's target API level.
## Extension Option
Developers can request an extension until November 1, 2026, to meet these requirements.
## Purpose
Google Play regularly raises its target API level requirements to ensure Android apps take advantage of the latest security protections, privacy features, performance improvements, and platform capabilities.
The deadline applies to all new app submissions and updates to existing apps on Google Play, with special considerations for specific device form factors like Wear OS, Android TV, and Android Automotive OS.

Источники:
- [Google Play target API requirements for Android apps (2026) | Median.co](https://median.co/blog/google-plays-target-api-level-requirement-for-android-apps)
- [Target API level requirements for Google Play apps - Play Console Help](https://support.google.com/googleplay/android-developer/answer/11926878?hl=en)
- [App must target Android 16 (API level 36) or higher | B4X Programming Forum](https://www.b4x.com/android/forum/threads/app-must-target-android-16-api-level-36-or-higher.171610/)
- [Google Play Requires Android 16 (API Level 36) by August 31, 2026 — React Native Migration Guide - DEV Community](https://dev.to/dainyjose/google-play-requires-android-16-api-level-36-by-august-31-2026-react-native-migration-guide-1d51)
- [Google Play Target API Level: Miss August 31 and Updates Stop | Testers Community](https://www.testerscommunity.com/blog/update-your-target-api-level-by-august-31-2026)

## 4. macOS Sequoia Tahoe notarization required Gatekeeper 2026 developer ID hardened runtime

I've performed the web search for your query. Here are the key findings related to macOS Sequoia, Tahoe, notarization, Gatekeeper, Developer ID, and hardened runtime:
## macOS Sequoia & Gatekeeper Changes
In macOS Sequoia, users will no longer be able to Control-click to override Gatekeeper when opening software that isn't signed correctly or notarized. They'll need to visit System Settings > Privacy & Security to review security information for software before allowing it to run.
## Notarization Requirements
If you distribute software outside of the Mac App Store, notarization is recommended, as the Apple notary service automatically scans your Developer ID-signed software and performs security checks. From a software publisher's perspective, notarization is now non-optional for professional macOS distribution.
## Hardened Runtime
When enabled for a macOS app, hardened runtime adds an extra layer of protection to the running code itself by preventing certain classes of exploits, like code injection, dynamically linked library (DLL) hijacking, and process memory space tampering.
## macOS Tahoe
macOS Tahoe was announced at WWDC 2025 on June 9, 2025, and was released on September 15, 2025. macOS Tahoe includes built-in malware protections like XProtect, Gatekeeper, and app notarization.
The search results show these security requirements and practices are actively in use for macOS development through 2026.

Источники:
- [How to Notarize & Publish an Electron App on macOS (2026)](https://www.forasoft.com/blog/article/the-pain-of-publishing-electron-apps-on-macos-303)
- [Updates to runtime protection in macOS Sequoia - Latest News - Apple Developer](https://developer.apple.com/news/?id=saqachfa)
- [MacOS Tahoe](https://en.wikipedia.org/wiki/MacOS_Tahoe)
- [MacOS Sequoia](https://en.wikipedia.org/wiki/MacOS_Sequoia)
- [macOS Apps: From Sandboxing to Notarization, The Basics – Xojo Programming Blog](https://blog.xojo.com/2024/08/22/macos-apps-from-sandboxing-to-notarization-the-basics/)

## 5. Google Play 16 KB page size requirement November 2025 native libraries deadline

Based on the search results, here's what you need to know about Google Play's 16 KB page size requirement:
## Timeline and Deadline
Starting November 1st, 2025, all new apps and updates to existing apps submitted to Google Play and targeting Android 15+ devices must support 16 KB page sizes. However, Google extended the deadline to May 31, 2026 in the Play Console.
## What This Requirement Means
New Android devices are using larger memory page sizes (16KB instead of 4KB) for better performance. Without recompiling to support 16 KB pages, your app might not function correctly on these devices when they become more widely available in future Android releases.
## Which Apps Are Affected
The requirement primarily impacts apps with native code. Apps with no native code should be compatible without any changes at all. However, apps using libraries or SDKs that contain native code may need to update these to a compatible version.
## What to Do
Most of the time, just updating your dependencies and rebuild tools will solve the problem. Many popular SDK providers, like React Native and Flutter, already offer compatible versions.

Источники:
- [Google Play 16KB Page Size Requirement: What You Need to Do Before November 2025 | by Ahmet Eren Atalay | Medium](https://medium.com/@ahmetatalay95/google-play-16kb-page-size-requirement-what-you-need-to-do-before-november-2025-9c85831ca11f)
- [Android Developers Blog: Prepare your apps for Google Play’s 16 KB page size compatibility requirement](https://android-developers.googleblog.com/2025/05/prepare-play-apps-for-devices-with-16kb-page-size.html)
- [[Android] Please add support for 16 KB memory page sizes (Google Play requirement) · Issue #970 · wonday/react-native-pdf](https://github.com/wonday/react-native-pdf/issues/970)
- [Google Play’s 16 KB Page Size Compatibility Requirement — What You Should Know, and How to Upgrade Your App](https://www.freecodecamp.org/news/google-16-kb-page-size-requirement-what-to-do/)
- [Support 16 KB page sizes - Policy request - 1 November 2025 or May 2026 - Google Play Developer Community](https://support.google.com/googleplay/android-developer/thread/368815999/support-16-kb-page-sizes-policy-request-1-november-2025-or-may-2026?hl=en)

## 6. Certum open source code signing certificate price 2026 OV cloud

Based on the search results, here's what I found about Certum open source code signing certificates:
## Pricing Information for 2026
Certum Open Source Code Signing Certificate pricing starts at $49.99. Additionally, Certum offers free code signing certificates for verified open source projects.
## Cloud Signing Options
For cloud-based deployment, a 3-year Certum Standard Code Signing in the Cloud certificate is available through SSLmentor at $108/year. For EV (Extended Validation) certificates, Certum offers cloud-based EV signing starting at $226/year.
## Key Features
Certum, operated by Poland-based Asseco Data Systems S.A., offers the cheapest traditional OV code signing certificate on the market, with their standout feature being SimplySign—a free cloud-based signing service that presents your certificate as a virtual smart card in Windows without needing a USB token.
## Important 2026 Validity Change
Starting from February 27, 2026, a single Code Signing certificate may be valid for a maximum of 459 days, and when purchasing 2 or 3-year products, one or more free reissues will be required during the service period.

Источники:
- [The Cheapest Code Signing Certificate for Business Central AppSource in 2026: A Complete Comparison Guide - Ivan Singleton](https://ivansingleton.dev/the-cheapest-code-signing-certificate-for-business-central-appsource-in-2026-a-complete-comparison-guide/)
- [Code Signing - Certum Shop](https://shop.certum.eu/code-signing.html)
- [Code Signing Certificate Costs (2026 Pricing Comparison)](https://desktopcore.com/compare/code-signing-costs)
- [Certum Cloud CODE Signing from $116 | SSLmentor](https://www.sslmentor.com/certum/certumcodecloud)
- [Certum Cloud EV CODE Signing from 226 USD | SSLmentor](https://www.sslmentor.com/certum/certumcodecloudev)

## 7. winget community repository submit manifest requirements unsigned installer MSI 2026

Based on the search results, here's what I found about Windows Package Manager (winget) community repository submission requirements:
## Supported Installer Formats
Installers must be MSIX, MSI, APPX, MSIXBundle, APPXBundle, or .exe application installers. MSI installers are among the supported formats for submission.
## Manifest Requirements
To submit a software package to the Windows Package Manager Community Repository, start by creating a package manifest, which is a YAML file that describes the application to be installed.
## Submission Process
To submit your manifest, you'll upload it to the open source https://github.com/microsoft/winget-pkgs repository on GitHub. After you submit a pull request to add a new manifest to the GitHub repository, an automated process will validate your manifest file and check to make sure the package complies with the Windows Package Manager policies and is not known to be malicious.
## Regarding Unsigned Installers
The search results do not contain specific information about whether unsigned MSI installers are permitted or required to be signed for submission to the Windows Package Manager community repository. You may need to consult the contributing guidelines in the GitHub repository directly or check the official Microsoft documentation for detailed signing requirements.

Источники:
- [GitHub - microsoft/winget-pkgs: The Microsoft community Windows Package Manager manifest repository · GitHub](https://github.com/microsoft/winget-pkgs)
- [Publish your first Windows app - Windows apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/publish-first-app)
- [Create your package manifest | Microsoft Learn](https://learn.microsoft.com/en-us/windows/package-manager/package/manifest)
- [GitHub - microsoft/winget-pkgs at 85f2cd525151a087851832c27f66b831889a2e6c · GitHub](https://github.com/microsoft/winget-pkgs/tree/85f2cd525151a087851832c27f66b831889a2e6c)
- [winget-cli/doc/windows/package-manager/package/manifest.md at master · microsoft/winget-cli](https://github.com/microsoft/winget-cli/blob/master/doc/windows/package-manager/package/manifest.md)

## 8. Flathub submission requirements 2026 tray StatusNotifier portal notifications sandbox permissions review

Based on my search results, here's what I found about Flathub submission requirements in 2026:
## Key 2026 Submission Requirements
**Generative AI Policy**: Flathub now explicitly bans AI-generated or AI-assisted applications and extends this restriction to the entire submission process. "Applications containing AI-generated or AI-assisted code, documentation, or any other content are not allowed. Submission pull requests must not be generated, opened, or automated using AI tools or agents."
**What Gets Rejected**: Console apps, minimal scripts, web wrappers without meaningful desktop integration, duplicate submissions of the same app built with different frameworks, and anything that violates the AI policy are not accepted.
**Development History Scrutiny**: The review team will also check your development history. A brand-new repository with a single commit is a red flag.
**Submission Process**: Flathub submissions are managed through pull requests on GitHub. Now open a pull request against the new-pr base branch on GitHub.
**Post-Merge Responsibilities**: Once your app is merged, you get a repository under the Flathub GitHub organization. You are responsible for updating the manifest when new versions are released, keeping runtimes current, and responding to user issues.
Regarding the specific technical aspects you mentioned (tray, StatusNotifier, portal, notifications, sandbox permissions), my search results don't contain detailed information about those specific requirements. You may want to consult the official Flathub documentation at https://docs.flathub.org/ for those technical specifications.

Источники:
- [Flathub Now Rejects AI-Assisted Apps and Submissions](https://linuxiac.com/flathub-now-rejects-ai-assisted-apps-and-submissions/)
- [Flathub and Flatpak in 2026: The Complete Guide to Finding, Installing, and Publishing Linux Apps](https://www.fosslinux.com/157752/flathub-flatpak-complete-guide.htm)
- [Home · flathub/flathub Wiki · GitHub](https://github.com/flathub/flathub/wiki/Submission-Guidelines)
- [Submission | Flathub Documentation](https://docs.flathub.org/docs/for-app-authors/submission)
- [Flatpak](https://en.wikipedia.org/wiki/Flatpak)

## 9. Android 15 foreground service dataSync 6 hour limit Android 16 changes mediaProcessing

Based on the search results, here's what I found regarding Android 15 and Android 16 foreground service changes:
## Android 15 Changes
Android 15 introduces a 6-hour time limit for all dataSync foreground services in a 24-hour period. After hitting this limit, the system calls the new onTimeout() method, giving the service just a few seconds to stop itself using stopSelf().
Make sure your app's dataSync services don't run for more than a total of 6 hours in any 24-hour period (unless the user interacts with the app, resetting the timer). If your app's dataSync foreground services have run for 6 hours in the last 24, you cannot start another dataSync foreground service unless the user has brought your app to the foreground (which resets the timer).
The same 6-hour limit also applies to mediaProcessing services: If your app's mediaProcessing foreground services have run for 6 hours in the last 24, you cannot start another mediaProcessing foreground service unless the user has brought your app to the foreground (which resets the timer). If you try to start another mediaProcessing foreground service, the system throws ForegroundServiceStartNotAllowedException with an error message like "Time limit already exhausted for foreground service type mediaProcessing".
## Android 16 Changes
Background jobs started from a foreground service now must adhere to their respective runtime quotas. This includes jobs scheduled directly with JobScheduler, as well as jobs created by other libraries like WorkManager or DownloadManager.

Источники:
- [📝 Behavior Changes: Apps Targeting Android 15 | by Nilesh B | Medium](https://medium.com/@nileshg994/behavior-changes-apps-targeting-android-15-part-1-e3d53174b3cd)
- [Behavior changes: Apps targeting Android 15 or higher | Android Developers](https://developer.android.com/about/versions/15/behavior-changes-15)
- [Android Foreground Services in 2026: What Changed and How to Adapt - DEV Community](https://dev.to/joe_wang_6a4a3e51566e8b52/android-foreground-services-in-2026-what-changed-and-how-to-adapt-2o3d)
- [Foreground services can only run for 6 hours tops during a day · Issue #5338 · home-assistant/android](https://github.com/home-assistant/android/issues/5338)
- [Foreground service timeouts | Background work | Android Developers](https://developer.android.com/develop/background-work/services/fgs/timeout)

## 10. F-Droid reproducible builds Rust NDK requirements 2026 cargo-ndk reproducible

I've completed the web search for your query. Here are the key findings:
## F-Droid Reproducible Builds with Rust and NDK
**Rust Toolchain Requirements:**
The Rust toolchain should be pinned to the same version as upstream, which can be done when installing rustup with `rustup-init.sh -y --default-toolchain <version>`.
**NDK Requirements:**
NDK also needs to be in the same path which can be solved by linking it to the same path.
**Environment Variables:**
SOURCE_DATE_EPOCH can be set to remove the embedded timestamps and CARGO_TARGET_DIR can be set to an absolute path, e.g. /tmp/build to make the embedded path reproducible between different machines. CARGO_HOME path plays an important part too and ends up in the built libs; it's recommended to match it between builds by exporting it before running rustup or any other build commands.
**cargo-ndk:**
cargo-ndk is a cargo extension that handles all the environment configuration needed for successfully building libraries or binaries for Android from a Rust codebase, with support for generating the correct jniLibs directory structure.
**Android 15 Compatibility:**
If your app uses any NDK libraries, either directly or indirectly through an SDK, then you will need to rebuild your app for it to work on Android 15's 16 KB page size devices.

Источники:
- [Reproducible Builds | F-Droid - Free and Open Source Android App Repository](https://f-droid.org/docs/Reproducible_Builds/)
- [Fix F-Droid build and bump Android NDK to r27c by basilgello · Pull Request #10105 · rustdesk/rustdesk](https://github.com/rustdesk/rustdesk/pull/10105)
- [cargo-ndk - Build Rust code for Android](https://lib.rs/crates/cargo-ndk)
- [GitHub - bbqsrc/cargo-ndk: Compile Rust projects with the Android NDK without hassle · GitHub](https://github.com/bbqsrc/cargo-ndk)
- [Reproducible Builds | F-Droid - Free and Open Source Android App Repository](https://pserwylo.gitlab.io/fdroid-website/en/docs/Reproducible_Builds/)

## 11. Tauri v2 2026 state updater plugin WebKitGTK Linux issues bundler code signing notarization

Based on the search results, here's what I found regarding Tauri v2 in 2026 and the related topics:
## Tauri v2 Status in 2026
Tauri v2 reached stable in late 2024 and has kept advancing since – 2.9.6 shipped December 9, 2025, Wikipedia marked 2.10.1 as the stable latest line in March 2026, and the core runtime crate had reached 2.11.5 by July 2026.
## WebKitGTK and Linux Issues
A previous issue caused the compiled AppImage to miss webkitgtk's internal libwebkit2gtkinjectedbundle.so file, though this appears to have been fixed. AppImage embeds the WebKitGTK 4.1 runtime so the binary works on distros that ship older WebKit, while .deb and .rpm declare WebKitGTK as a dependency and let the system supply it, which is why they stay around 4 MB while the AppImage climbs to ~76 MB.
## Bundler, Code Signing, and Notarization
A --skip-stapling option was added to make tauri build|bundle not wait for notarization to finish on macOS. The bundler now pulls the latest AppImage linuxdeploy plugin instead of using the built-in one, which should remove the libfuse requirement.
For code signing specifically, the bundler will skip signing the .dmg if self signing via "signingIdentity": "-" is used.
The search results don't contain specific information about a state updater plugin in 2026, but they do show ongoing improvements to the bundler and signing infrastructure.

Источники:
- [Tauri Core Releases | Tauri](https://tauri.app/release/core/)
- [tauri-bundler@2.2.3 | Tauri](https://tauri.app/release/tauri-bundler/v2.2.3/)
- [Updater | Tauri v1](https://v1.tauri.app/v1/guides/distribution/updater/)
- [Tauri 2 Beta bundle for Linux with "all needed depencies" included (not need to install WebKit2GTK-4.1 etc on all target machines) · tauri-apps · Discussion #10026](https://github.com/orgs/tauri-apps/discussions/10026)
- [Tauri v2 Tutorial 2026: Build a 5MB Desktop App | Rustify](https://rustify.rs/articles/rust-tauri-v2-desktop-app-tutorial-2026)

## 12. Homebrew cask policy unsigned unnotarized apps acceptable casks requirements 2026

Based on the search results, here's what I found about Homebrew's cask policy regarding unsigned and unnotarized apps in 2026:
## Key Policy Changes
Casks without codesigning and notarization are now deprecated and will be removed from the official Tap by September 2026, meaning they will no longer be installable using brew install.
Developers of apps who wish to distribute them via Homebrew Casks must now ensure their apps are signed and notarized.
## Requirements
On macOS, apps, installers and other executable artifacts that Gatekeeper can assess must pass Homebrew's Gatekeeper checks and must not require System Integrity Protection or Gatekeeper to be disabled or bypassed.
Homebrew's audit process for Casks now checks that Casks have been codesigned and notarized, and Casks that fail this audit will be removed by September 2026.
## Policy Rationale
The unpaid volunteer maintainers of Homebrew have decided they don't want to support unsigned/notarized software in the main Homebrew/cask tap anymore. However, this doesn't stop anyone from maintaining their own tap full of unsigned software.
In summary, unsigned and unnotarized apps are **not acceptable** for Homebrew's official casks as of 2026, with enforcement taking effect September 1, 2026.

Источники:
- [What Homebrew 5.0.0 means for your Mac fleet - Workbrew Blog](https://workbrew.com/blog/homebrew-5-0-0)
- [Why casks gets deprecated because of gatekeeper check (unsigned)? · Homebrew · Discussion #6482](https://github.com/orgs/Homebrew/discussions/6482)
- [Homebrew Documentation: Acceptable Casks](https://docs.brew.sh/Acceptable-Casks)
- [Removing support for `--no-quarantine` for casks · Issue #20755 · Homebrew/brew](https://github.com/Homebrew/brew/issues/20755)
- [brew/docs/Acceptable-Casks.md at master · Homebrew/brew](https://github.com/Homebrew/brew/blob/master/docs/Acceptable-Casks.md)

## 13. notarytool requirements Developer ID hardened runtime entitlements network client non-sandboxed app com.apple.security.network.client needed

Based on the search results, here's what I found about notarytool requirements regarding hardened runtime and entitlements:
## Key Requirements
The only security enhancement required by notarisation is the hardened runtime. To submit a macOS application to the Apple Notary service, you must use the options for hardened runtime, entitlements, and timestamp.
## For Non-Sandboxed Apps
Notarisation does not require that your app be sandboxed, and thus a notarised app can do pretty much anything any non-notarised app can do. Target → Signing & Capabilities → set ENABLE_APP_SANDBOX = NO, ENABLE_HARDENED_RUNTIME = YES.
## Entitlements for Network Access
Regarding the `com.apple.security.network.client` entitlement you mentioned: Hardened runtime opts you in to a bunch of default security enhancements but there are entitlements to opt you out of them if necessary. For non-sandboxed apps with hardened runtime, you can add specific entitlements (like network client permissions) directly to your entitlements file as needed.
The search results indicate that you do not need to whitelist entitlements via a provisioning profile from Apple, but can just add them to your .entitlements file.

Источники:
- [Notarization | Apple Developer Forums](https://developer.apple.com/forums/tags/notarization)
- [Notarization: the hardened runtime – The Eclectic Light Company](https://eclecticlight.co/2021/01/07/notarization-the-hardened-runtime/)
- [Signing and Notarizing a Protected Application](https://docs.sentinel.thalesgroup.com/ldk/LDKdocs/Env-Mac/Envelope/Mac_Signing_and_Notarizing.htm)
- [macOS Apps: From Sandboxing to Notarization, The Basics – Xojo Programming Blog](https://blog.xojo.com/2024/08/22/macos-apps-from-sandboxing-to-notarization-the-basics/)
- [MacOS Notarization "The executable does not have the hardened runtime enabled. " using anything other than Xcode codesign · Issue #83469 · godotengine/godot](https://github.com/godotengine/godot/issues/83469)

## 14. 

Artifact Signing" OR "Trusted Signing" individual identity validation "United States" Canada only individuals countries 2026 SmartScreen reputation immediate"
Based on the search results, here's what I found regarding Artifact Signing (formerly Trusted Signing) and individual identity validation:
## Service Overview
Artifact Signing (formerly Trusted Signing) is a fully managed, end-to-end code signing service integrated with Azure.
## Geographic Availability for Individuals
Individual developers must be located in the United States or Canada. This is a key restriction for individual identity validation with Public Trust certificates.
## Identity Validation Process
Once validated, your identity details, such as your individual or organization name, are included in the certificate. Individual verification uses Microsoft Entra Verified ID with biometric selfie checks.
## SmartScreen Reputation
An Artifact Signing signature ensures that your application is trusted by providing base reputation on smart screen, user mode trust on Windows, and integrity check signature validation compliant. Additionally, your signing reputation is anchored to your verified identity in Azure, and every signature reflects that verified identity.
## Certificate Management
The service provides "zero-touch" certificate management, meaning it handles the creation, protection, and even automatic rotation of code signing certificates on your behalf. These certificates are short-lived and auto renewed behind the scenes.
[RESULT WebSearch]

## 15. flatpak tray icon StatusNotifierWatcher talk-name org.kde.StatusNotifierWatcher notification portal libnotify sandbox

Based on the search results, here's what I found about Flatpak tray icons and StatusNotifierWatcher:
## Key Findings
**StatusNotifier and Flatpak Permissions:**
StatusNotifier style icons will not function without extra permissions, as they require talking to a non-hardened host service. To use StatusNotifier, you must at least have the --talk-name=org.kde.StatusNotifierWatcher permission to register an item.
**Implementation Challenges:**
Tray icons, specifically StatusNotifier, are a common permission need, and the proposed solution involves proxying calls to StatusNotifierWatcher while filtering out RegisterStatusNotifierHost() since that should be a privileged call.
**Notification Portals:**
A number of toolkits and frameworks provide transparent support for Linux desktop notifications, including Electron, GTK, KDE and QML. However, tray icons specifically StatusNotifier remain an area where there's no unified answer through portals.
**Practical Solution:**
Running Flatpak apps with the command "flatpak run --talk-name=org.kde.StatusNotifierWatcher" or enabling "D-Bus session bus" in flatseal can fix tray icon issues.
**Recommended Approach:**
To ensure compatibility, it is recommended to use status icons only in a supplementary manner, rather than relying on them as the only mechanism for providing status information.
The core issue is that Flatpak sandboxes restrict access to host services like org.kde.StatusNotifierWatcher for security reasons, requiring explicit D-Bus permissions to enable tray icon functionality.
[RESULT WebSearch]

## 16. Android 16 behavior changes foreground service dataSync BOOT_COMPLETED restriction targeting API 36

Based on the search results, here are the key findings for Android 16 (API level 36) behavior changes related to foreground services, dataSync, and BOOT_COMPLETED restrictions:
## Key Behavior Changes
**Job Runtime Quotas:**
Background jobs started from a foreground service now must adhere to their respective runtime quotas, including jobs scheduled directly with JobScheduler, as well as jobs created by other libraries like WorkManager or DownloadManager.
**DataSync Foreground Service Timeouts:**
There are new restrictions on how long a dataSync foreground service can run for apps that target API level 35 or higher. The system permits an app's dataSync services to run for a total of 6 hours in a 24-hour period, after which the system calls the running service's Service.onTimeout(int, int) method.
**BOOT_COMPLETED Restrictions:**
Apps that target Android 15 or higher are not allowed to launch a data sync foreground service from a BOOT_COMPLETED broadcast receiver. More broadly, BOOT_COMPLETED foreground services are no longer allowed to launch certain foreground services.
**Alternative Recommendation:**
To transfer data in response to a user action, consider using a user-initiated data transfer job, as these jobs are exempt from the ordinary job quotas.
[RESULT WebSearch]

## 17. Android developer verification requirement 2026 sideloading APK Brazil Indonesia Singapore Thailand F-Droid impact

Based on the web search results, here's what I found about Android developer verification requirements and their impact:
## Android Developer Verification - September 2026 Enforcement
Google will block normal installs of apps from unverified Android developers in Brazil, Indonesia, Singapore, and Thailand starting Sept. 30, 2026. On that date, certified Android phones in Brazil, Indonesia, Singapore, and Thailand will block normal installs of apps whose developers have not registered an identity with Google, whether the app comes from Google Play or the stores run by Samsung, Xiaomi, OPPO, vivo, Honor, and Transsion.
## Sideloading and APK Impact
Every app installed on a certified Android device, including sideloaded apps, must be tied to a developer who has verified their identity with Google. An identity check and a 24-hour wait are meant to break that. Google continues to stress that sideloading isn't going away, as power users will still be able to install apps from any source they choose, with the difference being that unregistered apps will require extra steps, while apps from verified developers should continue to install normally.
## F-Droid Impact
F-Droid, the free-software app repository, says the requirement would end its project, because it builds and signs apps from many pseudonymous contributors who will not hand Google a legal identity. Apps from unregistered developers in F-Droid's catalog will fail to install on certified Android devices in those countries on that date.
## Global Rollout
Following this initial phase with the four countries, Google will expand these protections globally in 2027 for all apps distributed to certified Android devices.
[RESULT WebSearch]

## 18. APK Signature Scheme v3 key rotation lineage apksigner rotate Play App Signing key upgrade 2026

Based on the search results, here's information about APK Signature Scheme v3, key rotation, lineage, and apksigner:
## Overview
The v3 signature scheme introduces key rotation support, which is a significant feature for Android app development. APK Signature Scheme v3 was introduced in Android 9.
## APK Signer Lineage
The v3 signature scheme introduces the APK Signer Lineage, which contains a history of signing certificates with each ancestor attesting to the validity of its descendant. The lineage contains a proof of rotation by which the APK containing it can demonstrate its ability to be trusted with its current signing certificate, as though it were signed by one of its older ones.
## Key Rotation Process
You can create a lineage file with a sequence of certificates with 'apksigner rotate' and apply it when you sign the application with 'apksigner sign'. Key rotation allows changing the signing certificate when a newer version of an Android app is released, so if the initial version of an Android app was signed with a given key, it is now possible to switch to a different key.
## Play App Signing
Developers enrolled in Play App Signing can request a key upgrade through the Play console.
## Best Practices
It is recommended as part of best practices to rotate your app's signing key at least every two years.

Источники:
- [Developers: APK Signature Scheme v3 is coming with support for Key Rotation](https://www.xda-developers.com/apk-signature-scheme-v3-key-rotation/)
- [Android APK Signature Scheme V3. Android 9 에서부터 apk key rotation이 새롭게… | by Vito | Medium](https://medium.com/@cpu815/android-apk-signature-scheme-v3-50e400db8ca1)
- [APK Signer | Keyfactor Docs](https://docs.keyfactor.com/signserver/latest/apk-signer)
- [Set up Android Signing | Keyfactor Docs](https://docs.keyfactor.com/signserver/latest/setting-up-android-signing)
- [Android APK signature scheme v3 | Guardsquare](https://www.guardsquare.com/blog/android-apk-signature-scheme-v3-context-and-new-opportunities)

## 19. cargo-vet adoption 2026 vs cargo-deny supply chain Rust audits Mozilla Google import

Based on the search results, here's what I found about cargo-vet adoption in 2026 and how it compares to cargo-deny:
## 2026 Adoption Status
Analysis of 408 open-source projects was conducted to measure cargo-vet adoption, audit workload, exemptions, and audit lag. Mozilla and Google expanded cargo-vet's shared audit pool to 14,000 crates in Q1 2025, and for a typical Rust binary with 400 dependencies, the shared pool now covers 60-75% of the graph.
## cargo-vet vs cargo-deny
cargo-vet is for high-security environments; cargo-deny is sufficient for most teams. The key difference is in their approach: cargo-vet takes a fundamentally different approach from advisory-based tools, rather than checking against a database of known vulnerabilities, it enforces that every dependency has been explicitly audited and certified to meet specific criteria.
## Mozilla and Google's Role
Both Google and Mozilla publish their Rust crate audits, so you can bootstrap your audit set by importing theirs and only need to manually review crates they haven't covered. You can import audits from trusted organizations with commands like `cargo vet import mozilla` and `cargo vet import google`.
## Audit Lag Challenges
Across the registries, the median lag between a crates.io release and its audit is 29 days, and only 51% of audits land within 30 days.
[RESULT WebSearch]

Источники:
- [6. Dependency Management and Supply Chain Security - Rust Engineering Practices — Beyond cargo build](https://microsoft.github.io/RustTraining/engineering-book/ch06-dependency-management-and-supply-chain-s.html)
- [Securing our Rust supply chain with cargo-vet](https://groups.google.com/a/mozilla.org/g/dev-platform/c/j6cKDRP7jWY)
- [GitHub - mozilla/supply-chain: Aggregated audits for Rust crates by Mozilla](https://github.com/mozilla/supply-chain)
- [Cargo Audit and the Gaps in Rust Dependency Security](https://tuxcare.com/blog/cargo-audit-rust-security/)
- [Auditing Dependencies - Rust Project Primer](https://rustprojectprimer.com/checks/audit.html)

## 20. GitHub artifact attestations SLSA build level 3 provenance Rust release binaries cosign verify 2026

Based on the web search results, here's what I found about GitHub artifact attestations, SLSA Build Level 3, provenance, and verification:
## GitHub Artifact Attestations and SLSA Build Level 3
GitHub artifact attestations cryptographically bind each artifact to its source repository and build workflow, helping you achieve SLSA Build Level 3 security. The artifact view surfaces all attestations created for an artifact, including build provenance, attested SBOMs, and any custom attestations that fit your software development lifecycle.
## How Provenance Works
Provenance refers to the cryptographic record generated for each artifact, providing an unforgeable paper trail of its build history. To generate artifact attestations, GitHub uses Sigstore, which is an open source project that offers a comprehensive solution for signing and verifying software artifacts via attestations.
## Verification
Public repositories that generate artifact attestations use the Sigstore Public Good Instance, with a copy of the generated Sigstore bundle stored with GitHub and written to an immutable transparency log that is publicly readable on the internet. SLSA provenance uses a signed, in-toto attestation: a JSON document, signed by sigstore via the GitHub Actions OIDC identity, that names every relevant input to the build.
## Implementation for Rust and Binaries
Building software with reusable workflows and artifact attestations can streamline your supply chain security and help you achieve SLSA v1.0 Build Level 3, with the reusable workflow generating artifact attestations to establish build provenance.
The search results indicate that verification tools for provenance attestations can include cosign and other verification utilities, though the specific cosign integration details weren't extensively covered in these particular results.
[RESULT WebSearch]

Источники:
- [Enhance build security and reach SLSA Level 3 with GitHub Artifact Attestations - The GitHub Blog](https://github.blog/enterprise-software/devsecops/enhance-build-security-and-reach-slsa-level-3-with-github-artifact-attestations/)
- [Strengthen your supply chain with code-to-cloud traceability and SLSA Build Level 3 security - GitHub Changelog](https://github.blog/changelog/2026-01-20-strengthen-your-supply-chain-with-code-to-cloud-traceability-and-slsa-build-level-3-security/)
- [Using artifact attestations and reusable workflows to achieve SLSA v1 Build Level 3 - GitHub Docs](https://docs.github.com/actions/security-guides/using-artifact-attestations-and-reusable-workflows-to-achieve-slsa-v1-build-level-3)
- [SLSA, it’s all about provenance attestation | by Rémi Rey | Medium](https://medium.com/@rrey94/slsa-its-all-about-provenance-attestation-09a83b7b9de7)
- [Artifact attestations - GitHub Docs](https://docs.github.com/en/actions/concepts/security/artifact-attestations)

## 21. UnifiedPush 2026 ntfy distributor Android 15 battery restrictions Sunup Google FCM UnifiedPush

Now let me search for more specific information about Android 15 battery restrictions and any mentions of Sunup or Distributor-specific issues:
Based on my search results, here's what I found regarding UnifiedPush, ntfy, Sunup, Android 15 battery restrictions, and their relationships:
## UnifiedPush Overview
UnifiedPush is a standard which allows for multiple methods of push notification delivery, with implementations including several client Android apps and optional server software for those who prefer to self-host.
## Battery Restrictions in Android 15
Apps that hold the SYSTEM_ALERT_WINDOW permission are only allowed to launch foreground services from the background if they currently have a visible overlay window (or if they meet one of the other exemptions from background start restrictions). Additionally, starting from Android 15, foreground services declared with the dataSync type have a strict maximum runtime of 6 hours, after which the system will automatically stop the service.
## Distributors: ntfy and Sunup
ntfy is an open-source push notification service that can be used as a UnifiedPush distributor. Sunup is a UnifiedPush distributor using Mozilla's push server.
Both distributors require battery optimization exemptions. Users must grant necessary permissions (e.g., notifications and battery optimization exemptions) to ensure proper background operation.
## Relationship to Google FCM
For a long time, the only option for push notifications on Android systems was using Google's proprietary Firebase Cloud Messaging (FCM) service, where the server would send a notification via FCM that would be received by the phone. UnifiedPush is now supported by various apps on F-Droid since version 20230227-01 as a free/libre replacement.

Источники:
- [Introducing UnifiedPush support in Jami](https://jami.net/unifiedpush/)
- [ntfy - Android | UnifiedPush](https://unifiedpush.org/users/distributors/ntfy/)
- [FAQ | UnifiedPush](https://unifiedpush.org/users/faq/)
- [Allow finer control over UnifiedPush in the android app · Issue #646 · binwiederhier/ntfy](https://github.com/binwiederhier/ntfy/issues/646)
- [Alert options for Unified Push Messages to reduce battery usage of UP-Client App · Issue #1524 · binwiederhier/ntfy](https://github.com/binwiederhier/ntfy/issues/1524)

## 22. OTF Red Team Lab security audit application open source messenger 2026 Cure53 Trail of Bits Radically Open Security cost

Based on the search results, I can provide you with information about the OTF Red Team Lab:
OTF's Red Team Lab engages in public safety audits of tools and works to strengthen the security of open-source internet freedom software. The Red Team Lab is focused on ensuring the highest possible security standards for internet freedom technologies and supports independent technology audits for all of OTF's supported projects.
The lab strives to strengthen the security of open-source Internet freedom software by providing professional security audits, supporting bug bounties, validating the privacy and security claims of software projects, and advancing projects' software security best practices.
Regarding specific audit work mentioned in the results, Radically Open Security performed a security audit of Briar (an open source messaging application) during September and October 2023 using a "crystal-box" assessment. The search results also indicate that audit firms including Cure53 and others have been involved in Red Team Lab audits.
However, the search results do not contain specific information about 2026 costs, Cure53's or Trail of Bits' specific involvement in 2026 projects, or detailed pricing information for the Red Team Lab's services. For more current pricing and 2026-specific audit project details, you may want to visit the OTF Red Team Lab application page directly at opentech.fund/labs/red-team-lab/.
[RESULT WebSearch]

## 23. SimpleX Chat release process reproducible builds signing checklist github releases 2026

Based on the search results, here's what I found about SimpleX Chat's release process and reproducible builds:
## Reproducible Builds
Linux desktop app, CLIs and server builds are now reproducible. This milestone was achieved in the v6.4 release, with @RunOnFlux verifying and co-signing the release builds.
## Release Process and Verification
SimpleX Chat has established a process for independent verification of builds. The GitHub release build is independently reproduced by external parties, and there's a dedicated resource available at `https://simplex.chat/reproduce/` for learning more about verifying and reproducing release builds.
## Signing and Checksums
Security experts or researchers can help the SimpleX network by signing the release checksums, which will be published. Additionally, releases include SHA2-256 checksums for verification purposes.
## Reproducible Build Process
For those wanting to reproduce builds, the process requires a Linux machine with x86-64 architecture with docker, curl and git installed, then executing a script that builds server binaries for the release in a docker container and compares them with the downloaded binaries from GitHub.
The search results don't show a detailed checklist document, but they do indicate that SimpleX Chat has implemented a comprehensive approach to reproducible builds, signing, and verification as part of their 2026 release process.
[RESULT WebSearch]

## 24. Briar messenger release process reproducible build F-Droid signing verification release checklist

Based on the search results, here's what I found about Briar's release process and reproducible builds with F-Droid:
## Briar's Reproducible Build Process
Briar has a reproducible build process that can prove that the application you downloaded from any of the above corresponds exactly to the published source code.
## F-Droid Integration and Signing Verification
Reproducible builds are the precondition for getting Briar into the official F-Droid repository with its official code signature. Briar developer Torsten Grote reported reproducibility issues to Google in June 2018 when trying to get the messenger as the first reproducibly built app into F-Droid, and three months later, Briar made it into F-Droid because Grote found a workaround by using a special file system called disorderfs.
## How F-Droid Verifies Reproducible Builds
F-Droid verifies reproducible builds using APK signature copying against upstream build and our rebuild. F-Droid ships APKs that are signed by the upstream developer(s), which proves to you that the developer confirmed the APK was built from their code.
## Release Verification Process
An application can be setup to publish the signed binaries from the upstream developer after verifying that they match the ones built using an fdroiddata build recipe, and F-Droid can verify that an app is free software while still using the original developer's APK signatures.
The search results don't contain a specific release checklist document, but they outline the key verification steps F-Droid uses to ensure reproducible builds are properly signed and verified.
[RESULT WebSearch]

## 25. Rust reproducible builds 2026 trim-paths stable SOURCE_DATE_EPOCH cargo release binary reproducibility

I found relevant search results about Rust reproducible builds in 2026. Here's what the search revealed:
## Key Findings
**trim-paths for Binary Reproducibility:**
Cargo should have a profile setting named trim-paths to sanitise absolute paths introduced during compilation that may be embedded in the compiled binary executable or library. cargo build with the default release profile should not produce any host filesystem dependent paths into binary executable.
**SOURCE_DATE_EPOCH Environment Variable:**
If you still need the current time for some reason during the compile, it is recommended to check if the SOURCE_DATE_EPOCH environment variable is set, and only read the current system time if it is not set. The SOURCE_DATE_EPOCH environment variable is passed through to build scripts (build.rs).
**Practical Implementation in 2026:**
Recent examples from 2026 show how reproducible builds are being applied in practice. A GitHub Actions job uses SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct) with RUSTFLAGS including --remap-path-prefix options and CARGO_INCREMENTAL=0 to achieve reproducible builds.
**Debian's Progress:**
As of 2026, over 95% of Debian packages in trixie build reproducibly.
The search results confirm that trim-paths, SOURCE_DATE_EPOCH, and related reproducibility features are actively being used and discussed in the Rust ecosystem as of 2026.
[RESULT WebSearch]

## 26. cargo-cyclonedx SBOM 2026 cargo sbom cargo-auditable Rust release SBOM best practice

Based on the search results, here's what I found about cargo-cyclonedx, SBOM generation, and related tools for Rust:
## Overview
cargo-cyclonedx creates CycloneDX Software Bill of Materials (SBOM) from Rust (Cargo) projects. The CycloneDX module for Rust (Cargo) creates a valid CycloneDX SBOM containing an aggregate of all project dependencies, and OWASP CycloneDX is a full-stack Bill of Materials standard providing advanced supply chain capabilities for cyber risk reduction.
## Key Tools in the Rust SBOM Ecosystem
The maintainer of cargo-auditable is Sergey, and changes in cyclonedx-rust-cargo and Cargo have the chance to significantly improve tooling around security and SBOMs in the Rust ecosystem.
**cargo-auditable** is particularly important: The cargo auditable crate allows embedding project-specific build information into resulting binary artifacts, which allows other tools like cargo audit or trivy to read this part of the binary and determine specific crate versions used to build the artifact and scan binaries for known bugs or security vulnerabilities.
## Best Practices for SBOM Generation
For Rust projects, start with Cargo.lock because it records the resolved crate versions that should appear in the SBOM, then use cargo-cyclonedx or a filesystem scanner such as Syft, then validate the CycloneDX or SPDX output with the SBOM Validator before attaching it to a release.
Cargo tools (cargo-cyclonedx, cargo-auditable, cargo-deny) allow building a reliable SBOM/CVE chain with minimal integration effort.
[RESULT WebSearch]

## 27. OSTIF audit funding open source 2026 NLnet NGI Zero Core grant security audit messenger apply

Based on the web search results, here's what I found about OSTIF, audit funding, and open source security programs:
## OSTIF (Open Source Technology Improvement Fund)
OSTIF is a corporate non-profit dedicated to securing open source apps by facilitating security audits and reviews. OSTIF receives funding from the Linux Foundation (via CNCF and OpenSSF) and has conducted audits on projects including OpenSSL, Kubernetes, and git. Additionally, the Sovereign Tech Agency funds security audits through OSTIF for critical open source technologies.
## NGI Zero and NLnet Funding
The NGI Zero coalition offers support services to free and open source projects such as accessibility and security audits, community building and mentoring, copyright and license due diligence, packaging and more. Depending on the fund, grantees can benefit from support services such as security and accessibility audits, mentoring, testing expertise, and copyright & licensing advice.
Regarding current application status: NLnet is temporarily pausing most open calls while it reviews a decade of Next Generation Internet work and prepares three new Open Internet Stack programs after the summer, with only NGI Taler and NGI Fediversity pilot proposals accepted during the pause.
The search results don't contain specific information about applying for messenger security audits in 2026 or the exact current grant amounts and deadlines for NGI Zero Core.
[RESULT WebSearch]

## 28. Session messenger open source bug bounty program 2026 Signal HackerOne SimpleX security disclosure policy

Now let me search more specifically for bug bounty programs and security disclosure policies for these messengers:
Based on my web search results, here's what I found regarding security and bug bounty programs for the messengers you asked about:
## Session Messenger
Session Token has an active Bug Bounty Program that aims to engage technical members of the Session community to contribute code improvements to the Session Token smart contracts. However, this program appears to focus on the token component rather than the core messaging application itself. I did not find evidence of a formal bug bounty program for Session messenger on HackerOne or other platforms in the 2026 timeframe.
## Signal
I found references to HackerOne's work on improving bug bounty programs, but did not locate a specific active Signal bug bounty program on HackerOne in the 2026 search results.
## SimpleX Chat
To report a security issue in SimpleX, users should contact them directly via email at chat@simplex.chat, and should NOT report security issues via GitHub issues or via any public channels. SimpleX completed a cryptographic review of SimpleX protocols design by Trail of Bits in July 2024, and has scheduled an implementation security assessment for June 2026.
SimpleX does not appear to operate a formal bug bounty program with financial rewards, but rather maintains a vulnerability disclosure policy for coordinated reporting.
## General Context
A vulnerability disclosure policy is broader and exists to provide a safe reporting path for anyone, while a bug bounty program rewards selected reports under defined scope and pr
[RESULT WebSearch]

Источники:
- [Bug Bounty Programs | HackerOne](https://www.hackerone.com/bug-bounty-programs)
- [HackerOne Alternatives 2026: Pentest Platforms Compared](https://www.stingrai.io/blog/hackerone-alternatives-2026)
- [Signal vs SimpleX vs Session: Messaging Compared 2026](https://cunicula.com/en/articles/encrypted-messaging-comparison)
- [Hot GitHub Repos — July 3, 2026 · The Next New Thing](https://2026-07-01.githubshow.codeshiftagent.com/)
- [Signal vs SimpleX vs Session 2026: Metadata Compared](https://vucense.com/comparisons-alternatives/app-versus/signal-vs-simplex-vs-session-2026-comparison/)

## 29. messenger persistent connection Android foreground service type specialUse vs dataSync XMPP Conversations Molly Android 15 6 hour limit workaround

I found search results related to Android foreground services and their limitations. Here's what the search revealed:
## Android 15 Foreground Service Changes
Starting from Android 15, foreground services declared with the dataSync type have a strict maximum runtime of 6 hours, after which the system will automatically stop the service.
## Foreground Service Types: specialUse vs dataSync
specialUse covers any valid foreground service use cases that aren't covered by the other foreground service types. To use this type, developers should declare use cases in the manifest by specifying the property element within the service element, which are reviewed when submitting the app in the Google Play Console.
Android 15 added stricter rules around starting FGS from the background and an updated dataSync timer (you cannot keep a dataSync FGS running forever).
## Workarounds
The search results suggest that WorkManager or sync adapters should be used for long-term or recurring syncs where possible, rather than relying on foreground services with time limits.
However, the search results don't contain specific information about Conversations, Molly, or specific technical workarounds for XMPP messenger apps dealing with the 6-hour limit on Android 15. You may need to search more specifically for those applications' documentation or GitHub discussions.
[RESULT WebSearch]

## 30. MSIX vs MSI 2026 desktop app distribution outside Store Rust tauri wix decision SmartScreen

Based on the search results, here's what I found about MSIX vs MSI for desktop app distribution in 2026:
## Current State of Desktop App Distribution
As organizations look to modernize application deployment strategies, MSIX has emerged as Microsoft's long-term solution for packaging and distributing Windows apps. While MSI and App-V have long histories in the enterprise, MSIX introduces a containerized model that simplifies management, improves security, and enhances compatibility with modern Windows environments.
## Key Differences for Outside-Store Distribution
The choice of distribution method is not merely about installer-format preference — it is a choice of how deeply you touch the OS and who owns update responsibility. If you assume Windows 10/11 and want clean install/clean uninstall, frequent updates, and package identity, MSIX is a strong candidate; if you install machine-wide, register services or COM, or need to install prerequisites, start your thinking from MSI.
## MSIX Advantages
MSIX installs and uninstalls more cleanly and updates more efficiently. MSIX supports sideloading, Microsoft Store distribution, Intune, and MSIX App Attach for Azure Virtual Desktop, and includes easy updates with delta updates, automatic background updates, and declarative configuration that simplify lifecycle management.
## Microsoft's Direction
App-V's server components are reaching end of support in April 2026. While the client and sequencer remain in fixed extended support, the full infrastructure is sunsetting. This transition to modern packaging formats like MSIX—Microsoft's containerized, secure, and cloud-ready solution for desktop apps—represents a substantial, multi-year opportunity.
The search results don't specifically address Rust, Tauri, WiX, or SmartScreen considerations. Would you like me to search for information about those specific tools and their relationship to MSIX/MSI packaging decisions?
[RESULT WebSearch]

## 31. Tauri v2 updater plugin minisign signature requirement endpoints 2026 WebKitGTK crash Linux tauri 2.x known issues

Based on the web search results, here's what I found regarding your queries:
## Tauri v2 Updater Plugin - Minisign Signature Requirement & Endpoints
Tauri's updater needs a signature to verify that the update is from a trusted source. This cannot be disabled. When present, the update response's signature field and the downloaded artifact will be checked against the configured pubkey using Minisign, a simple signature system using Ed25519 public-key signatures.
The required keys are "url", "version" and "signature"; the others are optional. Additionally, the strings {{current_version}} and {{target}} and {{arch}} are automatically replaced in the URL, allowing you to determine server-side if an update is available. If multiple endpoints are specified, the updater will fall back if a server is not responding within the pre-defined timeout.
Recent changes in 2026 include v2.10.1 released Apr 4, 2026, which fixed preservation of file extension of updater package, and v2.10.0 released Feb 3, 2026, which added no_proxy config to disable system proxy for updater plugin.
## WebKitGTK Crashes - Tauri 2.x Known Issues on Linux
Several WebKitGTK-related issues have been documented in Tauri 2.x on Linux:
1. **Graphics/Rendering Issues**: Most issues come from the WebKitGTK DMABUF renderer requesting buffer formats the NVIDIA driver does not provide. See the WebKitGTK bug tracker and the NVIDIA forums for upstream discussion.
2. **Blank Window Issues**: Running Tauri 2.0.0-rc with newer webkit2gtk versions shows an empty window, and the Web Dev tool also cannot be opened.
3. **Wayland Crashes**: Apps using tauri or webkit2gtk4.1 crash on launch when on wayland.
4. **Rendering Performance**: After WebKit2GTK 2.40 updates, Tauri apps felt incredibly sluggish, with the webview not refreshing after clicks.

Источники:
- [updater full changelog | Tauri Releases](https://tauri.app/release/updater/all-versions/)
- [Updater - The Tauri Documentation WIP](https://jonaskruckenberg.github.io/tauri-docs-wip/distributing/updater.html)
- [[Tauri v2] How to Verify Auto-Updates Locally (Signature & latest.json Setup)](https://zenn.dev/monkuma/articles/c947bca541cb48?locale=en)
- [Tauri v2 with Auto-Updater - Docs - CrabNebula](https://docs.crabnebula.dev/cloud/guides/auto-updates-tauri/)
- [tauri-docs/src/content/docs/plugin/updater.mdx at v2 · tauri-apps/tauri-docs](https://github.com/tauri-apps/tauri-docs/blob/v2/src/content/docs/plugin/updater.mdx)

## 32. Conversations XMPP Android foregroundServiceType specialUse PROPERTY_SPECIAL_USE_FGS_SUBTYPE messenger manifest Android 15

Based on the search results, here's what I found about the topics in your query:
## Conversations XMPP Client
Conversations is a free and open source Jabber/XMPP client for Android, and
...
</persisted-output>

Источники:
- [Question about Manifest Foreground service SpecialUse | B4X Programming Forum](https://www.b4x.com/android/forum/threads/question-about-manifest-foreground-service-specialuse.165630/)
- [Foreground service types | Background work | Android Developers](https://developer.android.com/develop/background-work/services/fgs/service-types)
- [Conversations | F-Droid - Free and Open Source Android App Repository](https://f-droid.org/en/packages/eu.siacs.conversations/)
- [Foreground service types are required | Android Developers](https://developer.android.com/about/versions/14/changes/fgs-types-required)
- [Conversations (Jabber / XMPP) - Apps on Google Play](https://play.google.com/store/apps/details?id=eu.siacs.conversations&hl=en_US)

## 33. cargo-ndk 16 KB page size Rust Android max-page-size=16384 linker flag NDK r28 default

Based on the search results, I found relevant information about 16KB page size alignment and NDK r28:
NDK r28 aligns .so files to 16KB pages by default, which matters because Google Play requires 16KB support for new apps and updates targeting Android 15+. This is an important consideration when building Rust code for Android using cargo-ndk, as it ensures compliance with Google Play's requirements for newer Android versions.
The search results show that cargo-ndk is a cargo extension that handles all the environment configuration needed for successfully building libraries or binaries for Android from a Rust codebase
[RESULT WebSearch]

## 34. Certum

"Open Source Code Signing" certificate requirements price 2026 SimplySign individual developer"
Based on the search results, here's information about Certum's Open Source Code Signing certificate and related offerings:
## Open Source Code Signing Certificate
An Open Source Code Signing certificate is the entry tier of publicly trusted code signing: a certificate authority verifies your identity as an individual developer and issues a certificate you use to sign your open-source software. It's cloud-based, so there's no hardware token to buy, and it's the lowest-priced option — but it comes with firm limits.
### Requirements
Applicants must verify their identity through a Registration or Identity Confirmation Point visit, notarized proof, or a full copy of an ID document. A utility bill and the URL of an active Open Source project proving the applicant's involvement are also needed.
### Limitations
It's for individuals only, the publisher line is fixed to "Open Source Developer" plus your name rather than your name alone, and it cannot be used to sign anything distributed commercially. Sign commercial software with it and the certificate gets revoked.
## SimplySign Integration
Certum meets that rule for the Open Source tier with the cloud, not a token: the certificate is issued on SimplySign, where your private key sits on a compliant cloud HSM you reach over an authenticated session.
[RESULT WebSearch]

## 35. Google Play 16 KB page size deadline extended May 31 2026 Play Console compliance new apps updates

Based on the search results, here's what I found about the Google Play 16 KB page size deadline and extension:
## Key Information
Google extended the deadline to May 31, 2026 in the Play Console. The original deadline was Nov 1, 2025, but you can automatically extend this deadline to May 31, 2026 in Play Console.
## What This Requirement Means
New Android devices are using larger memory page sizes (16KB instead of 4KB) for better performance. Google Play requires all apps targeting Android 15+ to support 16 KB memory page sizes.
## Compliance Timeline
The requirement has two phases:
- Nov 1, 2025 → Every new app or new build submitted to Google Play must support 16 KB memory pages.
- May 1, 2026 → All updates to existing apps must support 16 KB memory pages.
## Extension Option
[RESULT WebSearch]

## 36. Windows Package Manager repository policies winget-pkgs code signing

"installer" unsigned allowed SmartScreen validation pipeline"
Based on the search results, here's what I found about Windows Package Manager repository policies regarding code signing and validation:
## Code Signing Requirements
MSIX installers include digital signatures, while MSI and EXE files rely on the hash but can also carry Authenticode signatures.
## Unsigned Packages
The search results indicate that unsigned packages can present challenges in the winget-pkgs repository. Unsigned files must build reputation anew with every update. Additionally, submissions to the WinGet repository can be prevented if they trigger a SmartScreen warning.
## Validation Pipeline
[RESULT WebSearch]

## 37. Google Play new personal developer account closed testing 12 testers 14 days requirement production access 2026

Based on the search results, here's what I found about Google Play's closed testing requirement for new personal developer accounts in 2026:
## Overview
Developers with personal accounts created after November 13, 2023, must run a closed test for their app with a minimum of 12 testers who have been opted in continuously for at least 14 days. When you meet these criteria, you can apply for production access on the Dashboard in Play Console to distribute your app on Google Play.
## Key Requirements
At least 12 testers must be opted in to your closed test when you apply for production access, and they must have been opted in continuously for the preceding 14 days.
[RESULT WebSearch]

## 38. SimpleX protocol specification versioned protocol docs simplexmq protocol markdown Signal specifications published threat model

Based on the search results, here's what I found about the SimpleX protocol specifications:
## SimpleX Protocol Documentation
The current SimpleX Messaging Protocol (SMP) documentation describes SMP protocol version 20, and versions 1-5 are discontinued.
### Protocol Overview
Simplex Messaging Protocol is a transport agnostic client-router protocol for asynchronous distributed secure unidirectional message transmission via persistent simplex message queues. It's designed with the focus on communication security and integrity, under the assumption that any part of the message transmission network can be compromised.
### Available Specifications
The protocol specifications are available in markdown format in the official SimpleXMQ GitHub repository:
- **Main Protocol Spec**: `protocol/simplex-messaging.md` - describes SMP protocol version 20
- **Agent Protocol**: `protocol/agent-protocol.md` - SMP agents communicate with each other via SMP servers using simplex messaging protocol according to the API calls used by the client applications, serving as a middle layer in SimpleX protocols
- **Threat Model Overview**: `protocol/overview-tjr.md` - contains threat model documentation
These versioned specifications are maintained in the official SimpleXMQ repository at https://github.com/simplex-chat/simplexmq, with both master and stable branches containing protocol documentation.
[RESULT WebSearch]

## 39. Android developer verification hobbyist student account free limited distribution installs no fee 2026

Based on the search results, here's what I found about Android developer accounts for students and hobbyists in 2026:
## Limited Distribution Accounts for Students and Hobbyists
Google is building a free, no government ID required, limited distribution account so students and hobbyists can share their work with up to 20 devices. You only need an email account to get started.
## Key Features
- **No Fee**: There is no registration fee, and users can distribute an unlimited number of apps to up to 20 devices without needing to provide a government ID.
- **Limited Distribution**: Share apps with up to 20 devices that end-users have explicitly authorized. This account is free.
- **Distribution Method**: Sharing apps with a limited number of devices is achieved through a secure handshake process involving QR codes or links, user consent on the device, and registration using the Android Developer Console.
## Timeline for 2026
In June 2026, early access launched for limited distribution accounts for students and hobbyists, and limited distribution accounts launched globally.
## Use Cases
These accounts are designed for students, hobbyists, learners, and people building internal tools, not for public Play Store release.
[RESULT WebSearch]

## 40. Google Play privacy policy required all apps Data safety section 2026 requirement

Based on the search results, here's what I found about Google Play privacy policy and Data safety section requirements in 2026:
## Current Requirements
The Google Play Store requires all apps to have a compliant privacy policy, and app developers must also fill out a Data Safety Form and keep it updated.
Google Play's Data safety section provides developers with a transparent way to show users if and how they collect, share, and protect user data before installation. Developers are required to tell Google about their apps' privacy and security practices by completing a form in Play Console.
## 2026 Enforcement Updates
The Data Safety section is now strictly enforced, ensuring transparency. Apps that fail to comply face removal.
The Data Safety section has been expanded to require more detailed and accurate disclosures. Developers must clearly explain how user data is collected, stored, and shared. Any misleading or incomplete information can lead to penalties or app removal.
## Key Compliance Points
- All developers must declare how they collect and handle user data for the apps they publish on Google Play, and provide details about how they protect this data.
- A privacy policy is required to complete the Data safety form and have your data safety information shown to users.
- Third-party SDKs or libraries in your app that collect or share user data must be reflected in the Data safety form.

Источники:
- [Google Play Store Privacy Policy Requirements](https://termly.io/resources/articles/google-play-store-privacy-policy-updates/)
- [Provide information for Google Play's Data safety section - Play Console Help](https://support.google.com/googleplay/android-developer/answer/10787469?hl=en)
- [User Data - Play Console Help](https://support.google.com/googleplay/android-developer/answer/10144311?hl=en)
- [Google Play Data Safety Section: Step-by-Step Guide (2026)](https://respectlytics.com/blog/google-play-data-safety-guide/)
- [Google Play Store Policy Changes 2026: Guide to New Rules](https://theandroidnews.com/google-play-store-policy-changes/)

## 41. Apple Developer Program membership price 99 USD year 2026 Developer ID notarization requirement

Based on the search results, here's what I found:
**Apple Developer Program Membership Price:**
The Apple Developer Program is 99 USD per membership year. Prices may vary by region and are listed in local currency during the enrollment process.
**Developer ID Notarization:**
You can distribute your Mac apps outside the Mac App Store using your Developer ID certificate and Apple's notarization process. Importantly, once you're a member of the Apple Developer Program, you can notarize Mac apps for no additional fee.
The search results confirm that notarization is included as part of the Developer Program membership at no extra cost beyond the $99 annual membership fee.

Источники:
- [Become a member - Apple Developer Program - Apple Developer](https://developer.apple.com/programs/enroll/)
- [Enrollment - Membership - Account - Help - Apple Developer](https://developer.apple.com/help/account/membership/program-enrollment)
- [Membership Details - Apple Developer Program - Apple Developer](https://developer.apple.com/programs/whats-included/)
- [Apple Developer Program Fee Waiver - Membership - Account - Help - Apple Developer](https://developer.apple.com/help/account/membership/fee-waivers/)
- [Enroll in the Apple Developer Program: Quick Guide](https://www.webtonative.com/blog/apple-developer-program-enrollment)

## 42. open source security audit typical cost

"per week" OR "per day" Cure53 OR "Trail of Bits" OR "Radically Open Security" rate 2025 2026"
Links: [{"title":"When to audit a smart contract: The 2026 security timeline","url":"https://www.zealynx.io/research/audit-ops/audit-timeline"},{"title":"2026 Smart Contract Audit Costs: What to Expect and... | 7BlockLabs","url":"htt
[RESULT Bash]

## 43. learn.microsoft.com SmartScreen reputation for Windows app developers OV certificate reputation warning

[RESULT Bash] ### 11B.5 Relay anti-flood
Relay хранит зашифрованные конверты для офлайн пользователей. Защита:
```
Per-identity квоты:
  - 10 MB max на mailbox (ring buffer — старые вытесняются)
  - 100 сообщений max на mailbox
  - 30 deposits/min на отправителя
  - PoW (16 бит) на каждый deposit от не-контактов
Per-relay лимиты:
  - 1 GB total storage cap
  - GC каждые 6 часов: удаление expired (TTL 7 дней)
You've hit your session limit · resets 7:20am (Europe/Moscow)

## 44. OV code signing certificate SmartScreen reputation 2026 EV no longer instant reputation Microsoft change

Based on the search results, here's what changed regarding OV and EV code signing certificates and SmartScreen reputation in 2026:
## Key Change: EV Certificates No Longer Grant Instant Reputation
EV-signed files now go through the same reputation-building process as OV certificates. Microsoft changed how SmartScreen treats EV certificates in 2024, and as of Microsoft's current developer documentation, signing with an EV certificate no longer produces positive SmartScreen reputation by default.
## What This Means for Developers
Extended Validation (EV) certificates previously bypassed SmartScreen entirely on first download, making them the go-to choice for new apps with no reputation. That behavior was removed in 2024. 
Paying the EV premium ($400+/year) solely to avoid SmartScreen warnings is no longer justified — you will still see the same warnings as with an OV certificate.
## Additional 2026 Issue: CA Rotation Problems
Around March 26, 2026, Microsoft silently migrated many customers to new intermediate CAs, including "Microsoft ID Verified CS EOC CA 03." Apps signed with these new intermediates began triggering SmartScreen warnings even when previous builds with identical publishers were trusted.
The bottom line is that OV and EV certificates are now functionally equivalent for SmartScreen purposes, requiring organic reputation building through user adoption rather than instant trust based on certificate type.

Источники:
- [Code signing options for Windows app developers - Windows apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/code-signing-options)
- [Windows Apps PSA: EV Certs do not grant immediate reputation anymore | ToDesktop Blog](https://www.todesktop.com/blog/posts/windows-apps-psa-ev-certs-do-not-grant-immediate-reputation-anymore)
- [Why is my EV-signed application showing Microsoft Defender SmartScreen warnings?](https://knowledge.digicert.com/alerts/ev-signed-application-showing-microsoft-defender-smartscreen-warnings)
- [SmartScreen reputation for Windows app developers - Windows apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation)
- [SmartScreen Reputation Reset Following EV Certificate Renewal — Requesting Engineering Review - Microsoft Q&A](https://learn.microsoft.com/en-us/answers/questions/5900208/smartscreen-reputation-reset-following-ev-certific)

## 45. Android developer verification 2026 Android Developer Console fee government ID unverified app install

Based on the search results, here's a comprehensive overview of Android developer verification in 2026:
## Key Timeline & Implementation
In July 2026, Google launched the Android Developer ID Status API globally and began early access for the Android Developer Console API, with limited distribution accounts and the new Android Developer Console API launching globally in August 2026.
In August 2026, Google launched an advanced flow for installing apps from unverified developers, which includes security checkpoints to resist coercion scams, while allowing power users to maintain the ability to sideload apps from unverified developers.
These new developer verification protections will take effect on September 30, 2026, starting with users in Brazil, Indonesia, Singapore, and Thailand, with a global expansion planned for all apps on certified Android devices in 2027.
## Government ID & Fee Requirements
Limited distribution accounts are designed for students, hobbyists, and learners and let you share your apps to up to 20 devices without a government-issued ID or a fee. For full distribution, the $25 fee for the Full Distribution account in the Android Developer Console helps cover administrative costs and investment in protecting the ecosystem, similar to Play's $25 registration fee.
## Unverified App Installation & Advanced Flow
Google will block normal installs of apps from unverified Android developers in Brazil, Indonesia, Singapore, and Thailand starting September 30, 2026, and after that date, in the four launch markets, an unregistered app will not install through the normal path. However, it can still be installed over Android Debug Bridge (ADB) or through the advanced flow, which requires the user to turn on developer mode, restart, wait 24 hours, and reauthenticate before sideloading an unverified app.

Источники:
- [Android Developers Blog: Android developer verification: Building a safer ecosystem together](https://android-developers.googleblog.com/2026/06/android-developer-verification.html)
- [Google Sets Sept. 30 Deadline for Android Developer Verification in Four Countries](https://thehackernews.com/2026/06/google-sets-sept-30-deadline-for.html)
- [Learn about Android developer verification - Android Help](https://support.google.com/android/answer/17065026)
- [Frequently asked questions | Android developer verification | Android Developers](https://developer.android.com/developer-verification/guides/faq?hl=en)
- [Android Is Losing Its Freedom: Google's 2026 Developer Verification Explained - DEV Community](https://dev.to/dev-arafat-alim/android-is-losing-its-freedom-googles-2026-developer-verification-explained-2b5p)

## 46. security audit cost open source messenger Cure53

I found some relevant information about security audit firms that conduct audits on open source projects, including messengers. Let me search more specifically for pricing and cost information for security audits.
Now let me search for more specific information about open source messenger security audits and their typical costs.
Let me search for more specific information about security audit pricing and timelines for open source projects.

Источники:
- [Security Safety Audits | OTF - Open Tech Fund](https://www.opentech.fund/impact/security-safety-audits/)
- [MOSS/Secure Open Source/Completed - MozillaWiki](https://wiki.mozilla.org/MOSS/Secure_Open_Source/Completed)
- [Cure53 security audit](https://github.com/openpgpjs/openpgpjs/wiki/Cure53-security-audit)
- [Briar | OTF - Open Tech Fund](https://www.opentech.fund/security-safety-audits/briar/)
- [Obsidian Sync audits by Cure53 and Trail of Bits - Obsidian](https://obsidian.md/blog/cure53-tob-sync-audits/)

## 47. F-Droid inclusion policy Firebase Cloud Messaging proprietary dependency NonFreeNet anti-feature build flavor UnifiedPush 2026

Based on the search results, here's what I found regarding F-Droid's inclusion policy and its relationship to Firebase Cloud Messaging and UnifiedPush:
## F-Droid Inclusion Policy on Firebase Cloud Messaging
F-Droid strictly forbids the implementation of proprietary tracking or advertising libraries and analytics tools such as Google Play Services and Firebase. Using FCM requires the inclusion of the proprietary FCM client library into open source Android apps, which makes them effectively non-free software that cannot be distributed via the fully free F-Droid software repository.
## Build Flavor Solutions
Upstream developers must implement either a FLOSS alternative or a build flavour that does not require these dependencies when such features become necessary. This approach allows apps to maintain F-Droid compatibility while still offering proprietary features in other distribution channels.
## Anti-Features
F-Droid applies the "Non-Free Network Services" Anti-Feature to apps that promote or depend entirely on a proprietary network service.
## UnifiedPush as an Alternative
UnifiedPush is a new alternative that allows you to get push notifications without being tied to a single company.

Источники:
- [OpenPush - A Free, Decentralized Push Messaging Framework for Android | F-Droid - Free and Open Source Android App Repository](https://f-droid.org/2020/02/03/openpush-talk.html)
- [Inclusion Policy | F-Droid - Free and Open Source Android App Repository](https://f-droid.org/docs/Inclusion_Policy/)
- [Inclusion Policy | F-Droid - Free and Open Source Android App Repository](https://fdroid.gitlab.io/fdroid-website/en/docs/Inclusion_Policy/)
- [UnifiedPush: a decentralized, open-source push notification protocol | F-Droid - Free and Open Source Android App Repository](https://f-droid.org/2022/12/18/unifiedpush.html)
- [Implementing App notifications: The FOSS way - DEV Community](https://dev.to/dilutewater/implementing-app-notifications-the-foss-way-lc2)

## 48. Android 15 messenger foreground service persistent connection specialUse instead of dataSync 6 hour limit Conversations Molly Signal approach

Now let me search for more specific information about Molly and Signal approaches to this issue:
Now let me search more specifically for how messengers handle the Android 15 dataSync limit:

Источники:
- [Broken Persistent Connection due to Android 15 Time Limt on Foreground Service of Type dataSync · Issue #5987 · home-assistant/android](https://github.com/home-assistant/android/issues/5987)
- [Behavior changes: Apps targeting Android 15 or higher | Android Developers](https://developer.android.com/about/versions/15/behavior-changes-15)
- [Android, Android WorkManager, Android Background Work, Jetpack Compose | Medium](https://chaitanyaduse.medium.com/navigating-the-maze-long-running-background-work-in-android-and-its-quirks-2a8e53442985)
- [Android Foreground Services in 2026: What Changed and How to Adapt - DEV Community](https://dev.to/joe_wang_6a4a3e51566e8b52/android-foreground-services-in-2026-what-changed-and-how-to-adapt-2o3d)
- [Android Foreground Services: Types, Permissions and Limitations](https://softices.com/blogs/android-foreground-services-types-permissions-use-cases-limitations)

