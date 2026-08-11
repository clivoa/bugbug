---
name: mobile-static-analysis
version: "1.0.0"
description: "APK/IPA decompilation, manifest analysis, hardcoded secrets, deep link testing"
risk_level: L0
approval: auto
program_types: [mobile]
source: "reviewed from OWASP MASVS, APKTool, JADX, reference repositories"
actions: []
---

# Mobile Application Static Analysis

**status:** active
**risk:** L0
**approval:** auto
**program_types:** [mobile]
**source:** reviewed from OWASP MASVS, APKTool, JADX, reference repositories

## Static Analysis Workflow

### 1. App Acquisition (L0)
- Download from official app store only (APKPure, APKMirror for historical)
- Verify app bundle ID matches program scope
- Extract APK/IPA from device if needed (requires owned device)
- Verify signature: matches developer certificate for in-scope app

### 2. APK Analysis (Android)

#### Manifest Review (AndroidManifest.xml)
- **exported activities/services/receivers** — accessible to other apps?
- **intent filters** — what external intents are accepted? Implicit intents?
- **permissions** — custom permission protectionLevel? signature vs normal?
- **allowBackup** — is app data backed up without encryption?
- **debuggable** — debuggable flag set in release build?
- **networkSecurityConfig** — allows cleartext, user CA certificates?
- **taskAffinity / launchMode** — task hijacking possible?

#### Code Analysis (smali → Java via JADX)
- **Hardcoded secrets** — API keys, tokens, passwords, signing keys
- **Firebase / cloud DB** — open database URLs, anonymous access
- **Deep link handling** — any deep link trigger sensitive action without auth?
- **WebView configuration** — JavaScript enabled, file access, SSL error override
- **Intent handling** — data from intent used without validation
- **Root/jailbreak detection** — is it bypassable? What does it gate?
- **Certificate pinning** — is it implemented? Bypassable via frida/xposed?
- **Cryptographic mistakes** — ECB mode, static IV, hardcoded keys, weak PRNG

#### Native Library Analysis (.so files)
- Extract with `unzip`
- Strings analysis: `strings *.so | grep -E "(key|secret|token|password|http)"` 
- Symbol analysis: `nm -D *.so` — exported JNI functions
- Check for packers/obfuscators (UPX, OLLVM, DexGuard)

### 3. IPA Analysis (iOS)

#### Binary Analysis
- **PIE (ASLR)** — compiled with -fPIE?
- **ARC** — automatic reference counting (memory safety)
- **Stack canary** — buffer overflow protection
- **Encryption** — App Store encryption (cryptid in LC_ENCRYPTION_INFO)
- **Entitlements** — get-task-allow (debuggable), keychain groups, app groups
- **ATS (App Transport Security)** — exceptions allowing cleartext

#### Code Analysis
- `class-dump` — Objective-C class/method/protocol listings
- `Hopper` / `Ghidra` — disassembly for critical methods
- `strings` — embedded URLs, secrets, configuration
- Plist files — configuration, API endpoints, feature flags

#### Common Issues
- **Hardcoded secrets** in binary or plist
- **NSAppTransportSecurity** with NSAllowsArbitraryLoads: YES
- **URL schemes** registered without validation (scheme hijacking)
- **UIPasteboard** usage without expiry (sensitive data persistence)
- **Keychain** access with kSecAttrAccessibleAlways (accessible when locked)
- **WebView** with JavaScript enabled without input validation
- **Third-party SDK** versions with known vulnerabilities

### 4. Shared Mobile Concerns

- **API endpoints** discovered in app → test as API program type
- **GraphQL endpoints** with persisted queries → introspection, field suggestion
- **Firebase** — exposed realtime database, Firestore rules, cloud functions
- **Push notification** — can notification data contain sensitive info?
- **Biometric auth** — is the fallback weaker than the biometric? (device PIN vs fingerprint)
- **Clipboard/screenshot** — sensitive data in app switcher preview?

## Stop Conditions
- Static analysis only (L0): no dynamic testing without explicit approval
- Discovery of secrets: confirm existence, flag for program — don't use them
- Discovery of internal API endpoints: flag as hypothesis — don't probe without scope check
