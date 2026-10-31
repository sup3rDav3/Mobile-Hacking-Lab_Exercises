# Mobile & App Security Lab Writeups

A personal catalog of mobile application penetration-testing writeups from **authorized lab, CTF, and training targets** (e.g. Mobile Hacking Lab). Each entry documents the full chain — static analysis, the vulnerable code, and a reproduced proof-of-concept.

> ⚠️ **Scope & authorization.** Everything here targets deliberately vulnerable practice apps or environments I own or am explicitly authorized to test. Nothing in this repo is intended for use against systems without written permission.

---

## Index

| Target | Platform | Category | Key finding | Severity | Writeup |
|--------|----------|----------|-------------|----------|---------|
| Guess Me (`com.mobilehackinglab.guessme`) | Android | WebView / Deep Link | RCE via exported deep-link → JS bridge → `Runtime.exec()` | Critical | [REPORT-guessme.md](REPORT-guessme.md) |

---

## Guess Me — quick summary

Exported, browsable `WebviewActivity` loads an attacker-supplied URL into a WebView whose `AndroidBridge.getTime()` interface runs shell commands. The deep-link allowlist is a bypassable `endsWith("mobilehackinglab.com")` check.

```
mhl:// deep link  →  weak endsWith() URL check  →  attacker page in JS-bridged WebView
                  →  AndroidBridge.getTime()     →  Runtime.exec()  =  RCE
```

**Confirmed on emulator:** `id` executed as the app's uid (`u0_a174`, SELinux `untrusted_app`). Full chain, PoC, and the six findings are in the [writeup](REPORT-guessme.md).

---

## Conventions

- One writeup per target: `REPORT-<shortname>.md`.
- Each writeup includes: target metadata, a findings summary table (ID · severity · MASVS/OWASP ref), the vulnerable code, a reproducible PoC, and impact.
- Findings are tagged against [OWASP MASVS](https://mas.owasp.org/MASVS/) where applicable.
- Add new entries to the **Index** table above.

## Toolkit

`jadx` (decompile + manifest decode) · `apktool` · `adb` · Burp Suite · Frida / Objection · MobSF · an Android emulator or rooted device.
