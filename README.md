# Mobile & App Security Lab Writeups

A personal catalog of mobile application penetration-testing writeups from **authorized lab, CTF, and training targets** (e.g. Mobile Hacking Lab). Each entry documents the full chain — static analysis, the vulnerable code, and a reproduced proof-of-concept.

> ⚠️ **Scope & authorization.** Everything here targets deliberately vulnerable practice apps or environments I own or am explicitly authorized to test. Nothing in this repo is intended for use against systems without written permission.

---

## Index

| Target | Platform | Category | Key finding | Severity | Writeup |
|--------|----------|----------|-------------|----------|---------|
| Guess Me (`com.mobilehackinglab.guessme`) | Android | WebView / Deep Link | RCE via exported deep-link → JS bridge → `Runtime.exec()` | Critical | [REPORT-guessme.md](REPORT-guessme.md) |
| Strings (`com.mobilehackinglab.challenge`) | Android | Deep Link / Crypto / JNI | Deep-link auth bypass via hardcoded AES key + client-side date gate → native `getflag()` | High | [REPORT-strings.md](REPORT-strings.md) |

---

## Guess Me — quick summary

Exported, browsable `WebviewActivity` loads an attacker-supplied URL into a WebView whose `AndroidBridge.getTime()` interface runs shell commands. The deep-link allowlist is a bypassable `endsWith("mobilehackinglab.com")` check.

```
mhl:// deep link  →  weak endsWith() URL check  →  attacker page in JS-bridged WebView
                  →  AndroidBridge.getTime()     →  Runtime.exec()  =  RCE
```

**Confirmed on emulator:** `id` executed as the app's uid (`u0_a174`, SELinux `untrusted_app`). Full chain, PoC, and the six findings are in the [writeup](REPORT-guessme.md).

---

## Strings — quick summary

The flag lives in a native function `getflag()` whose string is assembled at runtime (so `strings` won't reveal it). The exported `Activity2` gates it behind a hardcoded-AES deep-link check plus a client-side SharedPreferences date check — all defeatable since the secrets ship in the app and it's debuggable.

```
set DAD4/UUU0133 = today (run-as, debuggable)  +  AES-decrypt hardcoded CT -> "mhl_secret_1337"
  →  mhl://labs/bWhsX3NlY3JldF8xMzM3  →  Activity2 passes  →  getflag()  →  flag Toast
```

Hardcoded key `your_secret_key_1234567890123456` / IV `1234567890123456`. Full chain and PoC in the [writeup](REPORT-strings.md).

---

## Conventions

- One writeup per target: `REPORT-<shortname>.md`.
- Each writeup includes: target metadata, a findings summary table (ID · severity · MASVS/OWASP ref), the vulnerable code, a reproducible PoC, and impact.
- Findings are tagged against [OWASP MASVS](https://mas.owasp.org/MASVS/) where applicable.
- Add new entries to the **Index** table above.

## Toolkit

`jadx` (decompile + manifest decode) · `apktool` · `adb` · Burp Suite · Frida / Objection · MobSF · an Android emulator or rooted device.
