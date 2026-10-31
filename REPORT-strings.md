# Mobile App Pentest — `com.mobilehackinglab.challenge` ("Strings")

**Target:** `com.mobilehackinglab.strings.apk` (package `com.mobilehackinglab.challenge`) — Mobile Hacking Lab "Strings" challenge
**Platform:** Android (minSdk 28, targetSdk 34), ships native libs (`libchallenge.so`, `libflag.so`)
**Basis:** CTF / lab / training
**Date:** 2026-10-31
**Verification:** Full chain **dynamically confirmed** on an Android emulator — `getflag()` reached, flag Toast ("Success") displayed.

---

## Summary

The flag is produced by a native function `Activity2.getflag()` in `libflag.so`. The string is **assembled at runtime** by helper functions (`flag13`, `flag_fill`, `flag_i`, …), so `strings` on the `.so` never reveals it — the challenge must be solved dynamically by reaching `getflag()`. Reaching it requires passing three gates in the exported `Activity2`, all of which are defeatable because every secret is hardcoded and the app is debuggable.

| ID | Finding | Severity |
|----|---------|----------|
| ST-01 | Hardcoded AES key/IV + ciphertext in app code → deep-link auth bypass | High |
| ST-02 | Exported `Activity2` reveals protected functionality via deep link | Medium |
| ST-03 | Client-side-only access control (SharedPreferences date gate) | Medium |
| ST-04 | `debuggable="true"` → `run-as` read/write of private data | Medium |
| ST-05 | `allowBackup="true"` | Low |

---

## How the gate works (`Activity2.onCreate`)

```
1. action == android.intent.action.VIEW
2. SharedPref DAD4/UUU0133  ==  today's date  (dd/MM/yyyy)      <- "date gate"
3. uri == mhl://labs/<seg>  AND
   base64decode(lastPathSegment) == AES_decrypt(hardcoded CT)   <- "crypto gate"
   => System.loadLibrary("flag"); Toast(getflag())
   else => finishAffinity(); System.exit(0)
```

- **Date gate**: `UUU0133` is written by `MainActivity.KLOW()`, invoked from the native `stringFromJNI()` (the method name is obfuscated inside `libchallenge.so`, not a plaintext string — the "Strings" twist). In testing the pref was not reliably set on launch, so it was written directly via `run-as` (ST-04).
- **Crypto gate**: hardcoded in `Activity2` / `Activity2Kt`:
  - key `your_secret_key_1234567890123456` (AES-256)
  - IV  `1234567890123456` (`Activity2Kt.fixedIV`)
  - cipher `AES/CBC/PKCS5Padding`, ciphertext (base64) `bqGrDKdQ8zo26HflRsGvVA==`
  - decrypts to **`mhl_secret_1337`**

## Exploit

Required deep-link segment = `base64("mhl_secret_1337")` = `bWhsX3NlY3JldF8xMzM3`.

```bash
# 1) set the date gate (run-as works because android:debuggable="true")
adb shell am force-stop com.mobilehackinglab.challenge
adb shell "run-as com.mobilehackinglab.challenge sh -c 'mkdir -p /data/data/com.mobilehackinglab.challenge/shared_prefs && echo <BASE64_PREFS_XML> | base64 -d > /data/data/com.mobilehackinglab.challenge/shared_prefs/DAD4.xml'"
#   where the XML is: <map><string name="UUU0133">31/10/2026</string></map>  (today, dd/MM/yyyy)

# 2) trigger the flag via the exported deep link
adb shell am start -n com.mobilehackinglab.challenge/.Activity2 -a android.intent.action.VIEW -d "mhl://labs/bWhsX3NlY3JldF8xMzM3"
```

**Result:** gate passes → `getflag()` runs → Toast shows the flag (**"Success"**). Confirmed on emulator.

### Deriving the secret (offline)
```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
key=b"your_secret_key_1234567890123456"; iv=b"1234567890123456"
ct=base64.b64decode("bqGrDKdQ8zo26HflRsGvVA==")
d=Cipher(algorithms.AES(key),modes.CBC(iv)).decryptor(); raw=d.update(ct)+d.finalize()
pt=raw[:-raw[-1]]                       # strip PKCS5 padding -> b"mhl_secret_1337"
print(base64.b64encode(pt).decode())    # -> bWhsX3NlY3JldF8xMzM3
```

---

## Notes
- The flag is not a static string in `libflag.so`; it is built at runtime, so static `strings`/grep is insufficient — reaching `getflag()` dynamically is the intended path.
- Root cause of the bypass: secrets (AES key/IV/ciphertext) embedded in the client, and access control enforced entirely client-side (a local SharedPreferences date check an attacker can set directly).
- Tooling: `jadx` (decompile + manifest), `strings` on the native libs, Python `cryptography` for the offline decrypt, `adb` for delivery.
