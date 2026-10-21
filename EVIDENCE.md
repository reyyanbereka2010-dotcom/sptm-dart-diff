# Comprehensive Binary & Static Analysis Evidence (T8110 / A15)

This document catalogs the complete empirical evidence, instruction metrics, and structural diffs proving the presence and remediation of the SPTM DART TOCTOU bypass on **Apple T8110 (A15 / iPhone14,6)**.

---

## 1. Target Images & Environment

| Property | Baseline Image (iOS 27.0.1) | Patched Image (iOS 27.2 Beta 3) |
|---|---|---|
| **OS Build** | `24A446` | `24B5099f` |
| **SPTM Version** | `SPTM-820.0.22` | `SPTM-820.40.23` |
| **Firmware Path** | `Firmware/sptm.t8110.release.im4p` | `Firmware/sptm.t8110.release.im4p` |
| **Binary Extract** | `sptm_27.0.1.bin` (1,196,064 B) | `sptm_27.2.bin` (1,212,448 B) |
| **Mach-O `__TEXT_EXEC`** | `0x5b7b0` bytes | `0x5c394` bytes (**+3,044 bytes**) |
| **Mach-O `__TEXT.__cstring`**| `0x14da2` bytes | `0x151be` bytes (**+1,052 bytes**) |
| **Total SPTM Functions** | 385 | 388 (**+3 functions**) |

---

## 2. Core Routine Delta: `t8110dart_verify_bypass`

The core function governing DART bypass verification with GMMU synchronization was mapped across builds:

```
Baseline (27.0.1):  sub_fffffff0270bfb0c  -->   360 bytes  ( 90 ARM64 instructions)
Patched  (27.2):    sub_fffffff0270c058c  --> 1,088 bytes  (272 ARM64 instructions)
────────────────────────────────────────────────────────────────────────────────
Delta:                                         +728 bytes  (+182 instructions / +202%)
```

### Instruction & Primitive Metrics:
- **Stack Allocation:** Grew from **32 bytes** (`sub sp, sp, #0x20`) to **176 bytes** (`sub sp, sp, #0xb0`) to accommodate saving 10+ callee-saved registers for the retry/spin loops.
- **Atomic Operations (`CASAB` family):** Increased from **24 to 27 (+3)** across the binary. Specifically, an atomic compare-and-swap acquire byte (`casab w10, w9, [x11]`) was inserted at `0xfffffff0270c0618`.
- **Privilege Gate:** Introduced `mrs x9, currentg` followed by `cbz x9, loc_panic` in the prologue, preventing non-guarded world execution.

---

## 3. Disassembly Comparison (Side-by-Side)

### Baseline Prologue & Verification (`0xfffffff0270bfb0c` - iOS 27.0.1)
```asm
; --- Vulnerable: Linear, no privilege check, no locks, fire-and-forget TLBI ---
pacibsp
sub  sp, sp, #0x20             ; 32-byte frame
stp  fp, lr, [sp, #0x10]
add  fp, sp, #0x10

adrp x8, 0xfffffff027090000
ldr  x11, [x8, #0x810]
ldr  x8, [x11, #0x238]         ; Load DART struct
ldr  w0, [x11, #0x40]          ; Read combined read_refcnt ONLY
cbnz w0, loc_panic_refcnt

; Proceed directly to retyping hardware registers
...
bl   dart_invalidate_tlb       ; Asynchronous issue, no drain wait
ldp  fp, lr, [sp, #0x10]
add  sp, sp, #0x20
retab
```

### Patched Implementation (`0xfffffff0270c058c` - iOS 27.2)
```asm
; --- Remediated: Serialized, world-checked, dual-counter, synchronous ---
pacibsp
sub  sp, sp, #0xb0             ; 176-byte frame (5.5x larger)
stp  x26, x25, [sp, #0x60]
stp  x24, x23, [sp, #0x70]
stp  x22, x21, [sp, #0x80]
stp  x20, x19, [sp, #0x90]
stp  fp, lr,   [sp, #0xa0]
add  fp, sp,   #0xa0

; 1. Privilege World Check
mrs  x9, currentg              ; Read security world state
cbz  x9, loc_panic_world       ; Trap if not in Guarded/SPTM context

; 2. Per-CPU Context & Atomic Dekker Lock Acquisition
mrs  x9, tpidr_gl2             ; SPTM per-CPU data register
ldr  x11, [x9, #0x208]         ; Load lock control structure
loc_lock_spin:
ldrb w10, [x11, #0x91]
tbnz w10, #0, loc_lock_retry
casab w10, w9, [x11]           ; Hardware atomic acquire
cbnz w10, loc_lock_retry

; 3. Independent IOMMU Reference Count Evaluation
ldr  x19, [sp, #0x18]          ; FTE pointer
ldrb w12, [x19, #0x42]         ; Load iommu_read_refcnt
cbnz w12, loc_panic_iommu      ; Must be 0 before retyping

ldr  w13, [x19, #0x40]         ; Load total read_refcnt
cmp  w12, w13
b.hi loc_panic_counter_skew    ; Panics if iommu_read_refcnt > read_refcnt

; 4. Hardware GMMU TLBI Drain Wait
...
loc_tlbi_drain_poll:
ldr  x14, [x21, #0x10]         ; Read gmmu-tlbi-verification-reg
tbz  x14, #0x1f, loc_tlbi_spin ; Spin until verification bit is acknowledged

; 5. Release Lock & Exit
strb wzr, [x11, #0x91]         ; Clear gate lock
...
retab
```

---

## 4. Complete String Diff Analysis (50 Added Strings)

Extracted directly via differential python analysis of `sptm_old_strings.txt` vs `sptm_new_strings.txt`:

### IOMMU & Reference Count Hardening
```text
+ %s(%s:%d) - fte(%p), new_type(%s), page_flags(%u), read_refcnt(%d) iommu_read_refcnt(%u)
+ %s: %s: iommu_read_refcnt (0x%hhx) > read_refcnt(0x%x) for FTE %p
+ VIOLATION_T8110_DART_UNGANG_GAPF_RACE
+ %s: dart %p (%s:%u): relaxed_rw_protections and allow_pte_remap are not supported together
```

### Dekker Lock & Concurrency Primitives
```text
+ uat_dekkerlock_lock
+ uat_dekker_gate_lock
+ %s: UAT Dekker lock acquisition timed out after %llu ns (spun for %llu cycles)
+ %s: UAT Dekker gate acquisition timed out after %llu ns (spun for %llu cycles)
+ uat_sync_outer_tlb_sapt_flush
```

### Synchronous Hardware TLBI Verification
```text
+ verify-gmmu-tlbis-at-sync
+ gmmu-tlbi-verification-reg
+ gmmu-tlbi-verification-bit
+ %s: Failed to verify TLBI
+ %s: The GMMU TLBI verification register should be 8B-aligned
+ %s: gmmu-tlbi-verification-bit (%llu) is unset or out of range [0, 63]
+ %s: verify-gmmu-tlbis-at-sync is enabled but gmmu-tlbi-verification-reg is not set
```

### Hibernation & Device Tree Guarding
```text
+ VIOLATION_NVME_ILLEGAL_HIBERNATION_QUEUE_LATCH
+ enforce_no_hib_latch
+ hib_header_copy->handoffPageCount < HIB_HANDOFF_PAGECOUNT_LIMIT
+ /chosen/manifest-properties
+ internal-use-only-unit
+ sptm_allow_vm_isa_internal_guests
+ sptm_is_iuou_or_iuos_device
```

---

## 5. Corroborating Kext & Kernel Subsystem Deltas

The fix inside SPTM was coordinated across kernel drivers interfacing with the DART and memory subsystems:

| Component | Code Delta | Metric Details |
|---|---|---|
| **`com.apple.driver.AppleT8110DART`** | +56 bytes text | Functions grew from **162 to 164 (+2)** |
| **`com.apple.iokit.IONVMeFamily`** | -4,524 bytes text | Refactored queue latching; **33 functions removed/streamlined** |
| **`com.apple.security.sandbox`** | +520 B text / **+15.2 KB const** | Profile bytecode expanded (`0x1eecb1` → `0x1f2991`) |
| **`com.apple.kernel` (XNU)** | **+97 KB text / +16 KB strings** | **233 new functions**; `__DATA.__lock_grp` grew by +176 B |
