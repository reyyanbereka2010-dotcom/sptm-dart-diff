# Binary & Static Analysis Evidence

This document details the binary-level metrics and differential analysis between extracted SPTM firmware builds:

- **v27.0.1 Baseline:** `SPTM-820.0.22` (`sptm_27.0.1.bin`)
- **v27.2 Patched:** `SPTM-820.40.23` (`sptm_27.2.bin`)

---

## 1. Metric Comparisons

| Metric | iOS 27.0.1 (`820.0.22`) | iOS 27.2 (`820.40.23`) | Delta |
|---|---|---|---|
| **Target Function Address** | `0xfffffff0270bfb0c` | `0xfffffff0270c058c` | New Entry Point |
| **Function Byte Size** | 360 bytes | 1,088 bytes | **+728 bytes (+202%)** |
| **Instruction Count** | 90 instructions | 272 instructions | **+182 instructions** |
| **Stack Allocation** | 32 bytes (`#0x20`) | 176 bytes (`#0xb0`) | **+144 bytes** |
| **CASAB (Atomic Acquire) Family** | 24 | 27 | **+3 instructions** |
| **Total SPTM Functions** | 385 | 388 | **+3 functions** |

---

## 2. New Security Assertion & Panic Strings

Extracted via direct binary comparison between the two firmware images:

```diff
+ %s(%s:%d) - fte(%p), new_type(%s), page_flags(%u), read_refcnt(%d) iommu_read_refcnt(%u)
+ %s: %s: iommu_read_refcnt (0x%hhx) > read_refcnt(0x%x) for FTE %p
+ %s: Failed to verify TLBI
+ %s: The GMMU TLBI verification register should be 8B-aligned
+ %s: UAT Dekker gate acquisition timed out after %llu ns (spun for %llu cycles)
+ %s: UAT Dekker lock acquisition timed out after %llu ns (spun for %llu cycles)
+ %s: dart %p (%s:%u): relaxed_rw_protections and allow_pte_remap are not supported together
+ %s: gmmu-tlbi-verification-bit (%llu) is unset or out of range [0, 63]
+ %s: verify-gmmu-tlbis-at-sync is enabled but gmmu-tlbi-verification-reg is not set
+ VIOLATION_NVME_ILLEGAL_HIBERNATION_QUEUE_LATCH
+ VIOLATION_T8110_DART_UNGANG_GAPF_RACE
+ enforce_no_hib_latch
+ gmmu-tlbi-verification-bit
+ gmmu-tlbi-verification-reg
+ hib_header_copy->handoffPageCount < HIB_HANDOFF_PAGECOUNT_LIMIT
+ uat_dekker_gate_lock
+ uat_dekkerlock_lock
+ uat_sync_outer_tlb_sapt_flush
+ verify-gmmu-tlbis-at-sync
```

---

## 3. Disassembly Excerpt (ARM64)

### iOS 27.0.1: Vulnerable Entry (`0xfffffff0270bfb0c`)
```asm
pacibsp
sub  sp, sp, #0x20             ; Minimal stack allocation
stp  fp, lr, [sp, #0x10]
add  fp, sp, #0x10
adrp x8, 0xfffffff027090000
ldr  x11, [x8, #0x810]
ldr  x8, [x11, #0x238]         ; Unsynchronized access to DART struct
ldr  w0, [x11, #0x40]          ; Reads single aggregate read_refcnt
cbnz w0, loc_panic
; Proceed directly to FTE retyping without acquiring locks or checking IOMMU status
```

### iOS 27.2: Patched Entry (`0xfffffff0270c058c`)
```asm
pacibsp
sub  sp, sp, #0xb0             ; Large stack frame (callee-saved registers)
stp  x26, x25, [sp, #0x60]
stp  x24, x23, [sp, #0x70]
stp  x22, x21, [sp, #0x80]
stp  x20, x19, [sp, #0x90]
stp  fp, lr,   [sp, #0xa0]
add  fp, sp,   #0xa0

; 1. Privilege World Check
mrs  x9, currentg
cbz  x9, loc_panic_wrong_world

; 2. Per-CPU Context & Dekker Lock Acquisition
mrs  x9, tpidr_gl2
...
casab w10, w9, [x11]           ; Hardware atomic acquire for Dekker lock
cbnz w10, loc_lock_retry

; 3. Evaluation of Independent IOMMU Counter
ldrb w12, [x19, #0x42]         ; Load iommu_read_refcnt
cbnz w12, loc_panic_refcnt

; 4. Synchronous TLBI Verification Loop
...
ldr  x14, [x21, #0x10]         ; Read gmmu-tlbi-verification-reg
tbz  x14, #0x1f, loc_wait_tlbi ; Loop until completion bit acknowledged
```
