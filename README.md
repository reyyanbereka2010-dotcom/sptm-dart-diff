# Technical Analysis: Patched SPTM / DART TOCTOU Bypass in iOS 27.2

**Target Platforms:** Apple Silicon (T8110 / A15 Family and related SoCs)  
**Vulnerable Version:** iOS 27.0.1 (Build 24A446, SPTM-820.0.22)  
**Patched Version:** iOS 27.2 (Build 24B5099f, SPTM-820.40.23)  
**Component:** Secure Page Table Monitor (SPTM) — DART / IOMMU Subsystem  
**Vulnerability Class:** Concurrency / Time-of-Check to Time-of-Use (TOCTOU) Memory Retyping Race  

---

## 1. Executive Summary

Binary diffing and static analysis of the Secure Page Table Monitor firmware (`Firmware/sptm.t8110.release.im4p`) between iOS 27.0.1 and iOS 27.2 confirms the remediation of a structural synchronization flaw in the Apple DART (Device Address Resolution Table) verification pipeline. 

In iOS 27.0.1, the routine responsible for validating and transitioning physical memory frames between normal-world DMA access and protected SPTM domains lacked mutual exclusion locking, did not verify IOMMU-specific reference counters, and did not synchronize against pending Translation Lookaside Buffer Invalidations (TLBI). This permitted a DMA engine to retain stale, translated access to physical pages after SPTM had retyped them into protected domains.

iOS 27.2 completely refactors this path by introducing a hardware atomic Dekker lock, an independent `iommu_read_refcnt` validation invariant, synchronous hardware TLBI polling, and GAPF race detection assertions.

---

## 2. Component Background

The **Secure Page Table Monitor (SPTM)** serves as the hardware-enforced memory virtualization supervisor on modern Apple Silicon SoCs. It manages:
1. **CPU Stage-2 Virtualization & Page Tables:** Restricting the XNU kernel from mapping arbitrary physical frames.
2. **IOMMU / DART Translation Tables:** Isolating DMA-capable hardware blocks (e.g., PCIe, NVMe, USB, Wi-Fi) from unauthorized physical memory access.
3. **Frame Table Entries (FTE):** Tracking ownership, permissions, and active reference counts for physical memory pages across security domains.

When a memory page transitions from general-purpose kernel/DMA usage to an isolated or secure domain, SPTM must ensure that all references across both CPU cores and IOMMU translation caches are fully invalidated and accounted for.

---

## 3. Vulnerability Analysis (iOS 27.0.1)

### The Vulnerable Routine: `t8110dart_verify_bypass` (`sub_fffffff0270bfb0c`)
* **Binary Size:** 360 bytes (90 ARM64 instructions)
* **Execution Flow:** Fully linear; devoid of synchronization primitives.

```
+-------------------------------------------------------------+
| 1. Read Frame Table Entry (FTE)                             |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
| 2. Check Generic Refcount: (fte->read_refcnt == 0)          |
|    - Flaw: Aggregates references; ignores active IOMMU refs  |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
| 3. Retype Frame Table Entry in Hardware Registers           |
|    - Updates page permissions to protected state            |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
| 4. Issue Asynchronous GMMU TLBI                             |
|    - Flaw: Returns immediately without waiting for hardware |
|      acknowledgment / drain                                 |
+-------------------------------------------------------------+
```

### Root Cause Flaws:
1. **Absence of Mutual Exclusion:** No locking mechanism serialized calls to `t8110dart_verify_bypass`. Concurrent core threads could retype or remap entries simultaneously.
2. **Omission of IOMMU Reference Accounting:** The verification only evaluated a combined `read_refcnt`. If an IOMMU mapping was retained by a peripheral device while software-side refcounts were cleared, SPTM proceeded with the retype operation.
3. **Asynchronous TLB Invalidation Window:** The routine issued an invalidation request to the DART GMMU but did not poll the completion register. During this drain latency, peripheral DMA engines holding cached translations could execute physical read/write operations against the retyped memory.

---

## 4. Remediation Analysis (iOS 27.2)

### The Patched Routine: `sub_fffffff0270c058c`
* **Binary Size:** 1,088 bytes (272 ARM64 instructions) — a **3.02× increase (+182 instructions / +728 bytes)**.
* **Execution Flow:** Guarded, serialized, and synchronous.

```
+-------------------------------------------------------------+
| 1. Privilege World Check (`mrs x9, currentg` -> `cbz`)      |
|    - Ensures execution strictly within the Guarded Monitor  |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
| 2. Acquire Atomic Dekker Lock (`casab` acquire primitive)   |
|    - Guarantees single-caller mutual exclusion              |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
| 3. Independent IOMMU Reference Count Evaluation             |
|    - Asserts: `iommu_read_refcnt == 0`                      |
|    - Asserts: `iommu_read_refcnt <= read_refcnt`           |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
| 4. Concurrency & Latch Assertions                           |
|    - Asserts: `VIOLATION_T8110_DART_UNGANG_GAPF_RACE`       |
|    - Asserts: `VIOLATION_NVME_ILLEGAL_HIBERNATION_QUEUE_...`|
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
| 5. Synchronous Hardware TLBI Verification                   |
|    - Polls `gmmu-tlbi-verification-reg`                     |
|    - Validates hardware bit drain before returning          |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
| 6. Release Dekker Lock and Return                           |
+-------------------------------------------------------------+
```

---

## 5. Repository Documentation

- [`EVIDENCE.md`](EVIDENCE.md) - Complete binary evidence, disassembly snippets, string diffs, and instruction counts.
- [`ARCHITECTURE.md`](ARCHITECTURE.md) - State-machine model comparison and formal synchronization invariants.

---

## 6. Conclusion

Static analysis of the firmware changes establishes conclusive proof that:
1. **A race condition existed in iOS 27.0.1** within `t8110dart_verify_bypass`, allowing physical frames undergoing retyping to remain accessible to active IOMMU channels.
2. **The bypass vector is resolved in iOS 27.2** via comprehensive mutual exclusion (Dekker locks), strict per-IOMMU reference counting, and mandatory hardware TLB drain verification.
