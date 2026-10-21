# Architectural Analysis: Concurrency & State Invariants

This document outlines the theoretical state machines and formal invariants governing DART frame retyping across versions.

---

## 1. Concurrent State Modeling

### Baseline Architecture (iOS 27.0.1)

```text
State: [ Page: Domain_A, RefCnt: 0, IOMMU_Active: 1, TLB: Valid ]

Execution Path:
1. Thread (Kernel Retype):
   - Check RefCnt == 0        --> PASS (only checks CPU/Kernel RefCnt)
   - Write Page Type = Domain_B
   - Issue TLBI (Asynchronous) --> Does not poll hardware status
   - Return

2. Concurrent Actor (IOMMU / DMA):
   - Operates via valid, un-flushed TLB entry
   - Result: Memory in Domain_B accessed by DMA actor
```

### Remediated Architecture (iOS 27.2)

```text
State: [ Page: Domain_A, RefCnt: 0, IOMMU_RefCnt: 1, TLB: Valid, Lock: Free ]

Execution Path:
1. Thread (Kernel Retype):
   - Acquire Atomic Dekker Lock (`CASAB`)
   - Check RefCnt == 0 AND IOMMU_RefCnt == 0
     * State Evaluation: IOMMU_RefCnt == 1 --> TRAP / PANIC
   - Synchronous Hardware TLB Wait (Polls completion bit)
   - Release Dekker Lock

2. Concurrent Actor (IOMMU / DMA):
   - Retype is blocked until all IOMMU channels have released references
   - Stale TLB lines are drained before lock release
```

---

## 2. Invariant Specifications

The patch introduces three formal memory-safety invariants enforced by SPTM:

### 1. Mutual Exclusion Invariant
$$\forall t, \; \text{Holders}(\text{Lock}_{\text{UAT}}) \le 1$$
* **Enforcement:** Atomic compare-and-swap acquire byte (`CASAB`) on per-CPU lock addresses prevents concurrent retyping operations across multiple cores.

### 2. Dangling DMA Invariant
$$\text{PageType}(P) \in \{\text{Protected}\} \implies \text{IOMMU\_RefCnt}(P) = 0$$
* **Enforcement:** Separation of `iommu_read_refcnt` from generic `read_refcnt` guarantees no device retains translation entries for secure/protected frames.

### 3. Translation Drain Invariant
$$\text{RetypeComplete}(P) \implies \text{TLB\_Drained}(P) = \text{True}$$
* **Enforcement:** The routine loops until the hardware acknowledgment bit in `gmmu-tlbi-verification-reg` is set, closing the asynchronous window.
