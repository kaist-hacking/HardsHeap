# USENIX SECURITY SYMPOSIUM

## 2021 Summer Accepted
- Preventing Use-After-Free Attacks with Fast Forward Allocation (Brian Wickman)
  - https://www.usenix.org/system/files/sec21summer_wickman.pdf
  - One-Time Allocation(OTA) with efficient execution and moderate memory overhead.
  - The memory manager always returns a distinct memory address for each request.
  - https://github.com/bwickman97/ffmalloc

## 2018 Accepted
- GUARDER: A Tunable Secure Allocator (Sam Silvestro)
  - https://www.usenix.org/system/files/conference/usenixsecurity18/sec18-silvestro.pdf
  - GUARDER ensures the desired randomization entropy, and provides an\
    unprecedented level of security guarantee by combining\
    all security features of existing allocators.
  - https://github.com/UTSASRG/Guarder

## 2010 Accepted
- Cling: A Memory Allocator to Mitigate Dangling Pointers
  - https://www.usenix.org/legacy/events/sec10/tech/full_papers/Akritidis.pdf
  - Cling, a memory allocator designed to defense use-after-free attacks at runtime.
  - Cling utilizes more address space to prevent type-unsafe address space reuse among objects of different types.
  - It infers type information about allocated objects at runtime by inspecting the call stack of memory allocation routines.
  - Not found yet

# ACM SIGSAC Conference on Computer and Communications (CCS)

## 2017 Accepted
- FreeGuard: A Faster Secure Heap Allocator
  - https://doi.org/10.1145/3133956.3133957
  - FreeGuard prevents or reduces a wide range of heap-related security attacks,\
    such as heap overflows, heap over-reads, use-after-frees, as well as double and invalid frees.
  - https://github.com/UTSASRG/FreeGuard

## 2010 Accepted
- DieHarder: Securing the Heap
  - https://doi.org/10.1145/1866307.1866371
  - This paper presents the first formal treatment of the impact of allocator design on security.
  - DieHarder, a new allocator whose design was guided by this analysis.
  - https://github.com/emeryberger/DieHard

# The Network and Distributed System Security Symposium (NDSS)

# IEEE Symposium on Security and Privacy (Oakland)

## 2020 Accepted
- MarkUs: Drop-in Use-After-Free Prevention for Low-Level Languages
  - https://doi.org/10.1109/SP40000.2020.00058
  - MarkUs, a memory allocator that prevents use-after-free attack at low overhead.
  - By quarantining data freed by the programmer and forbidding its reallocation\
    until we are sure that there are no dangling pointers targeting it.
  - https://github.com/SamAinsworth/MarkUs-sp2020

# Others

## 2019 the 20th International Middleware Conference
- SlimGuard: A Secure and Memory-Efficient Heap Allocator
  - https://doi.org/10.1145/3361525.3361532
  - SlimGuard protects against widespread heap-related attacks such as overflows, over-reads, double/invalid free, and use-after-free.
  - https://github.com/ssrg-vt/SlimGuard

## 2017 the Hardware and Architectural Support for Security and Privacy
- HA2lloc: Hardware-Assisted Secure Allocator
  - https://doi.org/10.1145/3092627.3092635
  - HA2lloc, a hardware-assisted allocator that is capable of leveraging an extended memory management unit to detect memory errors in the heap.
  - Not found yet

## Android native memory allocator
- Scudo
  - https://source.android.com/devices/tech/debug/scudo
  - Scudo detects and mitigates memory corruption bugs in the heap, such as Double free, Arbitrary free, Heap-based buffer overflow, Use-after-free.
  - https://github.com/llvm/llvm-project/tree/master/compiler-rt/lib/scudo

## Chromium memory allocator
- PartitionAlloc
  - https://chromium.googlesource.com/chromium/src/+/master/base/allocator/partition_allocator/PartitionAlloc.md
  - PartitionAlloc guarantees that different partitions exist in different regions of the process' address space.

## Other Allocators
- https://github.com/emeryberger/Malloc-Implementations

# Not Allocators
- Archipelago: Trading address space for reliability and security
- CRCount: Pointer Invalidation with Reference Counting to Mitigate Use-after-free in Legacy C/C++
- HeapExpo: Pinpointing Promoted Pointers to Prevent Use-After-Free Vulnerabilities
- Undangle: Early Detection of Dangling Pointers in Use-After-Free and Double-Free Vulnerabilities
- Gollum: Modular and Greybox Exploit Generation for Heap Overflows in Interpreters
- DangNull: Preventing Use-after-free with Dangling Pointers Nullification
