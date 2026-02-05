---
title: "Direct System Calls in Zig: Building zcircuit"
published: 2026-02-05
template: "post"
draft: false
slug: "direct-system-call-in-zig"
category: "Security"
tags: ['Security', 'Zig', 'Malware']
description: "A deep technical dive into zcircuit, a Zig library that implements Hell's Gate, TartarusGate, and Hell's Hall techniques for direct and indirect Windows syscall execution."
socialImage: "../../assets/images/posts/circuit.jpg"
---

![circuit](../../assets/images/posts/circuit.jpg)

In this article, I will walk through the internals of [zcircuit](https://github.com/Hiroki6/zcircuit), a Zig library I built for performing direct and indirect Windows system calls. It combines three well-known techniques -- Hell's Gate, TartarusGate, and Hell's Hall -- into a single, type-safe API with compile-time string obfuscation.

1. [Background: Why Direct Syscalls?](#background-why-direct-syscalls)
2. [Why Zig?](#why-zig)
3. [Architecture Overview](#architecture-overview)
4. [Finding ntdll.dll in Memory](#finding-ntdlldll-in-memory)
5. [Hell's Gate: SSN Resolution from the Export Address Table](#hells-gate-ssn-resolution-from-the-export-address-table)
6. [TartarusGate: Recovering SSNs from Hooked Functions](#tartarusgate-recovering-ssns-from-hooked-functions)
7. [Hell's Hall: Indirect Syscall Execution](#hells-hall-indirect-syscall-execution)
8. [Compile-Time CRC32 Hashing](#compile-time-crc32-hashing)
9. [The Syscall Trampoline (Assembly)](#the-syscall-trampoline-assembly)
10. [Putting It All Together](#putting-it-all-together)
11. [References](#references)

## Background: Why Direct Syscalls?

On Windows, user-mode applications interact with the kernel through **NT API functions** exported by `ntdll.dll`. When you call a function like `NtAllocateVirtualMemory`, the ntdll stub does the following:

1. Moves the first argument from `rcx` to `r10` (the kernel expects it there).
2. Loads a **System Service Number (SSN)** into `eax`.
3. Executes the `syscall` instruction to transition into kernel mode.

The kernel uses the SSN in `eax` to look up the correct handler in the System Service Descriptor Table (SSDT) and dispatches the call.

EDR (Endpoint Detection and Response) products typically hook these ntdll stubs by overwriting their first few bytes with a `JMP` instruction that redirects execution to the EDR's monitoring code. This allows the EDR to inspect every NT API call before it reaches the kernel.

**Direct syscalls** bypass this entirely. Instead of calling the ntdll stub (which may be hooked), we resolve the SSN ourselves and execute the `syscall` instruction from our own code. The EDR's hook never triggers because we never execute the hooked stub.

However, there are complications:
- SSNs are not documented and can change between Windows versions.
- Some EDR products also monitor the return address of `syscall` instructions -- if it points outside ntdll, the call is flagged as suspicious.

zcircuit addresses these problems with three techniques.

## Why Zig?

Most existing implementations of Hell's Gate and related techniques are written in C or C++. I have been personally drawn to Zig for a while -- its error handling model (explicit error unions instead of exceptions or errno), `comptime`, and the general philosophy of "no hidden control flow" make it feel like the right level of abstraction for systems programming. Building zcircuit was partly an excuse to go deeper with the language.

Zig is also an interesting choice for this kind of tooling, and its adoption in offensive security is growing. The [VoidLink](https://research.checkpoint.com/2026/voidlink-the-cloud-native-malware-framework/) malware framework -- a cloud-native Linux implant discovered in late 2025 -- was written in Zig. The [Zig Strike](https://www.webasha.com/blog/zig-strike-offensive-toolkit-evading-av-xdr-and-edr-detection) offensive toolkit demonstrated that Zig-compiled payloads can evade modern AV, XDR, and EDR stacks, partly because security engines lack training data on Zig's binary patterns and function epilogue structures.

Beyond the novelty-based evasion advantage, Zig has several language features that map directly onto the problems zcircuit needs to solve:

**`comptime` does the heavy lifting.** Zig's compile-time evaluation is the core of this library. The CRC32 hash of `"NtAllocateVirtualMemory"` is computed at compile time -- no preprocessor macro, no build script, just a regular function call with a `comptime` argument. The `Zcircuit(config)` generic returns a specialized type where dead branches (e.g., TartarusGate code when `search_neighbor = false`) are eliminated entirely by the compiler. Architecture validation is also `comptime`, so unsupported platforms fail at compile time, not at runtime.

**First-class inline assembly.** The syscall trampoline requires precise control over registers and instruction sequences. Zig's inline assembly integrates with the type system -- the result of an `asm` expression can be directly passed to `@ptrFromInt` without casts or intermediate variables.

**Explicit pointer arithmetic.** Parsing PE structures means reading memory at computed offsets. Zig forces every cast to be visible -- `@ptrCast`, `@alignCast`, `@intFromPtr` -- where C would let you silently cast `void*` to any struct pointer. When walking raw memory of a PE file, that explicitness catches alignment and signedness mistakes at compile time.

**`extern struct` for ABI-compatible layouts.** The `ImageDosHeader`, `ImageNtHeaders64`, and `ImageExportDirectory` definitions must match the exact byte layout Windows uses. Zig's `extern struct` guarantees C-compatible field ordering, while regular `struct` may reorder fields for optimization. The guarantee is explicit in the type system.

**No runtime, no libc.** Zig can produce standalone binaries without linking to libc. Fewer dependencies mean a smaller binary footprint and fewer entries in the PE import table -- less surface for static analysis to flag.

## Architecture Overview

The library consists of four source files:

| File | Purpose |
|---|---|
| `src/root.zig` | Core logic: the `Zcircuit` generic type, SSN resolution pipeline |
| `src/ntdll.zig` | PE parser: locates ntdll.dll in memory, extracts the Export Address Table |
| `src/asm.zig` | Inline x86-64 assembly: the syscall trampoline |
| `src/utils.zig` | Compile-time CRC32 hashing with configurable seed |

The high-level flow looks like this:

```
User code
  │
  ▼
Zcircuit(config).init()
  │  ── TEB → PEB → Ldr → ntdll base address
  │  ── Parse PE headers → Export Directory
  ▼
circuit.getSyscall("NtXxx", .{})
  │  ── CRC32 hash function name (comptime)
  │  ── Walk Export Address Table, compare hashes
  │  ── Hell's Gate: check stub, extract SSN
  │  ── TartarusGate: if hooked, search neighbors
  │  ── Hell's Hall: find syscall;ret gadget
  ▼
syscall.call(.{ arg1, arg2, ... })
  │  ── hells_gate(ssn, address)  → store SSN and target
  │  ── hell_descent(args...)     → mov r10,rcx; mov eax,SSN; jmp [addr]
  ▼
NTSTATUS result
```

## Finding ntdll.dll in Memory

Before we can resolve any SSN, we need to find ntdll.dll's base address in the current process. The standard approach is to walk the **Process Environment Block (PEB)**, which is accessible through the **Thread Environment Block (TEB)**.

On x86-64 Windows, the TEB is pointed to by the GS segment register at offset `0x30`:

```zig
fn rtlGetThreadEnvironmentBlock() *TEB {
    return @ptrFromInt(@as(usize, asm volatile (
        "mov %%gs:0x30, %[ret]"
        : [ret] "=r" (-> usize),
    )));
}
```

This single `mov` instruction retrieves the TEB pointer without calling any API function -- completely invisible to user-mode hooks.

From the TEB, we reach the PEB, then the **Loader Data** (`PEB.Ldr`), which contains a doubly-linked list of all loaded modules in the order they appear in memory. On Windows 10+, ntdll.dll is always the **second entry** in the `InMemoryOrderModuleList`:

```zig
pub fn init() NtDllError!NtDll {
    const teb = rtlGetThreadEnvironmentBlock();
    const peb = teb.ProcessEnvironmentBlock;

    // Ensure Windows 10+ (SSN stability)
    if (peb.OSMajorVersion != 0xA) {
        return NtDllError.E1;
    }

    // First Flink = executable, second Flink = ntdll.dll
    const load_module = peb.Ldr.InMemoryOrderModuleList.Flink.Flink;
    const table_entry: *LDR_DATA_TABLE_ENTRY = @fieldParentPtr(
        "InMemoryOrderLinks", load_module
    );

    const image_export_directory = try getImageExportDirectory(table_entry.DllBase);
    return .{
        .table_entry = table_entry,
        .export_directory = image_export_directory,
    };
}
```

The error names are intentionally obfuscated to `E1`, `E2`, `E3` to avoid descriptive strings in the binary.

Once we have the module base address, we parse the PE headers -- DOS Header → NT Headers → Optional Header → Data Directory[0] (Export Directory) -- to obtain the Export Address Table:

```zig
fn getImageExportDirectory(module_base: PVOID) NtDllError!*ImageExportDirectory {
    const module_address = @intFromPtr(module_base);
    const dos = @as(*ImageDosHeader, @ptrCast(@alignCast(module_base)));

    if (dos.e_magic != ImageDosSignature) { // 0x5A4D = "MZ"
        return NtDllError.E2;
    }

    const nt: *ImageNtHeaders64 = @ptrCast(@alignCast(
        @as(*u8, @ptrFromInt(module_address + @as(usize, @intCast(dos.e_lfanew))))
    ));

    if (nt.Signature != ImageNtSignature) { // 0x00004550 = "PE\0\0"
        return NtDllError.E2;
    }

    const exportRva = nt.OptionalHeader.DataDirectory[0].VirtualAddress;
    if (exportRva == 0) {
        return NtDllError.E3;
    }

    return @as(*ImageExportDirectory, @ptrFromInt(module_address + exportRva));
}
```

The Export Directory gives us three parallel arrays:
- **AddressOfNames**: RVAs to null-terminated function name strings
- **AddressOfNameOrdinals**: Maps each name index to a function index
- **AddressOfFunctions**: RVAs to the actual function code (syscall stubs)

## Hell's Gate: SSN Resolution from the Export Address Table

[Hell's Gate](https://github.com/am0nsec/HellsGate) is the foundation. The idea is simple: walk ntdll's export table, find the target function, and read the SSN directly from its syscall stub bytes.

A clean (unhooked) ntdll syscall stub looks like this:

```
Offset  Bytes           Instruction
0:      4C 8B D1        mov r10, rcx
3:      B8 XX YY 00 00  mov eax, <SSN>
```

The SSN is a 16-bit value stored at bytes 4 and 5 (little-endian). We check the surrounding bytes to confirm the stub is clean:

```zig
inline fn isCleanStub(ptr: [*]u8) bool {
    return ptr[0] == 0x4c and ptr[1] == 0x8b and ptr[2] == 0xd1 and // mov r10, rcx
           ptr[3] == 0xb8 and ptr[6] == 0x00 and ptr[7] == 0x00;    // mov eax, imm32
}

inline fn extractSsn(ptr: [*]u8) u16 {
    const low: u16 = ptr[4];
    const high: u16 = ptr[5];
    return (high << 8) | low;
}
```

The export table walk compares CRC32 hashes of each export name against the compile-time hash of the target function name:

```zig
for (0..self.nt_dll.export_directory.NumberOfNames) |cx| {
    const function_address = @as([*]u8, @ptrFromInt(
        module_address + pdw_address_of_functions[pdw_address_of_name_ordinales[cx]]
    ));
    const name_ptr: [*:0]const u8 = @ptrFromInt(
        module_address + pdw_address_of_names[cx]
    );

    if (utils.crc32(name_ptr, config.seed) == func_name_hash) {
        syscall.address = @intFromPtr(function_address);

        if (isCleanStub(function_address)) {
            syscall.ssn = extractSsn(function_address);
        }
        // ... TartarusGate fallback if hooked
    }
}
```

When this works, we have the SSN and can make the syscall directly. But what happens if the stub is hooked?

## TartarusGate: Recovering SSNs from Hooked Functions

When an EDR hooks a function, it typically overwrites the first bytes of the stub with a `JMP` instruction (`0xE9`). The `isCleanStub` check will fail, and we cannot read the SSN directly.

[TartarusGate](https://github.com/trickster0/TartarusGate) exploits a key property of ntdll: **syscall stubs are laid out sequentially in memory, and their SSNs are sequential too**. Each stub is exactly 32 bytes (`STUB_SIZE`). If function A has SSN `N`, the stub 32 bytes later has SSN `N+1`, and 32 bytes before has SSN `N-1`.

So if the target function is hooked, we search its neighbors in both directions for a clean stub:

```zig
if (function_address[0] == 0xe9 or function_address[3] == 0xe9) {
    for (1..RANGE) |i| {
        // Search DOWN (higher addresses)
        const down_addr = function_address + i * STUB_SIZE;
        if (isCleanStub(down_addr)) {
            syscall.ssn = extractSsn(down_addr) - @as(u16, @intCast(i));
            break;
        }
        // Search UP (lower addresses)
        const up_addr = function_address - (i * STUB_SIZE);
        if (isCleanStub(up_addr)) {
            syscall.ssn = extractSsn(up_addr) + @as(u16, @intCast(i));
            break;
        }
    }
}
```

If we find a clean neighbor at distance `i` stubs downward with SSN `X`, the target SSN is `X - i`. If the clean neighbor is `i` stubs upward with SSN `Y`, the target SSN is `Y + i`. The search range is up to 255 neighbors in each direction, making it extremely unlikely that all neighbors are hooked.

## Hell's Hall: Indirect Syscall Execution

Even with the correct SSN, there is still a detection risk. If we execute the `syscall` instruction from our own code segment, EDR call-stack analysis will see a return address pointing **outside ntdll** -- a strong indicator of direct syscall usage.

[Hell's Hall](https://github.com/Maldev-Academy/HellHall) solves this by finding a legitimate `syscall; ret` instruction sequence **within ntdll's own memory** and jumping to it:

```zig
if (options.indirect_syscall) {
    const start_ptr: [*]u8 = @ptrFromInt(syscall.address);
    const search_base = start_ptr + SEARCH_RANGE;

    for (0..RANGE) |z| {
        // 0F 05 = syscall instruction
        if (search_base[z] == 0x0f and search_base[z + 1] == 0x05) {
            syscall.address = @intFromPtr(search_base + z);
            break;
        }
    }
}
```

The code scans ntdll memory starting 255 bytes past the target function, looking for the byte sequence `0F 05` (the `syscall` opcode). It stores this address as the jump target.

At execution time, instead of executing `syscall` directly, we `jmp` to this ntdll address. The SSN in `eax` still corresponds to our target function, so the kernel dispatches the correct handler. But the call stack now shows a return address **inside ntdll**, which looks legitimate to EDR monitoring.

## Compile-Time CRC32 Hashing

A binary that contains strings like `"NtAllocateVirtualMemory"` is trivially detected by static analysis. zcircuit avoids this by hashing function names with CRC32 at **compile time**:

```zig
pub inline fn crc32(name: [*:0]const u8, seed: u32) u32 {
    var crc = Crc32.init();
    crc.crc = seed;
    const name_slice = std.mem.span(name);
    crc.update(name_slice);
    return crc.final();
}
```

The key design choices:
- **User-configurable seed**: The `crc.crc` field is overridden with the user's seed instead of the default `0xFFFFFFFF`. Different seeds produce different hashes for the same input, so static signature databases cannot predict the values.
- **Compile-time evaluation**: In `getSyscall`, the function name is a `comptime` parameter, so the hash is resolved entirely at compile time. No plaintext API name ever appears in the final binary.
- **Runtime matching**: During the export table walk, each export name is hashed at runtime with the same seed and compared against the compile-time constant.

## The Syscall Trampoline (Assembly)

The actual syscall execution uses two assembly functions defined with Zig's inline assembly:

```zig
comptime {
    asm (
        \\.intel_syntax noprefix
        \\.data
        \\  wSystemCall: .long 0
        \\  qSyscallInsAdress: .quad 0
        \\
        \\.text
        \\.global hells_gate
        \\.global hell_descent
        \\
        \\hells_gate:
        \\  mov dword ptr [rip + wSystemCall], ecx
        \\  mov qword ptr [rip + qSyscallInsAdress], rdx
        \\  ret
        \\
        \\hell_descent:
        \\  mov r10, rcx
        \\  mov eax, dword ptr [rip + wSystemCall]
        \\  jmp qword ptr [rip + qSyscallInsAdress]
        \\  ret
    );
}
```

**`hells_gate`** stores the SSN and target address into global variables. In the Windows x64 calling convention, `ecx` = first argument (SSN), `rdx` = second argument (address).

**`hell_descent`** performs the actual syscall:
1. `mov r10, rcx` -- The kernel expects the first argument in `r10`, not `rcx`. This register shuffle is what ntdll normally does.
2. `mov eax, [wSystemCall]` -- Load the SSN.
3. `jmp [qSyscallInsAdress]` -- Jump to the target. In indirect mode, this is a `syscall; ret` gadget inside ntdll. In direct mode, this is the original function address.

The `ret` after `jmp` is dead code but maintains the stack frame structure.

## Putting It All Together

Here is how you use zcircuit. First, add the dependency:

```
zig fetch --save git+https://github.com/Hiroki6/zcircuit
```

Import it in `build.zig`:

```zig
const zcircuit = b.dependency("zcircuit", .{});
exe.root_module.addImport("zcircuit", zcircuit.module("zcircuit"));
```

Then use it in your code:

```zig
const zc = @import("zcircuit");

// Create a specialized type with a custom CRC32 seed
const MyCircuit = zc.Zcircuit(.{ .seed = 0xABCD1234 });

pub fn main() !void {
    // Initialize: finds ntdll.dll, parses its Export Address Table
    var circuit = try MyCircuit.init();

    // Resolve SSN for NtAllocateVirtualMemory
    // The string "NtAllocateVirtualMemory" is hashed at comptime and
    // never appears in the binary
    const alloc = circuit.getSyscall("NtAllocateVirtualMemory", .{}) orelse return;

    var addr: ?*anyopaque = null;
    var size: usize = 4096;
    const handle = @as(*anyopaque, @ptrFromInt(@as(usize, 0xffffffffffffffff)));

    // Execute the syscall
    const status = alloc.call(.{
        handle,   // ProcessHandle (-1 = current process)
        &addr,    // BaseAddress
        0,        // ZeroBits
        &size,    // RegionSize
        0x3000,   // AllocationType (MEM_COMMIT | MEM_RESERVE)
        0x04,     // Protect (PAGE_READWRITE)
    });
}
```

The `Config` struct controls which techniques are used:

```zig
pub const Config = struct {
    seed: u32 = 5381,              // CRC32 seed
    search_neighbor: bool = true,  // Enable TartarusGate
    indirect_syscall: bool = true, // Enable Hell's Hall
};
```

Because `Config` is a `comptime` parameter to `Zcircuit`, all configuration decisions are resolved at compile time with zero runtime overhead. Each unique configuration produces a distinct type.

The `call` method accepts a tuple of up to 11 arguments and converts each to `usize` using type-aware coercion -- pointers are cast to integers, booleans become 0/1, and `null` becomes 0:

```zig
inline fn argToUsize(arg: anytype) usize {
    const T = @TypeOf(arg);
    if (T == @TypeOf(null)) return 0;
    return switch (@typeInfo(T)) {
        .pointer, .optional => @intFromPtr(arg),
        .int => @intCast(arg),
        .bool => @intFromBool(arg),
        else => @as(usize, arg),
    };
}
```

## References

- [Hell's Gate](https://github.com/am0nsec/HellsGate) - am0nsec & RtlMateusz
- [TartarusGate](https://github.com/trickster0/TartarusGate) - trickster0
- [Hell's Hall](https://github.com/Maldev-Academy/HellHall) - Maldev Academy
- [BananaPhone](https://github.com/C-Sto/BananaPhone) - C-Sto (API design inspiration)
- [04: Chapter 2 | Windows OS System Calls](https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/wiki/04:-Chapter-2-%7C-Windows-OS-System-Calls) - Windows OS System Calls
