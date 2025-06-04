# Kernel callback integrity bypass

The Windows kernel offers the ability to register event listeners in the form of callback for events like handle creation
or process/thread creation through APIs such as (`ObRegisterCallbacks` or `PsSetCreateThreadNotifyRoutineEx`). However, these
APIs require that the driver image be considered "valid", which amongst other things requires that the driver be signed. 

This creates problems for unsigned drivers that are sideloaded through means such as abusing vulnerable drivers to perform
arbitrary kernel read/write. Since these drivers are not signed, they cannot access these "privileged" APIs.

This repository explores three broad categories of methods bypassing this restriction, with a sample PoC for each, including
potential mitigation strategies for anti-virus or anti-cheat software.

## Code patching
![code patcher logs](https://raw.githubusercontent.com/thebowenfeng/kernel-integrity-bypass/refs/heads/master/images/code-patcher.PNG)

Refers to a broad family of techniques that involves patching `ntoskrnl.exe` image, specifically functions involved in the
integrity check flow, such as `MmVerifyCallbackFunctionCheckFlags` or `MiLookupDataTableEntry`. The attached PoC patches 
`MmVerifyCallbackFunctionCheckFlags` to always return `true`, in order to register callbacks via `ObRegisterCallbacks`. It then
restores the patch as not to trigger PatchGuard.

### Advantages

- Easy to perform
- Compatible with most modern Windows versions (attached PoC uses a non-compatible, version specific method of patching as it simpler to perform. Recommended method is to detour and overwrite return value)

### Disadvantages

- Potentially can trigger PatchGuard. Although practically PatchGuard almost never triggers instantaneously as long as modified bytes are restored.
- Easy to detect (discussed below in mitigation strategies)

### Mitigation strategies

AV/AC software can easily enumerate callback list directly and manually verify if each callback is registered in the address 
range of a valid image. Although the callback is registered and will execute, its address is within an invalid image.

## Integrity spoofing/hijacking
![integrity spoofer logs](https://raw.githubusercontent.com/thebowenfeng/kernel-integrity-bypass/refs/heads/master/images/integrity-spoofer.PNG)

Involves registering the callback itself in a valid image. Traditionally, this is done by finding "code caves" 
(empty bytes within an executable section of a driver image) and placing code there. However, this is easily 
detectable via rudimentary image integrity checks.

*The following section describes a technique that may be specific to `ObRegisterCallbacks`*

A better technique (included in the PoC) is to abuse `PreCallback` and `PostCallback`'s calling convention, `__fastcall`.
`__fastcall` will push the first two arguments (or two smallest, but in this case there are only 2 args anyways) into register
`RCX` and `RDX` (`ECX` and `EDX` for 32 bit equivalent), which is the caller's responsibility. This means right as a callback
is about to be executed, `RCX` and `RDX` is guaranteed to be populated with the callback's two arguments.

Both callbacks accepts `RegistrationContext` as the first argument (which will be in `RCX`). This is a user defined value
that is supplied upon registration. As such, if the callback function performs `jmp rcx`, and `RegistrationContext` is set
to a valid executable address, then we can effectively place our callback anywhere, as long as the first two bytes is `FF E1`
and within a valid driver image's executable section. This means we only need to find these two bytes *somewhere* within any
valid driver image's code segment, register our callbacks at that address, then place the address of our *real* callback 
as `RegistrationContext`.

### Advantages
- Difficult to detect (2nd technique)
- Doesn't involve patching PatchGuarded code

### Disadvantages
- Easy to detect (1st technique)
- Not portable. The process of finding a suitable driver image to hijack is a trial and error and involves extensive manual testing. For example, hijacking a driver that isn't mapped globally but to specific processes only (e.g `win32kbase.sys`) will lead to page fault BSODs.

### Mitigation strategies

If using the first technique, simply perform basic image integrity checks against valid driver images by comparing it with
image on disk.

Second technique is much harder to mitigate and usually involves some form of manual reverse engineering (as it doesn't modify
anything). A possible automated check is to programatically decompile, starting from the inital `jmp` (e.g `Zydis`), and verify
that subsequent instructions are valid. Chances are, `FF E1` belongs as part of a completely different instruction (say an operand),
which will lead to an invalid decompilation should the decompiler assume `FF E1` is a standalone instruction. Software may
build detection vectors for this specific pattern and flag callbacks that starts off with `FF E1` for manual analysis.

### Appendix

Code to enumerate valid kernel images.
```c++
unsigned char MiLookupDataTableEntrySignature[] = { 0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x08, 0x48, 0x89, 0x70, 0x18, 0x57, 0x48, 0x83, 0xEC, 0x20, 0x33, 0xF6 };
uintptr_t lookupAddr = FindCodeSignature(baseAddr, 100000000, MiLookupDataTableEntrySignature, sizeof(MiLookupDataTableEntrySignature));
MiLookupDataTableEntryType MiLookupDataTableEntry = (MiLookupDataTableEntryType)lookupAddr;
Print("MiLookupDataTableEntry address: %llX", lookupAddr);

ULONG bytesWritten = 0;
uintptr_t result = NULL;
ZwQuerySystemInformation(SystemModuleInformation, 0, bytesWritten, &bytesWritten);
if (!bytesWritten) {
	Print("Unable to get ZwQuerySystemInformation module size");
	return NULL;
}

PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePool2(POOL_FLAG_NON_PAGED, bytesWritten, 'pool');
if (!modules) {
	Print("Unable to allocate pool for ZwQuerySystemInformation modules");
	return NULL;
}
RtlZeroMemory(modules, bytesWritten);
NTSTATUS queryResult = ZwQuerySystemInformation(SystemModuleInformation, modules, bytesWritten, &bytesWritten);

if (queryResult == STATUS_SUCCESS)
{
	PRTL_PROCESS_MODULE_INFORMATION module = modules->Modules;
	for (ULONG i(0); i < modules->NumberOfModules; i++)
	{
		uintptr_t ldrAddr = MiLookupDataTableEntry((UINT64)module[i].ImageBase, 0);
		unsigned int isValid = *(unsigned int*)(ldrAddr + 104) & 32;
		if (isValid != 0) {
			Print("Image name: %s", (PCHAR)module[i].FullPathName);
		}
	}
}
else {
	result = NULL;
}

ExFreePoolWithTag(modules, 'pool');
```

## Integrity patcher
![Integrity patcher logs](https://raw.githubusercontent.com/thebowenfeng/kernel-integrity-bypass/refs/heads/master/images/integrity-patcher.PNG)

This technique attacks the underlying data structure used by `MiLookupDataTableEntry` which `MmVerifyCallbackFunctionCheckFlags`
uses to check if a supplied address (that being the callback function address) is within a valid image. `MiLookupDataTableEntry`
(supposedly) returns an opaque kernel structure `LDR_DATA_TABLE_ENTRY`, which contains a member that denotes if a image is
valid. The underlying structure that `MiLookupDataTableEntry` queries is another opaque structure contained in an AVL tree 
(used to be a linked list).

The PoC will simply modify the root tree node's base image address to the callback's address so `MiLookupDataTableEntry` will
return the root node when `MmVerifyCallbackFunctionCheckFlags` calls the function. Then, the return value is parsed and the 
`isValid` member is modified to pass checks. 

A more thorough and foulproof method is to insert a brand new node into the tree with fake information that denotes a 
supposedly valid kernel image. This is not done due to its complex nature, having to reverse engineer multiple opaque kernel
structures and having to work with AVL trees in general (which `ntoskrnl` conveniently has `RtlAvlInsertNodeEx`).

### Advantages

- No patching protected memory. Memory that is patched is meant to be modified.

### Disadvantages

- Not portable. Opaque kernel structures changes between versions and global variables (one that contains the AVL tree)'s static offsets also change.
- Depending on which technique there may be other drawbacks
  - Using technique #1 (PoC) will result in the same drawbacks as "code patcher"
  - Using technique #2 will leave traces of the unsigned driver, leaving it vulnerable for being flagged.

### Mitigation strategies

Mitigation strategies for technique #1 is virtually identical to the ones discussed for "code patcher". Namely, it involves
enumerating through the callback list, checking if each callback is registered in a valid image as the patch is temporary and
has to be restored

Technique #2 mainly leaves the unsigned driver vulnerable to exposure, as a permanent record of its existence is now available
for AV/AC software to log. One strategy can be enumerating through the AVL tree, checking if each image is backed on by an image
on disk, which is a common check performed by most AV/AC softwares already. However, this can theoretically be mitigated by
a well-spoofed fake record that points to some existing image on disk, which the AV/AC can then perform an image integrity validation
(discussed in part for "integrity spoofing") to check if the content of the actual image matches the fake supplised image on disk, which will
inevitably lead to discrepancies.
