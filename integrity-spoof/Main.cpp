#include <ntdef.h>
#include <ntifs.h>
#include <ntddk.h>
#include <ntimage.h>
#include <wdm.h>
#include <stdarg.h>
#include <stdio.h>

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation = 0x0,
	SystemProcessorInformation = 0x1,
	SystemPerformanceInformation = 0x2,
	SystemTimeOfDayInformation = 0x3,
	SystemPathInformation = 0x4,
	SystemProcessInformation = 0x5,
	SystemCallCountInformation = 0x6,
	SystemDeviceInformation = 0x7,
	SystemProcessorPerformanceInformation = 0x8,
	SystemFlagsInformation = 0x9,
	SystemCallTimeInformation = 0xa,
	SystemModuleInformation = 0xb,
	SystemLocksInformation = 0xc,
	SystemStackTraceInformation = 0xd,
	SystemPagedPoolInformation = 0xe,
	SystemNonPagedPoolInformation = 0xf,
	SystemHandleInformation = 0x10,
	SystemObjectInformation = 0x11,
	SystemPageFileInformation = 0x12,
	SystemVdmInstemulInformation = 0x13,
	SystemVdmBopInformation = 0x14,
	SystemFileCacheInformation = 0x15,
	SystemPoolTagInformation = 0x16,
	SystemInterruptInformation = 0x17,
	SystemDpcBehaviorInformation = 0x18,
	SystemFullMemoryInformation = 0x19,
	SystemLoadGdiDriverInformation = 0x1a,
	SystemUnloadGdiDriverInformation = 0x1b,
	SystemTimeAdjustmentInformation = 0x1c,
	SystemSummaryMemoryInformation = 0x1d,
	SystemMirrorMemoryInformation = 0x1e,
	SystemPerformanceTraceInformation = 0x1f,
	SystemObsolete0 = 0x20,
	SystemExceptionInformation = 0x21,
	SystemCrashDumpStateInformation = 0x22,
	SystemKernelDebuggerInformation = 0x23,
	SystemContextSwitchInformation = 0x24,
	SystemRegistryQuotaInformation = 0x25,
	SystemExtendServiceTableInformation = 0x26,
	SystemPrioritySeperation = 0x27,
	SystemVerifierAddDriverInformation = 0x28,
	SystemVerifierRemoveDriverInformation = 0x29,
	SystemProcessorIdleInformation = 0x2a,
	SystemLegacyDriverInformation = 0x2b,
	SystemCurrentTimeZoneInformation = 0x2c,
	SystemLookasideInformation = 0x2d,
	SystemTimeSlipNotification = 0x2e,
	SystemSessionCreate = 0x2f,
	SystemSessionDetach = 0x30,
	SystemSessionInformation = 0x31,
	SystemRangeStartInformation = 0x32,
	SystemVerifierInformation = 0x33,
	SystemVerifierThunkExtend = 0x34,
	SystemSessionProcessInformation = 0x35,
	SystemLoadGdiDriverInSystemSpace = 0x36,
	SystemNumaProcessorMap = 0x37,
	SystemPrefetcherInformation = 0x38,
	SystemExtendedProcessInformation = 0x39,
	SystemRecommendedSharedDataAlignment = 0x3a,
	SystemComPlusPackage = 0x3b,
	SystemNumaAvailableMemory = 0x3c,
	SystemProcessorPowerInformation = 0x3d,
	SystemEmulationBasicInformation = 0x3e,
	SystemEmulationProcessorInformation = 0x3f,
	SystemExtendedHandleInformation = 0x40,
	SystemLostDelayedWriteInformation = 0x41,
	SystemBigPoolInformation = 0x42,
	SystemSessionPoolTagInformation = 0x43,
	SystemSessionMappedViewInformation = 0x44,
	SystemHotpatchInformation = 0x45,
	SystemObjectSecurityMode = 0x46,
	SystemWatchdogTimerHandler = 0x47,
	SystemWatchdogTimerInformation = 0x48,
	SystemLogicalProcessorInformation = 0x49,
	SystemWow64SharedInformationObsolete = 0x4a,
	SystemRegisterFirmwareTableInformationHandler = 0x4b,
	SystemFirmwareTableInformation = 0x4c,
	SystemModuleInformationEx = 0x4d,
	SystemVerifierTriageInformation = 0x4e,
	SystemSuperfetchInformation = 0x4f,
	SystemMemoryListInformation = 0x50,
	SystemFileCacheInformationEx = 0x51,
	SystemThreadPriorityClientIdInformation = 0x52,
	SystemProcessorIdleCycleTimeInformation = 0x53,
	SystemVerifierCancellationInformation = 0x54,
	SystemProcessorPowerInformationEx = 0x55,
	SystemRefTraceInformation = 0x56,
	SystemSpecialPoolInformation = 0x57,
	SystemProcessIdInformation = 0x58,
	SystemErrorPortInformation = 0x59,
	SystemBootEnvironmentInformation = 0x5a,
	SystemHypervisorInformation = 0x5b,
	SystemVerifierInformationEx = 0x5c,
	SystemTimeZoneInformation = 0x5d,
	SystemImageFileExecutionOptionsInformation = 0x5e,
	SystemCoverageInformation = 0x5f,
	SystemPrefetchPatchInformation = 0x60,
	SystemVerifierFaultsInformation = 0x61,
	SystemSystemPartitionInformation = 0x62,
	SystemSystemDiskInformation = 0x63,
	SystemProcessorPerformanceDistribution = 0x64,
	SystemNumaProximityNodeInformation = 0x65,
	SystemDynamicTimeZoneInformation = 0x66,
	SystemCodeIntegrityInformation = 0x67,
	SystemProcessorMicrocodeUpdateInformation = 0x68,
	SystemProcessorBrandString = 0x69,
	SystemVirtualAddressInformation = 0x6a,
	SystemLogicalProcessorAndGroupInformation = 0x6b,
	SystemProcessorCycleTimeInformation = 0x6c,
	SystemStoreInformation = 0x6d,
	SystemRegistryAppendString = 0x6e,
	SystemAitSamplingValue = 0x6f,
	SystemVhdBootInformation = 0x70,
	SystemCpuQuotaInformation = 0x71,
	SystemNativeBasicInformation = 0x72,
	SystemErrorPortTimeouts = 0x73,
	SystemLowPriorityIoInformation = 0x74,
	SystemBootEntropyInformation = 0x75,
	SystemVerifierCountersInformation = 0x76,
	SystemPagedPoolInformationEx = 0x77,
	SystemSystemPtesInformationEx = 0x78,
	SystemNodeDistanceInformation = 0x79,
	SystemAcpiAuditInformation = 0x7a,
	SystemBasicPerformanceInformation = 0x7b,
	SystemQueryPerformanceCounterInformation = 0x7c,
	SystemSessionBigPoolInformation = 0x7d,
	SystemBootGraphicsInformation = 0x7e,
	SystemScrubPhysicalMemoryInformation = 0x7f,
	SystemBadPageInformation = 0x80,
	SystemProcessorProfileControlArea = 0x81,
	SystemCombinePhysicalMemoryInformation = 0x82,
	SystemEntropyInterruptTimingInformation = 0x83,
	SystemConsoleInformation = 0x84,
	SystemPlatformBinaryInformation = 0x85,
	SystemThrottleNotificationInformation = 0x86,
	SystemHypervisorProcessorCountInformation = 0x87,
	SystemDeviceDataInformation = 0x88,
	SystemDeviceDataEnumerationInformation = 0x89,
	SystemMemoryTopologyInformation = 0x8a,
	SystemMemoryChannelInformation = 0x8b,
	SystemBootLogoInformation = 0x8c,
	SystemProcessorPerformanceInformationEx = 0x8d,
	SystemSpare0 = 0x8e,
	SystemSecureBootPolicyInformation = 0x8f,
	SystemPageFileInformationEx = 0x90,
	SystemSecureBootInformation = 0x91,
	SystemEntropyInterruptTimingRawInformation = 0x92,
	SystemPortableWorkspaceEfiLauncherInformation = 0x93,
	SystemFullProcessInformation = 0x94,
	SystemKernelDebuggerInformationEx = 0x95,
	SystemBootMetadataInformation = 0x96,
	SystemSoftRebootInformation = 0x97,
	SystemElamCertificateInformation = 0x98,
	SystemOfflineDumpConfigInformation = 0x99,
	SystemProcessorFeaturesInformation = 0x9a,
	SystemRegistryReconciliationInformation = 0x9b,
	MaxSystemInfoClass = 0x9c,
} SYSTEM_INFORMATION_CLASS;

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	CHAR  FullPathName[MAXIMUM_FILENAME_LENGTH];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

EXTERN_C NTSYSAPI
NTSTATUS NTAPI ZwQuerySystemInformation(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
);

EXTERN_C NTSYSAPI
PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(
	PVOID   ModuleAddress
);

typedef INT64 (__fastcall *MiLookupDataTableEntryType)(UINT64 a1, int a2);

typedef struct SectionStruct {
	uintptr_t sectionBaseAddr;
	ULONG sectionSize;
} Section;

PVOID g_RegistrationHandle = NULL;

ULONG Print(
	_In_z_ _Printf_format_string_ PCSTR Format,
	...
) {
	char newFormat[2000];
	int formattedResult = sprintf(newFormat, "[IntegritySpoofer] %s", Format);
	if (formattedResult > 0) {
		va_list args;
		va_start(args, Format);
		ULONG result = vDbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, newFormat, args);
		va_end(args);
		return result;
	}
	return 0;
}

OB_PREOP_CALLBACK_STATUS PreOperationCallback(
	PVOID RegistrationContext,
	POB_PRE_OPERATION_INFORMATION OperationInformation
) {
	UNREFERENCED_PARAMETER(RegistrationContext);
	UNREFERENCED_PARAMETER(OperationInformation);

	//if (OperationInformation->ObjectType == *PsProcessType) {
	//    // Example: Deny handle duplication for processes
	//    if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
	//        OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0;
	//    }
	//}

	Print("PreCallback called");
	return OB_PREOP_SUCCESS;
}

uintptr_t GetModuleBaseAddress(PCCHAR moduleName) {
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
			if (strstr((PCHAR)module[i].FullPathName, moduleName) != NULL)
			{
				result = (uintptr_t)module[i].ImageBase;
				break;
			}
		}
	}
	else {
		result = NULL;
	}

	ExFreePoolWithTag(modules, 'pool');
	return result;
}

int ByteCompare(unsigned char* byteArr1, unsigned char* byteArr2, int size) {
	for (int i = 0; i < size; i++) {
		if (byteArr1[i] != byteArr2[i]) {
			return 0;
		}
	}
	return 1;
}

uintptr_t FindCodeSignature(uintptr_t baseAddr, int range, unsigned char* codeSignature, int sigSize) {
	for (int i = 0; i < baseAddr + range; i++) {
		uintptr_t currAddr = baseAddr + i;
		unsigned char buffer[1000];
		memcpy(buffer, (char*)currAddr, sigSize);
		if (ByteCompare(buffer, codeSignature, sigSize)) {
			return currAddr;
		}
	}
	return NULL;
}

void GetSection(PVOID baseAddress, PCCHAR sectionName, Section* sectionInfo)
{
	PIMAGE_NT_HEADERS64 header = RtlImageNtHeader(baseAddress);

	ANSI_STRING ansiSectionName, ansiCurrentSectionName;
	RtlInitAnsiString(&ansiSectionName, sectionName);

	PIMAGE_SECTION_HEADER firstSection = (PIMAGE_SECTION_HEADER)((uintptr_t)&header->FileHeader + header->FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_FILE_HEADER));

	for (PIMAGE_SECTION_HEADER section(firstSection); section < firstSection + header->FileHeader.NumberOfSections; section++)
	{
		RtlInitAnsiString(&ansiCurrentSectionName, (PCCHAR)section->Name);
		if (!RtlCompareString(&ansiSectionName, &ansiCurrentSectionName, FALSE))
		{
			sectionInfo->sectionBaseAddr = (uintptr_t)baseAddress + section->VirtualAddress;
			sectionInfo->sectionSize = section->Misc.VirtualSize;
			return;
		}
	}
}

NTSTATUS DriverEntry() {
	Print("driver loaded");

	uintptr_t baseAddr = GetModuleBaseAddress("ntoskrnl");
	Print("ntoskrnl base address: %llX", baseAddr);

	uintptr_t validImageBaseAddr = GetModuleBaseAddress("tcpip.sys");
	Print("tcpip.sys base address: %llx", validImageBaseAddr);

	Section section;
	GetSection((PVOID)validImageBaseAddr, ".text", &section);
	Print(".text addr: %llx, .text size: %ul", section.sectionBaseAddr, section.sectionSize);

	unsigned char jmpRcxSignature[] = { 0xFF, 0xE1 };
	uintptr_t jmpRcxAddr = FindCodeSignature(section.sectionBaseAddr, section.sectionSize, jmpRcxSignature, sizeof(jmpRcxSignature));
	Print("JMP RAX location: %llx", jmpRcxAddr);
	Print("PreCallback location: %p", PreOperationCallback);

	UNICODE_STRING altitude = { 0 };
	RtlInitUnicodeString(&altitude, L"1235.67891");
	OB_CALLBACK_REGISTRATION CallbackRegistration = { 0 };
	OB_OPERATION_REGISTRATION OperationRegistration = { 0 };

	OperationRegistration.ObjectType = PsProcessType;
	OperationRegistration.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	OperationRegistration.PreOperation = (POB_PRE_OPERATION_CALLBACK)jmpRcxAddr;

	CallbackRegistration.Version = OB_FLT_REGISTRATION_VERSION;
	CallbackRegistration.OperationRegistrationCount = 1;
	CallbackRegistration.Altitude = altitude;
	CallbackRegistration.RegistrationContext = &PreOperationCallback;
	CallbackRegistration.OperationRegistration = &OperationRegistration;

	NTSTATUS result = ObRegisterCallbacks(&CallbackRegistration, &g_RegistrationHandle);
	switch (result) {
	case STATUS_SUCCESS:
		Print("obregistercallback STATUS_SUCCESS");
		break;
	case STATUS_FLT_INSTANCE_ALTITUDE_COLLISION:
		Print("obregistercallback STATUS_FLT_INSTANCE_ALTITUDE_COLLISION");
		break;
	case STATUS_INVALID_PARAMETER:
		Print("obregistercallback STATUS_INVALID_PARAMETER");
		break;
	case STATUS_ACCESS_DENIED:
		Print("obregistercallback STATUS_ACCESS_DENIED");
		break;
	case STATUS_INSUFFICIENT_RESOURCES:
		Print("obregistercallback STATUS_INSUFFICIENT_RESOURCES");
		break;
	}

	return STATUS_SUCCESS;
}