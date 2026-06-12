#pragma once
#ifndef METRIC_STRUCTURES_H
#define METRIC_STRUCTURES_H

#define NOMINMAX
#include <windows.h>
#include <iostream>

// --- Native API Definitions ---
#define STATUS_SUCCESS ((NTSTATUS)0x00000000)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004)

// Защита от дублирования определений
#ifndef _SYSTEM_INFORMATION_CLASS_DEFINED
#define _SYSTEM_INFORMATION_CLASS_DEFINED
typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemProcessInformation = 5
} SYSTEM_INFORMATION_CLASS;
#endif

#ifndef _UNICODE_STRING_DEFINED
#define _UNICODE_STRING_DEFINED
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING;
#endif

#ifndef _CLIENT_ID_DEFINED
#define _CLIENT_ID_DEFINED
typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID;
#endif

#ifndef _SYSTEM_THREAD_INFORMATION_DEFINED
#define _SYSTEM_THREAD_INFORMATION_DEFINED
typedef struct _SYSTEM_THREAD_INFORMATION {
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    CLIENT_ID ClientId;
    LONG Priority;
    LONG BasePriority;
    ULONG ContextSwitches;
    ULONG ThreadState;
    ULONG ThreadWaitReason;
} SYSTEM_THREAD_INFORMATION, * PSYSTEM_THREAD_INFORMATION;
#endif

#pragma pack(push, 8)
#ifndef _VM_COUNTERS_EX_DEFINED
#define _VM_COUNTERS_EX_DEFINED
typedef struct _VM_COUNTERS_EX {
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG  PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivateUsage;
} VM_COUNTERS_EX;
#endif

#ifndef _SYSTEM_PROCESS_INFORMATION_DEFINED
#define _SYSTEM_PROCESS_INFORMATION_DEFINED
typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    LONG BasePriority;
    ULONG Reserved1;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey;
    VM_COUNTERS_EX VirtualMemoryCounters;
    SIZE_T PrivatePageCount;
    IO_COUNTERS IoCounters;
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;
#endif
#pragma pack(pop)

typedef NTSTATUS(WINAPI* pfnNtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

#endif // METRIC_STRUCTURES_H