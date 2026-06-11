#include <windows.h>
#include <iostream>
#include <vector>
#include <unordered_map>
#include <string>
#include <chrono>
#include <thread>
#include <iomanip>

#define STATUS_SUCCESS ((NTSTATUS)0x00000000)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004)

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemProcessInformation = 5
} SYSTEM_INFORMATION_CLASS;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID;

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

typedef struct _VM_COUNTERS_EX {
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
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

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG ThreadCount;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    LONG BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey;
    VM_COUNTERS_EX VirtualMemoryCounters;
    SIZE_T PrivatePageCount;
    IO_COUNTERS IoCounters;
    SYSTEM_THREAD_INFORMATION ThreadInfos;
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

typedef NTSTATUS(WINAPI* pfnNtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

struct ProcessHistoricalSnapshot {
    ULONGLONG lastKernelTime = 0;
    ULONGLONG lastUserTime = 0;
    ULONGLONG lastReadBytes = 0;
    ULONGLONG lastWriteBytes = 0;
    ULONGLONG lastOtherBytes = 0;
    std::chrono::steady_clock::time_point lastSampleTime;
};

class SystemPerformanceTelemetryMonitor {
private:
    pfnNtQuerySystemInformation m_pfnNtQuerySystemInformation = nullptr;
    std::vector<BYTE> m_telemetryBuffer;
    std::unordered_map<DWORD, ProcessHistoricalSnapshot> m_historicalDb;
    DWORD m_logicalProcessorCount = 1;

    void LocateNativeEntryPoints() {
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (hNtdll) {
            m_pfnNtQuerySystemInformation = reinterpret_cast<pfnNtQuerySystemInformation>(
                GetProcAddress(hNtdll, "NtQuerySystemInformation")
                );
        }
    }

    void RetrieveProcessorTopology() {
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        m_logicalProcessorCount = sysInfo.dwNumberOfProcessors;
    }

public:
    SystemPerformanceTelemetryMonitor() {
        LocateNativeEntryPoints();
        RetrieveProcessorTopology();
        // Первоначальное упреждающее резервирование буфера для снижения аллокаций
        m_telemetryBuffer.resize(1024 * 1024);
    }

    void ExecuteQueryAndProcess() {

        if (!m_pfnNtQuerySystemInformation) return;

        ULONG requiredSize = 0;
        NTSTATUS status;

        // Итеративный запуск опроса системных структур с защитой от нулевого размера в WoW64
        while (true) {
            system("cls");
            status = m_pfnNtQuerySystemInformation(
                SystemProcessInformation,
                m_telemetryBuffer.data(),
                static_cast<ULONG>(m_telemetryBuffer.size()),
                &requiredSize
            );

            if (status == STATUS_INFO_LENGTH_MISMATCH) {
                // Если система вернула неверный размер (или 0 в WoW64), увеличиваем буфер адаптивно
                ULONG targetSize = (requiredSize > 0) ? (requiredSize + 65536) : static_cast<ULONG>(m_telemetryBuffer.size() * 1.5);
                m_telemetryBuffer.resize(targetSize);
            }
            else {
                break;
            }
        }

        if (status != STATUS_SUCCESS) return;

        auto currentTimePoint = std::chrono::steady_clock::now();
        BYTE* pCurrentPosition = m_telemetryBuffer.data();

        while (pCurrentPosition) {
            auto* pProcessData = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(pCurrentPosition);
            DWORD pid = static_cast<DWORD>(reinterpret_cast<uintptr_t>(pProcessData->UniqueProcessId));

            // Корректная обработка имени Idle-процесса
            std::wstring processName = L"System Idle Process";
            if (pid != 0) {
                if (pProcessData->ImageName.Buffer != nullptr && pProcessData->ImageName.Length > 0) {
                    processName = std::wstring(pProcessData->ImageName.Buffer, pProcessData->ImageName.Length / sizeof(wchar_t));
                }
                else {
                    processName = L"System/Unknown";
                }
            }

            ULONGLONG currentKernel = pProcessData->KernelTime.QuadPart;
            ULONGLONG currentUser = pProcessData->UserTime.QuadPart;
            ULONGLONG currentRead = pProcessData->IoCounters.ReadTransferCount;
            ULONGLONG currentWrite = pProcessData->IoCounters.WriteTransferCount;
            ULONGLONG currentOther = pProcessData->IoCounters.OtherTransferCount;

            double cpuPercentage = 0.0;
            double readSpeed = 0.0;
            double writeSpeed = 0.0;
            double otherSpeed = 0.0;

            if (m_historicalDb.find(pid) != m_historicalDb.end()) {
                const auto& prevData = m_historicalDb[pid];
                auto elapsedMicroseconds = std::chrono::duration_cast<std::chrono::microseconds>(
                    currentTimePoint - prevData.lastSampleTime
                ).count();
                double elapsedSeconds = elapsedMicroseconds / 1000000.0;

                if (elapsedSeconds > 0.0001) {
                    // Вычисление процессорной нагрузки
                    ULONGLONG deltaKernel = currentKernel - prevData.lastKernelTime;
                    ULONGLONG deltaUser = currentUser - prevData.lastUserTime;
                    ULONGLONG processDeltaTime = deltaKernel + deltaUser;

                    double elapsedSystemTicks = elapsedSeconds * 10000000.0; // Конвертация в 100-наносекундные тики
                    cpuPercentage = (processDeltaTime / (elapsedSystemTicks * m_logicalProcessorCount)) * 100.0;
                    if (cpuPercentage > 100.0) cpuPercentage = 100.0;

                    // Вычисление скоростных характеристик I/O
                    readSpeed = (currentRead - prevData.lastReadBytes) / elapsedSeconds;
                    writeSpeed = (currentWrite - prevData.lastWriteBytes) / elapsedSeconds;
                    otherSpeed = (currentOther - prevData.lastOtherBytes) / elapsedSeconds;
                }
            }

            // Обновление исторического снимка состояния
            m_historicalDb[pid] = {
                currentKernel,
                currentUser,
                currentRead,
                currentWrite,
                currentOther,
                currentTimePoint
            };

            // Демонстрационный вывод процессов, проявляющих активность
            if (cpuPercentage > 1.0 || readSpeed > 500 * 1024 || writeSpeed > 500 * 1024) {
                
                std::wcout << std::left << std::setw(22) << processName
                    << L" PID: " << std::setw(6) << pid
                    << L" CPU: " << std::fixed << std::setprecision(1) << std::setw(5) << cpuPercentage << L"%"
                    << L" WS (RAM): " << std::setw(10) << (pProcessData->VirtualMemoryCounters.WorkingSetSize / 1024) << L" KB"
                    << L" Private: " << std::setw(10) << (pProcessData->PrivatePageCount * 4) << L" KB"
                    << L" Handles: " << std::setw(6) << pProcessData->HandleCount
                    << L" Threads: " << std::setw(4) << pProcessData->ThreadCount
                    << L" R/W/O Speed: "
                    << std::fixed << std::setprecision(1) << (readSpeed / 1024.0 / 1024.0) << L" / "
                    << (writeSpeed / 1024.0 / 1024.0) << L" / "
                    << (otherSpeed / 1024.0 / 1024.0) << L" MB/s"
                    << std::endl;
            }

            if (pProcessData->NextEntryOffset == 0) break;
            pCurrentPosition += pProcessData->NextEntryOffset;
        }
        
    }
};

int main() {
    SystemPerformanceTelemetryMonitor monitor;
    std::cout << "Starting high-speed thread and process telemetry monitor (Update frequency: 50Hz)..." << std::endl;

    while (true) {
        monitor.ExecuteQueryAndProcess();
        // Пауза 20 миллисекунд соответствует частоте опроса 50 Гц
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    return 0;
}