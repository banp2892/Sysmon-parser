#pragma once
#define NOMINMAX
#include <windows.h>
#include "MetricStructures.h"
#include <iostream>
#include <vector>
#include <unordered_map>
#include <string>
#include <chrono>
#include <thread>
#include <iomanip>
#include <mutex>
#include <functional>
#include <algorithm> 



#include <cstddef> // Для offsetof
#include <optional>
#include <shared_mutex>

#include <sstream>
//#include <winternl.h>

// --- Native API Definitions ---
#define STATUS_SUCCESS ((NTSTATUS)0x00000000)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004)

/**
 * @brief Включает поддержку ANSI-последовательностей в консоли Windows.
 */
void EnableAnsiSupport() {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut == INVALID_HANDLE_VALUE) return;
    DWORD dwMode = 0;
    GetConsoleMode(hOut, &dwMode);
    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(hOut, dwMode);
}

/**
 * @brief Форматирует байты в строку (MB или GB).
 * @param bytes Размер в байтах.
 * @return Отформатированная строка.
 */
std::wstring FormatMemory(SIZE_T bytes) {
    SIZE_T mb = bytes / 1024 / 1024;
    if (mb > 1024) {
        std::wstringstream ss;
        ss << std::fixed << std::setprecision(1) << (double)mb / 1024.0 << L" GB";
        return ss.str();
    }
    return std::to_wstring(mb) + L" MB";
}










/**
 * @brief Тип функции для вызова NtQuerySystemInformation.
 */
typedef NTSTATUS(WINAPI* pfnNtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

/**
 * @brief Хранит предыдущие значения для расчета дельты метрик.
 */
struct ProcessHistoricalSnapshot {
    ULONGLONG lastKernelTime = 0;
    ULONGLONG lastUserTime = 0;
    ULONGLONG lastReadBytes = 0;
    ULONGLONG lastWriteBytes = 0;
    ULONGLONG lastOtherBytes = 0;
    std::chrono::system_clock::time_point lastSampleTime;
};

/**
 * @brief Уникальный идентификатор процесса на основе PID и времени создания.
 */
struct ProcessKey {
    DWORD pid;
    LARGE_INTEGER createTime;

    bool operator==(const ProcessKey& other) const {
        return pid == other.pid && createTime.QuadPart == other.createTime.QuadPart;
    }
};

/**
 * @brief Хешер для ключа процесса.
 */
struct ProcessKeyHasher {
    std::size_t operator()(const ProcessKey& k) const {
        return std::hash<DWORD>{}(k.pid) ^ (std::hash<long long>{}(k.createTime.QuadPart) << 1);
    }
};

/**
 * @brief Содержит телеметрию процесса на момент измерения.
 */
struct ProcessTelemetry {
    std::chrono::system_clock::time_point time;
    ULONGLONG kernelTime;
    ULONGLONG userTime;
    DWORD ppid;
    DWORD threadCount;
    DWORD handleCount;
    SIZE_T privatePageCount;
    SIZE_T virtualSize;
    SIZE_T workingSetSize;
    ULONG pageFaultCount;
    SIZE_T pagedPoolUsage;
    SIZE_T nonPagedPoolUsage;
    ULONG sessionId;
    ULONG contextSwitches;
    double cpuUsage;
};

/**
 * @brief Хранит исторические данные и телеметрию процесса.
 */
struct ProcessRecord {
    std::wstring processName;
    std::chrono::system_clock::time_point lastUpdate;
    unsigned int visitCount = 0;

    std::vector<ProcessTelemetry> historyBuffer;
    size_t historyIndex = 0;
    bool isBufferFull = false;

    /**
     * @brief Инициализирует запись с заданным размером буфера.
     * @param bufferSize Максимальное количество хранимых снимков.
     */
    ProcessRecord(size_t bufferSize = 600) {
        historyBuffer.resize(bufferSize);
    }

    /**
     * @brief Ищет последний снимок, сделанный не позднее целевого времени.
     * @param targetTime Целевое время поиска.
     * @return Указатель на найденный снимок или nullptr.
     */
    ProcessTelemetry* FindSnapshotAtTime(std::chrono::system_clock::time_point targetTime) {
        size_t size = historyBuffer.size();
        size_t scanIndex = historyIndex;
        for (size_t i = 0; i < size; ++i) {
            scanIndex = (scanIndex + size - 1) % size;
            if (historyBuffer[scanIndex].time <= targetTime) {
                return &historyBuffer[scanIndex];
            }
            if (!isBufferFull && scanIndex == 0) break;
        }
        return nullptr;
    }

    /**
     * @brief Ищет ближайший по времени снимок относительно заданного момента.
     * @param targetTime Целевое время поиска.
     * @return Указатель на ближайший снимок или nullptr.
     */
    ProcessTelemetry* FindClosestSnapshot(std::chrono::system_clock::time_point targetTime) {
        size_t size = historyBuffer.size();
        if (size == 0) return nullptr;

        ProcessTelemetry* bestBefore = nullptr;
        ProcessTelemetry* bestAfter = nullptr;

        size_t limit = isBufferFull ? size : historyIndex;

        for (size_t i = 0; i < limit; ++i) {
            auto& entry = historyBuffer[i];

            if (entry.time <= targetTime) {
                if (!bestBefore || entry.time > bestBefore->time) {
                    bestBefore = &entry;
                }
            }
            else {
                if (!bestAfter || entry.time < bestAfter->time) {
                    bestAfter = &entry;
                }
            }
        }

        if (!bestBefore && !bestAfter) return nullptr;
        if (!bestBefore) return bestAfter;
        if (!bestAfter) return bestBefore;

        auto diffBefore = targetTime - bestBefore->time;
        auto diffAfter = bestAfter->time - targetTime;

        return (diffBefore <= diffAfter) ? bestBefore : bestAfter;
    }
};
/**
 * @brief Главный класс для мониторинга телеметрии системных процессов.
 */
class SystemPerformanceTelemetryMonitor {
private:
    mutable std::shared_mutex m_mutex;
    pfnNtQuerySystemInformation m_pfnNtQuerySystemInformation = nullptr;
    std::vector<BYTE> m_telemetryBuffer;
    SYSTEM_INFO m_sysInfo;

    std::unordered_map<ProcessKey, ProcessRecord, ProcessKeyHasher> m_processDatabase;
    std::unordered_map<DWORD, LARGE_INTEGER> m_activePidMap;

    /**
     * @brief Ищет адрес функции NtQuerySystemInformation в ntdll.dll.
     */
    void LocateNativeEntryPoints() {
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (hNtdll) {
            m_pfnNtQuerySystemInformation = reinterpret_cast<pfnNtQuerySystemInformation>(
                GetProcAddress(hNtdll, "NtQuerySystemInformation"));
        }
    }

public:
    /**
     * @brief Инициализирует монитор, подготавливает буферы и кэш.
     */
    SystemPerformanceTelemetryMonitor() {
        LocateNativeEntryPoints();
        GetSystemInfo(&m_sysInfo);
        m_telemetryBuffer.resize(1024 * 1024 * 2);
        m_processDatabase.reserve(500);
    }

    /**
     * @brief Получает копию записи телеметрии для указанного процесса.
     * @param pid Идентификатор процесса.
     * @param createTime Время создания процесса.
     * @return std::optional с данными записи или std::nullopt, если процесс не найден.
     */
    std::optional<ProcessRecord> GetRecord(DWORD pid, LARGE_INTEGER createTime) const {
        std::shared_lock<std::shared_mutex> lock(m_mutex);

        ProcessKey key{ pid, createTime };
        auto it = m_processDatabase.find(key);

        if (it != m_processDatabase.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    /**
     * @brief Выполняет запрос к системному API и обновляет локальную базу данных.
     */
    void ExecuteQueryAndProcess() {
        if (!m_pfnNtQuerySystemInformation) return;

        ULONG requiredSize = 0;

        NTSTATUS status = m_pfnNtQuerySystemInformation(
            SystemProcessInformation,
            m_telemetryBuffer.data(),
            static_cast<ULONG>(m_telemetryBuffer.size()),
            &requiredSize
        );

        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            m_telemetryBuffer.resize(requiredSize + 1024 * 1024);

            status = m_pfnNtQuerySystemInformation(
                SystemProcessInformation,
                m_telemetryBuffer.data(),
                static_cast<ULONG>(m_telemetryBuffer.size()),
                &requiredSize
            );
        }

        if (status == STATUS_SUCCESS) {
            ParseBuffer();
            PruneDatabase();
        }
    }

    /**
     * @brief Получает запись процесса по PID и времени создания.
     * @param pid Идентификатор процесса.
     * @param createTime Время создания процесса (LARGE_INTEGER).
     * @return Указатель на запись или nullptr, если не найдено.
     */
    ProcessRecord* GetRecord(DWORD pid, LARGE_INTEGER createTime) {
        std::shared_lock<std::shared_mutex> lock(m_mutex);

        ProcessKey key{ pid, createTime };
        auto it = m_processDatabase.find(key);

        if (it != m_processDatabase.end()) {
            return &it->second;
        }
        return nullptr;
    }

    /**
     * @brief Получает запись наиболее актуального процесса по его PID.
     * @param pid Идентификатор процесса.
     * @return Указатель на запись или nullptr.
     */
    ProcessRecord* GetRecord(DWORD pid) {
        std::shared_lock<std::shared_mutex> lock(m_mutex);

        auto activeIt = m_activePidMap.find(pid);
        if (activeIt == m_activePidMap.end()) {
            return nullptr;
        }

        ProcessKey key{ pid, activeIt->second };
        auto dbIt = m_processDatabase.find(key);

        if (dbIt != m_processDatabase.end()) {
            return &dbIt->second;
        }
        return nullptr;
    }

    /**
     * @brief Разбирает буфер данных из NtQuerySystemInformation и обновляет телеметрию.
     */
    void ParseBuffer() {
        std::shared_lock<std::shared_mutex> lock(m_mutex);
        auto currentTimePoint = std::chrono::system_clock::now();
        BYTE* pCurrentPosition = m_telemetryBuffer.data();

        while (pCurrentPosition) {
            auto* pData = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(pCurrentPosition);
            DWORD pid = static_cast<DWORD>(reinterpret_cast<uintptr_t>(pData->UniqueProcessId));

            ProcessKey key{ pid, pData->CreateTime };
            auto& record = m_processDatabase[key];

            if (record.processName.empty()) {
                if (pid == 0) record.processName = L"System Idle Process";
                else if (pData->ImageName.Buffer)
                    record.processName = std::wstring(pData->ImageName.Buffer, pData->ImageName.Length / sizeof(wchar_t));
                else record.processName = L"Unknown";
            }

            PSYSTEM_THREAD_INFORMATION pThreads = reinterpret_cast<PSYSTEM_THREAD_INFORMATION>(
                reinterpret_cast<BYTE*>(pData) + 0x100
                );

            ULONG totalContextSwitches = 0;
            for (ULONG i = 0; i < pData->NumberOfThreads; i++) {
                totalContextSwitches += pThreads[i].ContextSwitches;
            }

            auto& entry = record.historyBuffer[record.historyIndex];

            entry.time = currentTimePoint;
            entry.kernelTime = pData->KernelTime.QuadPart;
            entry.userTime = pData->UserTime.QuadPart;
            entry.ppid = (DWORD)(uintptr_t)pData->InheritedFromUniqueProcessId;
            entry.threadCount = pData->NumberOfThreads;
            entry.handleCount = pData->HandleCount;
            entry.privatePageCount = pData->PrivatePageCount;
            entry.virtualSize = pData->VirtualMemoryCounters.VirtualSize;
            entry.workingSetSize = pData->VirtualMemoryCounters.WorkingSetSize;
            entry.pageFaultCount = (ULONG)pData->VirtualMemoryCounters.PageFaultCount;
            entry.pagedPoolUsage = pData->VirtualMemoryCounters.QuotaPagedPoolUsage;
            entry.nonPagedPoolUsage = pData->VirtualMemoryCounters.QuotaNonPagedPoolUsage;
            entry.sessionId = pData->SessionId;
            entry.contextSwitches = totalContextSwitches;

            entry.cpuUsage = CalculateCpuUsage(record, 10);

            record.historyIndex = (record.historyIndex + 1) % record.historyBuffer.size();
            if (record.historyIndex == 0) record.isBufferFull = true;

            record.lastUpdate = currentTimePoint;
            record.visitCount++;

            m_activePidMap[pid] = pData->CreateTime;

            if (pData->NextEntryOffset == 0) break;
            pCurrentPosition += pData->NextEntryOffset;
        }
    }

    /**
     * @brief Удаляет из базы записи процессов, не обновлявшиеся более 10 секунд.
     */
    void PruneDatabase() {
        std::shared_lock<std::shared_mutex> lock(m_mutex);
        auto now = std::chrono::system_clock::now();
        for (auto it = m_processDatabase.begin(); it != m_processDatabase.end(); ) {
            if (now - it->second.lastUpdate > std::chrono::seconds(10)) {
                auto activeIt = m_activePidMap.find(it->first.pid);
                if (activeIt != m_activePidMap.end() && activeIt->second.QuadPart == it->first.createTime.QuadPart) {
                    m_activePidMap.erase(activeIt);
                }
                it = m_processDatabase.erase(it);
            }
            else {
                ++it;
            }
        }
    }

    /**
     * @brief Получает запись активного процесса по его PID.
     * @param pid Идентификатор процесса.
     * @param outRecord Ссылка для записи результата.
     * @return true если запись найдена, false в противном случае.
     */
    bool GetActiveRecordByPid(DWORD pid, ProcessRecord& outRecord) const {
        std::shared_lock<std::shared_mutex> lock(m_mutex);
        auto it = m_activePidMap.find(pid);
        if (it == m_activePidMap.end()) return false;

        ProcessKey key{ pid, it->second };
        auto dbIt = m_processDatabase.find(key);
        if (dbIt != m_processDatabase.end()) {
            outRecord = dbIt->second;
            return true;
        }
        return false;
    }

    /**
     * @brief Вычисляет процент использования CPU процессом на основе истории.
     * @param record Запись процесса.
     * @param lookbackFrames Количество кадров для усреднения.
     * @return Процент использования CPU (от 0.0 до 100.0 * количество ядер).
     */
    double CalculateCpuUsage(const ProcessRecord& record, int lookbackFrames) const {
        if (record.historyBuffer.empty()) return 0.0;

        size_t size = record.historyBuffer.size();
        size_t latestIdx = (record.historyIndex + size - 1) % size;
        const auto& latestSample = record.historyBuffer[latestIdx];

        size_t availableSamples = record.isBufferFull ? size : record.historyIndex;
        int actualLookback = (std::min)((int)availableSamples - 1, lookbackFrames);

        if (actualLookback <= 0) return 0.0;

        size_t oldIdx = (latestIdx + size - actualLookback) % size;
        const auto& oldSample = record.historyBuffer[oldIdx];

        auto durationNs = std::chrono::duration_cast<std::chrono::nanoseconds>(latestSample.time - oldSample.time).count();
        double duration100ns = static_cast<double>(durationNs) / 100.0;

        if (duration100ns <= 0) return 0.0;

        ULONGLONG deltaK = latestSample.kernelTime - oldSample.kernelTime;
        ULONGLONG deltaU = latestSample.userTime - oldSample.userTime;

        if ((long long)deltaK < 0 || (long long)deltaU < 0) return 0.0;

        double rawUsage = ((static_cast<double>(deltaK) + static_cast<double>(deltaU)) / duration100ns) * 100.0;
        return rawUsage / static_cast<double>(m_sysInfo.dwNumberOfProcessors);
    }


    /**
     * @brief Отображает топ процессов по потреблению CPU в консоль.
     * @param topCount Количество отображаемых процессов.
     */
    void DisplayTopProcesses(int topCount) {
        std::shared_lock<std::shared_mutex> lock(m_mutex);

        struct ProcessDisplay {
            DWORD pid;
            std::wstring name;
            double cpuUsage;
            DWORD ppid;
            ULONG sessionId;
            DWORD threadCount;
            DWORD handleCount;
            SIZE_T privateMB;
            SIZE_T virtualMB;
            SIZE_T workingSetMB;
            ULONG pageFaultCount;
            SIZE_T pagedPool;
            SIZE_T nonPagedPool;
            ULONG contextSwitches;
        };

        std::vector<ProcessDisplay> list;
        size_t totalHistorySnapshots = 0;

        for (auto it = m_processDatabase.begin(); it != m_processDatabase.end(); ++it) {
            const auto& key = it->first;
            const auto& record = it->second;

            size_t latestIdx = (record.historyIndex + record.historyBuffer.size() - 1) % record.historyBuffer.size();
            const auto& latest = record.historyBuffer[latestIdx];

            list.push_back({
                (DWORD)key.pid,
                record.processName,
                latest.cpuUsage,
                latest.ppid,
                latest.sessionId,
                latest.threadCount,
                latest.handleCount,
                latest.privatePageCount,
                latest.virtualSize,
                latest.workingSetSize,
                (ULONG)latest.pageFaultCount,
                latest.pagedPoolUsage,
                latest.nonPagedPoolUsage,
                latest.contextSwitches
                });

            totalHistorySnapshots += record.historyBuffer.size();
        }

        std::sort(list.begin(), list.end(), [](const ProcessDisplay& a, const ProcessDisplay& b) {
            return a.cpuUsage > b.cpuUsage;
            });

        std::wcout << L"\n========================================================" << std::endl;
        std::wcout << L"DATABASE STATS:" << std::endl;
        std::wcout << L"Total Processes tracked: " << m_processDatabase.size() << std::endl;
        std::wcout << L"Total history snapshots: " << totalHistorySnapshots << std::endl;
        std::wcout << L"Approx. memory footprint: " << FormatMemory(totalHistorySnapshots * sizeof(ProcessTelemetry)) << std::endl;
        std::wcout << L"========================================================\n" << std::endl;

        std::wcout << L"--- ТОП-" << topCount << L" ПРОЦЕССОВ (Расширенная телеметрия) ---\n";

        std::wcout << std::left
            << std::setw(7) << L"PID"
            << std::setw(16) << L"Name"
            << std::setw(7) << L"CPU%"
            << std::setw(5) << L"Thr"
            << std::setw(6) << L"Hnd"
            << std::setw(10) << L"Priv"
            << std::setw(10) << L"WS"
            << std::setw(10) << L"Paged"
            << std::setw(10) << L"NPaged"
            << std::setw(9) << L"CtxSw"
            << L"Faults" << std::endl;

        std::wcout << std::wstring(105, L'-') << std::endl;

        size_t count = (std::min)(list.size(), (size_t)topCount);
        for (size_t i = 0; i < count; ++i) {
            std::wcout << std::left
                << std::setw(7) << list[i].pid
                << std::setw(16) << list[i].name.substr(0, 15)
                << std::fixed << std::setprecision(1) << std::setw(7) << list[i].cpuUsage
                << std::defaultfloat << std::setprecision(0)
                << std::setw(5) << list[i].threadCount
                << std::setw(6) << list[i].handleCount
                << std::setw(10) << FormatMemory(list[i].privateMB)
                << std::setw(10) << FormatMemory(list[i].workingSetMB)
                << std::setw(10) << FormatMemory(list[i].pagedPool)
                << std::setw(10) << FormatMemory(list[i].nonPagedPool)
                << std::setw(9) << list[i].contextSwitches
                << list[i].pageFaultCount
                << L"\033[K"
                << std::endl;
        }
    }

};