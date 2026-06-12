#define NOMINMAX
#include <windows.h>
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
#include <iomanip>   
#include <vector>

// --- Native API Definitions ---
#define STATUS_SUCCESS ((NTSTATUS)0x00000000)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004)


void EnableAnsiSupport() {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut == INVALID_HANDLE_VALUE) return;
    DWORD dwMode = 0;
    GetConsoleMode(hOut, &dwMode);
    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(hOut, dwMode);
}


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

// --- Data Structures ---

struct ProcessHistoricalSnapshot {
    ULONGLONG lastKernelTime = 0;
    ULONGLONG lastUserTime = 0;
    ULONGLONG lastReadBytes = 0;
    ULONGLONG lastWriteBytes = 0;
    ULONGLONG lastOtherBytes = 0;
    std::chrono::steady_clock::time_point lastSampleTime;
};

struct ProcessSnapshot {
    // Basic Info
    DWORD pid;
    DWORD ppid;

    // Threads & Handles
    DWORD numberOfThreads;
    DWORD handleCount;

    // Session
    ULONG sessionId;

    // Memory Counters
    SIZE_T privatePageCount;
    SIZE_T virtualSize;
    SIZE_T workingSetSize;

    // Page Faults
    ULONG pageFaultCount;

    // Pool Usage
    SIZE_T pagedPoolUsage;
    SIZE_T nonPagedPoolUsage;

    // Computed (из буфера истории)
    double lastCalculatedCpu;
};


struct ProcessKey {
    DWORD pid;
    LARGE_INTEGER createTime;

    bool operator==(const ProcessKey& other) const {
        return pid == other.pid && createTime.QuadPart == other.createTime.QuadPart;
    }
};


struct ProcessKeyHasher {
    std::size_t operator()(const ProcessKey& k) const {
        return std::hash<DWORD>{}(k.pid) ^ (std::hash<long long>{}(k.createTime.QuadPart) << 1);
    }
};

struct ProcessTelemetry {
    std::chrono::steady_clock::time_point time;

    // CPU метрики (для расчета %)
    ULONGLONG kernelTime;
    ULONGLONG userTime;

    // Снепшот состояния (для Enrichment)
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
};


struct ProcessRecord {
    std::wstring processName;
    // ProcInfo тут больше не нужен, мы берем данные из последнего элемента истории
    std::chrono::steady_clock::time_point lastUpdate;
    unsigned int visitCount = 0;

    // Теперь буфер хранит полные снимки
    std::vector<ProcessTelemetry> historyBuffer;
    size_t historyIndex = 0;
    bool isBufferFull = false;

    ProcessRecord(size_t bufferSize = 600) {
        historyBuffer.resize(bufferSize);
    }

    // Метод для поиска "точки во времени"
    ProcessTelemetry* FindSnapshotAtTime(std::chrono::steady_clock::time_point targetTime) {
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
};

// --- Telemetry Monitor ---

class SystemPerformanceTelemetryMonitor {
private:
    mutable std::mutex m_mutex;
    pfnNtQuerySystemInformation m_pfnNtQuerySystemInformation = nullptr;
    std::vector<BYTE> m_telemetryBuffer;
    SYSTEM_INFO m_sysInfo;

    // БД: Ключ - уникальный процесс, Значение - его данные
    std::unordered_map<ProcessKey, ProcessRecord, ProcessKeyHasher> m_processDatabase;

    // Индекс для защиты от PID Reuse: Какой CreateTime сейчас "актуален" для этого PID
    std::unordered_map<DWORD, LARGE_INTEGER> m_activePidMap;

    void LocateNativeEntryPoints() {
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (hNtdll) {
            m_pfnNtQuerySystemInformation = reinterpret_cast<pfnNtQuerySystemInformation>(
                GetProcAddress(hNtdll, "NtQuerySystemInformation"));
        }
    }

public:
    SystemPerformanceTelemetryMonitor() {
        LocateNativeEntryPoints();
        GetSystemInfo(&m_sysInfo);
        m_telemetryBuffer.resize(1024 * 1024 * 2); // 2MB начальный буфер
        m_processDatabase.reserve(500); // Оптимизация аллокации
    }

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
            m_telemetryBuffer.resize(requiredSize + 1024 * 1024); ///< @todo тут возможно надо сделать более умный ресайз, иначе может падать при долгой работе

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



    void ParseBuffer() {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto currentTimePoint = std::chrono::steady_clock::now();
        BYTE* pCurrentPosition = m_telemetryBuffer.data();

        while (pCurrentPosition) {
            auto* pData = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(pCurrentPosition);
            DWORD pid = static_cast<DWORD>(reinterpret_cast<uintptr_t>(pData->UniqueProcessId));

            ProcessKey key{ pid, pData->CreateTime };

            // 1. Получаем запись
            auto& record = m_processDatabase[key];

            // Имя берем только при создании, чтобы не копировать строку постоянно
            if (record.processName.empty()) {
                if (pid == 0) record.processName = L"System Idle Process";
                else if (pData->ImageName.Buffer)
                    record.processName = std::wstring(pData->ImageName.Buffer, pData->ImageName.Length / sizeof(wchar_t));
                else record.processName = L"Unknown";
            }

            // 2. Добавляем данные в циклический буфер (Unfied approach)
            auto& entry = record.historyBuffer[record.historyIndex];

            // Время и CPU
            entry.time = currentTimePoint;
            entry.kernelTime = pData->KernelTime.QuadPart;
            entry.userTime = pData->UserTime.QuadPart;

            // Остальные поля для Enrichment (логи Sysmon)
            entry.ppid = (DWORD)(uintptr_t)pData->InheritedFromProcessId;
            entry.threadCount = pData->ThreadCount;
            entry.handleCount = pData->HandleCount;
            entry.privatePageCount = pData->PrivatePageCount;
            entry.virtualSize = pData->VirtualMemoryCounters.VirtualSize;
            entry.workingSetSize = pData->VirtualMemoryCounters.WorkingSetSize;
            entry.pageFaultCount = pData->VirtualMemoryCounters.PageFaultCount;
            entry.pagedPoolUsage = pData->VirtualMemoryCounters.QuotaPagedPoolUsage;
            entry.nonPagedPoolUsage = pData->VirtualMemoryCounters.QuotaNonPagedPoolUsage;
            entry.sessionId = pData->SessionId;

            // Обновляем индексы
            record.historyIndex = (record.historyIndex + 1) % record.historyBuffer.size();
            if (record.historyIndex == 0) record.isBufferFull = true;

            // 3. Обновляем метаданные
            record.lastUpdate = currentTimePoint;
            record.visitCount++;

            // Обновляем индекс актуальности PID
            m_activePidMap[pid] = pData->CreateTime;

            if (pData->NextEntryOffset == 0) break;
            pCurrentPosition += pData->NextEntryOffset;
        }
    }

    // Удаление "мертвых" процессов (которые не обновлялись 5 секунд)
    void PruneDatabase() {
        auto now = std::chrono::steady_clock::now();
        for (auto it = m_processDatabase.begin(); it != m_processDatabase.end(); ) {
            if (now - it->second.lastUpdate > std::chrono::seconds(10)) {
                // Если запись в базе - это тот же процесс, что и активный в индексе, удаляем из индекса
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

    // Быстрый доступ к активному процессу по PID ($O(1)$)
    bool GetActiveRecordByPid(DWORD pid, ProcessRecord& outRecord) const {
        std::lock_guard<std::mutex> lock(m_mutex);
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

    double CalculateCpuUsage(const ProcessRecord& record, int lookbackFrames) const {
        if (record.historyBuffer.empty()) return 0.0;

        size_t size = record.historyBuffer.size();

        // Индекс самого последнего (свежего) кадра
        size_t latestIdx = (record.historyIndex + size - 1) % size;
        const auto& latestSample = record.historyBuffer[latestIdx];

        // Определяем, сколько реально кадров мы можем "отмотать" назад
        // Нельзя отмотать больше, чем есть записей
        size_t availableSamples = record.isBufferFull ? size : record.historyIndex;
        int actualLookback = std::min((int)availableSamples - 1, lookbackFrames);

        if (actualLookback <= 0) return 0.0;

        // Индекс кадра в прошлом
        size_t oldIdx = (latestIdx + size - actualLookback) % size;
        const auto& oldSample = record.historyBuffer[oldIdx];

        // Расчет времени
        auto durationNs = std::chrono::duration_cast<std::chrono::nanoseconds>(latestSample.time - oldSample.time).count();
        double duration100ns = static_cast<double>(durationNs) / 100.0;

        if (duration100ns <= 0) return 0.0;

        // Расчет CPU
        ULONGLONG deltaK = latestSample.kernelTime - oldSample.kernelTime;
        ULONGLONG deltaU = latestSample.userTime - oldSample.userTime;

        // Защита от отрицательных дельт (если процесс перезапустился или данные "битые")
        if ((long long)deltaK < 0 || (long long)deltaU < 0) return 0.0;

        double rawUsage = ((static_cast<double>(deltaK) + static_cast<double>(deltaU)) / duration100ns) * 100.0;
        return rawUsage / static_cast<double>(m_sysInfo.dwNumberOfProcessors);
    }


    void DisplayTopProcesses(int topCount) {
        std::lock_guard<std::mutex> lock(m_mutex);

        struct ProcessDisplay {
            DWORD pid;
            std::wstring name;
            double cpuUsage;
            unsigned int visitCount;
            // Новые поля для отображения
            SIZE_T workingSetMB;
            ULONG threads;
            ULONG handles;
        };

        std::vector<ProcessDisplay> list;
        unsigned long long totalGlobalRecords = 0;
        size_t totalMemoryUsage = 0;

        for (auto it = m_processDatabase.begin(); it != m_processDatabase.end(); ++it) {
            const auto& key = it->first;
            const auto& record = it->second;

            totalGlobalRecords += record.visitCount;
            totalMemoryUsage += sizeof(key) + sizeof(record) +
                (record.processName.capacity() * sizeof(wchar_t)) +
                (record.historyBuffer.capacity() * sizeof(ProcessTelemetry));

            // 1. Расчет CPU (как и просил)
            double cpu = CalculateCpuUsage(record, 10);

            // 2. Получаем последние метрики из буфера
            size_t latestIdx = (record.historyIndex + record.historyBuffer.size() - 1) % record.historyBuffer.size();
            const auto& latest = record.historyBuffer[latestIdx];

            // 3. Сохраняем в список для вывода
            list.push_back({
                (DWORD)key.pid,
                record.processName,
                cpu,
                (unsigned int)record.visitCount,
                latest.workingSetSize / 1024 / 1024, // RAM в MB
                latest.threadCount,
                latest.handleCount
                });
        }

        // Сортировка
        std::sort(list.begin(), list.end(), [](const ProcessDisplay& a, const ProcessDisplay& b) {
            return a.cpuUsage > b.cpuUsage;
            });

        // --- Вывод ---
        std::wcout << L"\n--- ТОП-" << topCount << L" ПРОЦЕССОВ ---\n";
        std::wcout << L"Всего уникальных: " << m_processDatabase.size()
            << L" | Память БД: ~" << (totalMemoryUsage / 1024) << L" KB" << std::endl;

        // Расширенные заголовки
        std::wcout << std::left << std::setw(8) << L"PID"
            << std::setw(20) << L"Name"
            << std::setw(8) << L"CPU%"
            << std::setw(8) << L"RAM(MB)"
            << std::setw(8) << L"Threads"
            << std::setw(8) << L"Handles" << std::endl;

        std::wcout << std::wstring(60, L'-') << std::endl;

        size_t count = std::min(list.size(), (size_t)topCount);
        for (size_t i = 0; i < count; ++i) {
            std::wcout << std::left << std::setw(8) << list[i].pid
                << std::setw(20) << list[i].name.substr(0, 19)
                << std::setw(8) << std::fixed << std::setprecision(1) << list[i].cpuUsage
                << std::setw(8) << list[i].workingSetMB
                << std::setw(8) << list[i].threads
                << std::setw(8) << list[i].handles << std::endl;
        }
    }

};

int main() {
    // 1. Настройка окружения
    std::setlocale(LC_ALL, ""); // Для корректного вывода русских имен процессов
    EnableAnsiSupport();        // Включаем поддержку ANSI для высокой скорости отрисовки

    SystemPerformanceTelemetryMonitor monitor;

    // Переменные для замера частоты (Hz)
    auto lastTime = std::chrono::steady_clock::now();
    int frameCounter = 0;
    double currentHz = 0.0;

    std::cout << "Monitoring system... Press Ctrl+C to exit." << std::endl;

    while (true) {
        monitor.ExecuteQueryAndProcess();

        // ANSI-код "\033[H" перемещает курсор в верхний левый угол без очистки всего буфера
        std::cout << "\033[H";

       monitor.DisplayTopProcesses(30);

        // --- Блок замера частоты (Hz) ---
        frameCounter++;
        auto now = std::chrono::steady_clock::now();
        std::chrono::duration<double> elapsed = now - lastTime;
        if (elapsed.count() >= 1.0) {
            currentHz = frameCounter / elapsed.count();
            frameCounter = 0;
            lastTime = now;
        }

        std::wcout << L"\n[Performance: " << currentHz << L" Hz]" << std::endl;

        // Минимальная задержка, чтобы не грузить CPU вхолостую
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }

    return 0;
}