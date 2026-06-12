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

struct ProcessRecord {
    std::wstring processName;
    SYSTEM_PROCESS_INFORMATION procInfo;
    ProcessHistoricalSnapshot history;
    std::chrono::steady_clock::time_point lastUpdate;
    unsigned int visitCount = 0;


    struct Sample {
        std::chrono::steady_clock::time_point time;
        ULONGLONG kernelTime;
        ULONGLONG userTime;
    };

    std::vector<Sample> historyBuffer; // Буфер на 2700 записей
    size_t historyIndex = 0;           // Текущая позиция записи
    bool isBufferFull = false;         // Заполнился ли буфер хотя бы раз

    ProcessRecord() {
        historyBuffer.resize(2700); // Резервируем память сразу при создании
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

            // 1. Если процесса нет — создаем (ProcessRecord инициализирует буфер в конструкторе)
            auto& record = m_processDatabase[key];
            if (record.processName.empty()) { // Простая проверка на новую запись
                if (pid == 0) record.processName = L"System Idle Process";
                else if (pData->ImageName.Buffer)
                    record.processName = std::wstring(pData->ImageName.Buffer, pData->ImageName.Length / sizeof(wchar_t));
                else record.processName = L"Unknown";
            }

            // 2. Добавляем текущие данные в циклический буфер
            // Теперь мы просто пишем в ячейку по индексу и двигаем его
            auto& sample = record.historyBuffer[record.historyIndex];
            sample.time = currentTimePoint;
            sample.kernelTime = pData->KernelTime.QuadPart;
            sample.userTime = pData->UserTime.QuadPart;

            record.historyIndex = (record.historyIndex + 1) % record.historyBuffer.size();
            if (record.historyIndex == 0) record.isBufferFull = true;

            // 3. Обновляем текущие данные
            record.procInfo = *pData;
            record.lastUpdate = currentTimePoint;
            record.visitCount++;

            // Обновляем индекс актуальности
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


    void DisplayTopProcesses(int topCount) {
        std::lock_guard<std::mutex> lock(m_mutex);

        struct ProcessDisplay {
            DWORD pid;
            std::wstring name;
            double cpuUsage;
            unsigned int visitCount;
        };

        std::vector<ProcessDisplay> list;
        auto now = std::chrono::steady_clock::now();

        unsigned long long totalGlobalRecords = 0;
        size_t totalMemoryUsage = 0;

        // Используем классический цикл, чтобы избежать ошибок с C++17
        for (auto it = m_processDatabase.begin(); it != m_processDatabase.end(); ++it) {
            const auto& key = it->first;
            const auto& record = it->second;

            totalGlobalRecords += record.visitCount;
            totalMemoryUsage += sizeof(key) + sizeof(record) +
                (record.processName.capacity() * sizeof(wchar_t)) +
                (record.historyBuffer.capacity() * sizeof(ProcessRecord::Sample));

            double cpu = 0.0;

            // Расчет CPU через кольцевой буфер
            size_t oldestIndex = record.isBufferFull ? record.historyIndex : 0;
            const auto& oldSample = record.historyBuffer[oldestIndex];

            // Используем duration_cast правильно
            auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(now - oldSample.time).count();
            double duration100ns = static_cast<double>(duration) / 100.0;

            if (duration100ns > 0) {
                ULONGLONG deltaK = record.procInfo.KernelTime.QuadPart - oldSample.kernelTime;
                ULONGLONG deltaU = record.procInfo.UserTime.QuadPart - oldSample.userTime;
                double rawUsage = ((static_cast<double>(deltaK) + static_cast<double>(deltaU)) / duration100ns) * 100.0;
                cpu = rawUsage / static_cast<double>(m_sysInfo.dwNumberOfProcessors);
            }

            // Явно приводим типы в конструктор, чтобы не было "narrowing conversion"
            list.push_back({ (DWORD)key.pid, record.processName, cpu, (unsigned int)record.visitCount });
        }

        // 2. Сортируем
        std::sort(list.begin(), list.end(), [](const ProcessDisplay& a, const ProcessDisplay& b) {
            return a.cpuUsage > b.cpuUsage;
            });

        // 3. Вывод
        std::wcout << L"\n--- ТОП-" << topCount << L" ПРОЦЕССОВ ---\n";
        std::wcout << L"Всего уникальных: " << m_processDatabase.size()
            << L" | Всего записей: " << totalGlobalRecords
            << L" | Память БД: ~" << (totalMemoryUsage / 1024) << L" KB" << std::endl;

        std::wcout << std::left << std::setw(8) << L"PID"
            << std::setw(25) << L"Name"
            << std::setw(10) << L"CPU%"
            << std::setw(10) << L"Records" << std::endl;

        std::wcout << std::wstring(55, L'-') << std::endl;

        size_t count = std::min(list.size(), (size_t)topCount);
        for (size_t i = 0; i < count; ++i) {
            std::wcout << std::left << std::setw(8) << list[i].pid
                << std::setw(25) << list[i].name.substr(0, 24)
                << std::setw(10) << std::fixed << std::setprecision(2) << list[i].cpuUsage
                << std::setw(10) << list[i].visitCount << std::endl;
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
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    return 0;
}