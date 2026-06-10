/**
 * @file SystemPerformanceTelemetryMonitor.cpp
 * @brief Монитор телеметрии процессов с полным сохранением состояния в БД.
 * * Данная программа собирает данные через недокументированные API Windows (NtQuerySystemInformation),
 * формирует "снимки" (snapshots) состояния каждого процесса и сохраняет их в
 * структурированную базу данных (std::map), индексированную по уникальному ключу {PID + CreateTime}.
 */

#include <windows.h>
#include <iostream>
#include <vector>
#include <map>
#include <string>
#include <chrono>
#include <thread>
#include <iomanip>

#define STATUS_SUCCESS ((NTSTATUS)0x00000000)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004)

 /**
  * @enum _SYSTEM_INFORMATION_CLASS
  * @brief Классы системной информации. 5 соответствует SystemProcessInformation.
  */
typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemProcessInformation = 5
} SYSTEM_INFORMATION_CLASS;

/**
 * @struct _UNICODE_STRING
 * @brief Структура для представления Unicode-строк в Native API.
 */
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING;

/**
 * @struct _CLIENT_ID
 * @brief Идентификаторы процесса и потока.
 */
typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID;

/**
 * @struct _SYSTEM_THREAD_INFORMATION
 * @brief Статистика потока.
 */
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

/**
 * @struct _VM_COUNTERS_EX
 * @brief Счетчики виртуальной памяти.
 */
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

/**
 * @struct _SYSTEM_PROCESS_INFORMATION
 * @brief Структура с данными процесса (Native API).
 */
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
    SYSTEM_THREAD_INFORMATION ThreadInfos; // Первый элемент в массиве потоков
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

/**
 * @typedef pfnNtQuerySystemInformation
 * @brief Сигнатура функции NtQuerySystemInformation.
 */
typedef NTSTATUS(WINAPI* pfnNtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

/**
 * @struct ProcessHistoricalSnapshot
 * @brief Хранит предыдущие значения для расчета динамики (CPU, I/O).
 */
struct ProcessHistoricalSnapshot {
    ULONGLONG lastKernelTime = 0;
    ULONGLONG lastUserTime = 0;
    ULONGLONG lastReadBytes = 0;
    ULONGLONG lastWriteBytes = 0;
    ULONGLONG lastOtherBytes = 0;
    std::chrono::steady_clock::time_point lastSampleTime;
};

/**
 * @struct ProcessKey
 * @brief Уникальный ключ для индексации в БД. Использует PID + CreateTime.
 */
struct ProcessKey {
    DWORD pid;
    LARGE_INTEGER createTime;

    /**
     * @brief Оператор сравнения для использования в std::map.
     */
    bool operator<(const ProcessKey& other) const {
        if (pid != other.pid) return pid < other.pid;
        return createTime.QuadPart < other.createTime.QuadPart;
    }
};

/**
 * @struct ProcessRecord
 * @brief Полный набор данных процесса для сохранения в БД.
 */
struct ProcessRecord {
    std::wstring processName;            ///< Имя процесса
    SYSTEM_PROCESS_INFORMATION procInfo; ///< Структура данных процесса
    VM_COUNTERS_EX vmCounters;           ///< Статистика памяти
    ProcessHistoricalSnapshot history;   ///< Исторические данные (для дельт)
    std::chrono::steady_clock::time_point lastUpdate; ///< Метка времени записи
};

/**
 * @class SystemPerformanceTelemetryMonitor
 * @brief Класс мониторинга, осуществляющий сбор данных и управление БД.
 */
class SystemPerformanceTelemetryMonitor {
private:
    pfnNtQuerySystemInformation m_pfnNtQuerySystemInformation = nullptr;
    std::vector<BYTE> m_telemetryBuffer;
    std::map<ProcessKey, ProcessRecord> m_processDatabase; ///< Основное хранилище
    DWORD m_logicalProcessorCount = 1;

    /**
     * @brief Динамическая загрузка функции из ntdll.
     */
    void LocateNativeEntryPoints() {
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (hNtdll) {
            m_pfnNtQuerySystemInformation = reinterpret_cast<pfnNtQuerySystemInformation>(
                GetProcAddress(hNtdll, "NtQuerySystemInformation")
                );
        }
    }

    /**
     * @brief Определение топологии процессора для расчетов.
     */
    void RetrieveProcessorTopology() {
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        m_logicalProcessorCount = sysInfo.dwNumberOfProcessors;
    }

public:
    /**
     * @brief Конструктор инициализации.
     */
    SystemPerformanceTelemetryMonitor() {
        LocateNativeEntryPoints();
        RetrieveProcessorTopology();
        m_telemetryBuffer.resize(1024 * 1024); // Начальный буфер 1MB
    }

    /**
     * @brief Выполнение запроса к системе и обновление БД.
     */
    void ExecuteQueryAndProcess() {
        if (!m_pfnNtQuerySystemInformation) return;

        ULONG requiredSize = 0;
        NTSTATUS status;

        // Цикл расширения буфера, если данных больше, чем выделено
        while (true) {
            status = m_pfnNtQuerySystemInformation(
                SystemProcessInformation,
                m_telemetryBuffer.data(),
                static_cast<ULONG>(m_telemetryBuffer.size()),
                &requiredSize
            );

            if (status == STATUS_INFO_LENGTH_MISMATCH) {
                ULONG targetSize = (requiredSize > 0) ? (requiredSize + 65536) : static_cast<ULONG>(m_telemetryBuffer.size() * 1.5);
                m_telemetryBuffer.resize(targetSize);
            }
            else {
                break;
            }
        }

        if (status == STATUS_SUCCESS) {
            ParseBuffer();
        }
    }

    /**
     * @brief Парсинг сырого буфера и обновление записей в БД.
     */
    void ParseBuffer() {
        auto currentTimePoint = std::chrono::steady_clock::now();
        BYTE* pCurrentPosition = m_telemetryBuffer.data();

        while (pCurrentPosition) {
            auto* pProcessData = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(pCurrentPosition);
            DWORD pid = static_cast<DWORD>(reinterpret_cast<uintptr_t>(pProcessData->UniqueProcessId));

            // Обработка имени
            std::wstring processName = L"System Idle Process";
            if (pid != 0) {
                if (pProcessData->ImageName.Buffer != nullptr && pProcessData->ImageName.Length > 0) {
                    processName = std::wstring(pProcessData->ImageName.Buffer, pProcessData->ImageName.Length / sizeof(wchar_t));
                }
                else {
                    processName = L"System/Unknown";
                }
            }

            // Формируем ключ
            ProcessKey key{ pid, pProcessData->CreateTime };

            // Подготовка записи для сохранения
            ProcessRecord newRecord;
            newRecord.processName = processName;
            newRecord.procInfo = *pProcessData;
            newRecord.vmCounters = pProcessData->VirtualMemoryCounters;
            newRecord.lastUpdate = currentTimePoint;

            // Логика расчета дельт (история)
            if (m_processDatabase.count(key)) {
                newRecord.history = m_processDatabase[key].history;
            }

            // Обновляем исторические данные
            newRecord.history.lastKernelTime = pProcessData->KernelTime.QuadPart;
            newRecord.history.lastUserTime = pProcessData->UserTime.QuadPart;
            newRecord.history.lastReadBytes = pProcessData->IoCounters.ReadTransferCount;
            newRecord.history.lastWriteBytes = pProcessData->IoCounters.WriteTransferCount;
            newRecord.history.lastOtherBytes = pProcessData->IoCounters.OtherTransferCount;
            newRecord.history.lastSampleTime = currentTimePoint;

            // Запись в базу
            m_processDatabase[key] = newRecord;

            // Переход к следующему элементу
            if (pProcessData->NextEntryOffset == 0) break;
            pCurrentPosition += pProcessData->NextEntryOffset;
        }
    }

    /**
     * @brief Возвращает доступ к базе данных для внешней программы.
     */
    const std::map<ProcessKey, ProcessRecord>& GetProcessDatabase() const {
        return m_processDatabase;
    }

    /**
     * @brief Находит все записи процессов по заданному PID.
     * @param pid Идентификатор процесса для поиска.
     * @return Вектор пар {имя процесса, время создания}.
     */
    std::vector<std::pair<std::wstring, LARGE_INTEGER>> GetProcessesByPid(DWORD pid) const {
        std::vector<std::pair<std::wstring, LARGE_INTEGER>> results;

        // Создаем ключ с PID и нулевым временем, чтобы найти первую запись
        ProcessKey searchKey{ pid, {0} };

        // Используем lower_bound для быстрого перехода к первому вхождению PID
        auto it = m_processDatabase.lower_bound(searchKey);

        // Перебираем записи, пока PID совпадает (так как map отсортирован по PID)
        while (it != m_processDatabase.end() && it->first.pid == pid) {
            results.push_back({ it->second.processName, it->first.createTime });
            ++it;
        }

        return results;
    }

    /**
     * @brief Возвращает PID процесса по порядковому номеру записи в базе.
     * @param index Порядковый номер записи (0-based).
     * @return PID процесса, если индекс валиден, иначе 0.
     */
    DWORD GetPidByIndex(size_t index) const {
        if (index >= m_processDatabase.size()) {
            return 0; // Ошибка: индекс вне диапазона
        }
        auto it = m_processDatabase.begin();
        std::advance(it, index); // Переход к i-тому элементу
        return it->first.pid;
    }

    /**
     * @brief Находит PID процесса, который был обновлен самым последним.
     * @return PID процесса или 0, если база пуста.
     */
    DWORD GetLastUpdatedPid() const {
        if (m_processDatabase.empty()) return 0;

        // Используем явное указание типа std::chrono::steady_clock::time_point
        // Вместо ::min() используем пустой конструктор (он равен 0)
        std::chrono::steady_clock::time_point latestTime;
        DWORD latestPid = 0;

        // Используем классический итератор map (для совместимости со старыми стандартами)
        for (std::map<ProcessKey, ProcessRecord>::const_iterator it = m_processDatabase.begin();
            it != m_processDatabase.end(); ++it) {

            // it->second — это доступ к записи (record)
            // it->first — это доступ к ключу (key)
            if (it->second.lastUpdate > latestTime) {
                latestTime = it->second.lastUpdate;
                latestPid = it->first.pid;
            }
        }
        return latestPid;
    }

    /**
     * @brief Находит PID процесса, который был создан в системе самым последним.
     * @return PID процесса или 0, если база пуста.
     */
    DWORD GetNewestProcessPid() const {
        if (m_processDatabase.empty()) return 0;

        LARGE_INTEGER maxCreateTime;
        maxCreateTime.QuadPart = 0; // Инициализация минимальным значением
        DWORD latestPid = 0;

        for (std::map<ProcessKey, ProcessRecord>::const_iterator it = m_processDatabase.begin();
            it != m_processDatabase.end(); ++it) {

            // Сравниваем CreateTime процесса с текущим максимумом
            if (it->first.createTime.QuadPart > maxCreateTime.QuadPart) {
                maxCreateTime = it->first.createTime;
                latestPid = it->first.pid;
            }
        }
        return latestPid;
    }

    /**
     * @brief Находит уникальный ключ процесса, который был создан самым последним.
     */
    ProcessKey GetNewestProcessKey() const {
        ProcessKey newestKey = { 0, {0} };
        LARGE_INTEGER maxCreateTime;
        maxCreateTime.QuadPart = 0;

        for (std::map<ProcessKey, ProcessRecord>::const_iterator it = m_processDatabase.begin();
            it != m_processDatabase.end(); ++it) {

            if (it->first.createTime.QuadPart > maxCreateTime.QuadPart) {
                maxCreateTime = it->first.createTime;
                newestKey = it->first;
            }
        }
        return newestKey;
    }
};

/**
 * @brief Точка входа.
 */
int main() {
    std::setlocale(LC_ALL, "Russian");

    SystemPerformanceTelemetryMonitor monitor;

    std::cout << "Запуск сбора телеметрии..." << std::endl;
    monitor.ExecuteQueryAndProcess();


    while (true) {
        monitor.ExecuteQueryAndProcess();

        // 1. Получаем ключ последнего процесса
        ProcessKey key = monitor.GetNewestProcessKey();

        // 2. Получаем запись из базы по этому ключу
        const auto& db = monitor.GetProcessDatabase();
        auto it = db.find(key);

        if (it != db.end()) {
            std::cout << "Последний запущенный PID: " << it->first.pid << " Его имя: ";

            // Вывод wstring требует использования std::wcout
            std::wcout << it->second.processName << std::endl;
        }

        std::cout << "Всего записей в базе: " << monitor.GetProcessDatabase().size() << std::endl;

        Sleep(200);
    }


    return 0;
}