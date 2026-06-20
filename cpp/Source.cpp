#define NOMINMAX
#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <ctime>
#include <filesystem>
#include <mutex>
#include <unordered_map>
#include <windows.h>
#include <winevt.h>
#include "SysmonCollector.h"
//#include "LogEnricher.h"
#include <shlobj.h> ///< Для проверки запуска программы от имени администратора
#include "Metrics.h"

#include <atomic>
#include <thread>
#include <chrono>


namespace fs = std::filesystem;
using json = nlohmann::json;

struct ProcessState {
    uint64_t last_cpu_time = 0;
};

uint64_t numbers_of_logs=0;

std::unordered_map<DWORD, ProcessState> g_ProcessCache;
std::mutex g_CacheMutex;


/**
* @brief преобразует время utcTime, которое мы получаем из лога Sysmon во время std::chrono::system_clock::time_point
*/
std::chrono::system_clock::time_point ParseSysmonUtcTime(const std::string& utcTime) {
    // Формат: "YYYY-MM-DD HH:MM:SS.mmm"
    // Пример: "2026-06-19 12:09:10.123"

    SYSTEMTIME st = { 0 };
    int milliseconds = 0;

    // Быстрый парсинг (sscanf)
    if (sscanf_s(utcTime.c_str(), "%hu-%hu-%hu %hu:%hu:%hu.%d",
        &st.wYear, &st.wMonth, &st.wDay,
        &st.wHour, &st.wMinute, &st.wSecond, &milliseconds) != 7) {
        return std::chrono::system_clock::time_point::min();
    }
    st.wMilliseconds = (WORD)milliseconds;

    // Преобразуем в FILETIME
    FILETIME ft;
    SystemTimeToFileTime(&st, &ft);

    // Преобразуем FILETIME в system_clock::time_point
    ULARGE_INTEGER uli;
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;

    // FILETIME — это количество 100-нс интервалов с 1601 года
    // system_clock — это количество 100-нс интервалов с 1970 года
    // Разница между 1601 и 1970 годами в 100-нс интервалах
    const long long WINDOWS_TICK = 10000000;
    const long long SEC_TO_UNIX_EPOCH = 11644473600LL;

    long long unixTime = (uli.QuadPart / WINDOWS_TICK) - SEC_TO_UNIX_EPOCH;

    return std::chrono::system_clock::time_point(std::chrono::seconds(unixTime) +
        std::chrono::milliseconds(st.wMilliseconds));
}



/**
 * @brief Генерирует имя файла внутри папки data/
 */
std::string GetFilePath() {
    auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::tm tm;
    localtime_s(&tm, &now);
    std::ostringstream oss;
    oss << "data/sysmon_log_" << std::put_time(&tm, "%Y-%m-%d_%H-%M-%S") << ".jsonl";
    return oss.str();
}

/**
* Из FILETIME преобразует время в читаемое
*/

std::string FileTimeToReadable(const FILETIME& ft) {
    SYSTEMTIME st;
    if (!FileTimeToSystemTime(&ft, &st)) return "Invalid Time";

    std::stringstream ss;
    ss << st.wYear << "-"
        << std::setw(2) << std::setfill('0') << st.wMonth << "-"
        << std::setw(2) << std::setfill('0') << st.wDay << " "
        << std::setw(2) << std::setfill('0') << st.wHour << ":"
        << std::setw(2) << std::setfill('0') << st.wMinute << ":"
        << std::setw(2) << std::setfill('0') << st.wSecond;
    return ss.str();
}


struct SubscriptionContext {
    SysmonCollector::SysmonProcessesMap* pSysmonMap;
    SystemPerformanceTelemetryMonitor* pMonitor;
};

/**
* @brief Функция, принимающая лог Sysmon и обрабатывающая его обогащение и сохранение
*/
DWORD WINAPI SubscriptionCallback(EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID pContext, EVT_HANDLE hEvent) {
    auto* pCtx = static_cast<SubscriptionContext*>(pContext);

    auto* pMap = pCtx->pSysmonMap;
    auto* pMonitor = pCtx->pMonitor;
    if (action != EvtSubscribeActionDeliver) return ERROR_SUCCESS;

    std::string xml = SysmonCollector::GetXmlFromEvent(hEvent);
    if (xml.empty()) {
        std::cout << "Failed to get XML" << std::endl;
        return ERROR_SUCCESS;
    }

    StaticSysmonData StaticSysmon = SysmonCollector::ParseSysmonEvent(xml); ///< Парсим Sysmon структуру


    

    DWORD pid = StaticSysmon.ProcessId;
    int eventId = StaticSysmon.EventId;
    std::string Guid = StaticSysmon.ProcessGuid;

    
    
    


    //if (!pMap->Exists(Guid)) { ///< Если записи не существует
    //    SysmonCollector::EnrichProcessData(pid, StaticSysmon); ///< Добавляем время и то, что не смогли дописать до этого
    //   
    //    pMap->UpdateData(Guid, pid, StaticSysmon.createTime); ///< обнавляем данные
    //    if (pMap->size() % 5 == 0) {
    //        // Оставляем флаг, чтобы в логе сразу видеть, если время "нулевое"
    //        bool isTimeInvalid = (StaticSysmon.createTime.dwLowDateTime == 0 &&
    //            StaticSysmon.createTime.dwHighDateTime == 0);
    //        std::cout << "[DEBUG] Size: " << pMap->size()
    //            << " | PID: " << pid
    //            << " | Eventid: " << eventId
    //            << " | UtcTime: " << (StaticSysmon.UtcTime.empty() ? "EMPTY" : StaticSysmon.UtcTime)
    //            << " | CreateTime: " << (isTimeInvalid ? "INVALID" : FileTimeToReadable(StaticSysmon.createTime))
    //            << " | Image: " << StaticSysmon.Image
    //            << std::endl;
    //    }
    //}
    //else {
    //}

    auto* pRecord = pMonitor->GetRecord(pid);
    if (!pRecord) {
        // ВАЖНО: Это сообщение поможет понять, почему нет телеметрии: 
        // либо процесс еще не попал в базу, либо он уже удален (PID reuse).
        std::cout << "[DEBUG] [Telemetry] Process record NOT FOUND for PID: " << pid
            << " | Event: " << StaticSysmon.EventId << std::endl;
    }
    else {
        auto logTime = ParseSysmonUtcTime(StaticSysmon.UtcTime);

        // Дополнительная проверка на валидность времени
        if (logTime == std::chrono::system_clock::time_point::min()) {
            std::cout << "[DEBUG] [Telemetry] Failed to parse UtcTime for PID: " << pid << std::endl;
        }

        auto* snapshot = pRecord->FindClosestSnapshot(logTime);

        if (snapshot) {
            StaticSysmon.telemetrySnapshot = *snapshot;
            StaticSysmon.hasTelemetry = true;

            // Опционально: можно логировать успешное сопоставление
            // std::cout << "[DEBUG] [Telemetry] Attached data for PID: " << pid << std::endl;
        }
        else {
            // ЭТО КРИТИЧЕСКАЯ ТОЧКА. Если сюда попадает, значит:
            // 1. У вас пустой буфер истории метрик
            // 2. Или logTime "старше", чем самый старый снимок в буфере
            // 3. Или процесс живой, но метрики еще ни разу не собрались
            std::cout << "[DEBUG] [Telemetry] No snapshot found for PID: " << pid
                << " at time: " << StaticSysmon.UtcTime << std::endl;
        }
    }

    std::string jsonString = StaticSysmon.ToJson();

    // 2. Сохраняем в файл (формат JSONL - каждая строка отдельный JSON)
    static std::string currentFile = GetFilePath();
    std::ofstream file(currentFile, std::ios::app);

    if (file.is_open()) {
        file << jsonString << std::endl;
        file.close(); // Закрываем, чтобы данные сбросились на диск
    }

    // 3. Логируем в консоль (используем поля структуры для скорости)
    numbers_of_logs++;
    if (numbers_of_logs % 10 == 0) {
        std::cout << "[Event] PID: " << StaticSysmon.ProcessId
            << " | Name: " << StaticSysmon.Image.substr(StaticSysmon.Image.find_last_of("\\/") + 1)
            << " | EventID: " << StaticSysmon.EventId
            << " | Total: " << numbers_of_logs
            << std::endl;
    }
    return ERROR_SUCCESS;
}

bool EnableDebugPrivilege() {
    HANDLE hToken;
    LUID luid;
    TOKEN_PRIVILEGES tkp;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) return false;
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) { CloseHandle(hToken); return false; }
    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = luid;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    bool result = AdjustTokenPrivileges(hToken, false, &tkp, sizeof(tkp), NULL, NULL);
    CloseHandle(hToken);
    return result;
}


void MetricsCollectionWorker(SystemPerformanceTelemetryMonitor& monitor, std::atomic<bool>& running) {
    std::cout << "[MetricsWorker] Thread started." << std::endl;
    int counter = 0;
    while (running) {
        monitor.ExecuteQueryAndProcess();
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    std::cout << "[MetricsWorker] Thread stopped." << std::endl;
}

int main() {
    setlocale(LC_ALL, "Russian");

    if (!IsUserAnAdmin()) {
        std::cout << "[-] FAILED: Run as Administarator." << std::endl;
        return 1;
    }

    if (!fs::exists("data")) fs::create_directory("data");

    if (!EnableDebugPrivilege()) {
        std::cerr << "[-] Run as Administarator to get access for all process." << std::endl;
    }

    SysmonCollector::SysmonProcessesMap SysmonMap;
    SystemPerformanceTelemetryMonitor monitor;
    static SubscriptionContext subCtx = { &SysmonMap, &monitor };

    // --- 1. Флаг управления потоком ---
    std::atomic<bool> isRunning(true);

    // --- 2. Запуск потока метрик ---
    // Передаем monitor и isRunning по ссылке
    std::thread metricsThread(MetricsCollectionWorker, std::ref(monitor), std::ref(isRunning));

    EVT_HANDLE hSub = EvtSubscribe(NULL, NULL, L"Microsoft-Windows-Sysmon/Operational",
        L"*", NULL, &subCtx, SubscriptionCallback, EvtSubscribeToFutureEvents);

    if (!hSub) {
        std::cerr << "[-] FAILED: Failed subscribe to Sysmon." << std::endl;
        // Если подписка не удалась, нужно корректно закрыть поток
        isRunning = false;
        if (metricsThread.joinable()) metricsThread.join();
        return 1;
    }

    std::cout << "[+] Monitoring has been started. Press ENTER to stop." << std::endl;

    // --- 3. Ожидание завершения вместо Sleep(INFINITE) ---
    // Это позволит программе работать, пока вы не нажмете Enter
    std::cin.get();

    // --- 4. Корректное завершение ---
    std::cout << "[!] Stopping... Please wait." << std::endl;

    isRunning = false;           // Сигнал потоку остановиться
    if (metricsThread.joinable()) {
        metricsThread.join();    // Ждем, пока поток завершит итерацию
    }

    EvtClose(hSub);
    std::cout << "[+] Stopped." << std::endl;
    return 0;
}