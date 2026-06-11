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
#include "LogEnricher.h"
#include <shlobj.h> ///< Для проверки запуска программы от имени администратора

namespace fs = std::filesystem;
using json = nlohmann::json;

struct ProcessState {
    uint64_t last_cpu_time = 0;
};

uint64_t numbers_of_logs=0;

std::unordered_map<DWORD, ProcessState> g_ProcessCache;
std::mutex g_CacheMutex;

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
* @brief Функция, принимающая лог Sysmon и обрабатывающая его обогащение и сохранение
*/
DWORD WINAPI SubscriptionCallback(EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID pContext, EVT_HANDLE hEvent) {
    if (action != EvtSubscribeActionDeliver) return ERROR_SUCCESS;

    std::string xml = SysmonCollector::GetXmlFromEvent(hEvent);
    if (xml.empty()) {
        std::cout << "Failed to get XML" << std::endl;
        return ERROR_SUCCESS;
    }

    SysmonCollector::StaticSysmonData StaticSysmon = SysmonCollector::ParseSysmonEvent(xml);

    DWORD pid = StaticSysmon.ProcessId;
    int eventId = StaticSysmon.EventId;


    if (eventId == 5) {
        std::lock_guard<std::mutex> lock(g_CacheMutex);
        g_ProcessCache.erase(pid);
    }
    else {
        uint64_t last_cpu = 0;
        {
            std::lock_guard<std::mutex> lock(g_CacheMutex);
            last_cpu = g_ProcessCache[pid].last_cpu_time;
        }

        // Обогащаем
        json fullLog = LogEnricher::Enrich(xml, pid, last_cpu);
        uint64_t startTime = 0;
        std::string procName = "";


        // 1. Проверяем, существует ли вообще ключ process_info
        if (fullLog.contains("process_info") && fullLog["process_info"].is_object()) {

            // 2. Получаем данные безопасно
            auto& info = fullLog["process_info"];

            // Используем тот ключ, который вы реально записали в Enrich (стандартно у нас start_time)
            startTime = info.value("start_time", 0ULL);
            procName = info.value("name", "Unknown");

        }
        else {
            // Если ключа нет, выводим ошибку в консоль, чтобы понять, что не так
            std::cerr << "[!] Debug: process_info key missing in log: " << fullLog.dump() << std::endl;
        }
        // вот если я убираю эти строчки, то перестает падать, дел в них
        // Обновляем кэш, если данные получены успешно
        if (fullLog.contains("metrics") && fullLog["metrics"].contains("_raw_cpu")) {
            std::lock_guard<std::mutex> lock(g_CacheMutex);
            g_ProcessCache[pid].last_cpu_time = fullLog["metrics"]["_raw_cpu"].get<uint64_t>();
        }

        // Запись в файл с автоматическим созданием пути
        static std::string currentFile = GetFilePath();
        std::ofstream file(currentFile, std::ios::app);
        if (file.is_open()) {
            file << fullLog.dump() << std::endl;
        }
        numbers_of_logs++;
        //if (numbers_of_logs % 10 == 0) { 
        std::cout << "[Event] PID: " << pid
            << " | Name: " << procName
            << " | Start: " << startTime
            << " | EventID: " << eventId
            << " | Total: " << numbers_of_logs


            << std::endl;
        //}
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

int main() {
    setlocale(LC_ALL, "Russian");

    if (!IsUserAnAdmin()) {
        std::cout << "[-] FAILED: Run as Administarator." << std::endl;
        return 1;
    }

    // Подготовка среды
    if (!fs::exists("data")) fs::create_directory("data");

    if (!EnableDebugPrivilege()) {
        std::cerr << "[-] Run as Administarator to get access for all process." << std::endl;
    }

    EVT_HANDLE hSub = EvtSubscribe(NULL, NULL, L"Microsoft-Windows-Sysmon/Operational", ///< Подписываемся на логи от Sysmon, если они приходят, то мы вызываем функцию SubscriptionCallback()
        L"*", NULL, NULL, SubscriptionCallback, EvtSubscribeToFutureEvents);

    if (!hSub) {
        std::cerr << "[-] FAILED: Failed subscribe to Sysmon." << std::endl;
        return 1;
    }

    std::cout << "[+] Monitoring has been started. The data will be saved in /data" << std::endl;
    Sleep(INFINITE);

    EvtClose(hSub);
    return 0;
}