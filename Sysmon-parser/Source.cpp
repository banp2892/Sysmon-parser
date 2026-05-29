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

namespace fs = std::filesystem;
using json = nlohmann::json;

struct ProcessState {
    uint64_t last_cpu_time = 0;
};

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

DWORD WINAPI SubscriptionCallback(EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID pContext, EVT_HANDLE hEvent) {
    if (action != EvtSubscribeActionDeliver) return ERROR_SUCCESS;

    std::string xml = SysmonCollector::GetXmlFromEvent(hEvent);
    if (xml.empty()) return ERROR_SUCCESS;

    DWORD pid = SysmonCollector::GetPidFromXml(xml);
    int eventId = SysmonCollector::GetEventIdFromXml(xml);

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

        std::cout << "[Event Captured] PID: " << pid << " | EventID: " << eventId << std::endl;
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

    // Подготовка среды
    if (!fs::exists("data")) fs::create_directory("data");

    if (!EnableDebugPrivilege()) {
        std::cerr << "[-] ВНИМАНИЕ: Запустите от имени Администратора для доступа ко всем процессам." << std::endl;
    }

    EVT_HANDLE hSub = EvtSubscribe(NULL, NULL, L"Microsoft-Windows-Sysmon/Operational",
        L"*", NULL, NULL, SubscriptionCallback, EvtSubscribeToFutureEvents);

    if (!hSub) {
        std::cerr << "[-] ОШИБКА: Не удалось подписаться на Sysmon. Проверьте, установлен ли он." << std::endl;
        return 1;
    }

    std::cout << "[+] Мониторинг запущен. Данные сохраняются в папку /data" << std::endl;
    Sleep(INFINITE);

    EvtClose(hSub);
    return 0;
}