#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <ctime>
#include "SysmonCollector.h"
#include "LogEnricher.h"

#include <mutex>
#include <unordered_map>

using json = nlohmann::json;

/**
 * @struct ProcessState
 * @brief Хранит историю потребления ресурсов конкретным процессом.
 */
struct ProcessState {
    uint64_t last_cpu_time = 0;
};

// Глобальное хранилище состояний
std::unordered_map<DWORD, ProcessState> g_ProcessCache;
std::mutex g_CacheMutex;



/**
 * @brief Генерирует уникальное имя файла для текущей сессии.
 * @return std::string Имя файла.
 */
std::string GetUniqueFilename() {
    auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::tm tm;
    localtime_s(&tm, &now);
    std::ostringstream oss;
    oss << "sysmon_log_" << std::put_time(&tm, "%Y-%m-%d_%H-%M-%S") << ".jsonl";
    return oss.str();
}

/**
 * @brief Функция-обработчик событий Sysmon.
 */
DWORD WINAPI SubscriptionCallback(EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID pContext, EVT_HANDLE hEvent) {
    if (action == EvtSubscribeActionDeliver) {
        std::string xml = SysmonCollector::GetXmlFromEvent(hEvent);

        if (!xml.empty()) {
            DWORD pid = SysmonCollector::GetPidFromXml(xml);
            json fullLog = LogEnricher::Enrich(xml, pid);

            // 1. Получаем EventID из XML, чтобы понять, нужно ли удалять процесс
            int eventId = SysmonCollector::GetEventIdFromXml(xml);

            if (eventId == 5) {
                // Процесс завершен, чистим кэш
                std::lock_guard<std::mutex> lock(g_CacheMutex);
                g_ProcessCache.erase(pid);
            }
            else {
                // 2. Обогащаем данными с учетом CPU Slice
                uint64_t last_cpu = 0;
                {
                    std::lock_guard<std::mutex> lock(g_CacheMutex);
                    last_cpu = g_ProcessCache[pid].last_cpu_time;
                }

                // Вызываем Enrich (с учетом нашей доработки)
                json fullLog = LogEnricher::Enrich(xml, pid, last_cpu);

                // Вывод в консоль
                std::cout << "[Event Captured] Sysmon log received. PID = " << pid << std::endl;

                // Запись в файл
                static std::string currentFile = GetUniqueFilename();
                std::ofstream file(currentFile, std::ios::app);
                if (file.is_open()) {
                    file << fullLog.dump() << std::endl;
                }
            }
        }
        return ERROR_SUCCESS;
    };
}
int main() {
    setlocale(LC_ALL, "Russian");

    // Подписка на события Sysmon
    EVT_HANDLE hSub = EvtSubscribe(NULL, NULL, L"Microsoft-Windows-Sysmon/Operational",
        L"*", NULL, NULL, SubscriptionCallback, EvtSubscribeToFutureEvents);

    if (!hSub) {
        std::cerr << "[-] ОШИБКА: Запустите от имени АДМИНИСТРАТОРА!" << std::endl;
        return 1;
    }

    std::cout << "[+] Мониторинг Sysmon запущен. Пишем в " << GetUniqueFilename() << "..." << std::endl;
    Sleep(INFINITE);

    EvtClose(hSub);
    return 0;
}