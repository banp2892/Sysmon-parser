#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <ctime>
#include "SysmonCollector.h"
#include "LogEnricher.h"

using json = nlohmann::json;

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
            json fullLog = LogEnricher::Enrich(xml);

            // Вывод в консоль
            std::cout << "[Event Captured] Sysmon log received." << std::endl;

            // Запись в файл
            static std::string currentFile = GetUniqueFilename();
            std::ofstream file(currentFile, std::ios::app);
            if (file.is_open()) {
                file << fullLog.dump() << std::endl;
            }
        }
    }
    return ERROR_SUCCESS;
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