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

/// Глобальный экземпляр монитора производительности ядра Windows.
SystemPerformanceTelemetryMonitor g_TelemetryMonitor;

/// Мьютекс для синхронизации вывода в консоль и записи в файл между потоками подписки.
std::mutex g_FileMutex;

/// Общий счетчик перехваченных и успешно обработанных логов.
uint64_t numbers_of_logs = 0;

/**
 * @brief Генерирует уникальный путь к файлу лога внутри директории data/.
 * * Формирует имя файла на основе текущей даты и времени сборщика.
 * Пример: data/sysmon_log_2026-06-06_17-30-00.jsonl
 * * @return std::string Относительный путь к файлу логирования.
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
 * @brief Функция обратного вызова (Callback) для подписки Windows Event Log.
 * * Вызывается ядром ОС при появлении нового события в канале Sysmon. Извлекает XML,
 * запрашивает расширенный снимок метрик из буфера телеметрии и сохраняет агрегированный JSON.
 * * @param action Действие, вызвавшее уведомление (ожидается EvtSubscribeActionDeliver).
 * @param pContext Пользовательский контекст, переданный при подписке.
 * @param hEvent Дескриптор пришедшего события.
 * @return DWORD Возвращает ERROR_SUCCESS в случае успешной обработки.
 */
DWORD WINAPI SubscriptionCallback(EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID pContext, EVT_HANDLE hEvent) {
    if (action != EvtSubscribeActionDeliver) return ERROR_SUCCESS;

    std::string xml = SysmonCollector::GetXmlFromEvent(hEvent);
    if (xml.empty()) return ERROR_SUCCESS;

    DWORD pid = SysmonCollector::GetPidFromXml(xml);
    int eventId = SysmonCollector::GetEventIdFromXml(xml);

    // Получаем текущую метку времени для сопоставления со срезами метрик производительности
    uint64_t currentUnixTime = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();

    // Обогащаем Sysmon XML-лог данными из нашего циклического буфера метрик
    json fullLog = g_TelemetryMonitor.MergeSysmonLogWithTelemetry(xml, pid, currentUnixTime);

    // Потокобезопасная запись лога в файл JSONL
    {
        std::lock_guard<std::mutex> lock(g_FileMutex);
        static std::string currentFile = GetFilePath();
        std::ofstream file(currentFile, std::ios::app);
        if (file.is_open()) {
            file << fullLog.dump() << std::endl;
        }
        numbers_of_logs++;
    }

    // Вывод диагностической информации в консоль каждые 10 событий
    if (numbers_of_logs % 10 == 0) {
        std::cout << "[Event Captured] PID: " << pid
            << " | EventID: " << eventId
            << " | Total Logs: " << numbers_of_logs << std::endl;
    }

    return ERROR_SUCCESS;
}

/**
 * @brief Включает привилегию SE_DEBUG_NAME для текущего процесса.
 * * Необходима для получения дескрипторов сторонних процессов (включая системные)
 * с правами PROCESS_QUERY_LIMITED_INFORMATION и PROCESS_VM_READ при чтении PEB.
 * * @return true Привилегия успешно скорректирована.
 * @return false Не удалось изменить маркер доступа (токен).
 */
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

/**
 * @brief Точка входа в приложение.
 * * Выполняет проверку прав администратора, инициализирует дерево каталогов,
 * активирует отладочные привилегии, запускает асинхронный сборщик и подписывается на события ОС.
 * * @return int Код завершения программы (0 — успех, 1 — критическая ошибка).
 */
int main() {
    setlocale(LC_ALL, "Russian");

    // Проверка прав локального администратора
    if (!IsUserAnAdmin()) {
        std::cout << "[-] FAILED: Run as Administrator." << std::endl;
        return 1;
    }

    // Создание папки для выходных датасетов, если она отсутствует
    if (!fs::exists("data")) fs::create_directory("data");

    if (!EnableDebugPrivilege()) {
        std::cerr << "[-] Failed to adjust token privileges. Check internal security policies." << std::endl;
    }

    // 1. Запуск низкоуровневого монитора системной телеметрии (заполнение буфера истории)
    g_TelemetryMonitor.Start();
    std::cout << "[+] Background performance telemetry collector thread started." << std::endl;

    // 2. Регистрация асинхронной подписки на события Sysmon
    EVT_HANDLE hSub = EvtSubscribe(NULL, NULL, L"Microsoft-Windows-Sysmon/Operational",
        L"*", NULL, NULL, SubscriptionCallback, EvtSubscribeToFutureEvents);

    if (!hSub) {
        std::cerr << "[-] FAILED: Failed to subscribe to Sysmon event channel." << std::endl;
        g_TelemetryMonitor.Stop();
        return 1;
    }

    std::cout << "[+] Monitoring has been started. The data will be saved in /data" << std::endl;

    // Перевод главного потока в режим вечного сна для удержания процесса
    Sleep(INFINITE);

    // Корректное завершение работы при остановке службы/демона (если применим прерывающий вызов)
    EvtClose(hSub);
    g_TelemetryMonitor.Stop();
    return 0;
}