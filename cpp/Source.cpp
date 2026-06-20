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



/**
 * @brief Глобальный счетчик обработанных событий Sysmon для статистики.
 */
uint64_t numbers_of_logs = 0;



/**
 * @brief Преобразует строковое представление времени из Sysmon в системный формат.
 * Использует ручной разбор строки для максимальной производительности.
 */
std::chrono::system_clock::time_point ParseSysmonUtcTime(const std::string& utcTime) {
    SYSTEMTIME st = { 0 };
    int milliseconds = 0;

    // Парсим строку формата "YYYY-MM-DD HH:MM:SS.mmm"
    if (sscanf_s(utcTime.c_str(), "%hu-%hu-%hu %hu:%hu:%hu.%d",
        &st.wYear, &st.wMonth, &st.wDay,
        &st.wHour, &st.wMinute, &st.wSecond, &milliseconds) != 7) {
        return std::chrono::system_clock::time_point::min();
    }
    st.wMilliseconds = (WORD)milliseconds;

    FILETIME ft;
    SystemTimeToFileTime(&st, &ft);

    // Конвертация FILETIME (отсчет с 1601 г.) в Unix Time (отсчет с 1970 г.)
    ULARGE_INTEGER uli;
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;

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

/**
 * @brief Контекст для передачи объектов в функцию обратного вызова Event Log.
 */
struct SubscriptionContext {
    SysmonCollector::SysmonProcessesMap* pSysmonMap;
    SystemPerformanceTelemetryMonitor* pMonitor;
};

/**
 * @brief Функция-обработчик событий Sysmon.
 * Принимает лог, обогащает его системной телеметрией и сохраняет в JSONL-файл.
 */
DWORD WINAPI SubscriptionCallback(EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID pContext, EVT_HANDLE hEvent) {
    auto* pCtx = static_cast<SubscriptionContext*>(pContext);

    auto* pMap = pCtx->pSysmonMap;
    auto* pMonitor = pCtx->pMonitor;

    // Выполняем обработку только при успешной доставке события
    if (action != EvtSubscribeActionDeliver) return ERROR_SUCCESS;

    // Извлекаем XML-представление события
    std::string xml = SysmonCollector::GetXmlFromEvent(hEvent);
    if (xml.empty()) {
        std::cout << "Failed to get XML" << std::endl;
        return ERROR_SUCCESS;
    }

    // Парсинг базовых полей Sysmon из XML
    StaticSysmonData StaticSysmon = SysmonCollector::ParseSysmonEvent(xml);
    StaticSysmon.rawXml = xml;

    DWORD pid = StaticSysmon.ProcessId;
    int eventId = StaticSysmon.EventId;
    std::string Guid = StaticSysmon.ProcessGuid;

    // Дополнительный сбор данных о процессе через системные API
    SysmonCollector::EnrichProcessData(pid, StaticSysmon);

    // Попытка привязать накопленную телеметрию к текущему событию
    auto* pRecord = pMonitor->GetRecord(pid);
    if (!pRecord) {
        // Запись отсутствует (процесс завершен или данные еще не собраны)
        std::cout << "[DEBUG] [Telemetry] Process record NOT FOUND for PID: " << pid
            << " | Event: " << StaticSysmon.EventId << std::endl;
    }
    else {
        auto logTime = ParseSysmonUtcTime(StaticSysmon.UtcTime);

        // Проверка корректности парсинга времени
        if (logTime == std::chrono::system_clock::time_point::min()) {
            std::cout << "[DEBUG] [Telemetry] Failed to parse UtcTime for PID: " << pid << std::endl;
        }

        // Поиск ближайшего снимка метрик в истории процесса
        auto* snapshot = pRecord->FindClosestSnapshot(logTime);

        if (snapshot) {
            StaticSysmon.telemetrySnapshot = *snapshot;
            StaticSysmon.hasTelemetry = true;
        }
        else {
            // Ошибка сопоставления времени (снимок отсутствует в окне видимости)
            std::cout << "[DEBUG] [Telemetry] No snapshot found for PID: " << pid
                << " at time: " << StaticSysmon.UtcTime << std::endl;
        }
    }

    // Сериализация данных события в JSON
    std::string jsonString = StaticSysmon.ToJson();

    // Сохранение в файл в формате JSONL (каждая запись — новая строка)
    static std::string currentFile = GetFilePath();
    std::ofstream file(currentFile, std::ios::app);

    if (file.is_open()) {
        file << jsonString << std::endl;
        file.close(); // Принудительный сброс на диск
    }

    // Инкремент общего счетчика и вывод отладочной статистики в консоль
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
/**
 * @brief Запрашивает привилегию SeDebugPrivilege для текущего процесса.
 * Необходима для получения доступа к информации о процессах, запущенных от других пользователей (SYSTEM и т.д.).
 * @return true, если привилегия успешно включена, иначе false.
 */
bool EnableDebugPrivilege() {
    HANDLE hToken;
    LUID luid;
    TOKEN_PRIVILEGES tkp;

    // Открываем токен доступа текущего процесса
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) return false;

    // Получаем локальный уникальный идентификатор (LUID) для привилегии отладки
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken);
        return false;
    }

    // Настраиваем структуру привилегий
    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = luid;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    // Применяем изменения к токену
    bool result = AdjustTokenPrivileges(hToken, false, &tkp, sizeof(tkp), NULL, NULL);

    CloseHandle(hToken);
    return result;
}

/**
 * @brief Функция рабочего потока для сбора метрик производительности системы.
 * @param monitor Объект-монитор, выполняющий сбор данных.
 * @param running Атомарный флаг для управления циклом жизни потока.
 */
void MetricsCollectionWorker(SystemPerformanceTelemetryMonitor& monitor, std::atomic<bool>& running) {
    std::cout << "[MetricsWorker] Thread started." << std::endl;

    // Цикл опроса выполняется до тех пор, пока флаг running равен true
    while (running) {
        // Выполнение запроса к Native API и обновление данных телеметрии
        monitor.ExecuteQueryAndProcess();

        // Пауза 10 мс между итерациями для снижения нагрузки на CPU
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    std::cout << "[MetricsWorker] Thread stopped." << std::endl;
}


int main() {
    setlocale(LC_ALL, "Russian");

    // Проверка прав администратора (необходимы для подписки на события Sysmon)
    if (!IsUserAnAdmin()) {
        std::cout << "[-] FAILED: Run as Administarator." << std::endl;
        return 1;
    }

    // Инициализация директории для хранения логов
    if (!fs::exists("data")) fs::create_directory("data");

    // Попытка повышения привилегий до отладочных (SeDebugPrivilege)
    if (!EnableDebugPrivilege()) {
        std::cerr << "[-] Run as Administarator to get access for all process." << std::endl;
    }

    // Инициализация объектов управления процессами и мониторинга производительности
    SysmonCollector::SysmonProcessesMap SysmonMap;
    SystemPerformanceTelemetryMonitor monitor;
    static SubscriptionContext subCtx = { &SysmonMap, &monitor };

    // Флаг для управления жизненным циклом фоновых потоков
    std::atomic<bool> isRunning(true);

    // --- Запуск потока сбора метрик ---
    // Передаем экземпляры monitor и isRunning по ссылке для синхронизации
    std::thread metricsThread(MetricsCollectionWorker, std::ref(monitor), std::ref(isRunning));

    // Подписка на журнал событий Sysmon (Microsoft-Windows-Sysmon/Operational)
    EVT_HANDLE hSub = EvtSubscribe(NULL, NULL, L"Microsoft-Windows-Sysmon/Operational",
        L"*", NULL, &subCtx, SubscriptionCallback, EvtSubscribeToFutureEvents);

    // Проверка успешности подписки
    if (!hSub) {
        std::cerr << "[-] FAILED: Failed subscribe to Sysmon." << std::endl;
        isRunning = false;
        if (metricsThread.joinable()) metricsThread.join();
        return 1;
    }

    std::cout << "[+] Monitoring has been started. Press ENTER to stop." << std::endl;

    // Ожидание пользовательского ввода для остановки программы
    std::cin.get();

    // --- Корректное завершение работы ---
    std::cout << "[!] Stopping... Please wait." << std::endl;

    // Сигнализируем потоку метрик о необходимости завершения
    isRunning = false;
    if (metricsThread.joinable()) {
        metricsThread.join(); // Ожидаем завершения потока
    }

    // Закрытие дескриптора подписки
    EvtClose(hSub);
    std::cout << "[+] Stopped." << std::endl;

    return 0;
}