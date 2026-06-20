#pragma once
#include <windows.h>
#include <winevt.h>
#include <vector>
#include <string>
#include "json.hpp"
#include "Metrics.h"


#pragma comment(lib, "wevtapi.lib")

/**
 * @brief Преобразует std::wstring в UTF-8 std::string.
 * @param wstr Исходная широкая строка.
 * @return Строка в кодировке UTF-8.
 */
inline std::string WStringToString(const std::wstring& wstr) {
    if (wstr.empty()) return std::string();
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string str(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &str[0], size_needed, NULL, NULL);
    return str;
}

/**
 * @brief Преобразует UTF-8 std::string в std::wstring.
 * @param str Входная строка.
 * @return Результат конвертации в UTF-16.
 */
inline std::wstring StringToWString(const std::string& str) {
    if (str.empty()) return std::wstring();
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstr(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstr[0], size_needed);
    return wstr;
}

/**
 * @brief Преобразует time_point в форматированную строку (ГГГГ-ММ-ДД ЧЧ:ММ:СС).
 * @param tp Точка времени.
 * @return Отформатированная строка времени.
 */
std::string FormatTime(std::chrono::system_clock::time_point tp) {
    auto time = std::chrono::system_clock::to_time_t(tp);
    struct tm tm;
    localtime_s(&tm, &time);
    std::stringstream ss;
    ss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

/**
 * @struct StaticSysmonData
 * @brief Хранит разобранные данные событий Sysmon и связанную телеметрию.
 */
struct StaticSysmonData {
    std::string rawXml;

    int EventId;
    std::string UtcTime;

    std::string Image;
    DWORD ProcessId;
    std::string ProcessGuid;

    FILETIME createTime;

    std::wstring commandLine;
    std::wstring companyName;
    DWORD integrityLevel;
    std::wstring ParentProcessGuid;
    DWORD ParentProcessId;
    std::wstring ParentImage;
    std::wstring ParentCommandLine;
    std::wstring ParentUser;

    bool hasTelemetry = false;
    ProcessTelemetry telemetrySnapshot;

    /**
     * @brief Сериализует данные события в JSON-строку.
     * @return JSON-представление данных процесса и его метрик.
     */
    std::string ToJson() const {
        using json = nlohmann::json;

        json staticField = {
            {"EventId", EventId},
            {"UtcTime", UtcTime},
            {"Image", Image},
            {"ProcessId", ProcessId},
            {"ProcessGuid", ProcessGuid},
            {"CommandLine", WStringToString(commandLine)},
            {"CompanyName", WStringToString(companyName)},
            {"IntegrityLevel", integrityLevel},
            {"ParentProcessGuid", WStringToString(ParentProcessGuid)},
            {"ParentProcessId", ParentProcessId},
            {"ParentImage", WStringToString(ParentImage)},
            {"ParentCommandLine", WStringToString(ParentCommandLine)},
            {"ParentUser", WStringToString(ParentUser)}
        };

        json metrics;
        if (hasTelemetry) {
            const auto& t = telemetrySnapshot;
            metrics = {
                {"Time", FormatTime(t.time)},
                {"CpuUsage", t.cpuUsage},
                {"KernelTime", t.kernelTime},
                {"UserTime", t.userTime},
                {"ParentPid", t.ppid},
                {"ThreadCount", t.threadCount},
                {"HandleCount", t.handleCount},
                {"PrivatePageCount", t.privatePageCount},
                {"VirtualSize", t.virtualSize},
                {"WorkingSetSize", t.workingSetSize},
                {"PageFaultCount", t.pageFaultCount},
                {"PagedPoolUsage", t.pagedPoolUsage},
                {"NonPagedPoolUsage", t.nonPagedPoolUsage},
                {"SessionId", t.sessionId},
                {"ContextSwitches", t.contextSwitches}
            };
        }
        else {
            metrics = { {"Status", "NoData"} };
        }

        json j = {
            {"raw_event", rawXml},
            {"Event", {
                {"static_field", staticField},
                {"metrics", metrics}
            }}
        };

        return j.dump();
    }
};

/**
 * @brief Перечисление классов информации о процессе для работы с Native API.
 */
typedef enum _PROCESSINFOCLASS {
    ProcessBasicInformation = 0,
    ProcessTimes = 4,
} PROCESSINFOCLASS;

/** @brief Тип для хранения приоритета процесса. */
typedef long KPRIORITY;

/**
 * @namespace SysmonCollector
 * @brief Модуль для сбора и первичной обработки событий Sysmon.
 */
namespace SysmonCollector {

    /**
     * @brief Получает XML-представление события Sysmon через дескриптор.
     * @param hEvent Дескриптор события Windows (EvtHandle).
     * @return XML-строка события или пустая строка в случае ошибки.
     */
    inline std::string GetXmlFromEvent(EVT_HANDLE hEvent) {
        DWORD bufferSize = 0, bufferUsed = 0, propertyCount = 0;
        if (!EvtRender(NULL, hEvent, EvtRenderEventXml, 0, NULL, &bufferSize, &propertyCount)) {
            if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                std::vector<wchar_t> buffer(bufferSize);
                if (EvtRender(NULL, hEvent, EvtRenderEventXml, bufferSize, buffer.data(), &bufferUsed, &propertyCount)) {
                    return WStringToString(buffer.data());
                }
            }
        }
        return "";
    }

    /**
     * @brief Извлекает EventID из XML-данных события.
     * @param xml Строка XML.
     * @return Идентификатор события (EventID) или 0 при ошибке.
     */
    inline DWORD GetEventIdFromXml(const std::string& xml) {
        const std::string openTag = "<EventID>";
        const std::string closeTag = "</EventID>";

        size_t startPos = xml.find(openTag);
        if (startPos == std::string::npos) return 0;

        startPos += openTag.length();
        size_t endPos = xml.find(closeTag, startPos);

        if (endPos == std::string::npos) return 0;

        try {
            return std::stoul(xml.substr(startPos, endPos - startPos));
        }
        catch (...) {
            return 0;
        }
    }

    /**
     * @brief Извлекает PID из блока EventData в XML-данных события.
     * @param xml Строка XML.
     * @return Идентификатор процесса (PID) или 0 при ошибке.
     */
    inline DWORD GetPidFromXml(const std::string& xml) {
        size_t eventDataPos = xml.find("<EventData>");
        if (eventDataPos == std::string::npos) return 0;

        std::string searchKey = "Name='ProcessId'>";
        size_t namePos = xml.find(searchKey, eventDataPos);

        if (namePos == std::string::npos) {
            searchKey = "Name=\"ProcessId\">";
            namePos = xml.find(searchKey, eventDataPos);
        }

        if (namePos == std::string::npos) return 0;

        size_t startPos = namePos + searchKey.length();
        size_t endPos = xml.find("</Data>", startPos);

        if (endPos == std::string::npos) return 0;

        try {
            return std::stoul(xml.substr(startPos, endPos - startPos));
        }
        catch (...) {
            return 0;
        }
    }

    /**
     * @brief Статус жизненного цикла процесса в системе мониторинга.
     */
    enum ProcessStatus {
        STATUS_NEW = 0,
        STATUS_EVENT_ID_1 = 1,
        STATUS_SNAPSHOT = 2,
        STATUS_DEAD = 3
    };

    /**
     * @brief Метаданные для идентификации процесса.
     */
    struct ProcessMetadata_2 {
        DWORD pid = 0;
        FILETIME createTime = { 0, 0 };
        ULONGLONG lastSeen = 0;
    };


    /**
 * @class SysmonProcessesMap
 * @brief Хранит соответствие между GUID процесса Sysmon и его метаданными для корректной интеграции телеметрии.
 */
    class SysmonProcessesMap {
    private:
        std::unordered_map<std::string, ProcessMetadata_2> guidMap;
        std::mutex mtx;

    public:
        /**
         * @brief Добавляет или обновляет метаданные процесса в карте.
         * @param guid Уникальный идентификатор процесса Sysmon.
         * @param pid Идентификатор процесса.
         * @param createTime Время создания процесса (FILETIME).
         */
        void UpdateData(const std::string& guid, DWORD pid, FILETIME createTime) {
            std::lock_guard<std::mutex> lock(mtx);
            auto& entry = guidMap[guid];
            entry.pid = pid;
            entry.createTime = createTime;
            entry.lastSeen = GetTickCount64();
        }

        /**
         * @brief Возвращает количество активных записей в карте.
         * @return Размер карты.
         */
        uint64_t size() {
            std::lock_guard<std::mutex> lock(mtx);
            return guidMap.size();
        }

        /**
         * @brief Проверяет наличие GUID в карте без извлечения данных.
         * @param guid Идентификатор процесса.
         * @return true, если GUID найден, иначе false.
         */
        bool Exists(const std::string& guid) {
            std::lock_guard<std::mutex> lock(mtx);
            return guidMap.find(guid) != guidMap.end();
        }

        /**
         * @brief Извлекает метаданные процесса по GUID.
         * @param guid Идентификатор процесса.
         * @param outMetadata Ссылка для записи найденных метаданных.
         * @return true, если процесс найден, иначе false.
         */
        bool TryGet(const std::string& guid, ProcessMetadata_2& outMetadata) {
            std::lock_guard<std::mutex> lock(mtx);
            auto it = guidMap.find(guid);
            if (it != guidMap.end()) {
                outMetadata = it->second;
                return true;
            }
            return false;
        }
    };

    /**
     * @brief Перечисление классов информации о процессе для Native API.
     */
    typedef enum _PROCESSINFOCLASS_CUSTOM {
        ProcessBasicInformation = 0,
        ProcessTimes = 4,
    } PROCESSINFOCLASS_CUSTOM;

    /**
     * @brief Структура для хранения времени выполнения процесса в режиме ядра и пользователя.
     */
    typedef struct _KERNEL_USER_TIMES {
        LARGE_INTEGER CreateTime;
        LARGE_INTEGER ExitTime;
        LARGE_INTEGER KernelTime;
        LARGE_INTEGER UserTime;
    } KERNEL_USER_TIMES, * PKERNEL_USER_TIMES;

    /**
     * @brief Структура базовой информации о процессе (аналог PROCESS_BASIC_INFORMATION).
     */
    typedef struct _MY_PROCESS_BASIC_INFORMATION {
        NTSTATUS ExitStatus;
        PVOID PebBaseAddress;
        ULONG_PTR AffinityMask;
        KPRIORITY BasePriority;
        ULONG_PTR UniqueProcessId;
        ULONG_PTR InheritedFromUniqueProcessId;
    } MY_PROCESS_BASIC_INFORMATION;

    /**
 * @brief Обогащает данные о процессе, запрашивая информацию у ОС через Native API.
 * @param pid Идентификатор процесса.
 * @param data Ссылка на структуру для заполнения собранными данными.
 */
    void EnrichProcessData(DWORD pid, StaticSysmonData& data) {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!hProcess) return;

        auto NtQueryInfo = (NTSTATUS(NTAPI*)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG))
            GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");

        if (!NtQueryInfo) {
            CloseHandle(hProcess);
            return;
        }

        // Заполнение пути исполняемого файла
        if (data.Image.empty()) {
            WCHAR pathBuffer[MAX_PATH];
            DWORD size = MAX_PATH;
            if (QueryFullProcessImageNameW(hProcess, 0, pathBuffer, &size)) {
                data.Image = WStringToString(pathBuffer);
            }
        }

        // Заполнение времени создания процесса
        if (data.createTime.dwLowDateTime == 0 && data.createTime.dwHighDateTime == 0) {
            KERNEL_USER_TIMES times = { 0 };
            if (NtQueryInfo(hProcess, (PROCESSINFOCLASS)ProcessTimes, &times, sizeof(times), NULL) == 0) {
                data.createTime.dwLowDateTime = times.CreateTime.LowPart;
                data.createTime.dwHighDateTime = times.CreateTime.HighPart;
            }
        }

        // Заполнение PID родительского процесса
        if (data.ParentProcessId == 0) {
            MY_PROCESS_BASIC_INFORMATION pbi = { 0 };
            if (NtQueryInfo(hProcess, (PROCESSINFOCLASS)ProcessBasicInformation, &pbi, sizeof(pbi), NULL) == 0) {
                data.ParentProcessId = (DWORD)pbi.InheritedFromUniqueProcessId;
            }
        }

        CloseHandle(hProcess);
    }

    /**
     * @brief Парсит XML-данные события Sysmon в структуру StaticSysmonData.
     * @param xml Строка, содержащая XML-разметку.
     * @return Заполненная структура с данными события.
     */
    StaticSysmonData ParseSysmonEvent(const std::string& xml) {
        StaticSysmonData data = {};

        auto GetValue = [&](const std::string& fieldName, bool isSystemTag) -> std::string {
            if (isSystemTag) {
                std::string openTag = "<" + fieldName + ">";
                std::string closeTag = "</" + fieldName + ">";
                size_t start = xml.find(openTag);
                if (start == std::string::npos) return "";

                start += openTag.length();
                size_t end = xml.find(closeTag, start);
                return (end != std::string::npos) ? xml.substr(start, end - start) : "";
            }
            else {
                std::string keyDouble = "Name=\"" + fieldName + "\">";
                std::string keySingle = "Name='" + fieldName + "'>";

                size_t pos = xml.find(keyDouble);
                size_t keyLen = keyDouble.length();

                if (pos == std::string::npos) {
                    pos = xml.find(keySingle);
                    keyLen = keySingle.length();
                }

                if (pos == std::string::npos) return "";

                size_t start = pos + keyLen;
                size_t end = xml.find("</Data>", start);
                return (end != std::string::npos) ? xml.substr(start, end - start) : "";
            }
            };

        data.UtcTime = GetValue("UtcTime", false);

        std::string eid = GetValue("EventID", true);
        if (!eid.empty()) {
            try { data.EventId = std::stoi(eid); }
            catch (...) { data.EventId = 0; }
        }

        data.ProcessGuid = GetValue("ProcessGuid", false);
        data.Image = GetValue("Image", false);

        std::string pidStr = GetValue("ProcessId", false);
        if (!pidStr.empty()) {
            try { data.ProcessId = std::stoul(pidStr); }
            catch (...) { data.ProcessId = 0; }
        }

        if (data.EventId == 1) {
            std::string cmd = GetValue("CommandLine", false);
            if (!cmd.empty()) {
                if (cmd.find("\\??\\") == 0) cmd = cmd.substr(4);
                std::replace(cmd.begin(), cmd.end(), '\n', ' ');
                data.commandLine = std::wstring(cmd.begin(), cmd.end());
            }

            std::string comp = GetValue("Company", false);
            data.companyName = std::wstring(comp.begin(), comp.end());

            std::string integ = GetValue("IntegrityLevel", false);
            if (integ == "System") data.integrityLevel = 4;
            else if (integ == "High") data.integrityLevel = 3;
            else if (integ == "Medium") data.integrityLevel = 2;
            else data.integrityLevel = 1;

            std::string pPid = GetValue("ParentProcessId", false);
            if (!pPid.empty()) {
                try { data.ParentProcessId = std::stoul(pPid); }
                catch (...) { data.ParentProcessId = 0; }
            }

            std::string pImg = GetValue("ParentImage", false);
            data.ParentImage = std::wstring(pImg.begin(), pImg.end());

            std::string pCmd = GetValue("ParentCommandLine", false);
            data.ParentCommandLine = std::wstring(pCmd.begin(), pCmd.end());

            std::string pUser = GetValue("ParentUser", false);
            data.ParentUser = std::wstring(pUser.begin(), pUser.end());

            std::string ParentProcessGuid = GetValue("ParentProcessGuid", false);
            data.ParentProcessGuid = std::wstring(ParentProcessGuid.begin(), ParentProcessGuid.end());
        }

        return data;
    }


}