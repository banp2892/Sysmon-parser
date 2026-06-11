#pragma once
#include "json.hpp"
#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <string>
#include <chrono>
#include <tlhelp32.h>
#include <cstdint>
#include <sddl.h>
#include <wintrust.h>
#include <softpub.h>


#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "version.lib")
#pragma comment(lib, "wintrust.lib")












/**
 * @struct ProcessMetadata
 * @brief Хранит детальную информацию о процессе для анализа. 
 */
struct ProcessMetadata {
    std::wstring name;               ///< Имя процесса
    std::wstring commandLine;        ///< Строка аргументов командной строки
    std::wstring companyName;        ///< Имя компании, чья подпись стоит на процессе
    uint64_t startTime;              ///< Время старта процесса
    bool isSigned;                   ///< Флаг, подтверждающий наличие валидной цифровой подписи
};

/**
 * @struct ParentProcessInfo
 * @brief Полная информация о родительском процессе, включая права доступа и метаданные.
 */
struct ParentProcessInfo {
    DWORD pid;                       ///< Идентификатор процесса (PID) родителя
    std::wstring name;               ///< Имя исполняемого файла процесса
    std::wstring commandLine;        ///< Строка аргументов командной строки
    std::wstring sid;                ///< Строковое представление SID владельца процесса
    DWORD integrityLevel;            ///< Уровень целостности (1:Low, 2:Medium, 3:High, 4:System)
    bool isElevated;                 ///< Флаг повышения прав (true, если запущен от имени администратора)
    uint64_t startTime;              ///< Время запуска родителя (Unix Timestamp)
    bool isService;                  ///< Признак того, что процесс является системной службой
    bool isSigned;                   ///< Флаг, подтверждающий наличие валидной цифровой подписи

    /**
     * @brief Конструктор по умолчанию.
     * @param pPid PID родительского процесса.
     */
    ParentProcessInfo(DWORD pPid = 0)
        : pid(pPid), name(L"Unknown"), commandLine(L""),
        sid(L""), integrityLevel(0), isElevated(false),
        startTime(0), isService(false), isSigned(false) {
    }
};


/**
 * @struct StaticSysmonData
 * @brief Структура для хранения разобранных данных события Sysmon.
 */
struct StaticSysmonData {
    ///< Можно собрать из почти каждого ивента
    int EventId; ///< Номер приходящего ивента
    uint64_t UtcTime; ///< Время формирования ивента
    std::string Image; ///< Полный путь к исполняемогу файл, можно взять от сюда имя процесса (есть во многих ивентах)
    DWORD ProcessId; ///< PID процесса (есть во многих ивентах)

    ///< Если есть EventId1
    std::wstring commandLine;        ///< Строка аргументов командной строки
    std::wstring companyName;        ///< Имя компании, чья подпись стоит на процессе
    DWORD integrityLevel;            ///< Уровень целостности (1:Low, 2:Medium, 3:High, 4:System)
    std::wstring ParentProcessGuid;  ///< [ParentProcessGuid] GUID родительского процесса
    DWORD ParentProcessId;           ///< [ParentProcessId] PID родительского процесса
    std::wstring ParentImage;        ///< [ParentImage] Путь к исполняемому файлу родителя
    std::wstring ParentCommandLine;  ///< [ParentCommandLine] Командная строка родителя
    std::wstring ParentUser;         ///< [ParentUser] Имя пользователя родительского процесса
};


/**
 * @brief Парсит XML-строку события Sysmon и заполняет структуру StaticSysmonData.
 * * @param xml Строка, содержащая XML-разметку события Sysmon.
 * @return Заполненная структура StaticSysmonData с данными события.
 */
StaticSysmonData ParseSysmonEvent(const std::string& xml) {
    StaticSysmonData data = {};

    /**
     * @brief Внутренняя лямбда-функция для поиска значений тегов.
     * @param fieldName Имя тега или имя параметра Data Name.
     * @param isSystemTag Флаг: true, если ищем обычный XML тег, false - если ищем атрибут Data Name.
     */
    auto GetValue = [&](const std::string& fieldName, bool isSystemTag) -> std::string {
        std::string pattern = isSystemTag ? ("<" + fieldName + ">") : ("Name=\"" + fieldName + "\"");
        size_t start = xml.find(pattern);
        if (start == std::string::npos) return "";

        if (!isSystemTag) {
            start = xml.find(">", start);
            if (start == std::string::npos) return "";
            start += 1;
        }
        else {
            start += pattern.length();
        }

        size_t end = xml.find(isSystemTag ? ("</" + fieldName + ">") : "</Data>", start);
        return (end != std::string::npos) ? xml.substr(start, end - start) : "";
        };

    // Парсинг ID события
    std::string eid = GetValue("EventID", true);
    if (!eid.empty()) data.EventId = std::stoi(eid);

    // Основные данные процесса
    data.Image = GetValue("Image", false);

    std::string pidStr = GetValue("ProcessId", false);
    if (!pidStr.empty()) data.ProcessId = std::stoul(pidStr);

    // Обработка командной строки (удаление префикса NT и замена переносов)
    std::string cmd = GetValue("CommandLine", false);
    if (cmd.find("\\??\\") == 0) cmd = cmd.substr(4);
    std::replace(cmd.begin(), cmd.end(), '\n', ' ');
    data.commandLine = std::wstring(cmd.begin(), cmd.end());

    // Имя компании
    data.companyName = std::wstring(GetValue("Company", false).begin(), GetValue("Company", false).end());

    // Уровень целостности
    std::string integ = GetValue("IntegrityLevel", false);
    if (integ == "System") data.integrityLevel = 4;
    else if (integ == "High") data.integrityLevel = 3;
    else if (integ == "Medium") data.integrityLevel = 2;
    else data.integrityLevel = 1;

    // Данные родительского процесса
    std::string pPidStr = GetValue("ParentProcessId", false);
    if (!pPidStr.empty()) data.ParentProcessId = std::stoul(pPidStr);

    data.ParentImage = std::wstring(GetValue("ParentImage", false).begin(), GetValue("ParentImage", false).end());
    data.ParentCommandLine = std::wstring(GetValue("ParentCommandLine", false).begin(), GetValue("ParentCommandLine", false).end());
    data.ParentUser = std::wstring(GetValue("ParentUser", false).begin(), GetValue("ParentUser", false).end());

    return data;
}





/**
 * @namespace ProcessMetrics
 * @brief Вспомогательные функции для сбора метрик процесса.
 */
namespace ProcessMetrics {











    /**
     * @brief Получает объем частной памяти процесса (Private Bytes).
     * @param hProcess Дескриптор процесса.
     * @return uint64_t Объем памяти в байтах.
     */
    inline uint64_t GetPrivateBytes(HANDLE hProcess) {
        PROCESS_MEMORY_COUNTERS_EX pmc;
        if (GetProcessMemoryInfo(hProcess, (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc))) {
            return static_cast<uint64_t>(pmc.PrivateUsage);
        }
        return 0;
    }




    /**
     * @brief Получает счетчики ввода-вывода (I/O) процесса.
     * @param hProcess Дескриптор процесса.
     * @return nlohmann::json JSON-объект со счетчиками операций.
     */
    inline nlohmann::json GetIOCounters(HANDLE hProcess) {
        IO_COUNTERS io;
        nlohmann::json j;
        if (GetProcessIoCounters(hProcess, &io)) {
            j["read_bytes"] = static_cast<uint64_t>(io.ReadTransferCount);
            j["write_bytes"] = static_cast<uint64_t>(io.WriteTransferCount);
            j["other_bytes"] = static_cast<uint64_t>(io.OtherTransferCount);
        }
        else {
            j["read_bytes"] = 0;
            j["write_bytes"] = 0;
            j["other_bytes"] = 0;
        }
        return j;
    }

    /**
     * @brief Вычисляет суммарное время CPU (User + Kernel mode).
     * * @param hProcess Дескриптор открытого процесса.
     * @return uint64_t Суммарное время в 100-наносекундных интервалах.
     * @note Используется для расчета интенсивности нагрузки (CPU Slice).
     */
    inline uint64_t GetTotalCPUTime(HANDLE hProcess) {
        FILETIME creationTime, exitTime, kernelTime, userTime;
        if (GetProcessTimes(hProcess, &creationTime, &exitTime, &kernelTime, &userTime)) {
            auto to_uint64 = [](const FILETIME& ft) {
                return (static_cast<uint64_t>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
                };
            return to_uint64(kernelTime) + to_uint64(userTime);
        }
        return 0;
    }

    /**
     * @brief Проверяет наличие валидной цифровой подписи у файла.
     */
    inline bool IsFileSigned(const std::wstring& filePath) {
        if (filePath.empty()) return false;
        WINTRUST_FILE_INFO fileInfo = { 0 };
        fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
        fileInfo.pcwszFilePath = filePath.c_str();

        WINTRUST_DATA trustData = { 0 };
        trustData.cbStruct = sizeof(WINTRUST_DATA);
        trustData.dwUIChoice = WTD_UI_NONE;
        trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
        trustData.dwUnionChoice = WTD_CHOICE_FILE;
        trustData.dwStateAction = WTD_STATEACTION_VERIFY;
        trustData.pFile = &fileInfo;

        GUID guidAction = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        LONG result = WinVerifyTrust(NULL, &guidAction, &trustData);

        trustData.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(NULL, &guidAction, &trustData);

        return (result == ERROR_SUCCESS);
    }


    /**
    * @brief Получает текущее количество потоков процесса по его PID.
    * @param pid Идентификатор процесса.
    * @return DWORD Количество потоков.
    */
    inline DWORD GetThreadCount(DWORD pid) {
        DWORD threadCount = 0;
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

        if (hSnapshot != INVALID_HANDLE_VALUE) {
            THREADENTRY32 te;
            te.dwSize = sizeof(THREADENTRY32);

            if (Thread32First(hSnapshot, &te)) {
                do {
                    if (te.th32OwnerProcessID == pid) {
                        threadCount++;
                    }
                } while (Thread32Next(hSnapshot, &te));
            }
            CloseHandle(hSnapshot);
        }
        return threadCount;
    }

    /**
     * @brief Получает количество открытых дескрипторов.
     * @param hProcess Дескриптор процесса.
     * @return DWORD Количество дескрипторов.
     */
    inline DWORD GetHandleCount(HANDLE hProcess) {
        DWORD count = 0;
        if (GetProcessHandleCount(hProcess, &count)) {
            return count;
        }
        return 0;
    }

    /**
     * @brief Получает родительский PID для текущего процесса через Toolhelp32.
     * @param pid PID процесса, для которого ищем родителя.
     * @return DWORD Родительский PID (или 0, если не найден).
     */
    inline DWORD GetParentProcessId(DWORD pid) {
        DWORD parentPid = 0;
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe32;
            pe32.dwSize = sizeof(PROCESSENTRY32);
            if (Process32First(hSnapshot, &pe32)) {
                do {
                    if (pe32.th32ProcessID == pid) {
                        parentPid = pe32.th32ParentProcessID;
                        break;
                    }
                } while (Process32Next(hSnapshot, &pe32));
            }
            CloseHandle(hSnapshot);
        }
        return parentPid;
    }

    /**
     * @brief Получает полную информацию о родительском процессе по его PID.
     * @param parentPid PID родительского процесса.
     * @return ParentProcessInfo Структура с собранными данными.
     */
    inline ParentProcessInfo GetParentDetails(DWORD parentPid) {
        ParentProcessInfo info(parentPid);

        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, parentPid);
        if (!hProcess) return info;

        // Получаем имя 
        wchar_t path[MAX_PATH];
        DWORD size = MAX_PATH;
        if (QueryFullProcessImageName(hProcess, 0, path, &size)) {
            std::wstring fullPath(path);
            size_t lastSlash = fullPath.find_last_of(L"\\/");
            info.name = (lastSlash != std::wstring::npos) ? fullPath.substr(lastSlash + 1) : fullPath;

        }
        // Получаем коммандную строку родителя
        ULONG returnLength;
        NtQueryInformationProcess(hProcess, (PROCESSINFOCLASS)60, NULL, 0, &returnLength);
        if (returnLength > 0) {
            std::vector<BYTE> buffer(returnLength);
            if (NtQueryInformationProcess(hProcess, (PROCESSINFOCLASS)60, buffer.data(), returnLength, &returnLength) == 0) {
                PUNICODE_STRING pCmdLine = (PUNICODE_STRING)buffer.data();
                info.commandLine = std::wstring(pCmdLine->Buffer, pCmdLine->Length / sizeof(wchar_t));
            }
        }

        // Проверяем цифорвую подпись
        if (QueryFullProcessImageName(hProcess, 0, path, &size)) {
            info.isSigned = ProcessMetrics::IsFileSigned(path);
        }

        // Получаем время запуска
        FILETIME creation, exit, kernel, user;
        if (GetProcessTimes(hProcess, &creation, &exit, &kernel, &user)) {
            uint64_t intervals = (static_cast<uint64_t>(creation.dwHighDateTime) << 32) | creation.dwLowDateTime;
            info.startTime = (intervals / 10000000ULL) - 11644473600ULL;
        }

        // Проверка на службу (Parent_Is_Service)
        DWORD sessionId = 0;
        if (ProcessIdToSessionId(parentPid, &sessionId)) {
            // Службы чаще всего работают в Session 0
            if (sessionId == 0) {
                info.isService = true;
            }
        }

        // Получаем токен для прав безопасности
        HANDLE hToken;
        if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
            // SID
            DWORD dwSize = 0;
            GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize);
            std::vector<BYTE> buffer(dwSize);
            PTOKEN_USER pTokenUser = reinterpret_cast<PTOKEN_USER>(buffer.data());
            if (GetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize)) {
                LPWSTR sidString = NULL;
                if (ConvertSidToStringSid(pTokenUser->User.Sid, &sidString)) {
                    info.sid = sidString;
                    LocalFree(sidString);
                }
            }

            // Integrity Level
            GetTokenInformation(hToken, TokenIntegrityLevel, buffer.data(), dwSize, &dwSize);
            PTOKEN_MANDATORY_LABEL pLabel = reinterpret_cast<PTOKEN_MANDATORY_LABEL>(buffer.data());
            DWORD subAuth = *GetSidSubAuthority(pLabel->Label.Sid, 0);
            if (subAuth == SECURITY_MANDATORY_LOW_RID) info.integrityLevel = 1;
            else if (subAuth == SECURITY_MANDATORY_MEDIUM_RID) info.integrityLevel = 2;
            else if (subAuth == SECURITY_MANDATORY_HIGH_RID) info.integrityLevel = 3;
            else if (subAuth == SECURITY_MANDATORY_SYSTEM_RID) info.integrityLevel = 4;

            // Elevation
            TOKEN_ELEVATION elevation;
            DWORD retSize;
            if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &retSize)) {
                info.isElevated = (elevation.TokenIsElevated != 0);
            }

            CloseHandle(hToken);
        }

        CloseHandle(hProcess);
        return info;
    }


    /**
     * @brief Получает имя, командную строку и издателя процесса по его PID.
     * @param pid Идентификатор процесса.
     * @return ProcessMetadata Структура с собранными данными.
     */
    inline ProcessMetadata GetProcessDetails(DWORD pid) {
        ProcessMetadata meta = { L"Unknown", L"", L"Unknown", false };
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!hProcess) return meta;

        wchar_t path[MAX_PATH];
        DWORD size = MAX_PATH;
        if (QueryFullProcessImageName(hProcess, 0, path, &size)) {
            // Имя файла
            std::wstring fullPath(path);
            size_t lastSlash = fullPath.find_last_of(L"\\/");
            meta.name = (lastSlash != std::wstring::npos) ? fullPath.substr(lastSlash + 1) : fullPath;

            // Издатель (через версию файла)
            DWORD dwHandle;
            DWORD dwVerSize = GetFileVersionInfoSize(path, &dwHandle);
            if (dwVerSize > 0) {
                std::vector<BYTE> buffer(dwVerSize);
                if (GetFileVersionInfo(path, 0, dwVerSize, buffer.data())) {
                    struct LANGANDCODEPAGE { WORD wLanguage; WORD wCodePage; } *lpTranslate;
                    UINT cbTranslate;
                    if (VerQueryValue(buffer.data(), L"\\VarFileInfo\\Translation", (LPVOID*)&lpTranslate, &cbTranslate)) {
                        wchar_t subBlock[100];
                        wsprintf(subBlock, L"\\StringFileInfo\\%04x%04x\\CompanyName", lpTranslate[0].wLanguage, lpTranslate[0].wCodePage);
                        LPWSTR lpBuffer;
                        UINT dwBytes;
                        if (VerQueryValue(buffer.data(), subBlock, (LPVOID*)&lpBuffer, &dwBytes)) {
                            meta.companyName = std::wstring(lpBuffer);
                        }
                    }
                }
            }
        }
        // Командная строка (через PEB)
        ULONG_PTR pbi[6];
        ULONG retLen;
        if (NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen) == 0) {
            PEB peb;
            if (ReadProcessMemory(hProcess, (LPCVOID)pbi[1], &peb, sizeof(peb), NULL)) {
                RTL_USER_PROCESS_PARAMETERS params;
                if (ReadProcessMemory(hProcess, (LPCVOID)peb.ProcessParameters, &params, sizeof(params), NULL)) {
                    std::vector<wchar_t> buffer(params.CommandLine.Length / sizeof(wchar_t) + 1);
                    if (ReadProcessMemory(hProcess, (LPCVOID)params.CommandLine.Buffer, buffer.data(), params.CommandLine.Length, NULL)) {
                        meta.commandLine = std::wstring(buffer.data());
                    }
                }
            }
        }

        // Проверка на подпись
        if (QueryFullProcessImageName(hProcess, 0, path, &size)) {
            meta.isSigned = ProcessMetrics::IsFileSigned(path);
        }

        // Время старта процесса
        FILETIME creation, exit, kernel, user;
        if (GetProcessTimes(hProcess, &creation, &exit, &kernel, &user)) {
            uint64_t intervals = (static_cast<uint64_t>(creation.dwHighDateTime) << 32) | creation.dwLowDateTime;
            // Конвертация в Unix Timestamp (секунды с 1970)
            meta.startTime = (intervals / 10000000ULL) - 11644473600ULL;
        }

        CloseHandle(hProcess);
        return meta;
    }

    


}

/**
 * @namespace LogEnricher
 * @brief Основной модуль для формирования JSON-логов.
 */
namespace LogEnricher {
    /**
     * @brief Обогащает лог данными о ресурсах процесса с проверкой состояния.
     * @param xmlData Исходный XML.
     * @param pid PID процесса.
     * @return nlohmann::json JSON-объект.
     */
    inline nlohmann::json Enrich(const std::string& xmlData, DWORD pid, uint64_t last_cpu_time = 0) {
        nlohmann::json j;
        j["timestamp"] = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        j["data"] = xmlData;

        if (pid == 0) {
            j["metrics"]["status"] = "Invalid PID";
            return j;
        }

        HANDLE hProcess = OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            FALSE,
            pid
        );

        if (hProcess) {
            uint64_t current_cpu = ProcessMetrics::GetTotalCPUTime(hProcess);


            j["metrics"]["private_bytes"] = ProcessMetrics::GetPrivateBytes(hProcess); ///< Количество частной памяти процесса?
            j["metrics"]["io"] = ProcessMetrics::GetIOCounters(hProcess); ///< Количество ввода и вывода процесса в байтах?

            j["metrics"]["thread_count"] = ProcessMetrics::GetThreadCount(pid); ///< текущее количество потоков процесса
            j["metrics"]["handle_count"] = ProcessMetrics::GetHandleCount(hProcess); ///< количество открытых декскрипторов

            ProcessMetadata meta = ProcessMetrics::GetProcessDetails(pid);
            j["process_info"]["name"] = std::string(meta.name.begin(), meta.name.end());
            j["process_info"]["company"] = std::string(meta.companyName.begin(), meta.companyName.end());
            j["process_info"]["command_line"] = std::string(meta.commandLine.begin(), meta.commandLine.end());
            j["process_info"] ["is_signed"] = meta.isSigned;
            j["process_info"]["startTime"] = meta.startTime;

            DWORD pPid = ProcessMetrics::GetParentProcessId(pid);
            ParentProcessInfo pInfo = ProcessMetrics::GetParentDetails(pPid);

            j["parent_info"] = {
            {"pid", pInfo.pid},
            {"name", std::string(pInfo.name.begin(), pInfo.name.end())},
            {"sid", std::string(pInfo.sid.begin(), pInfo.sid.end())},
            {"integrity_level", pInfo.integrityLevel},
            {"is_elevated", pInfo.isElevated},
            {"parent_start_time", pInfo.startTime },
            { "is_service", pInfo.isService },
            {"is_signed", pInfo.isSigned}
            };


            // Считаем дельту @todo это можно перенести в питон, а тут сохранять только время цп?
            if (last_cpu_time > 0 && current_cpu > last_cpu_time) {
                j["metrics"]["cpu_slice"] = current_cpu - last_cpu_time;
            }
            else {
                j["metrics"]["cpu_slice"] = 0;
            }

            // Сохраняем текущее для будущего сравнения
            j["metrics"]["_raw_cpu"] = current_cpu;

            CloseHandle(hProcess);
        }
        else {
            DWORD err = GetLastError();
            
            j["metrics"]["status"] = "error";
            j["metrics"]["error_code"] = err;

            
            if (err == ERROR_INVALID_PARAMETER) {
                j["metrics"]["error_type"] = "process_finished";
            }
            else if (err == ERROR_ACCESS_DENIED) {
                j["metrics"]["error_type"] = "access_denied";
            }
            else {
                j["metrics"]["error_type"] = "unknown";
            }
        }

        return j;
    }
}