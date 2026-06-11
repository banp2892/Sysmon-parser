#pragma once
#include <windows.h>
#include <winevt.h>
#include <vector>
#include <string>
#include "json.hpp"
#include <winternl.h>


#pragma comment(lib, "wevtapi.lib")

/**
 * @namespace SysmonCollector
 * @brief Модуль для сбора и первичной обработки событий Sysmon.
 */
namespace SysmonCollector {

    /**
     * @brief Преобразует wstring в string (UTF-8).
     * @param wstr Исходная широкая строка.
     * @return std::string Строка в кодировке UTF-8.
     */
    inline std::string WStringToString(const std::wstring& wstr) {
        int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
        std::string str(size_needed, 0);
        WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &str[0], size_needed, NULL, NULL);
        return str;
    }

    /**
     * @brief Получает XML-представление события Sysmon.
     * @param hEvent Дескриптор события Windows.
     * @return std::string XML-строка события.
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
     * @brief Извлекает идентификатор события (EventID) из XML-события.
     * @param xml Строка XML.
     * @return DWORD Идентификатор события или 0, если тег не найден.
     */
    inline DWORD GetEventIdFromXml(const std::string& xml) {
        // Тег EventID находится в блоке <System>, который идет в начале XML
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
     * @brief Извлекает идентификатор процесса (PID) из XML-события.
     * @param xml Строка XML.
     * @return DWORD Идентификатор процесса или 0, если тег не найден.
     */
    inline DWORD GetPidFromXml(const std::string& xml) {
        // 1. Сначала отрезаем часть <System>, чтобы не найти там лишний PID
        size_t eventDataPos = xml.find("<EventData>");
        if (eventDataPos == std::string::npos) return 0;

        // 2. Ищем PID именно внутри блока EventData
        // Ищем ключ Name='ProcessId' или Name="ProcessId" (учитывая разные кавычки)
        std::string searchKey = "Name='ProcessId'>";
        size_t namePos = xml.find(searchKey, eventDataPos);

        // Если не нашли с одинарными кавычками, ищем с двойными
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


    enum ProcessStatus {
        STATUS_NEW = 0,
        STATUS_EVENT_ID_1 = 1,
        STATUS_SNAPSHOT = 2,
        STATUS_DEAD = 3
    };

    struct ProcessMetadata_2{
        DWORD pid = 0;
        FILETIME createTime = { 0, 0 };
        ProcessStatus status = STATUS_NEW;
        ULONGLONG lastSeen = 0;
    };


    /*
    * @brief Для склеивания с метриками и хранения данных о процессах, разделяемых GUID`ом
    */
    class SysmonProcessesMap {
    private:
        std::unordered_map<std::string, ProcessMetadata_2> guidMap; ///< Для склеивания с метриками
        std::mutex mtx; ///< для защиты карты процессов

    public:



        /**
        * @brief Добавляет или обновляет данные по ключу
        */
        void UpdateData(const std::string& guid, DWORD pid, FILETIME createTime, ProcessStatus status) {
            std::lock_guard<std::mutex> lock(mtx); ///< анлочить не надо, поскольку после завершения выполнения функции, деструктор мьютекса анлокнет его сам)
            auto& entry = guidMap[guid];
            entry.pid = pid;
            entry.createTime = createTime;
            entry.status = status;
            entry.lastSeen = GetTickCount64();
        }


        /**
         * @brief Быстрая проверка на существование (без копирования данных)
         */
        bool Exists(const std::string& guid) {
            std::lock_guard<std::mutex> lock(mtx);
            return guidMap.find(guid) != guidMap.end();
        }


        /**
         * @brief Пытается найти процесс по GUID
         * @return true, если процесс найден, и записывает данные в outMetadata
         */
        bool TryGet(const std::string& guid, ProcessMetadata_2& outMetadata) {
            std::lock_guard<std::mutex> lock(mtx); // Блокируем для безопасного чтения

            auto it = guidMap.find(guid); // Ищем элемент
            if (it != guidMap.end()) {
                outMetadata = it->second; // Копируем данные
                return true;
            }
            return false; // Элемента нет
        }
    };

    typedef enum _PROCESSINFOCLASS_CUSTOM {
        ProcessBasicInformation = 0,
        ProcessTimes = 4,
    } PROCESSINFOCLASS_CUSTOM;

    // 2. Структура KERNEL_USER_TIMES
    typedef struct _KERNEL_USER_TIMES {
        LARGE_INTEGER CreateTime;
        LARGE_INTEGER ExitTime;
        LARGE_INTEGER KernelTime;
        LARGE_INTEGER UserTime;
    } KERNEL_USER_TIMES, * PKERNEL_USER_TIMES;

    // 3. Исправленная структура PROCESS_BASIC_INFORMATION
    // В winternl.h она часто неполная. Используем эту версию:
    typedef struct _MY_PROCESS_BASIC_INFORMATION {
        NTSTATUS ExitStatus;
        PVOID PebBaseAddress;
        ULONG_PTR AffinityMask;
        KPRIORITY BasePriority;
        ULONG_PTR UniqueProcessId;
        ULONG_PTR InheritedFromUniqueProcessId; // Тот самый член, на который ругается компилятор
    } MY_PROCESS_BASIC_INFORMATION;


    void EnrichProcessData(DWORD pid, StaticSysmonData& data) {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!hProcess) return;

        auto NtQueryInfo = (NTSTATUS(NTAPI*)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG))
            GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");

        if (!NtQueryInfo) {
            CloseHandle(hProcess);
            return;
        }

        // --- ЗАПОЛНЯЕМ Image ---
        if (data.Image.empty()) {
            WCHAR pathBuffer[MAX_PATH];
            DWORD size = MAX_PATH;
            if (QueryFullProcessImageNameW(hProcess, 0, pathBuffer, &size)) {
                data.Image = WStringToString(pathBuffer);
            }
        }

        // --- ЗАПОЛНЯЕМ CreateTime ---
        if (data.createTime.dwLowDateTime == 0 && data.createTime.dwHighDateTime == 0) {
            KERNEL_USER_TIMES times = { 0 };
            // Приводим enum к (PROCESSINFOCLASS)
            if (NtQueryInfo(hProcess, (PROCESSINFOCLASS)ProcessTimes, &times, sizeof(times), NULL) == 0) {
                // КОПИРУЕМ ЧЕРЕЗ LOW/HIGH PART
                data.createTime.dwLowDateTime = times.CreateTime.LowPart;
                data.createTime.dwHighDateTime = times.CreateTime.HighPart;
            }
        }

        // --- ЗАПОЛНЯЕМ ParentProcessId ---
        if (data.ParentProcessId == 0) {
            // Используем твою кастомную структуру как буфер
            MY_PROCESS_BASIC_INFORMATION pbi = { 0 };
            // Приводим enum к (PROCESSINFOCLASS)
            if (NtQueryInfo(hProcess, (PROCESSINFOCLASS)ProcessBasicInformation, &pbi, sizeof(pbi), NULL) == 0) {
                data.ParentProcessId = (DWORD)pbi.InheritedFromUniqueProcessId;
            }
        }

        CloseHandle(hProcess);
    }


    /**
    * @struct StaticSysmonData
    * @brief Структура для хранения разобранных данных события Sysmon.
    */
    struct StaticSysmonData {
        ///< Можно собрать из почти каждого ивента

        int EventId; ///< Номер приходящего ивента
        //uint64_t UtcTime; ///< Время формирования ивента
        
        std::string Image; ///< Полный путь к исполняемогу файл, можно взять от сюда имя процесса (есть во многих ивентах)
        DWORD ProcessId; ///< PID процесса (есть во многих ивентах)
        std::string ProcessGuid; ///< Уникальный GUID процесса в рамках Sysmon


        ///< Собирается отдельной функцией
        FILETIME createTime; ///< Время создания процесса


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


        ///< Копируем GUID процесса:
        std::string procGuid = GetValue("ProcessGuid", false);
        if (!procGuid.empty()) {
            data.ProcessGuid = procGuid;
        }

        // Парсинг ID события
        std::string eid = GetValue("EventID", true);
        if (!eid.empty()) data.EventId = std::stoi(eid);

        // Основные данные процесса
        data.Image = GetValue("Image", false);

        std::string pidStr = GetValue("ProcessId", false);
        if (!pidStr.empty()) data.ProcessId = std::stoul(pidStr);

        // Обработка командной строки (удаление префикса NT и замена переносов)
        if (stoi(eid) == 1) {
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
        }
        return data;
    }







}