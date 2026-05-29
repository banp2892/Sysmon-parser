#pragma once
#include <windows.h>
#include <winevt.h>
#include <vector>
#include <string>
#include "json.hpp"

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
}