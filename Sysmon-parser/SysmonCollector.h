#pragma once
#include <windows.h>
#include <winevt.h>
#include <vector>
#include <string>
#include <chrono>
#include "nlohmann/json.hpp"

#pragma comment(lib, "wevtapi.lib")

namespace SysmonCollector {
    /*
    * @brief Преобразует wstring в string
    */
    inline std::string WStringToString(const std::wstring& wstr) {
        int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
        std::string str(size_needed, 0);
        WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &str[0], size_needed, NULL, NULL);
        return str;
    }

    /*
    * @brief Получает лог от Sysmon и преобразует его в json строку
    * @return string - весь json файл спаршенный
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
}