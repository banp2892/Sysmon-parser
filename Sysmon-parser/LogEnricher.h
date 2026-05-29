#pragma once
#include "json.hpp"
#include <windows.h>
#include <psapi.h>
#include <string>
#include <chrono>
#include <cstdint>

#pragma comment(lib, "psapi.lib")

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
    inline nlohmann::json Enrich(const std::string& xmlData, DWORD pid) {
        nlohmann::json j;
        j["timestamp"] = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        j["data"] = xmlData;

        if (pid == 0) {
            j["metrics"]["status"] = "Invalid PID";
            return j;
        }

        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);

        if (hProcess) {
            j["metrics"]["private_bytes"] = ProcessMetrics::GetPrivateBytes(hProcess);
            j["metrics"]["io"] = ProcessMetrics::GetIOCounters(hProcess);
            CloseHandle(hProcess);
        }
        else {
            DWORD err = GetLastError();
            if (err == ERROR_INVALID_PARAMETER || err == ERROR_ACCESS_DENIED) {
                j["metrics"]["status"] = "Process likely finished or protected";
            }
            else {
                j["metrics"]["status"] = "Error code: " + std::to_string(err);
            }
        }

        return j;
    }
}