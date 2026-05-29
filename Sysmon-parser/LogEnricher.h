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

        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);

        if (hProcess) {
            uint64_t current_cpu = ProcessMetrics::GetTotalCPUTime(hProcess);

            j["metrics"]["private_bytes"] = ProcessMetrics::GetPrivateBytes(hProcess);
            j["metrics"]["io"] = ProcessMetrics::GetIOCounters(hProcess);

            // Считаем дельту (слайс)
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