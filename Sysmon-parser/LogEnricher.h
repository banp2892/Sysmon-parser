#pragma once
#include "json.hpp"
#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <string>
#include <chrono>
#include <tlhelp32.h>
#include <cstdint>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "ntdll.lib")

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
            if (last_cpu_time > 0) {
                printf("[DEBUG] PID: %lu, Current: %llu, Last: %llu, Diff: %lld\n",
                    pid, current_cpu, last_cpu_time, (long long)(current_cpu - last_cpu_time));
            }

            j["metrics"]["private_bytes"] = ProcessMetrics::GetPrivateBytes(hProcess);
            j["metrics"]["io"] = ProcessMetrics::GetIOCounters(hProcess);

            j["metrics"]["thread_count"] = ProcessMetrics::GetThreadCount(pid);
            j["metrics"]["handle_count"] = ProcessMetrics::GetHandleCount(hProcess);

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