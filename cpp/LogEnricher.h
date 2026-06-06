#pragma once
#include "json.hpp"
#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <map>
#include <mutex>
#include <chrono>
#include <thread>
#include <tlhelp32.h>
#include <cstdint>
#include <sddl.h>
#include <wintrust.h>
#include <softpub.h>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "version.lib")
#pragma comment(lib, "wintrust.lib")

using json = nlohmann::json;

#define STATUS_SUCCESS ((NTSTATUS)0x00000000)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004)

typedef NTSTATUS(WINAPI* pfnNtQuerySystemInformationInternal)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

struct ProcessMetricsSnapshot {
    uint32_t threadCount = 0;
    uint32_t threadHighWatermark = 0;
    uint64_t handleCount = 0;
    uint32_t sessionId = 0;
    uint64_t uniqueProcessKey = 0;
    uint64_t cycleTime = 0;
    uint64_t hardFaultCount = 0;
    uint64_t workingSetPrivateSize = 0;

    double cpuPercentage = 0.0;
    double readSpeedBytesPerSec = 0.0;
    double writeSpeedBytesPerSec = 0.0;
    double otherSpeedBytesPerSec = 0.0;

    uint64_t vmPeakVirtualSize = 0;
    uint64_t vmVirtualSize = 0;
    uint32_t vmPageFaultCount = 0;
    uint64_t vmPeakWorkingSetSize = 0;
    uint64_t vmWorkingSetSize = 0;
    uint64_t vmQuotaPeakPagedPoolUsage = 0;
    uint64_t vmQuotaPagedPoolUsage = 0;
    uint64_t vmQuotaPeakNonPagedPoolUsage = 0;
    uint64_t vmQuotaNonPagedPoolUsage = 0;
    uint64_t vmPagefileUsage = 0;
    uint64_t vmPeakPagefileUsage = 0;
    uint64_t vmPrivateUsage = 0;
    uint64_t privatePageCount = 0;

    uint64_t ioReadOperations = 0;
    uint64_t ioWriteOperations = 0;
    uint64_t ioOtherOperations = 0;
    uint64_t ioReadTransferBytes = 0;
    uint64_t ioWriteTransferBytes = 0;
    uint64_t ioOtherTransferBytes = 0;

    struct ThreadSummary {
        uint32_t tid = 0;
        uint64_t createTime = 0;
        uint32_t state = 0;
        uint32_t waitReason = 0;
        uint64_t contextSwitches = 0;
        uint64_t startAddress = 0;
    };
    std::vector<ThreadSummary> activeThreads;
};

using TimeHistoryMap = std::map<uint64_t, ProcessMetricsSnapshot>;

struct StaticProcessContext {
    std::string name;
    std::string commandLine;
    std::string companyName;
    bool isSigned = false;
    uint64_t createTime = 0;
    DWORD parentPid = 0;
    std::string parentName;
    std::string parentSid;
    DWORD parentIntegrityLevel = 0;
    bool parentIsElevated = false;
    uint64_t parentStartTime = 0;
    bool parentIsService = false;
    bool parentIsSigned = false;
};

class SystemPerformanceTelemetryMonitor {
private:
    pfnNtQuerySystemInformationInternal m_pfnNtQuerySystemInformation = nullptr;
    std::vector<BYTE> m_telemetryBuffer;
    DWORD m_logicalProcessorCount = 1;
    bool m_isRunning = false;
    std::thread m_pollingThread;
    std::mutex m_dbMutex;

    std::unordered_map<DWORD, TimeHistoryMap> m_metricsHistoryDb;
    std::unordered_map<DWORD, StaticProcessContext> m_staticContextCache;

    struct InternalHistory {
        ULONGLONG lastKernelTime = 0;
        ULONGLONG lastUserTime = 0;
        ULONGLONG lastReadBytes = 0;
        ULONGLONG lastWriteBytes = 0;
        ULONGLONG lastOtherBytes = 0;
        std::chrono::steady_clock::time_point lastSampleTime;
    };
    std::unordered_map<DWORD, InternalHistory> m_internalHistoryDb;
    const size_t MAX_HISTORY_SAMPLES_PER_PROCESS = 10000;

    static inline bool IsFileSignedInternal(const std::wstring& filePath) {
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

    StaticProcessContext FetchStaticContext(DWORD pid, const std::wstring& fallbackName, uint64_t kernelCreateTime) {
        StaticProcessContext ctx;

        // Безопасная конвертация строки без использования дебаг-итераторов .begin() / .end()
        if (!fallbackName.empty()) {
            int size_needed = WideCharToMultiByte(CP_UTF8, 0, fallbackName.c_str(), (int)fallbackName.length(), NULL, 0, NULL, NULL);
            if (size_needed > 0) {
                ctx.name.resize(size_needed);
                WideCharToMultiByte(CP_UTF8, 0, fallbackName.c_str(), (int)fallbackName.length(), &ctx.name[0], size_needed, NULL, NULL);
            }
        }
        else {
            ctx.name = "Unknown";
        }

        ctx.createTime = kernelCreateTime;
        ctx.companyName = "Unknown";
        ctx.commandLine = "";

        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!hProcess) return ctx;

        wchar_t path[MAX_PATH];
        DWORD size = MAX_PATH;
        if (QueryFullProcessImageName(hProcess, 0, path, &size)) {
            std::wstring fullPath(path);
            size_t lastSlash = fullPath.find_last_of(L"\\/");
            std::wstring wName = (lastSlash != std::wstring::npos) ? fullPath.substr(lastSlash + 1) : fullPath;

            int s_needed = WideCharToMultiByte(CP_UTF8, 0, wName.c_str(), (int)wName.length(), NULL, 0, NULL, NULL);
            if (s_needed > 0) {
                ctx.name.resize(s_needed);
                WideCharToMultiByte(CP_UTF8, 0, wName.c_str(), (int)wName.length(), &ctx.name[0], s_needed, NULL, NULL);
            }

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
                            std::wstring compName(lpBuffer);
                            int c_needed = WideCharToMultiByte(CP_UTF8, 0, compName.c_str(), (int)compName.length(), NULL, 0, NULL, NULL);
                            if (c_needed > 0) {
                                ctx.companyName.resize(c_needed);
                                WideCharToMultiByte(CP_UTF8, 0, compName.c_str(), (int)compName.length(), &ctx.companyName[0], c_needed, NULL, NULL);
                            }
                        }
                    }
                }
            }
        }

        typedef NTSTATUS(WINAPI* pfnNtQueryInformationProcess)(HANDLE, ULONG, PVOID, ULONG, PULONG);
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        pfnNtQueryInformationProcess NtQueryInfoProc = hNtdll ? (pfnNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess") : nullptr;

        if (NtQueryInfoProc) {
            ULONG_PTR pbi[6];
            ULONG retLen;
            if (NtQueryInfoProc(hProcess, 0, &pbi, sizeof(pbi), &retLen) == 0) {
                PEB peb;
                SIZE_T bytesRead = 0;
                if (ReadProcessMemory(hProcess, (LPCVOID)pbi[1], &peb, sizeof(peb), &bytesRead)) {
                    RTL_USER_PROCESS_PARAMETERS params;
                    if (ReadProcessMemory(hProcess, (LPCVOID)peb.ProcessParameters, &params, sizeof(params), &bytesRead)) {
                        std::vector<wchar_t> cmdBuffer(params.CommandLine.Length / sizeof(wchar_t) + 1);
                        if (ReadProcessMemory(hProcess, (LPCVOID)params.CommandLine.Buffer, cmdBuffer.data(), params.CommandLine.Length, &bytesRead)) {
                            std::wstring cmdLine(cmdBuffer.data());
                            int cmd_needed = WideCharToMultiByte(CP_UTF8, 0, cmdLine.c_str(), (int)cmdLine.length(), NULL, 0, NULL, NULL);
                            if (cmd_needed > 0) {
                                ctx.commandLine.resize(cmd_needed);
                                WideCharToMultiByte(CP_UTF8, 0, cmdLine.c_str(), (int)cmdLine.length(), &ctx.commandLine[0], cmd_needed, NULL, NULL);
                            }
                        }
                    }
                }
            }
        }

        if (QueryFullProcessImageName(hProcess, 0, path, &size)) {
            ctx.isSigned = IsFileSignedInternal(path);
        }

        ctx.parentPid = 0;
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe32;
            pe32.dwSize = sizeof(PROCESSENTRY32);
            if (Process32First(hSnapshot, &pe32)) {
                do {
                    if (pe32.th32ProcessID == pid) {
                        ctx.parentPid = pe32.th32ParentProcessID;
                        break;
                    }
                } while (Process32Next(hSnapshot, &pe32));
            }
            CloseHandle(hSnapshot);
        }

        if (ctx.parentPid != 0) {
            HANDLE hParent = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, ctx.parentPid);
            if (hParent) {
                if (QueryFullProcessImageName(hParent, 0, path, &size)) {
                    std::wstring pFullPath(path);
                    size_t lastSlash = pFullPath.find_last_of(L"\\/");
                    std::wstring pName = (lastSlash != std::wstring::npos) ? pFullPath.substr(lastSlash + 1) : pFullPath;

                    int p_needed = WideCharToMultiByte(CP_UTF8, 0, pName.c_str(), (int)pName.length(), NULL, 0, NULL, NULL);
                    if (p_needed > 0) {
                        ctx.parentName.resize(p_needed);
                        WideCharToMultiByte(CP_UTF8, 0, pName.c_str(), (int)pName.length(), &ctx.parentName[0], p_needed, NULL, NULL);
                    }
                    ctx.parentIsSigned = IsFileSignedInternal(path);
                }

                FILETIME creation, exit, kernel, user;
                if (GetProcessTimes(hParent, &creation, &exit, &kernel, &user)) {
                    uint64_t intervals = (static_cast<uint64_t>(creation.dwHighDateTime) << 32) | creation.dwLowDateTime;
                    ctx.parentStartTime = (intervals / 10000000ULL) - 11644473600ULL;
                }

                DWORD pSessionId = 0;
                if (ProcessIdToSessionId(ctx.parentPid, &pSessionId) && pSessionId == 0) {
                    ctx.parentIsService = true;
                }

                HANDLE hToken;
                if (OpenProcessToken(hParent, TOKEN_QUERY, &hToken)) {
                    DWORD dwSize = 0;
                    GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize);
                    if (dwSize > 0) {
                        std::vector<BYTE> tokBuffer(dwSize);
                        PTOKEN_USER pTokenUser = reinterpret_cast<PTOKEN_USER>(tokBuffer.data());
                        if (GetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize)) {
                            LPWSTR sidString = NULL;
                            if (ConvertSidToStringSid(pTokenUser->User.Sid, &sidString)) {
                                std::wstring wSid(sidString);
                                int sid_needed = WideCharToMultiByte(CP_UTF8, 0, wSid.c_str(), (int)wSid.length(), NULL, 0, NULL, NULL);
                                if (sid_needed > 0) {
                                    ctx.parentSid.resize(sid_needed);
                                    WideCharToMultiByte(CP_UTF8, 0, wSid.c_str(), (int)wSid.length(), &ctx.parentSid[0], sid_needed, NULL, NULL);
                                }
                                LocalFree(sidString);
                            }
                        }
                    }

                    dwSize = 0;
                    GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwSize);
                    if (dwSize > 0) {
                        std::vector<BYTE> tokBuffer(dwSize);
                        PTOKEN_MANDATORY_LABEL pLabel = reinterpret_cast<PTOKEN_MANDATORY_LABEL>(tokBuffer.data());
                        if (GetTokenInformation(hToken, TokenIntegrityLevel, pLabel, dwSize, &dwSize)) {
                            if (pLabel && pLabel->Label.Sid) {
                                DWORD subAuth = *GetSidSubAuthority(pLabel->Label.Sid, 0);
                                if (subAuth == SECURITY_MANDATORY_LOW_RID) ctx.parentIntegrityLevel = 1;
                                else if (subAuth == SECURITY_MANDATORY_MEDIUM_RID) ctx.parentIntegrityLevel = 2;
                                else if (subAuth == SECURITY_MANDATORY_HIGH_RID) ctx.parentIntegrityLevel = 3;
                                else if (subAuth == SECURITY_MANDATORY_SYSTEM_RID) ctx.parentIntegrityLevel = 4;
                            }
                        }
                    }

                    TOKEN_ELEVATION elevation;
                    DWORD retSize;
                    if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &retSize)) {
                        ctx.parentIsElevated = (elevation.TokenIsElevated != 0);
                    }
                    CloseHandle(hToken);
                }
                CloseHandle(hParent);
            }
        }

        CloseHandle(hProcess);
        return ctx;
    }

    void PollingLoop() {
        while (m_isRunning) {
            auto loopStart = std::chrono::steady_clock::now();
            ExecuteMetricsCollection();

            auto loopEnd = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(loopEnd - loopStart);
            if (elapsed < std::chrono::milliseconds(200)) {
                std::this_thread::sleep_for(std::chrono::milliseconds(200) - elapsed);
            }
        }
    }

    void ExecuteMetricsCollection() {
        if (!m_pfnNtQuerySystemInformation) {
            std::cerr << "[DEBUG][Collector] Error: NtQuerySystemInformation pointer is null!\n";
            return;
        }

        ULONG requiredSize = 0;
        NTSTATUS status;
        auto queryStart = std::chrono::steady_clock::now();
        size_t retryCount = 0;

        // Loop for handling buffer resizing
        while (true) {
            status = m_pfnNtQuerySystemInformation(5, m_telemetryBuffer.data(), static_cast<ULONG>(m_telemetryBuffer.size()), &requiredSize);
            if (status == STATUS_INFO_LENGTH_MISMATCH) {
                retryCount++;
                m_telemetryBuffer.resize(requiredSize + 65536);
            }
            else {
                break;
            }
        }

        auto queryEnd = std::chrono::steady_clock::now();
        auto queryDuration = std::chrono::duration_cast<std::chrono::milliseconds>(queryEnd - queryStart).count();

        if (status != STATUS_SUCCESS) {
            std::cerr << "[DEBUG][Collector] NtQuerySystemInformation failed with status: 0x"
                << std::hex << status << std::dec << " after " << retryCount << " retries.\n";
            return;
        }

        auto currentTimePoint = std::chrono::steady_clock::now();
        uint64_t currentUnixTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count();

        BYTE* pCurrentPosition = m_telemetryBuffer.data();
        std::lock_guard<std::mutex> lock(m_dbMutex);

        size_t processedProcessesCount = 0;
        size_t totalThreadsTracked = 0;
        size_t cacheHits = 0;
        size_t cacheMisses = 0;

        while (pCurrentPosition) {
            processedProcessesCount++;

            // Parsing base properties via raw offsets for Windows NT x64 architecture
            ULONG numberOfThreads = *reinterpret_cast<ULONG*>(pCurrentPosition + 4);
            uint32_t threadHighWatermark = *reinterpret_cast<uint32_t*>(pCurrentPosition + 28);
            uint64_t cycleTime = *reinterpret_cast<uint64_t*>(pCurrentPosition + 32);
            uint64_t createTime = *reinterpret_cast<uint64_t*>(pCurrentPosition + 64);
            uint64_t userTime = *reinterpret_cast<uint64_t*>(pCurrentPosition + 72);
            uint64_t kernelTime = *reinterpret_cast<uint64_t*>(pCurrentPosition + 80);

            UNICODE_STRING* pImageName = reinterpret_cast<UNICODE_STRING*>(pCurrentPosition + 56);
            HANDLE uniqueProcessId = *reinterpret_cast<HANDLE*>(pCurrentPosition + 152);
            DWORD pid = static_cast<DWORD>(reinterpret_cast<uintptr_t>(uniqueProcessId));

            ULONG handleCount = *reinterpret_cast<ULONG*>(pCurrentPosition + 160);
            ULONG sessionId = *reinterpret_cast<ULONG*>(pCurrentPosition + 164);

            if (pid != 0) {
                std::wstring wideName = L"System/Unknown";
                if (pImageName->Buffer != nullptr && pImageName->Length > 0) {
                    USHORT charCount = pImageName->Length / sizeof(wchar_t);
                    if (charCount < MAX_PATH) {
                        wideName = std::wstring(pImageName->Buffer, charCount);
                    }
                }

                // Check static context cache performance
                if (m_staticContextCache.find(pid) == m_staticContextCache.end()) {
                    cacheMisses++;
                    m_staticContextCache[pid] = FetchStaticContext(pid, wideName, createTime);
                }
                else {
                    cacheHits++;
                }

                // VM Metrics via exact physical offsets of the SYSTEM_PROCESS_INFORMATION struct (x64)
                uint64_t vmPeakVirtualSize = *reinterpret_cast<SIZE_T*>(pCurrentPosition + 88);
                uint64_t vmVirtualSize = *reinterpret_cast<SIZE_T*>(pCurrentPosition + 96);
                uint32_t pageFaultCount = *reinterpret_cast<ULONG*>(pCurrentPosition + 104);
                uint64_t vmPeakWorkingSetSize = *reinterpret_cast<SIZE_T*>(pCurrentPosition + 112);
                uint64_t vmWorkingSetSize = *reinterpret_cast<SIZE_T*>(pCurrentPosition + 120);
                uint64_t quotaPeakPaged = *reinterpret_cast<SIZE_T*>(pCurrentPosition + 128);
                uint64_t quotaPaged = *reinterpret_cast<SIZE_T*>(pCurrentPosition + 136);
                uint64_t quotaPeakNonPaged = *reinterpret_cast<SIZE_T*>(pCurrentPosition + 144);
                uint64_t quotaNonPaged = *reinterpret_cast<SIZE_T*>(pCurrentPosition + 152);
                uint64_t pagefileUsage = *reinterpret_cast<SIZE_T*>(pCurrentPosition + 160);
                uint64_t peakPagefileUsage = *reinterpret_cast<SIZE_T*>(pCurrentPosition + 168);

                IO_COUNTERS* pIoCounters = reinterpret_cast<IO_COUNTERS*>(pCurrentPosition + 176);
                SIZE_T privatePageCount = *reinterpret_cast<SIZE_T*>(pCurrentPosition + 224);

                double cpuPercentage = 0.0;
                double readSpeed = 0.0, writeSpeed = 0.0, otherSpeed = 0.0;

                ULONGLONG currentRead = pIoCounters->ReadTransferCount;
                ULONGLONG currentWrite = pIoCounters->WriteTransferCount;
                ULONGLONG currentOther = pIoCounters->OtherTransferCount;

                if (m_internalHistoryDb.find(pid) != m_internalHistoryDb.end()) {
                    const auto& prev = m_internalHistoryDb[pid];
                    double elapsedSeconds = std::chrono::duration_cast<std::chrono::microseconds>(currentTimePoint - prev.lastSampleTime).count() / 1000000.0;

                    if (elapsedSeconds > 0.001) {
                        ULONGLONG deltaCpu = (kernelTime - prev.lastKernelTime) + (userTime - prev.lastUserTime);
                        cpuPercentage = (deltaCpu / (elapsedSeconds * 10000000.0 * m_logicalProcessorCount)) * 100.0;

                        // Debug log for anomaly CPU values before clamping
                        if (cpuPercentage > 100.0 || cpuPercentage < 0.0) {
                            std::cerr << "[WARNING][Collector] Anomaly CPU calculated for PID " << pid
                                << " (" << m_staticContextCache[pid].name << "): " << cpuPercentage
                                << "%, DeltaCpu: " << deltaCpu << ", Elapsed: " << elapsedSeconds << "s\n";
                            cpuPercentage = 100.0;
                        }

                        readSpeed = (currentRead - prev.lastReadBytes) / elapsedSeconds;
                        writeSpeed = (currentWrite - prev.lastWriteBytes) / elapsedSeconds;
                        otherSpeed = (currentOther - prev.lastOtherBytes) / elapsedSeconds;
                    }
                }

                m_internalHistoryDb[pid] = { kernelTime, userTime, currentRead, currentWrite, currentOther, currentTimePoint };

                ProcessMetricsSnapshot snap;
                snap.threadCount = numberOfThreads;
                snap.threadHighWatermark = threadHighWatermark;
                snap.handleCount = handleCount;
                snap.sessionId = sessionId;
                snap.cycleTime = cycleTime;
                snap.workingSetPrivateSize = vmWorkingSetSize;

                snap.cpuPercentage = cpuPercentage;
                snap.readSpeedBytesPerSec = readSpeed;
                snap.writeSpeedBytesPerSec = writeSpeed;
                snap.otherSpeedBytesPerSec = otherSpeed;

                snap.vmPeakVirtualSize = vmPeakVirtualSize;
                snap.vmVirtualSize = vmVirtualSize;
                snap.vmPageFaultCount = pageFaultCount;
                snap.vmPeakWorkingSetSize = vmPeakWorkingSetSize;
                snap.vmWorkingSetSize = vmWorkingSetSize;
                snap.vmQuotaPeakPagedPoolUsage = quotaPeakPaged;
                snap.vmQuotaPagedPoolUsage = quotaPaged;
                snap.vmQuotaPeakNonPagedPoolUsage = quotaPeakNonPaged;
                snap.vmQuotaNonPagedPoolUsage = quotaNonPaged;
                snap.vmPagefileUsage = pagefileUsage;
                snap.vmPeakPagefileUsage = peakPagefileUsage;
                snap.vmPrivateUsage = privatePageCount;
                snap.privatePageCount = privatePageCount;

                snap.ioReadOperations = pIoCounters->ReadOperationCount;
                snap.ioWriteOperations = pIoCounters->WriteOperationCount;
                snap.ioOtherOperations = pIoCounters->OtherOperationCount;
                snap.ioReadTransferBytes = pIoCounters->ReadTransferCount;
                snap.ioWriteTransferBytes = pIoCounters->WriteTransferCount;
                snap.ioOtherTransferBytes = pIoCounters->OtherTransferCount;

                // The thread array offset on x64 systems starts exactly at 232 bytes
                BYTE* pThreadsStart = pCurrentPosition + 232;
                const size_t SYSTEM_THREAD_INFO_SIZE = 80;

                if (numberOfThreads > 0) {
                    if (pThreadsStart + (numberOfThreads * SYSTEM_THREAD_INFO_SIZE) <= m_telemetryBuffer.data() + m_telemetryBuffer.size()) {
                        for (ULONG t = 0; t < numberOfThreads; ++t) {
                            BYTE* pCurrentThread = pThreadsStart + (t * SYSTEM_THREAD_INFO_SIZE);

                            ProcessMetricsSnapshot::ThreadSummary tSum;
                            HANDLE uniqueThreadId = *reinterpret_cast<HANDLE*>(pCurrentThread + 40);

                            tSum.tid = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(uniqueThreadId));
                            tSum.createTime = reinterpret_cast<LARGE_INTEGER*>(pCurrentThread + 16)->QuadPart;
                            tSum.state = *reinterpret_cast<ULONG*>(pCurrentThread + 64);
                            tSum.waitReason = *reinterpret_cast<ULONG*>(pCurrentThread + 68);
                            tSum.contextSwitches = *reinterpret_cast<ULONG*>(pCurrentThread + 56);
                            tSum.startAddress = *reinterpret_cast<uint64_t*>(pCurrentThread + 24);

                            snap.activeThreads.push_back(tSum);
                            totalThreadsTracked++;
                        }
                    }
                    else {
                        std::cerr << "[ERROR][Collector] Thread array bounds violation for PID " << pid
                            << ". Thread count: " << numberOfThreads << " exceeds telemetry buffer boundary!\n";
                    }
                }

                auto& history = m_metricsHistoryDb[pid];
                history[currentUnixTimestamp] = snap;

                if (history.size() > MAX_HISTORY_SAMPLES_PER_PROCESS) {
                    history.erase(history.begin());
                }
            }

            ULONG nextEntryOffset = *reinterpret_cast<ULONG*>(pCurrentPosition);
            if (nextEntryOffset == 0) break;
            pCurrentPosition += nextEntryOffset;
        }

        // Periodic high-level iteration telemetry summary (throttled conceptually via output execution metrics)
        static size_t iterationCounter = 0;
        if (++iterationCounter % 50 == 0) { // Outputs roughly every 10 seconds (50 * 200ms)
            std::cerr << "[INFO][Collector] --- Iteration #" << iterationCounter << " Telemetry Summary ---\n"
                << "  Buffer size: " << m_telemetryBuffer.size() << " bytes (API Query duration: " << queryDuration << " ms)\n"
                << "  Total parsed processes: " << processedProcessesCount << "\n"
                << "  Total active threads parsed: " << totalThreadsTracked << "\n"
                << "  Static context cache performance: Hits=" << cacheHits << ", Misses=" << cacheMisses << "\n"
                << "--------------------------------------------------------\n";
        }
    }

public:
    SystemPerformanceTelemetryMonitor() {
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (hNtdll) {
            m_pfnNtQuerySystemInformation = reinterpret_cast<pfnNtQuerySystemInformationInternal>(
                GetProcAddress(hNtdll, "NtQuerySystemInformation")
                );
        }
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        m_logicalProcessorCount = sysInfo.dwNumberOfProcessors;
        m_telemetryBuffer.resize(1024 * 1024);
    }

    ~SystemPerformanceTelemetryMonitor() { Stop(); }

    void Start() {
        m_isRunning = true;
        m_pollingThread = std::thread(&SystemPerformanceTelemetryMonitor::PollingLoop, this);
    }

    void Stop() {
        m_isRunning = false;
        if (m_pollingThread.joinable()) m_pollingThread.join();
    }

    json MergeSysmonLogWithTelemetry(const std::string& rawSysmonXml, DWORD pid, uint64_t sysmonTimestampSec) {
        json root;
        root["sysmon_raw_xml"] = rawSysmonXml;
        root["event_pid"] = pid;

        // 1. Извлекаем точный UtcTime из XML (миллисекунды)
        uint64_t sysmonTimestampMs = 0;
        size_t utcTimePos = rawSysmonXml.find("Name='UtcTime'>");

        if (utcTimePos != std::string::npos) {
            size_t start = rawSysmonXml.find(">", utcTimePos) + 1;
            size_t end = rawSysmonXml.find("</Data>", start);
            if (end != std::string::npos) {
                std::string utcStr = rawSysmonXml.substr(start, end - start);

                std::tm tm = {};
                std::istringstream ss(utcStr);
                ss >> std::get_time(&tm, "%Y-%m-%d %H:%M:%S");

                if (!ss.fail()) {
                    time_t timeSec = _mkgmtime(&tm);
                    sysmonTimestampMs = static_cast<uint64_t>(timeSec) * 1000;

                    size_t dotPos = utcStr.find('.');
                    if (dotPos != std::string::npos) {
                        std::string msStr = utcStr.substr(dotPos + 1, 3);
                        try { sysmonTimestampMs += std::stoul(msStr); }
                        catch (...) {}
                    }
                }
            }
        }

        uint64_t currentSystemTimeMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count();

        if (sysmonTimestampMs == 0) {
            sysmonTimestampMs = currentSystemTimeMs;
        }

        root["timestamp"] = sysmonTimestampMs / 1000;

        // --- НАЧАЛО ОТЛАДКИ: Входные параметры ---
        std::cerr << "[DEBUG][Merge] ==========================================\n"
            << "[DEBUG][Merge] Processing Log for PID: " << pid << "\n"
            << "[DEBUG][Merge] Sysmon Event Timestamp (ms): " << sysmonTimestampMs << "\n"
            << "[DEBUG][Merge] Current System Timestamp (ms): " << currentSystemTimeMs << "\n"
            << "[DEBUG][Merge] Event Delivery Latency (ms): " << (currentSystemTimeMs - sysmonTimestampMs) << "\n";
        // --------------------------------------------------

        std::lock_guard<std::mutex> lock(m_dbMutex);

        // ПОТОКИ РАЗДЕЛЕНЫ: Сначала собираем статический контекст, если он есть
        auto staticIt = m_staticContextCache.find(pid);
        if (staticIt != m_staticContextCache.end()) {
            std::cerr << "[DEBUG][Merge][Static Cache] HIT! Found context for PID: " << pid
                << " (Name: " << staticIt->second.name << ")\n";

            const auto& sCtx = staticIt->second;
            root["process_info"] = {
                {"name", sCtx.name},
                {"command_line", sCtx.commandLine},
                {"company", sCtx.companyName},
                {"is_signed", sCtx.isSigned},
                {"kernel_create_time", sCtx.createTime}
            };

            root["parent_info"] = {
                {"pid", sCtx.parentPid},
                {"name", sCtx.parentName},
                {"sid", sCtx.parentSid},
                {"integrity_level", sCtx.parentIntegrityLevel},
                {"is_elevated", sCtx.parentIsElevated},
                {"parent_start_time", sCtx.parentStartTime},
                {"is_service", sCtx.parentIsService},
                {"is_signed", sCtx.parentIsSigned}
            };
        }
        else {
            std::cerr << "[DEBUG][Merge][Static Cache] MISS! PID " << pid << " not found in cache.\n";
            root["process_info"] = { {"status", "not_in_static_cache_yet"} };
        }

        // Теперь отдельно собираем динамические метрики
        auto historyIt = m_metricsHistoryDb.find(pid);
        if (historyIt != m_metricsHistoryDb.end() && !historyIt->second.empty()) {
            const auto& history = historyIt->second;

            std::cerr << "[DEBUG][Merge][Dynamic Metrics] History found for PID: " << pid
                << " (Available samples: " << history.size() << ")\n";
            std::cerr << "[DEBUG][Merge][Dynamic Metrics] Oldest sample: " << history.begin()->first
                << ", Newest sample: " << history.rbegin()->first << "\n";

            auto it = history.lower_bound(sysmonTimestampMs);
            ProcessMetricsSnapshot bestSnap;
            uint64_t chosenTimestamp = 0;

            if (it != history.end()) {
                bestSnap = it->second;
                chosenTimestamp = it->first;
                int64_t timeDelta = static_cast<int64_t>(chosenTimestamp - sysmonTimestampMs);
                std::cerr << "[DEBUG][Merge][Dynamic Metrics] lower_bound matched sample: " << chosenTimestamp
                    << " (Delta to Sysmon: " << timeDelta << " ms)\n";
            }
            else {
                bestSnap = history.rbegin()->second;
                chosenTimestamp = history.rbegin()->first;
                int64_t timeDelta = static_cast<int64_t>(chosenTimestamp - sysmonTimestampMs);
                std::cerr << "[DEBUG][Merge][Dynamic Metrics] lower_bound hit end(). Fallback to newest sample: "
                    << chosenTimestamp << " (Delta to Sysmon: " << timeDelta << " ms)\n";
            }

            root["metrics"] = {
                {"thread_count", bestSnap.threadCount},
                {"thread_high_watermark", bestSnap.threadHighWatermark},
                {"handle_count", bestSnap.handleCount},
                {"session_id", bestSnap.sessionId},
                {"cycle_time", bestSnap.cycleTime},
                {"working_set_private_size", bestSnap.workingSetPrivateSize},
                {"cpu_percentage", bestSnap.cpuPercentage},
                {"speeds", {
                    {"read_bytes_sec", bestSnap.readSpeedBytesPerSec},
                    {"write_bytes_sec", bestSnap.writeSpeedBytesPerSec},
                    {"other_bytes_sec", bestSnap.otherSpeedBytesPerSec}
                }},
                {"virtual_memory", {
                    {"peak_virtual_size", bestSnap.vmPeakVirtualSize},
                    {"virtual_size", bestSnap.vmVirtualSize},
                    {"page_fault_count", bestSnap.vmPageFaultCount},
                    {"working_set_size", bestSnap.vmWorkingSetSize},
                    {"private_usage", bestSnap.vmPrivateUsage},
                    {"private_page_count", bestSnap.privatePageCount}
                }},
                {"io_counters", {
                    {"read_ops", bestSnap.ioReadOperations},
                    {"write_ops", bestSnap.ioWriteOperations},
                    {"read_transfer_bytes", bestSnap.ioReadTransferBytes},
                    {"write_transfer_bytes", bestSnap.ioWriteTransferBytes}
                }}
            };

            root["metrics"]["threads"] = json::array();
            for (const auto& t : bestSnap.activeThreads) {
                root["metrics"]["threads"].push_back({
                    {"tid", t.tid},
                    {"create_time", t.createTime},
                    {"state", t.state},
                    {"wait_reason", t.waitReason},
                    {"context_switches", t.contextSwitches}
                    });
            }
        }
        else {
            if (historyIt == m_metricsHistoryDb.end()) {
                std::cerr << "[DEBUG][Merge][Dynamic Metrics] FAILED. No history entry at all for PID: " << pid << "\n";
            }
            else {
                std::cerr << "[DEBUG][Merge][Dynamic Metrics] FAILED. History entry exists for PID " << pid << " but it is empty.\n";
            }
            root["metrics"] = { {"status", "no_historical_metrics_due_to_short_lifetime"} };
        }

        std::cerr << "[DEBUG][Merge] ==========================================\n\n";
        return root;
    }
};