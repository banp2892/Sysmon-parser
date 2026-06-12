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


