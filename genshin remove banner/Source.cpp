#include <iostream>
#include <windows.h>
#include <tlhelp32.h>
#include <vector>

HANDLE hProcess;

template <typename T>
T Read(LPVOID Address)
{
    T Data;
    ReadProcessMemory(hProcess, (LPVOID)Address, &Data, sizeof(T), nullptr);
    return Data;
}

template <typename T>
void Write(LPVOID Address, T Data)
{
    WriteProcessMemory(hProcess, (LPVOID)Address, &Data, sizeof(T), nullptr);
}

DWORD GetProcId(const wchar_t* procName)
{
    DWORD procId = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 procEntry;
        procEntry.dwSize = sizeof(procEntry);
        if (Process32First(hSnap, &procEntry)) {
            do {
                if (!_wcsicmp(procEntry.szExeFile, procName)) {
                    procId = procEntry.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnap, &procEntry));
        }
    }
    CloseHandle(hSnap);
    return procId;
}

uintptr_t GetModuleBaseAddress(DWORD procId, const wchar_t* modName)
{
    uintptr_t modBaseAddr = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procId);
    if (hSnap != INVALID_HANDLE_VALUE) {
        MODULEENTRY32 modEntry;
        modEntry.dwSize = sizeof(modEntry);
        if (Module32First(hSnap, &modEntry)) {
            do {
                if (!_wcsicmp(modEntry.szModule, modName)) {
                    modBaseAddr = (uintptr_t)modEntry.modBaseAddr;
                    break;
                }
            } while (Module32Next(hSnap, &modEntry));
        }
    }
    CloseHandle(hSnap);
    return modBaseAddr;
}

void SearchAndReplace(HANDLE hProcess, const std::vector<BYTE>& searchBytes, const std::vector<BYTE>& replaceBytes)
{
    // Get system information to determine the range of valid memory addresses
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    // Calculate the size of the search pattern
    size_t searchSize = searchBytes.size();

    // Iterate over the entire memory space of the process
    for (BYTE* pAddress = (BYTE*)sysInfo.lpMinimumApplicationAddress; pAddress < sysInfo.lpMaximumApplicationAddress; pAddress += sysInfo.dwPageSize) {
        // Read the memory at the current address
        std::vector<BYTE> buffer(searchSize);
        SIZE_T bytesRead;
        if (ReadProcessMemory(hProcess, pAddress, buffer.data(), searchSize, &bytesRead)) {
            // Check if the read memory matches the search pattern
            if (std::equal(buffer.begin(), buffer.end(), searchBytes.begin())) {
                // Write the replacement bytes to the found address
                WriteProcessMemory(hProcess, pAddress, replaceBytes.data(), replaceBytes.size(), nullptr);
            }
        }
    }
}

int main()
{
    // get the game's process id
    DWORD procId = GetProcId(L"GenshinImpact.exe");

    if (procId) {
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, NULL, procId);
        std::cout << "Successfully attached to the process." << std::endl;

        // Perform operations on the attached process here
        uintptr_t address1 = GetModuleBaseAddress(procId, L"mhyprot.dll") + 0x377064;
        Write<int>(LPVOID(address1), 50);
        uintptr_t address2 = GetModuleBaseAddress(procId, L"mhyprot.dll") + 0x377050;
        Write<int>(LPVOID(address2), 7);
        std::cout << "Successfully wrote value to memory." << std::endl;

        // Continuously check and rewrite values at specified memory addresses
        while (true) {
            int value1 = Read<int>(LPVOID(address1));
            if (value1 != 50) {
                Write<int>(LPVOID(address1), 50);
            }
            int value2 = Read<int>(LPVOID(address2));
            if (value2 != 7) {
                Write<int>(LPVOID(address2), 7);
            }
            Sleep(2*60*1000); // Sleep for 2 mins to avoid high CPU usage
        }

    }
    else {
        std::cout << "Process not found! Press enter to exit!";
    }

    getchar();
    return 0;
}