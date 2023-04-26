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

// Function to check if a process is running
bool IsProcessRunning(const wchar_t* processName) {
    bool exists = false;
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    if (Process32First(snapshot, &entry)) {
        while (Process32Next(snapshot, &entry)) {
            if (wcscmp(entry.szExeFile, processName) == 0) {
                exists = true;
                break;
            }
        }
    }

    CloseHandle(snapshot);
    return exists;
}

bool IsAdmin() {
    BOOL isAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID pAdministratorsGroup;

    // Allocate memory for the SID
    if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &pAdministratorsGroup)) {
        // Check if the current process is a member of the Administrators group
        if (!CheckTokenMembership(NULL, pAdministratorsGroup, &isAdmin)) {
            isAdmin = FALSE;
        }

        // Free the allocated memory for the SID
        FreeSid(pAdministratorsGroup);
    }

    return isAdmin != FALSE;
}

int main()
{


    SetConsoleTitle(L"GENSHIN BANNER REMOVER BY ELJoOker#8401");

    if (!IsAdmin()) {
        std::cout << "Warning: Not running with admin privileges. please run as adminstartor to make it work." << std::endl;
        Sleep(5000);
        exit(0);
    }
    

    std::cout << "Made with love by ELJoOker#8401\n\n\n";
    Sleep(2000);
    // Get the current directory
    char currentDirectory[MAX_PATH];
    GetModuleFileNameA(NULL, currentDirectory, MAX_PATH);
    std::string currentDirectoryStr(currentDirectory);
    std::size_t found = currentDirectoryStr.find_last_of("\\/");
    std::string path = currentDirectoryStr.substr(0, found + 1);

    // Specify the name of the executable to run
    std::string exeName = "injector.exe";

    // Build the full path to the executable
    std::string exePath = path + exeName;

    // Start the process
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    if (CreateProcessA(NULL, const_cast<char*>(exePath.c_str()), NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
    {
        std::cout << "Process started successfully.\n";
        // Optionally, you can wait for the process to finish using WaitForSingleObject
        // WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    else
    {
        std::cerr << "Failed to start process. Error code: " << GetLastError() << "\n";
        return 1;
    }
    // Process ID of the target process to attach to
   // Name of the process to wait for
    const wchar_t* processName = L"GenshinImpact.exe";
    std::cout << "Waiting for process to start...\n";
    // Wait for the process to start
    while (!IsProcessRunning(processName)) {

        Sleep(1000);
    }

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
            DWORD procId = GetProcId(L"GenshinImpact.exe");
            if (procId == 0) {
                std::cout << "Genshin Impact has closed" << std::endl;
                 DWORD procId = GetProcId(L"GenshinImpact.exe");
            if (procId == 0) {
                std::cout << "Genshin Impact has closed" << std::endl;
                exit(0);
            }
            }
            Sleep(50); 
        }

    }
    else {
        std::cout << "Process not found! Press enter to exit!";
    }

    getchar();
    return 0;
}