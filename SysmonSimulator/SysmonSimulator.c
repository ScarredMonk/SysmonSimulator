#include <winsock.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <windns.h>
#include <tchar.h>
#include <winternl.h>
#include <winnt.h>
#include <tchar.h>
#include <dbghelp.h>
#include <tlhelp32.h>
#include <time.h>

#pragma comment(lib,"WS2_32")
#pragma comment(lib,"dnsapi")
#pragma comment(lib, "ntdll")

EXTERN_C NTSTATUS NTAPI NtTerminateProcess(HANDLE, NTSTATUS);
EXTERN_C NTSTATUS NTAPI NtReadVirtualMemory(HANDLE, PVOID, PVOID, ULONG, PULONG);
EXTERN_C NTSTATUS NTAPI NtWriteVirtualMemory(HANDLE, PVOID, PVOID, ULONG, PULONG);
EXTERN_C NTSTATUS NTAPI NtGetContextThread(HANDLE, PCONTEXT);
EXTERN_C NTSTATUS NTAPI NtSetContextThread(HANDLE, PCONTEXT);
EXTERN_C NTSTATUS NTAPI NtUnmapViewOfSection(HANDLE, PVOID);
EXTERN_C NTSTATUS NTAPI NtResumeThread(HANDLE, PULONG);

typedef NTSTATUS(WINAPI* _NtQueryInformationProcess) (
    HANDLE,
    PROCESSINFOCLASS,
    PVOID,
    ULONG,
    PULONG
    );

typedef NTSTATUS(WINAPI* _NtUnmapViewOfSection) (
    HANDLE,
    PVOID
    );

typedef struct BASE_RELOCATION_ENTRY {
    USHORT Offset : 12;
    USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;



void printText(char* ptr, WORD newColor) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
    WORD saved_attributes;
    GetConsoleScreenBufferInfo(hConsole, &consoleInfo);
    saved_attributes = consoleInfo.wAttributes;
    SetConsoleTextAttribute(hConsole, newColor);
    printf("%s", ptr);
    SetConsoleTextAttribute(hConsole, saved_attributes);
}


int ProcessCreate1() {

    LPSTR cmdline = "calc.exe";
    HANDLE hProcess = INVALID_HANDLE_VALUE;
    STARTUPINFOA sinfo = { 0 };
    sinfo.cb = sizeof(STARTUPINFOA);
    PROCESS_INFORMATION pinfo = { 0 };

    if (hProcess == INVALID_HANDLE_VALUE) {
        if (!CreateProcessA(NULL, cmdline, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &sinfo, &pinfo))
        {
            printText("[-] Error creating process: ", FOREGROUND_RED);
            printf("%d (Check gestlasterror 2 or net HELPMSG 2)\n", GetLastError());
            return 0;
        }
        else {
            printf("[+] Process Name : calc.exe\n");
            int createdPID = pinfo.dwProcessId;
            printf("[+] Process ID   : %d \n", pinfo.dwProcessId);
            CloseHandle(pinfo.hProcess);
            CloseHandle(pinfo.hThread);
        }
    }
    return 0;
}

int FileCreateTime2() {

    FILETIME ft1 = { 0 };

    HANDLE hFile = CreateFile(
        L"SysmonCreateFileTime.txt",     // Filename
        GENERIC_WRITE,          // Desired access
        FILE_SHARE_READ,        // Share mode
        NULL,                   // Security attributes
        CREATE_ALWAYS,             // Creates a new file, only if it doesn't already exist
        FILE_ATTRIBUTE_NORMAL,  // Flags and attributes
        NULL);                  // Template file handle

    if (hFile == INVALID_HANDLE_VALUE)
    {
        // Failed to open/create file
        printf("[-] Could not create file SysmonCreateFileTime.txt. Error code is: %d\n", GetLastError());
        return 2;
    }
    else {
        printf("[+] File Creation: SysmonCreateFileTime.txt is created in the same directory\n");
    }
    ft1.dwLowDateTime = ft1.dwLowDateTime - 900000000;
    if (!SetFileTime(hFile, &ft1, NULL, NULL)) {
        printf("[-] Error changing file creation time : %d\n", GetLastError());
    }
    else {
        printf("[+] Time changed : Creation time of file SysmonCreateFileTime.txt is changed\n");
    }

    return 0;
}

int NetworkConnect3() {
    WSADATA version;
    WSAStartup(MAKEWORD(2, 2), &version);
    u_short port = 31337;

    SOCKET newSocket;
    struct sockaddr_in addr;
    newSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("45.33.32.156");
    addr.sin_port = htons(port);

    if (connect(newSocket, (SOCKADDR*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        printText("[+] Description  : Tried to initiate a network connection to port 31337 on NMAP which is closed\n", FOREGROUND_RED);
    }
    else {
        printf("[+] Description  : Tried to initiate a network connection to port 31337 on NMAP which is opened\n");
        printf("[+] Successful   : Created Network connection Event successfully\n");
    }

    closesocket(newSocket);
    WSACleanup();
    return 0;
}

int processtermination5(process_id)
{
    HANDLE hProcessToKill;
    hProcessToKill = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id);
    if (hProcessToKill == NULL) {
        printf("[-] Error getting handle for PID %d. Error code is : %d\n", process_id, GetLastError());
    }
    else
    {
        TerminateProcess(hProcessToKill, 1);
        CloseHandle(hProcessToKill);
    }
    return 0;
}

int driverLoad6() {
    //UNICODE_STRING RegPath;
    //NTSTATUS Status;
    ///* Try to load ourself */
    //RtlInitUnicodeString(&RegPath, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\HTTP");
    ///* Load the driver */
    //
    //Status = ZwLoadDriver(&RegPath);
    //
    //return NT_SUCCESS(Status);
    return 0;

}

int ImageLoaded7() {
    HMODULE hntdll = LoadLibraryA("GameChatOverlayExt.dll");
    if (hntdll) {
        wprintf(L"[+] Image Loaded : Loaded GameChatOverlayExt.dll\n");
    }
    return 0;
}

int createRemoteThread8(int process_id) {
    HANDLE processHandle;
    HANDLE rThread;
    PVOID buff;

    //Messagebox Shellcode
    unsigned char shellcode[] =
        "\x48\x83\xEC\x28\x48\x83\xE4\xF0\x48\x8D\x15\x66\x00\x00\x00"
        "\x48\x8D\x0D\x52\x00\x00\x00\xE8\x9E\x00\x00\x00\x4C\x8B\xF8"
        "\x48\x8D\x0D\x5D\x00\x00\x00\xFF\xD0\x48\x8D\x15\x5F\x00\x00"
        "\x00\x48\x8D\x0D\x4D\x00\x00\x00\xE8\x7F\x00\x00\x00\x4D\x33"
        "\xC9\x4C\x8D\x05\x61\x00\x00\x00\x48\x8D\x15\x4E\x00\x00\x00"
        "\x48\x33\xC9\xFF\xD0\x48\x8D\x15\x56\x00\x00\x00\x48\x8D\x0D"
        "\x0A\x00\x00\x00\xE8\x56\x00\x00\x00\x48\x33\xC9\xFF\xD0\x4B"
        "\x45\x52\x4E\x45\x4C\x33\x32\x2E\x44\x4C\x4C\x00\x4C\x6F\x61"
        "\x64\x4C\x69\x62\x72\x61\x72\x79\x41\x00\x55\x53\x45\x52\x33"
        "\x32\x2E\x44\x4C\x4C\x00\x4D\x65\x73\x73\x61\x67\x65\x42\x6F"
        "\x78\x41\x00\x48\x65\x6C\x6C\x6F\x20\x77\x6F\x72\x6C\x64\x00"
        "\x4D\x65\x73\x73\x61\x67\x65\x00\x45\x78\x69\x74\x50\x72\x6F"
        "\x63\x65\x73\x73\x00\x48\x83\xEC\x28\x65\x4C\x8B\x04\x25\x60"
        "\x00\x00\x00\x4D\x8B\x40\x18\x4D\x8D\x60\x10\x4D\x8B\x04\x24"
        "\xFC\x49\x8B\x78\x60\x48\x8B\xF1\xAC\x84\xC0\x74\x26\x8A\x27"
        "\x80\xFC\x61\x7C\x03\x80\xEC\x20\x3A\xE0\x75\x08\x48\xFF\xC7"
        "\x48\xFF\xC7\xEB\xE5\x4D\x8B\x00\x4D\x3B\xC4\x75\xD6\x48\x33"
        "\xC0\xE9\xA7\x00\x00\x00\x49\x8B\x58\x30\x44\x8B\x4B\x3C\x4C"
        "\x03\xCB\x49\x81\xC1\x88\x00\x00\x00\x45\x8B\x29\x4D\x85\xED"
        "\x75\x08\x48\x33\xC0\xE9\x85\x00\x00\x00\x4E\x8D\x04\x2B\x45"
        "\x8B\x71\x04\x4D\x03\xF5\x41\x8B\x48\x18\x45\x8B\x50\x20\x4C"
        "\x03\xD3\xFF\xC9\x4D\x8D\x0C\x8A\x41\x8B\x39\x48\x03\xFB\x48"
        "\x8B\xF2\xA6\x75\x08\x8A\x06\x84\xC0\x74\x09\xEB\xF5\xE2\xE6"
        "\x48\x33\xC0\xEB\x4E\x45\x8B\x48\x24\x4C\x03\xCB\x66\x41\x8B"
        "\x0C\x49\x45\x8B\x48\x1C\x4C\x03\xCB\x41\x8B\x04\x89\x49\x3B"
        "\xC5\x7C\x2F\x49\x3B\xC6\x73\x2A\x48\x8D\x34\x18\x48\x8D\x7C"
        "\x24\x30\x4C\x8B\xE7\xA4\x80\x3E\x2E\x75\xFA\xA4\xC7\x07\x44"
        "\x4C\x4C\x00\x49\x8B\xCC\x41\xFF\xD7\x49\x8B\xCC\x48\x8B\xD6"
        "\xE9\x14\xFF\xFF\xFF\x48\x03\xC3\x48\x83\xC4\x28\xC3";

    printf("[+] Inject into  : PID %i\n", process_id);

    processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id);
    printf("[+] Opened process's handle\n");

    buff = VirtualAllocEx(processHandle, NULL, sizeof(shellcode), (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);

    if (buff) {
        WriteProcessMemory(processHandle, buff, shellcode, sizeof(shellcode), NULL);
        rThread = CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)buff, NULL, 0, NULL);
        printf("[+] Created Remote Thread\n");
        CloseHandle(processHandle);
        printf("[+] Closed Handle to the process\n");
    }
    else {
        printf("[-] Error code is : %d\n", GetLastError());
    }
    return 0;
}

int processaccess10(process_id) {
    printf("Opening process with PID: %lu\n", process_id);
    HANDLE hProcessToAccess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, process_id);
    if (!hProcessToAccess) {
        printf("Err 0: %lu\n", GetLastError());
        return 0;
    }
    else
    {
        printf("Opening process handle\n");
        CloseHandle(hProcessToAccess);
    }
    return 0;
}

int fileCreate11() {
    HANDLE hFile = CreateFile(
        L"NewFile.bat",
        GENERIC_WRITE,
        FILE_SHARE_READ,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("[!] Could not create file NewFile.bat\n");
        return 2;
    }
    else {
        printf("[+] Created File : NewFile.bat\n");
        CloseHandle(hFile);
    }
    return 0;
}


BOOL CreateRegistryKey()
{
    HKEY  hKey;
    if (RegCreateKeyA(HKEY_CURRENT_USER, "TestSysmon", &hKey) != ERROR_SUCCESS) {
        printf("[!] Error opening or creating key.\n");
        return FALSE;
    }
    else {
        RegCloseKey(hKey);
        return TRUE;
    }
}

BOOL writeStringInRegistry()
{
    HKEY hKey;
    if (RegOpenKeyEx(HKEY_CURRENT_USER, L"TestSysmon", 0, KEY_WRITE, &hKey) == ERROR_SUCCESS)
    {
        if (ERROR_SUCCESS != RegSetValueEx(hKey, L"Message", 0, REG_SZ, (LPBYTE)(L"Testing"), ((((DWORD)strlen("Tested") + 1)) * 2)))
        {
            RegCloseKey(hKey);
            printf("FALSE.\n");
            return FALSE;
        }
        RegCloseKey(hKey);
        return TRUE;
    }
    return FALSE;
}

INT registryEvent12()
{
    BOOL status;
    status = CreateRegistryKey();

    if (status != TRUE)
        return FALSE;
    else {
        printf("[+] Successful   : Registry object created\n");
    }
    return 0;
}

INT registryEvent13()
{
    BOOL status;

    HKEY subKey = NULL;
    LONG result = RegOpenKeyEx(HKEY_CURRENT_USER, L"TestSysmon", 0, KEY_READ, &subKey);
    if (result != ERROR_SUCCESS) {
        CreateRegistryKey();
    }
    status = writeStringInRegistry(); //write string
    if (status != TRUE)
        return FALSE;
    printf("[+] Successful   : Registry value modified to 'Tested'\n");

    return 0;
}

INT registryEvent14()
{
    RegRenameKey(
        HKEY_CURRENT_USER,
        L"TestSysmon",
        L"TestSysmonRenamed"
    );
    return 0;
}


int fileCreateStreamHash15() {
    DWORD dwRet;
    static const char testdata[] = "Hello World";
    WIN32_FIND_STREAM_DATA streaminfo = { 0 };
    HANDLE hFile = CreateFileA("Streamfile.txt:SysmonStream", GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[!] Could not create stream for file Streamfile.txt\n");
        printf("E: %lu\n", GetLastError());
    }
    else {
        printf("[+] Successful   : Created stream for file Streamfile.txt\n");
        WriteFile(hFile, "Sysmon simulator has written in ADS SysmonStream of Streamfile.txt", 67, &dwRet, NULL);
    }
    return 0;
}

int pipeCreated17() {
    HANDLE hPipe = NULL;
    SECURITY_ATTRIBUTES secAt = { 0 };
    static LPCSTR lpName = "\\\\.\\pipe\\sysmontestnamedpipe";
    hPipe = CreateNamedPipeA(lpName,
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_BYTE | PIPE_WAIT,
        10,
        2048,
        2048,
        0,
        &secAt);
    if (hPipe == INVALID_HANDLE_VALUE)
    {
        printf("CreateNamedPipeA(): FAILED\n");
        return 0;
    }
    else {
        printf("[+] Successful   : Pipe %s has been created\n", lpName);
    }
    return 0;
}

int pipeConnect18() {
    HANDLE hPipe, hConnectPipe;
    SECURITY_ATTRIBUTES secAt = { 0 };
    static LPCSTR lpName = "\\\\.\\pipe\\sysmontestconnectpipe";

    hPipe = CreateNamedPipeA(lpName,
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_BYTE | PIPE_WAIT,
        10,
        2048,
        2048,
        0,
        &secAt);
    if (hPipe == INVALID_HANDLE_VALUE)
    {
        printf("CreateNamedPipeA(): FAILED\n");
        return 0;
    }
    else {
        printf("[+] Successful   : Pipe %s has been connected\n", lpName);
    }
    hConnectPipe = CreateFileA(lpName, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, 0, NULL, OPEN_EXISTING, FILE_FLAG_WRITE_THROUGH, NULL);
    if (hConnectPipe == INVALID_HANDLE_VALUE) {
        printf("Error: %lu\n", GetLastError());
        return 0;
    }
    CloseHandle(hPipe);
    return 0;
}

int dnsquery22() {
    DWORD response = 0;
    PDNS_RECORD base = NULL;
    DWORD options = DNS_QUERY_WIRE_ONLY;
    PIP4_ARRAY pSrvList = NULL;
    unsigned short wType = { 0 };

    response = DnsQuery_A("google.com", wType, options, pSrvList, &base, NULL);
    if (response) {
        printf("[+] Successful   : Performed DNS Lookup for 'google.com' \n");
    }
    else {
        printf("[+] Tried to perform lookup for domain 'google.com' but got an error \n");
        printf("[!} Error is: %lu\n", GetLastError());
    }
    return 0;
}


int setClipboard24() {

    const char* output = "New Sysmon Test data in clipboard";
    const size_t len = strlen(output) + 1;

    HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, len);

    if (hMem) {
        memcpy(GlobalLock(hMem), output, len);
        GlobalUnlock(hMem);
        OpenClipboard(0);
        EmptyClipboard();
        SetClipboardData(CF_TEXT, hMem);
        CloseClipboard();
    }

    return 0;

}

int deleteFile26() {
    HANDLE hFile = CreateFile(
        L"NewFile.bat",
        GENERIC_WRITE,
        FILE_SHARE_READ,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    CloseHandle(hFile);

    BOOL deleted = DeleteFile(L"test.txt");
    if (!deleted) {
        printf("[-] Error deleting file: %d\n", GetLastError());
    }
    return 0;
}

int processTampering25()
{
    PIMAGE_DOS_HEADER pDosH;
    PIMAGE_NT_HEADERS pNtH;
    PIMAGE_SECTION_HEADER pSecH;
    PVOID image, mem, base;
    DWORD i, read, nSizeOfFile;
    HANDLE hFile;

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    CONTEXT ctx;

    ctx.ContextFlags = CONTEXT_FULL;

    memset(&si, 0, sizeof(si));
    memset(&pi, 0, sizeof(pi));

    LPSTR replacement = "c:\\windows\\system32\\cmd.exe";
    LPSTR target = "c:\\Windows\\System32\\svchost.exe";

    if (!CreateProcessA(NULL, replacement, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
    {
        printf("\nError: Unable to run the target executable. CreateProcess failed with error %d\n", GetLastError());
        return 1;
    }

    hFile = CreateFileA(target, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("\nError: Unable to open the replacement executable. CreateFile failed with error %d\n", GetLastError());

        NtTerminateProcess(pi.hProcess, 1);
        return 1;
    }

    nSizeOfFile = GetFileSize(hFile, NULL);

    image = VirtualAlloc(NULL, nSizeOfFile, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!ReadFile(hFile, image, nSizeOfFile, &read, NULL))
    {
        printf("\nError: Unable to read the replacement executable. ReadFile failed with error %d\n", GetLastError());

        NtTerminateProcess(pi.hProcess, 1);
        return 1;
    }

    NtClose(hFile);

    pDosH = (PIMAGE_DOS_HEADER)image;

    if (pDosH->e_magic != IMAGE_DOS_SIGNATURE)
    {
        printf("\nError: Invalid executable format.\n");
        NtTerminateProcess(pi.hProcess, 1);
        return 1;
    }

    pNtH = (PIMAGE_NT_HEADERS)((LPBYTE)image + pDosH->e_lfanew);

    NtGetContextThread(pi.hThread, &ctx);

#ifdef _WIN64
    NtReadVirtualMemory(pi.hProcess, (PVOID)(ctx.Rdx + (sizeof(SIZE_T) * 2)), &base, sizeof(PVOID), NULL);
#endif

#ifdef _X86_
    NtReadVirtualMemory(pi.hProcess, (PVOID)(ctx.Ebx + 8), &base, sizeof(PVOID), NULL);
#endif
    if ((SIZE_T)base == pNtH->OptionalHeader.ImageBase)
    {
        printf("\nUnmapping original executable image from child process. Address: %#zx\n", (SIZE_T)base);
        NtUnmapViewOfSection(pi.hProcess, base);
    }

    mem = VirtualAllocEx(pi.hProcess, (PVOID)pNtH->OptionalHeader.ImageBase, pNtH->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!mem)
    {
        printf("\nError: Unable to allocate memory in child process. VirtualAllocEx failed with error %d\n", GetLastError());

        NtTerminateProcess(pi.hProcess, 1);
        return 1;
    }

    NtWriteVirtualMemory(pi.hProcess, mem, image, pNtH->OptionalHeader.SizeOfHeaders, NULL);

    for (i = 0; i < pNtH->FileHeader.NumberOfSections; i++)
    {
        pSecH = (PIMAGE_SECTION_HEADER)((LPBYTE)image + pDosH->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));
        NtWriteVirtualMemory(pi.hProcess, (PVOID)((LPBYTE)mem + pSecH->VirtualAddress), (PVOID)((LPBYTE)image + pSecH->PointerToRawData), pSecH->SizeOfRawData, NULL);
    }


#ifdef _WIN64
    ctx.Rcx = (SIZE_T)((LPBYTE)mem + pNtH->OptionalHeader.AddressOfEntryPoint);
    NtWriteVirtualMemory(pi.hProcess, (PVOID)(ctx.Rdx + (sizeof(SIZE_T) * 2)), &pNtH->OptionalHeader.ImageBase, sizeof(PVOID), NULL);
#endif

#ifdef _X86_
    ctx.Eax = (SIZE_T)((LPBYTE)mem + pNtH->OptionalHeader.AddressOfEntryPoint);
    NtWriteVirtualMemory(pi.hProcess, (PVOID)(ctx.Ebx + (sizeof(SIZE_T) * 2)), &pNtH->OptionalHeader.ImageBase, sizeof(PVOID), NULL);
#endif

    NtSetContextThread(pi.hThread, &ctx);
    NtResumeThread(pi.hThread, NULL);
    NtWaitForSingleObject(pi.hProcess, FALSE, NULL);
    NtClose(pi.hThread);
    NtClose(pi.hProcess);
    if (image) {
        VirtualFree(image, 0, MEM_RELEASE);
        printf("[+] Successful\n");
    }
    else {
        printf("Error: %lu\n", GetLastError());
    }
    return 0;
}


void timestamp()
{
    SYSTEMTIME lt;
    GetLocalTime(&lt);
    printf("%02d/%02d/%02d at %02d:%02d:%02d\n", lt.wDay, lt.wMonth, lt.wYear, lt.wHour, lt.wMinute, lt.wSecond);
}

void checkEvent(int eid) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
    WORD saved_attributes;
    GetConsoleScreenBufferInfo(hConsole, &consoleInfo);
    saved_attributes = consoleInfo.wAttributes;
    SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN);
    printf("[+] Event Viewer : Check Sysmon Event ID %d for detection\n", eid);
    printf("[+] Event Time   : Event %d simulation is performed on ", eid);
    timestamp();
    SetConsoleTextAttribute(hConsole, saved_attributes);
}

int rawaccessread9() {

    PTCHAR deviceName = _T("\\\\.\\C:");
    PWCHAR search = _T("*lsass*.dmp");
    HANDLE hfileHandle = INVALID_HANDLE_VALUE;

    hfileHandle = CreateFile(
        deviceName,
        FILE_WRITE_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (INVALID_HANDLE_VALUE == hfileHandle)
    {
        printf("\r\nERROR: %u\r\n", GetLastError());
        if (GetLastError() == 5) {
            printText("\r\n[!] This command requires administrator privileges\r\n", FOREGROUND_RED);
        }
        return 0;
    }
    else
    {
        printf("Success\r\n");
    }


    return 0;
}

VOID
PrintUsage()
{
    printf("Usage: SysmonSimulator.exe -eid <event id>\n");
}

VOID
PrintHelp()
{
    printf("\nSysmon Simulator v0.1 - Sysmon event simulation utility\n");
    printf("    A Windows utility to simulate Sysmon event logs\n\n");

    printText("Usage: \n", FOREGROUND_GREEN);
    printf("Run simulation : .\\SysmonSimulator.exe -eid <event id>\nShow help menu : .\\SysmonSimulator.exe -help\n\n");

    printText("Example: \n", FOREGROUND_GREEN);
    printf("SysmonSimulator.exe -eid 1\n\n");

    printText("Parameters:\n", FOREGROUND_GREEN);
    printf("-eid 1  : Process creation\n");
    printf("-eid 2  : A process changed a file creation time\n");
    printf("-eid 3  : Network connection\n");
    printf("-eid 5  : Process terminated\n");
    printf("-eid 6  : Driver loaded\n"); //Pending
    printf("-eid 7  : Image loaded\n");
    printf("-eid 8  : CreateRemoteThread\n");
    printf("-eid 9  : RawAccessRead\n");//Pending
    printf("-eid 10 : ProcessAccess\n");//Pending
    printf("-eid 11 : FileCreate\n");
    printf("-eid 12 : RegistryEvent - Object create and delete\n");
    printf("-eid 13 : RegistryEvent - Value Set\n");
    printf("-eid 14 : RegistryEvent - Key and Value Rename\n");
    printf("-eid 15 : FileCreateStreamHash\n");
    printf("-eid 16 : ServiceConfigurationChange\n"); //Pending
    printf("-eid 17 : PipeEvent - Pipe Created\n");
    printf("-eid 18 : PipeEvent - Pipe Connected\n");
    printf("-eid 19 : WmiEvent - WmiEventFilter activity detected\n");
    printf("-eid 20 : WmiEvent - WmiEventConsumer activity detected\n");
    printf("-eid 21 : WmiEvent - WmiEventConsumerToFilter activity detected\n");
    printf("-eid 22 : DNSEvent - DNS query\n");
    printf("-eid 24 : ClipboardChange - New content in the clipboard\n");
    printf("-eid 25 : ProcessTampering - Process image change\n"); //Pending
    printf("-eid 26 : FileDeleteDetected - File Delete logged\n\n"); //Pending

    printText("Description: \n", FOREGROUND_GREEN);
    printf("Enter an event ID from the above parameters list and the related Windows API function is called\nto simulate the attack and Sysmon event log will be generated which can be viewed in the Windows Event Viewer\n\n");

    printText("Prerequisite: \n", FOREGROUND_GREEN);
    printf("Sysmon must be installed on the system\n\n");
}

VOID
PrintBanner()
{
    printText(" __                        __                              \n", FOREGROUND_INTENSITY);
    printText("(_      _ ._ _   _  ._    (_  o ._ _      |  _. _|_  _  ._ \n", FOREGROUND_INTENSITY);
    printText("__) \\/ _> | | | (_) | |   __) | | | | |_| | (_|  |_ (_) |  \n", FOREGROUND_INTENSITY);
    printText("    /                                                      \n", FOREGROUND_INTENSITY);
    printText("                                            by @ScarredMonk\n", FOREGROUND_RED);
}

int main(int argc, char* argv[]) {

    int eid = 0;
    int process_id = 0;

    //If no args are provided
    if (argc < 2) {
        PrintUsage();
        return 0;
    }

    //If -eid or -help args are provided
    else if (argc >= 2) {
        if (strcmp(argv[1], "-eid") == 0 || strcmp(argv[1], "-e") == 0) {
            if (!argv[2]) {
                printf("Enter an event ID");
                return;
            }

            if (atoi(argv[2]) > 0 && atoi(argv[2]) <= 26) {
                eid = atoi(argv[2]);
            }
            else if (!argv[2] || atoi(argv[2]) > 25 || atoi(argv[2]) < 1) {
                printf("Enter valid value of *EID* ranging from 1-25\n");
                return;
            }
        }
        else if (strcmp(argv[1], "-help") == 0 || strcmp(argv[1], "-h") == 0) {
            PrintBanner();
            PrintHelp();
            return;
        }
        else {
            printf("Invalid flag entered. Please enter -eid with followed by an event ID or -help for more information\n");
            return 0;
        }
    }

    switch (eid) {

    case 1:
        printf("[+] Simulation   : Started successfully\n");
        printf("[+] Event Name   : Process Creation Event\n");
        printf("[+] Event ID     : 1\n");
        ProcessCreate1();
        checkEvent(eid);
        break;

    case 2:
        printf("[+] Simulation   : Started successfully\n");
        printf("[+] Event Name   : File Creation Time Change Event\n");
        printf("[+] Event ID     : 2\n");
        FileCreateTime2();
        checkEvent(eid);
        break;

    case 3:
        printf("[+] Simulation   : Started successfully\n");
        printf("[+] Event ID     : 3\n");
        printf("[+] Event Name   : Network Connection Event\n");
        NetworkConnect3();
        checkEvent(eid);
        break;

    case 4:
        printText("[!] Simulation for Event ID 4 is not present (Internal sysmon related event) \n", FOREGROUND_RED);
        break;

    case 5:
        printText("If you press Ctrl+c, it will generate process termination log for current process \n", FOREGROUND_RED);
        printf("Or enter another process ID to kill the process:\n>");
        scanf_s("%d", &process_id);
        printf("[+] Simulation   : Started successfully\n");
        printf("[+] Event ID     : 5\n");
        printf("[+] Event Name   : Process Termination Event\n");
        printf("[+] PID to kill  : %d\n", process_id);
        processtermination5(process_id);
        checkEvent(eid);
        break;

    case 6:
        printf("[+] Simulation   : Started successfully\n"); //Not working right now
        printf("[+] Event ID     : 6\n");
        printf("[+] Event Name   : Driver Load Event\n");
        driverLoad6();
        checkEvent(eid);
        break;

    case 7:
        printf("[+] Simulation   : Started successfully\n");
        printf("[+] Event ID     : 7\n");
        printf("[+] Event Name   : Image Load Event\n");
        ImageLoaded7();
        printf("[+] Image Loaded : image name ENDS WITH GameChatOverlayExt.dll\n");
        checkEvent(eid);
        break;

    case 8:
        printf("Enter the process ID of remote process to create a remote thread in it:\n>");
        scanf_s("%d", &process_id);
        printf("[+] Simulation   : Started successfully\n");
        printf("[+] Event ID     : 8\n");
        printf("[+] Event Name   : Create Remote Thread Event\n");
        createRemoteThread8(process_id);
        checkEvent(eid);
        break;

    case 9:
        rawaccessread9();
        break;

    case 10:
        printf("Enter the process ID of remote process to be opened/accessed:\n>");
        scanf_s("%d", &process_id);
        printf("[+] Simulation   : Started successfully\n");
        printf("[+] Event ID     : 10\n");
        printf("[+] Event Name   : Process Access Event\n");
        processaccess10(process_id);
        checkEvent(eid);
        break;
    case 11:
        printf("[+] Simulation   : Started successfully\n");
        printf("[+] Event ID     : 11\n");
        printf("[+] Event Name   : File Create Event\n");
        fileCreate11();
        checkEvent(eid);
        break;
    case 12:
        printf("[+] Simulation   : Started successfully\n");
        printf("[+] Event ID     : 12\n");
        printf("[+] Event Name   : Registry Event\n");
        registryEvent12();
        checkEvent(eid);
        break;
    case 13:
        printf("[+] Simulation   : Started successfully\n");
        printf("[+] Event ID     : 13\n");
        printf("[+] Event Name   : Registry Event\n");
        registryEvent13();
        checkEvent(eid);
        break;
    case 14:
        printf("[+] Simulation   : Started successfully\n");
        printf("[+] Event ID     : 14\n");
        printf("[+] Event Name   : Registry Event\n");
        registryEvent14();
        checkEvent(eid);
        break;
    case 15:
        printf("[+] Simulation   : Started successfully\n");
        printf("[+] Event ID     : 15\n");
        printf("[+] Event Name   : Creation of Alternate Data Streams (ADS) Event\n");
        fileCreateStreamHash15();
        checkEvent(eid);
        break;
    case 17:
        printf("[+] Simulation   : Started successfully\n");
        printf("[+] Event ID     : 17\n");
        printf("[+] Event Name   : Pipe Creation Event\n");
        pipeCreated17();
        checkEvent(eid);
        break;
    case 18:
        printf("[+] Simulation   : Started successfully\n");
        printf("[+] Event ID     : 18\n");
        printf("[+] Event Name   : Pipe Connection Event\n");
        pipeConnect18();
        checkEvent(eid);
        break;
    case 22:
        printf("[+] Simulation   : Started successfully\n");
        printf("[+] Event ID     : 22\n");
        printf("[+] Event Name   : DNS Query Event\n");
        dnsquery22();
        checkEvent(eid);
        break;
    case 23:
        printf("[+] Simulation   : Started successfully\n");
        printf("[+] Event ID     : 26\n");
        printf("[+] Event Name   : File deletion Event\n");
        deleteFile26();
        checkEvent(eid);
        break;
    case 24:
        printf("[+] Simulation   : Started successfully\n");
        printf("[+] Event ID     : 24\n");
        printf("[+] Event Name   : Clipboard Content Change Event\n");
        setClipboard24();
        checkEvent(eid);
        break;
    case 25:
        printf("[+] Simulation   : Started successfully\n");
        printf("[+] Event ID     : 25\n");
        printf("[+] Event Name   : Process Tampering Event\n");
        processTampering25();
        checkEvent(eid);
        break;
    case 26:
        printf("[+] Simulation   : Started successfully\n");
        printf("[+] Event ID     : 26\n");
        printf("[+] Event Name   : File deletion Event\n");
        deleteFile26();
        checkEvent(eid);
        break;
    default:
        printf("No argument is passed. Enter an event ID to generate event for it\n");
        printf("Usage   : sysmonSimulator.exe <Event ID>\n");
        printf("Example : (For event ID 1 i.e. process creation)sysmonSimulator.exe \n");
        printf("sysmonSimulator.exe 1\n");
        break;
    }

    return 0;
}