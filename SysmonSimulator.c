#include <winsock.h>
#include <windows.h>
#include <stdio.h>
#include <windns.h>
#include <winternl.h>
#include <tchar.h>
#include <wbemidl.h>

#pragma comment(lib,"WS2_32")
#pragma comment(lib,"dnsapi")
#pragma comment(lib, "ntdll")
#pragma comment(lib, "wbemuuid")

#define _WIN32_DCOM

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
    CONSOLE_SCREEN_BUFFER_INFO consoleInfo = { 0 };
    WORD saved_attributes = 0;
    
    if (!hConsole) {
        printf("Error -: %lu\n", GetLastError());
    }
    else {
        if (!GetConsoleScreenBufferInfo(hConsole, &consoleInfo)) {
            printf("Error -: %lu\n", GetLastError());
        }
    }
    
    saved_attributes = consoleInfo.wAttributes;   
    
    if (hConsole!=0) {
        if (!SetConsoleTextAttribute(hConsole, newColor)) {
            printf("Error -: %lu\n", GetLastError());
        }
    }
    printf("%s", ptr);

    if (hConsole != 0) {
        if (!SetConsoleTextAttribute(hConsole, saved_attributes)) {
            printf("Error -: %lu\n", GetLastError());
        }
    }
}


void ProcessCreate1() {

    LPSTR cmdline = "C:\\Windows\\System32\\wbem\\WMIC.exe";
    HANDLE hProcess = INVALID_HANDLE_VALUE;
    STARTUPINFOA sinfo = { 0 };
    sinfo.cb = sizeof(STARTUPINFOA);
    PROCESS_INFORMATION pinfo = { 0 };

    
        if (!CreateProcessA(NULL, cmdline, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &sinfo, &pinfo))
        {
            printf("Error -: %lu\n", GetLastError());
        }
        else {
            printf("[+] Process Name : C:\\Windows\\System32\\wbem\\WMIC.exe\n");
            printf("[+] Process ID   : %lu \n", pinfo.dwProcessId);
        }

        CloseHandle(pinfo.hProcess);
        CloseHandle(pinfo.hThread);
}

void FileCreateTime2() {

    FILETIME ft1 = { 0 };
    LPCWSTR fileName = { L"SysmonCreateFileTime.txt" };

    HANDLE hFile = CreateFileW(
        fileName,
        GENERIC_WRITE,          
        FILE_SHARE_READ,        
        NULL,                   
        CREATE_ALWAYS,          
        FILE_ATTRIBUTE_NORMAL,  
        NULL);                  

    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("[-] Could not create file SysmonCreateFileTime.txt. Error code is: %lu\n", GetLastError());
    }
    else {
        printf("[+] File Creation: %S is created in the same directory\n", fileName);
    }
    ft1.dwLowDateTime = 2421641397;
    ft1.dwHighDateTime = 30933186;

    if (!SetFileTime(hFile, &ft1, NULL, NULL)) {
        printf("[-] Error changing file creation time : %lu\n", GetLastError());
    }
    else {
        printf("[+] Time changed : Creation time of file SysmonCreateFileTime.txt is changed\n");
    }
    CloseHandle(hFile);
}

void NetworkConnect3() {
    WSADATA version = {0};
    WSAStartup(MAKEWORD(2, 2), &version);
    u_short port = 31337;

    SOCKET newSocket = {0};
    struct sockaddr_in addr = { 0 };
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
}

void processtermination5(int process_id)
{
    HANDLE hProcessToKill = NULL;
    hProcessToKill = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id);
    if (hProcessToKill == NULL) {
        printf("[-] Error getting handle for PID %d. Error code is : %lu\n", process_id, GetLastError());
    }
    else
    {
        TerminateProcess(hProcessToKill, 1);
        CloseHandle(hProcessToKill);
    }
}

void driverLoad6() {
    printText("\nSteps to generate Driver Load event log: \n\n", FOREGROUND_GREEN);
    printf(" -> Go to Settings >> Windows Security >> Virus & threat protection settings  \n -> Disable Real-time protection \n -> Enable Real-time protection\n\n");
    printText(" This will load C:\\Windows\\System32\\drivers\\wd\\WdNisDrv.sys which is Microsoft Network Realtime Inspection Driver file\r\n\n", FOREGROUND_GREEN);
}

void ImageLoaded7() {
    HMODULE hntdll = LoadLibraryA("crypt32.dll");
    if (hntdll) {
        printf("[+] Image Loaded : Loaded crypt32.dll\n");
        FreeLibrary(hntdll);
        CloseHandle(hntdll);
    }
    else
    {
        printf("Error -: %lu\n", GetLastError());
    }
}

void createRemoteThread8() {
    HANDLE processHandle;
    PVOID buff;
    LPSTR cmdline = "C:\\Windows\\System32\\PING.exe";
    HANDLE hProcess = INVALID_HANDLE_VALUE;
    STARTUPINFOA sinfo = { 0 };
    sinfo.cb = sizeof(STARTUPINFOA);
    PROCESS_INFORMATION pinfo = { 0 };


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


        if (CreateProcessA(NULL, cmdline, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &sinfo, &pinfo)) {
            int process_id = pinfo.dwProcessId;
            printf("[+] Inject into  : PID %lu\n", process_id);

            processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id);
            printf("[+] Opened process's handle\n");

            buff = VirtualAllocEx(processHandle, NULL, sizeof(shellcode), (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);

            if (buff) {
                WriteProcessMemory(processHandle, buff, shellcode, sizeof(shellcode), NULL);
                CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)buff, NULL, 0, NULL);
                printf("[+] Created Remote Thread\n");
                printf("[+] Closed Handle to the process\n");
            }
            else {
                printf("[-] Error code is : %lu\n", GetLastError());
            }
            
            CloseHandle(pinfo.hProcess);
            CloseHandle(pinfo.hThread);
        }
}

DWORD rawaccessread9() {

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

    if (hfileHandle == INVALID_HANDLE_VALUE)
    {
        printf("\r\nERROR code is : %lu\r\n", GetLastError());
        if (GetLastError() == 5) {
            printText("\r\n[!] This command requires administrator privileges\r\n\n", FOREGROUND_RED);
            return GetLastError();
        }
    }
    else
    {
        printf("[+] Successful   : Successfully created RawAccessRead Event\r\n");
        CloseHandle(hfileHandle);
    }
    return GetLastError();
}

void processaccess10(int process_id) {

    printf("[+] ProcessAccess: Process ID %lu\n", process_id);
    HANDLE hProcessToAccess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, process_id);
    if (hProcessToAccess) {
        printf("[+] Successful   : Process handle was opened\n");
        CloseHandle(hProcessToAccess);
    }
    else
    {
        printf("Error code is : %lu\n", GetLastError());
    }
}

void fileCreate11() {
    HANDLE hFile = CreateFileW(
        L"NewFile.bat",
        GENERIC_WRITE,
        FILE_SHARE_READ,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("[!] Error creating file. Error code is : %lu\n", GetLastError());
    }
    else {
        printf("[+] Created File : NewFile.bat\n");
        CloseHandle(hFile);
    }
}


BOOL CreateRegistryKey()
{
    HKEY  hKey = NULL;
    if (RegCreateKeyA(HKEY_CURRENT_USER, "TestSysmon", &hKey) != ERROR_SUCCESS) {
        printf("[!] Error opening or creating key. Error code is : %lu\n", GetLastError());
        return FALSE;
    }
    else {
        RegCloseKey(hKey);
        return TRUE;
    }
}

BOOL writeStringInRegistry()
{
    HKEY hKey = NULL;
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

void registryEvent12()
{
    if(CreateRegistryKey()) {
        printf("[+] Successful   : Registry object created\n");
    }
    else {
        printf("Error code is : %lu\n", GetLastError());
    }
}

void registryEvent13()
{
    HKEY subKey = NULL;
    LONG result = RegOpenKeyEx(HKEY_CURRENT_USER, L"TestSysmon", 0, KEY_READ, &subKey);
    if (result != ERROR_SUCCESS) {
        CreateRegistryKey();
    }
    if (writeStringInRegistry()) {
        printf("[+] Successful   : Registry value modified to 'Tested'\n");
    }
    else {
        printf("Error code is : %lu\n", GetLastError());
    }
}

void registryEvent14()
{
    HKEY  hKey = NULL;
    if (RegCreateKeyA(HKEY_CURRENT_USER, "NewRegistrySysmonTesting", &hKey) != ERROR_SUCCESS) {
        printf("[!] Error opening or creating key. Error code is : %lu\n", GetLastError());
    }
    else {
        RegCloseKey(hKey);
    }
    
    RegRenameKey(
        HKEY_CURRENT_USER,
        L"NewRegistrySysmonTesting",
        L"RegistrySysmonTestingRenamed"
    );
}

void fileCreateStreamHash15() {
    DWORD dwRet = 0;
    char testdata[] = "Hello World";
    WIN32_FIND_STREAM_DATA streaminfo = { 0 };
    HANDLE hFile = CreateFileA("Streamfile.txt:SysmonStream", GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[!] Could not create stream for file Streamfile.txt\n");
        printf("Error code is : %lu\n", GetLastError());
    }
    else {
        printf("[+] Successful   : Created stream for file Streamfile.txt\n");
        if (!WriteFile(hFile, "Sysmon simulator has written in ADS SysmonStream of Streamfile.txt", 67, &dwRet, NULL)) {
            printf("Error code is : %lu\n", GetLastError());
            CloseHandle(hFile);
        }
    }
}

void pipeCreated17() {
    HANDLE hPipe = NULL;
    SECURITY_ATTRIBUTES secAttrib = { 0 };
    static LPCSTR lpName = "\\\\.\\pipe\\sysmontestnamedpipe";
    hPipe = CreateNamedPipeA(lpName,
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_BYTE | PIPE_WAIT,
        10,
        2048,
        2048,
        0,
        &secAttrib);
    if (hPipe == INVALID_HANDLE_VALUE)
    {
        printf("CreateNamedPipeA(): FAILED.Error code is : %lu\n", GetLastError());
    }
    else {
        printf("[+] Successful   : Pipe %s has been created\n", lpName);
        LocalFree(hPipe);
        CloseHandle(hPipe);
    }
}

void pipeConnect18() {
    HANDLE hPipe = NULL;
    HANDLE hConnectPipe = NULL;
    SECURITY_ATTRIBUTES secAttrib = { 0 };
    LPCSTR lpName = "\\\\.\\pipe\\sysmontestconnectpipe";

    hPipe = CreateNamedPipeA(lpName,
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_BYTE | PIPE_WAIT,
        10,
        2048,
        2048,
        0,
        &secAttrib);
    if (hPipe == INVALID_HANDLE_VALUE)
    {
        printf("CreateNamedPipeA(): FAILED.Error code is : %lu\n", GetLastError());
    }
    else {
        printf("[+] Successful   : Pipe connection event created for pipe %s \n", lpName);
    }
    hConnectPipe = CreateFileA(lpName, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, 0, NULL, OPEN_EXISTING, FILE_FLAG_WRITE_THROUGH, NULL);
    if (hConnectPipe == INVALID_HANDLE_VALUE) {
        printf("Error: %lu\n", GetLastError());
    }
    else {
        if (hPipe != 0) {
            LocalFree(hPipe);
            CloseHandle(hPipe);
        }
        if (hConnectPipe != 0) {
            CloseHandle(hConnectPipe);
        }
    }
}

void dnsquery22() {
    DWORD response = 0;
    PDNS_RECORD base = NULL;
    DWORD options = DNS_QUERY_WIRE_ONLY;
    PIP4_ARRAY pSrvList = NULL;
    unsigned short wType = 0;

    response = DnsQuery_A("google.com", wType, options, pSrvList, &base, NULL);
    if (response) {
        printf("[+] Successful   : Performed DNS Lookup for 'google.com' \n");
    }
    else {
        printf("[+] Tried to perform lookup for domain 'google.com' but got an error \n");
        printf("[!] Error code is: %lu\n", GetLastError());
    }
}


void setClipboard24() {

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
        GlobalFree(hMem);
    }
    else {
        printf("[!] Error code is: %lu\n", GetLastError());
    }
}

void deleteFile26() {
    HANDLE hFile = CreateFile(
        L"NewFile.bat",
        GENERIC_WRITE,
        FILE_SHARE_READ,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[!] Error code is: %lu\n", GetLastError());
    }
    else {
        CloseHandle(hFile);
    }

    if (!DeleteFile(L"NewFile.bat")) {
        printf("[-] Error deleting file: %lu\n", GetLastError());
    }
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
    LPSTR targetExe = "c:\\Windows\\System32\\svchost.exe";

    if (!CreateProcessA(NULL, replacement, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
    {
        printf("\nNot able to run the target executable. Error code is : % lu\n", GetLastError());
        return 1;
    }

    hFile = CreateFileA(targetExe, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("\nNot able to open the replacement executable. Error code is : % lu\n", GetLastError());
        NtTerminateProcess(pi.hProcess, 1);
        return 1;
    }

    nSizeOfFile = GetFileSize(hFile, NULL);
    image = VirtualAlloc(NULL, nSizeOfFile, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!ReadFile(hFile, image, nSizeOfFile, &read, NULL))
    {
        printf("\nNot able to read the replacement executable. Error code is : % lu\n", GetLastError());
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
        printf("\nError: Unable to allocate memory in child process. VirtualAllocEx failed with error %lu\n", GetLastError());

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

void wmiactivity19() {

    printText("\n[+] Run the following code from an elevated PowerShell console \n\n", FOREGROUND_GREEN);
    printText("This will create a __EventFilter that will check for a modification of the Win32_Service class every 5 seconds \r\n\n", FOREGROUND_GREEN);
    printText("# Creating a new event filter\n", FOREGROUND_INTENSITY);

    printf(
        "$ServiceFilter = ([wmiclass]\"\\\\.\\root\\subscription:__EventFilter\").CreateInstance()\n"
        "$ServiceFilter.QueryLanguage = 'WQL'\n"
        "$ServiceFilter.Query = \"select * from __instanceModificationEvent within 5 where targetInstance isa 'win32_Service'\"\n"
        "$ServiceFilter.Name = \"ServiceFilter\"\n"
        "$ServiceFilter.EventNamespace = 'root\\cimv2'\n"
        "\n"
    );
    printText("# Sets the intance in the namespace\n", FOREGROUND_INTENSITY);
    printf(
        "$FilterResult = $ServiceFilter.Put()\n"
        "$ServiceFilterObj = $FilterResult.Path\n\n"
    );

    printf("After running these commands, go to event Viewer and check Sysmon Event ID 19 for the event\n\n");
    printText("Note: The action is logged with Event Id 19, and we should be able to see a Data element (under EventData) where the Operation attribute says Created\r\n\n", FOREGROUND_RED);
    printText("Credits:  Carlos Perez (@darkoperator)\nReference: https://www.darkoperator.com/blog/2017/10/15/sysinternals-sysmon-610-tracking-of-permanent-wmi-events\n\n", FOREGROUND_BLUE);
}

void wmiactivity20() {

    printText("\n[+] Run the following code from an elevated PowerShell console \n\n", FOREGROUND_GREEN);
    printf("Run this PowerShell Code in the existing window where we created the filter (for event ID 19)\r\n\n");
    printText("This will create a consumer that will create a log file on the C:\\ drive\r\n\n", FOREGROUND_GREEN);

    printText("# Creating a new event consumer \n", FOREGROUND_INTENSITY);
    printf("$LogConsumer = ([wmiclass]\"\\\\.\\root\\subscription:LogFileEventConsumer\").CreateInstance()\n\n");
    
    printText("# Set properties of consumer\n", FOREGROUND_INTENSITY);
    printf(
        "$LogConsumer.Name = 'ServiceConsumer'\n"
        "$LogConsumer.Filename = \"C:\\Log.log\"\n"
        "$LogConsumer.Text = 'A change has occurred on the service: %%TargetInstance.DisplayName%%'\n"
    );

    printText("# Creating a new event consumer \n", FOREGROUND_INTENSITY);
    printf(
        "$LogResult = $LogConsumer.Put()\n"
        "$LogConsumerObj = $LogResult.Path\r\n\n"
    );

    printf("After running these commands, go to event Viewer and check Sysmon Event ID 20 for the event\n\n");
    printText("Note: The action is logged with Event Id 20 and we should be able to see that the LogFileEventConsumer creation was logged and all its properties are parsed under EventData Element of the log structure\r\n\n", FOREGROUND_RED);
    printText("Credits:  Carlos Perez (@darkoperator)\nReference: https://www.darkoperator.com/blog/2017/10/15/sysinternals-sysmon-610-tracking-of-permanent-wmi-events\n\n", FOREGROUND_BLUE);
}

void wmiactivity21() {

    printText("\n[+] Run the following code from an elevated PowerShell console \n\n", FOREGROUND_GREEN);
    printf("Run this PowerShell Code in the existing window where we created the filter (for event ID 19 and 20)\r\n\n");
    printText("This will create a __FilterToConsumerBinding class instance using the __EventFilterand the LogFileEventConsumer class instance we created earlier \n\n", FOREGROUND_GREEN);

    printText("# Creating new binder\n", FOREGROUND_INTENSITY);
    printf(
        "$instanceBinding = ([wmiclass]\"\\\\.\\root\\subscription:__FilterToConsumerBinding\").CreateInstance()\r\n\n"

        "$instanceBinding.Filter = $ServiceFilterObj\n"
        "$instanceBinding.Consumer = $LogConsumerObj\n"
        "$result = $instanceBinding.Put()\n"
        "$newBinding = $result.Path\r\n\n"
    );
    printf("After running these commands, go to event Viewer and check Sysmon Event ID 21 for the event\n\n");
    printText("Note: The action is logged with Event Id 21 and that the Filter and Consumer paths in the CIM Database are included under EventData\r\n\n",FOREGROUND_RED);
    printText("Credits:  Carlos Perez (@darkoperator)\nReference: https://www.darkoperator.com/blog/2017/10/15/sysinternals-sysmon-610-tracking-of-permanent-wmi-events\n\n", FOREGROUND_BLUE);
}

void timestamp() {

    SYSTEMTIME lt;
    GetLocalTime(&lt);
    printf("%02d/%02d/%02d at %02d:%02d:%02d\r\n\n", lt.wDay, lt.wMonth, lt.wYear, lt.wHour, lt.wMinute, lt.wSecond);
}

void checkEvent(int eid) {

    printf("[+] Event Viewer : Check Sysmon Event ID %d for detection\n", eid);
    printf("[+] Event Time   : Event %d simulation is performed on ", eid);
    timestamp();

}


void PrintUsage(){

    printf("Usage: SysmonSimulator.exe -eid <event id>\n");
}


void PrintHelp() {

    printf("\nSysmon Simulator v0.1 - Sysmon event simulation utility\n");
    printf("    A Windows utility to simulate Sysmon event logs\n\n");

    printText("Usage: \n", FOREGROUND_GREEN);
    printf("Run simulation : .\\SysmonSimulator.exe -eid <event id>\nShow help menu : .\\SysmonSimulator.exe -help\n\n");

    printText("Example: \n", FOREGROUND_GREEN);
    printf("SysmonSimulator.exe -eid 1\n\n");

    printText("Parameters:\n", FOREGROUND_GREEN);
    printf(
        "-eid 1  : Process creation\n"
        "-eid 2  : A process changed a file creation time\n"
        "-eid 3  : Network connection\n"
        "-eid 5  : Process terminated\n"
        "-eid 6  : Driver loaded\n"
        "-eid 7  : Image loaded\n"
        "-eid 8  : CreateRemoteThread\n"
        "-eid 9  : RawAccessRead\n"
        "-eid 10 : ProcessAccess\n"
        "-eid 11 : FileCreate\n"
        "-eid 12 : RegistryEvent - Object create and delete\n"
        "-eid 13 : RegistryEvent - Value Set\n"
        "-eid 14 : RegistryEvent - Key and Value Rename\n"
        "-eid 15 : FileCreateStreamHash\n"
        "-eid 16 : ServiceConfigurationChange\n"
        "-eid 17 : PipeEvent - Pipe Created\n"
        "-eid 18 : PipeEvent - Pipe Connected\n"
        "-eid 19 : WmiEvent - WmiEventFilter activity detected\n"
        "-eid 20 : WmiEvent - WmiEventConsumer activity detected\n"
        "-eid 21 : WmiEvent - WmiEventConsumerToFilter activity detected\n"
        "-eid 22 : DNSEvent - DNS query\n"
        "-eid 24 : ClipboardChange - New content in the clipboard\n"
        "-eid 25 : ProcessTampering - Process image change\n"
        "-eid 26 : FileDeleteDetected - File Delete logged\n\n"
    );

    printText("Description: \n", FOREGROUND_GREEN);
    printf("Enter an event ID from the above parameters list and the related Windows API function is called\nto simulate the attack and Sysmon event log will be generated which can be viewed in the Windows Event Viewer\n\n");

    printText("Prerequisite: \n", FOREGROUND_GREEN);
    printf("Sysmon must be installed on the system\n\n");
}

void PrintBanner()
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
    DWORD error = 0;

    if (argc < 2) {
        PrintUsage();
        return 0;
    }

    if (argc >= 2) {
        if (strcmp(argv[1], "-eid") == 0 || strcmp(argv[1], "-e") == 0) {
            if (argc >= 3) {
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
        printf("\r\n[+] Simulation   : Started successfully\n");
        printf("[+] Event Name   : Process Creation Event\n");
        printf("[+] Event ID     : 1\n");
        ProcessCreate1();
        checkEvent(eid);
        break;

    case 2:
        printf("\r\n[+] Simulation   : Started successfully\n");
        printf("[+] Event Name   : File Creation Time Change Event\n");
        printf("[+] Event ID     : 2\n");
        FileCreateTime2();
        checkEvent(eid);
        break;

    case 3:
        printf("\r\n[+] Simulation   : Started successfully\n");
        printf("[+] Event ID     : 3\n");
        printf("[+] Event Name   : Network Connection Event\n");
        NetworkConnect3();
        checkEvent(eid);
        break;

    case 4:
        printText("\r\n[!] Simulation for Event ID 4 is not present (Internal sysmon related event) \r\n\n", FOREGROUND_RED);
        break;

    case 5:
        printText("If you press Ctrl+c, it will generate process termination log for current process \n", FOREGROUND_RED);
        printf("Or enter another process ID to kill the process:\n>");
        scanf_s("%d", &process_id);
        printf(
            "\r\n[+] Simulation   : Started successfully\n"
            "[+] Event ID     : 5\n"
            "[+] Event Name   : Process Termination Event\n"
            "[+] PID to kill  : %d\n", process_id
        );
        processtermination5(process_id);
        checkEvent(eid);
        break;

    case 6:
        printf(
            "\r\n[+] Event ID     : 6\n"
            "[+] Event Name   : Driver Load Event\n"
        );
        driverLoad6();
        break;

    case 7:
        printf(
            "\r\n[+] Simulation   : Started successfully\n"
            "[+] Event ID     : 7\n"
            "[+] Event Name   : Image Load Event\n"
        );
        ImageLoaded7();
        checkEvent(eid);
        break;

    case 8:
        printf(
            "\r\n[+] Simulation   : Started successfully\n"
            "[+] Event ID     : 8\n"
            "[+] Event Name   : Create Remote Thread Event\n"
        );
        createRemoteThread8();
        checkEvent(eid);
        break;

    case 9:
        printf(
            "\r\n[+] Simulation   : Started successfully\n"
            "[+] Event ID     : 9\n"
            "[+] Event Name   : RawAccessRead Event\n"
        );
        error = rawaccessread9();
        if (error != 5) {
            checkEvent(eid);
        }
        break;

    case 10:
        printf("\r\nEnter the process ID of remote process to be opened/accessed:\n>");
        scanf_s("%d", &process_id);
        printf(
            "\r\n[+] Simulation   : Started successfully\n"
            "[+] Event ID     : 10\n"
            "[+] Event Name   : Process Access Event\n"
        );
        processaccess10(process_id);
        checkEvent(eid);
        break;

    case 11:
        printf(
            "\r\n[+] Simulation   : Started successfully\n"
            "[+] Event ID     : 11\n"
            "[+] Event Name   : File Create Event\n"
        );
        fileCreate11();
        checkEvent(eid);
        break;

    case 12:
        printf(
            "\r\n[+] Simulation   : Started successfully\n"
            "[+] Event ID     : 12\n"
            "[+] Event Name   : Registry Event\n"
        );
        registryEvent12();
        checkEvent(eid);
        break;

    case 13:
        printf(
            "\r\n[+] Simulation   : Started successfully\n"
            "[+] Event ID     : 13\n"
            "[+] Event Name   : Registry Event\n"
        );
        registryEvent13();
        checkEvent(eid);
        break;

    case 14:
        printf(
            "\r\n[+] Simulation   : Started successfully\n"
            "[+] Event ID     : 14\n"
            "[+] Event Name   : Registry Event\n"
        );
        registryEvent14();
        checkEvent(eid);
        break;

    case 15:
        printf(
            "\r\n[+] Simulation   : Started successfully\n"
            "[+] Event ID     : 15\n"
            "[+] Event Name   : Creation of Alternate Data Streams (ADS) Event\n"
        );
        fileCreateStreamHash15();
        checkEvent(eid);
        break;

    case 17:
        printf(
            "\r\n[+] Simulation   : Started successfully\n"
            "[+] Event ID     : 17\n"
            "[+] Event Name   : Pipe Creation Event\n"
        );
        pipeCreated17();
        checkEvent(eid);
        break;

    case 18:
        printf(
            "\r\n[+] Simulation   : Started successfully\n"
            "[+] Event ID     : 18\n"
            "[+] Event Name   : Pipe Connection Event\n"
        );
        pipeConnect18();
        checkEvent(eid);
        break;

    case 19:
        printf(
            "\r\n[+] Simulation   : Started successfully\n"
            "[+] Event ID     : 19\n"
            "[+] Event Name   : WmiEvent\n"
        );
        wmiactivity19();
        break;

    case 20:
        printf(
            "\r\n[+] Simulation   : Started successfully\n"
            "[+] Event ID     : 20\n"
            "[+] Event Name   : WmiEvent\n"
        );
        wmiactivity20();
        break;

    case 21:
        printf(
            "\r\n[+] Simulation   : Started successfully\n"
            "[+] Event ID     : 21\n"
            "[+] Event Name   : WmiEvent\n"
        );
        wmiactivity21();
        break;

    case 22:
        printf(
            "\r\n[+] Simulation   : Started successfully\n"
            "[+] Event ID     : 22\n"
            "[+] Event Name   : DNS Query Event\n"
        );
        dnsquery22();
        checkEvent(eid);
        break;

    case 23:
        printf(
            "\r\n[+] Simulation   : Started successfully\n"
            "[+] Event ID     : 26\n"
            "[+] Event Name   : File deletion Event\n"
        );
        deleteFile26();
        checkEvent(eid);
        break;

    case 24:
        printf(
            "\r\n[+] Simulation   : Started successfully\n"
            "[+] Event ID     : 24\n"
            "[+] Event Name   : Clipboard Content Change Event\n"
        );
        setClipboard24();
        checkEvent(eid);
        break;

    case 25:
        printf(
            "\r\n[+] Simulation   : Started successfully\n"
            "[+] Event ID     : 25\n"
            "[+] Event Name   : Process Tampering Event\n"
        );
        processTampering25();
        checkEvent(eid);
        break;

    case 26:
        printf(
            "\r\n[+] Simulation   : Started successfully\n"
            "[+] Event ID     : 26\n"
            "[+] Event Name   : File deletion Event\n"
        );
        deleteFile26();
        checkEvent(eid);
        break;

    default:
        printf(
            "\nEnter an event ID to generate event for it\n"
            "Usage   : sysmonSimulator.exe -eid <Event ID>\n"
            "Example : (For event ID 1 i.e. process creation)\n"
            "sysmonSimulator.exe -eid 1\n\n"
        );
        break;
    }

    return 0;
}
