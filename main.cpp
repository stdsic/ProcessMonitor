#include <windows.h>
#include <winsvc.h>
#include <winternl.h>
#include <ntstatus.h>       // STATUS_INFO_LENGTH_MIMATCH
#include <psapi.h>
#include <stdlib.h>
#include <locale.h>
#include <stdio.h>
#include <string.h>

#define PROCESSLIST     0x400
#define SERVICELIST     0x400

/*
   토큰 격리(Integrity Level) 문제
   - Windows는 관리자 권한을 부여받은 프로세스와 일반 프로세스를 격리한다.
   - 해당 프로그램이 관리자 권한으로 실행되면 일반 사용자 권한에서 실행된 프로세스 정보를 올바르게 조회하지 못할 수 있다.

   따라서 특권을 부여해야 한다.
   특권과 관련된 내용은 보안 섹션에서 다뤘는데 프로세스 토큰을 열어 특권을 설정해야 한다.

   1. SeDebugPrivilege:                모든 프로세스를 조회하고 디버깅할 수 있도록 허용(System 권한 프로세스)
   2. SeIncreaseQuotaPrivilege:        프로세스의 메모리 할당량을 조정
   3. SeSecurityPrivilege:             보안 정보를 확인할 수 있도록 허용(ACL)
   4. SeProfileSingleProcessPrivilege: 프로세스 프로파일링이 가능하게끔 허용(성능 및 리소스 사용량 측정)
   5. SeLoadDriverPrivilege:           드라이버를 로드할 수 있도록 허용
 */

static const wchar_t* Privileges[] = {
    SE_DEBUG_NAME,
    SE_INCREASE_QUOTA_NAME,
    SE_SECURITY_NAME,
    SE_PROF_SINGLE_PROCESS_NAME,
    SE_LOAD_DRIVER_NAME
};

DWORD PrevProcessList[PROCESSLIST];
wchar_t PrevProcessNameList[PROCESSLIST][MAX_PATH];

typedef struct tag_ServiceInfo{
    ENUM_SERVICE_STATUS_PROCESS ServiceStatus;
    wchar_t ServiceName[MAX_PATH];
} SERVICE_INFO;
SERVICE_INFO PrevServiceList[SERVICELIST];

int PrevProcessCount = 0,
    PrevServiceCount = 0;

void CurrentTime(wchar_t *buf){
    SYSTEMTIME st;
    GetLocalTime(&st);
    wsprintf(buf, L"%02d:%02d:%02d", st.wHour, st.wMinute, st.wSecond);
}

BOOL EnablePrivilege(const wchar_t* PrivilegeName) {
    HANDLE hToken;
    if(!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)){
        wprintf(L"프로세스 토큰을 열 수 없습니다.\n");
        return FALSE;
    }

    TOKEN_PRIVILEGES tp;
    if (!LookupPrivilegeValueW(NULL, PrivilegeName, &tp.Privileges[0].Luid)) {
        wprintf(L"특권을 찾을 수 없습니다. %ls\n", PrivilegeName);
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        wprintf(L"특권을 활성화 할 수 없습니다.%ls\n");
        CloseHandle(hToken);
        return FALSE;
    }

    CloseHandle(hToken);
    return TRUE;
}

/******************************************************************
  ntdll.dll은 링크 타임에 제공되는 import library (ntdll.lib)가 공식적으로 존재하지 않기 때문에, MinGW에서는 함수 포인터를 통해 동적으로 로드하는 방식이 일반적이다.

  또, Native API라 ProcessProtectionLevelInfo와 관련된 정보를 따로 정의하여 오프셋을 맞추지 않으면 정보를 얻어오기 힘들고 윈도우 버전에 따라 새로운 멤버가 추가/삭제되거나 오프셋이 바뀔 수 있으므로 이번 프로젝트에서는 사용자 모드 수준의 API만을 이용하기로 한다.

  typedef NTSTATUS (NTAPI *PFN_NTQUERYINFORMATIONPROCESS)(
  HANDLE ProcessHandle,
  PROCESSINFOCLASS ProcessInformationClass,
  PVOID ProcessInformation,
  ULONG ProcessInformationLength,
  PULONG ReturnLength
  );

  typedef NTSTATUS (NTAPI *PFN_NTQUERYSYSTEMINFORMATION)(
  SYSTEM_INFORMATION_CLASS SystemInformationClass,
  PVOID SystemInformation,
  ULONG SystemInformationLength,
  PULONG ReturnLength
  );

  typedef NTSTATUS(WINAPI* NtQueryInformationProcess_t)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
 ******************************************************************/

static HMODULE hNtDll;
typedef NTSTATUS(WINAPI *pNtQueryInformationProcess)(HANDLE, PROCESS_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(WINAPI *pNtOpenProcess)(HANDLE*, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
typedef NTSTATUS(WINAPI *pNtQueryInformationProcess)( HANDLE, PROCESS_INFORMATION_CLASS, PVOID, ULONG, PULONG);

int GetProcessProtectionLevelWithoutHandle(DWORD dwPID){
    pNtQueryInformationProcess NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess");
    if(!NtQueryInformationProcess){
        wprintf(L"Failed to GetProcAddress\n");
        return -1;
    }

    pNtOpenProcess NtOpenProcess = (pNtOpenProcess)GetProcAddress(hNtDll, "NtOpenProcess");
    if(!NtOpenProcess){
        wprintf(L"Failed to GetProcAddress for NtOpenProcess\n");
        return -1;
    }

    HANDLE hProcess;
    CLIENT_ID ClientID = { 0 };
    ClientID.UniqueProcess = (HANDLE)(ULONG_PTR)dwPID;

    OBJECT_ATTRIBUTES ObjAttr;
    InitializeObjectAttributes(&ObjAttr, NULL, 0, NULL, NULL);

    NTSTATUS Status = NtOpenProcess(&hProcess, PROCESS_QUERY_LIMITED_INFORMATION, &ObjAttr, &ClientID);
    if(!NT_SUCCESS(Status)){
        wprintf(L"Failed to access process (PID: %d)\n", dwPID);
        return -1;
    }

    ULONG ReturnLength = 0;
    PROCESS_PROTECTION_LEVEL_INFORMATION pplInfo = { 0 };
    Status = NtQueryInformationProcess(hProcess, (PROCESS_INFORMATION_CLASS)ProcessProtectionLevelInfo, NULL, 0, &ReturnLength);
    if(Status != STATUS_INFO_LENGTH_MISMATCH){
        wprintf(L"Unexpected failure for size check: 0x%08X\n", Status);
        CloseHandle(hProcess);
        return -1;
    }

    PVOID Buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ReturnLength);
    if(!Buffer){
        wprintf(L"HeapAlloc failed\n");
        CloseHandle(hProcess);
        return -1;
    }

    int ProtectionLevel = -1;
    Status = NtQueryInformationProcess(hProcess, (PROCESS_INFORMATION_CLASS)ProcessProtectionLevelInfo, Buffer, ReturnLength, NULL);
    if(NT_SUCCESS(Status)){
        ProtectionLevel = ((PROCESS_PROTECTION_LEVEL_INFORMATION*)Buffer)->ProtectionLevel;
    }

    HeapFree(GetProcessHeap(), 0, Buffer);
    CloseHandle(hProcess);

    return ProtectionLevel;
}

/*****************************************************************************************
  PPL인지 판단할 수 있는 공식 API가 존재하지 않는다.
  정확히는 사용자 모드에서의 공식 API가 존재하지 않는다. 커널 모드, 즉 드라이버 수준의 커널 코드(시스템 코드)를 작성하면 PPL인지 판단할 수 있다.
  다만, wdk가 필요하며 .sys 파일, 즉 시스템 파일로 빌드하여 서비스 등록 및 여러 동작을 추가해야 하므로 이 방법은 사용하지 않기로 한다.
  typedef struct _PS_PROTECTION {
  UCHAR Type : 3;
  UCHAR Audit : 1;
  UCHAR Signer : 4;
  } PS_PROTECTION;

  VOID CheckPPLStatus(HANDLE pid) {
  PEPROCESS Process = NULL;
  NTSTATUS status = PsLookupProcessByProcessId(pid, &Process);
  if (!NT_SUCCESS(status)) {
  DbgPrint("Failed to lookup process: 0x%08X\n", status);
  return;
  }

// Protection 필드 오프셋은 Windows 버전에 따라 다름
// 예: Windows 10 22H2 기준 약 0x6FA
// 예시값, 반드시 확인 필요
ULONG offset = 0x6FA;
PS_PROTECTION protection = *(PS_PROTECTION *)((PUCHAR)Process + offset);

DbgPrint("PPL Type: %d, Signer: %d\n", protection.Type, protection.Signer);

if (protection.Type == 2) {
DbgPrint("This process is PPL (Protected Process Light)\n");
} else if (protection.Type == 1) {
DbgPrint("This process is a full Protected Process\n");
} else {
DbgPrint("This process is not protected\n");
}

ObDereferenceObject(Process);
}
 */

int GetProcessList(DWORD* ProcessList, wchar_t ProcessNameList[PROCESSLIST][MAX_PATH]) {
    int cnt = 0;
    DWORD dwBytes;

    pNtQueryInformationProcess NtQueryInformationProcess = nullptr;
    if(hNtDll){
        NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess");
    }

    if(EnumProcesses(ProcessList, sizeof(DWORD) * PROCESSLIST, &dwBytes)){
        cnt = dwBytes / sizeof(DWORD);
        for(int i = 0; i < cnt; i++){
            HANDLE hProcess = OpenProcess(/* PROCESS_ALL_ACCESS */ PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, ProcessList[i]);
            if(!hProcess){
                DWORD Error = GetLastError();
                if(Error == ERROR_ACCESS_DENIED){
                    /*
                       if(hNtDll && NtQueryInformationProcess){
                       PROCESS_PROTECTION_LEVEL_INFORMATION ProtectionInfo = { 0 };
                       ULONG ReturnLength;
                       NTSTATUS Status = NtQueryInformationProcess(
                       OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ProcessList[i]),
                       (PROCESS_INFORMATION_CLASS)ProcessProtectionLevelInfo,
                       &ProtectionInfo,
                       sizeof(ProtectionInfo),
                       &ReturnLength
                       );
                    // 0: 보호없음, 1: Light(PPL), 2: 강력(Windows Services 등), 3: 매우 높은 수준(System Critical)
                    // wcscpy(ProcessNameList[i], (NT_SUCCESS(Status) && ProtectionInfo.ProtectionLevel > 0) ? 
                    //      L"Protected Process Light(PPL)" : L"Warning: Unknown Process (Access Denied)");

                    int ProtectionLevel = GetProcessProtectionLevelWithoutHandle(ProcessList[i]);
                    wcscpy(ProcessNameList[i], ProtectionLevel > 0 ? L"Protected Process Light(PPL)" : L"Warning: Unknown Process (Access Denied)");
                    }else{
                    wcscpy(ProcessNameList[i], L"Protected Process Light(PPL)");
                    }
                     */
                    wcscpy(ProcessNameList[i], L"Protected Process Light(PPL)");
                }else{
                    wcscpy(ProcessNameList[i], L"Warning: Unknown Process");
                }
                continue;
            }

            if(!GetModuleBaseName(hProcess, NULL, ProcessNameList[i], MAX_PATH)){
                if(!GetModuleFileNameEx(hProcess, NULL, ProcessNameList[i], MAX_PATH)){
                    DWORD dwSize = MAX_PATH;
                    if(QueryFullProcessImageName(hProcess, 0, ProcessNameList[i], &dwSize)){
                        wchar_t* Filename = wcsrchr(ProcessNameList[i], '\\');
                        if(Filename && (*Filename + 1)){
                            wcscpy(ProcessNameList[i], Filename + 1);
                        }
                    }
                }
            }

            if(wcslen(ProcessNameList[i]) == 0){
                wcscpy(ProcessNameList[i], L"Warning: Unknown Process");
            }

            CloseHandle(hProcess);
        }
    }

    return cnt;
}

void DetectProcessChanges(){
    DWORD CurrentProcessList[PROCESSLIST];
    wchar_t CurrentProcessNameList[PROCESSLIST][MAX_PATH], TimeBuffer[0x20];
    int CurrentCount = GetProcessList(CurrentProcessList, CurrentProcessNameList);

    CurrentTime(TimeBuffer);
    for(int i=0; i<CurrentCount; i++){
        int found = 0;
        for(int j=0; j<PrevProcessCount; j++){
            if(CurrentProcessList[i] == PrevProcessList[j]){ found = 1; break; }
        }

        if(!found){
            wprintf(L"[%ls] New Process | PID: %lu | Name: %ls\n", TimeBuffer, CurrentProcessList[i], CurrentProcessNameList[i]);
        }
    }

    for(int i=0; i<PrevProcessCount; i++){
        int found = 0;
        for(int j=0; j<CurrentCount; j++){
            if(PrevProcessList[i] == CurrentProcessList[j]){ found = 1; break; }
        }

        if(!found){
            wprintf(L"[%ls] Process Terminated | PID: %lu | Name: %ls\n", TimeBuffer, PrevProcessList[i], PrevProcessNameList[i]);
        }
    }

    PrevProcessCount = CurrentCount;
    memcpy(PrevProcessList, CurrentProcessList, sizeof(DWORD) * CurrentCount);
    memcpy(PrevProcessNameList, CurrentProcessNameList, sizeof(CurrentProcessNameList));
}

int GetServiceList(SERVICE_INFO *ServiceList){
    SC_HANDLE hScm = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if(hScm == NULL){ wprintf(L"OpenSCManager failed: %d\n", GetLastError()); }

    DWORD dwSize = 0, dwReturn = 0;
    ENUM_SERVICE_STATUS_PROCESS ServiceBuffer[SERVICELIST];

    if(!EnumServicesStatusEx(hScm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_ACTIVE, (LPBYTE)ServiceBuffer, sizeof(ServiceBuffer), &dwSize, &dwReturn, NULL, NULL)){
        wprintf(L"EnumServicesStatusEx failed: %d\n", GetLastError());
        CloseHandle(hScm);
        return 0;
    }

    for(int i=0; i<dwReturn; i++){
        ServiceList[i].ServiceStatus = ServiceBuffer[i];

        wcsncpy(ServiceList[i].ServiceName, ServiceBuffer[i].lpServiceName, MAX_PATH - 1);
        ServiceList[i].ServiceName[MAX_PATH - 1] = 0;
    }

    CloseHandle(hScm);
    return dwReturn;
}

void GetServiceDescription(SC_HANDLE hSCM, const wchar_t *ServiceName, wchar_t *Description){
    SC_HANDLE hService = OpenService(hSCM, ServiceName, SERVICE_QUERY_CONFIG);
    if(hService == NULL){ wsprintf(Description, L"No Description"); return; }

    DWORD dwBytes = 0;
    if(!QueryServiceConfig2(hService, SERVICE_CONFIG_DESCRIPTION, NULL, 0, &dwBytes) && GetLastError() != ERROR_INSUFFICIENT_BUFFER){
        wsprintf(Description, L"No Description");
        CloseServiceHandle(hService);
        return;
    }

    BYTE *pBuffer = (BYTE*)malloc(dwBytes);
    if(pBuffer == NULL){
        wsprintf(Description, L"Allocation failed: %d\n", GetLastError());
        CloseServiceHandle(hService);
        return;
    }

    if(QueryServiceConfig2(hService, SERVICE_CONFIG_DESCRIPTION, pBuffer, dwBytes, &dwBytes)){
        SERVICE_DESCRIPTION *pDesc = (SERVICE_DESCRIPTION*)pBuffer;
        if (pDesc->lpDescription && wcslen(pDesc->lpDescription) > 0) {
            wsprintf(Description, L"%ls", pDesc->lpDescription);
        } else {
            wsprintf(Description, L"No Description");
        }
    } else {
        wsprintf(Description, L"No Description");
    }

    free(pBuffer);
    CloseServiceHandle(hService);
}

void DetectServiceChanges(){
    SERVICE_INFO CurrentServiceList[SERVICELIST];

    int CurrentServiceCount = GetServiceList(CurrentServiceList);  
    wchar_t TimeBuffer[32];
    CurrentTime(TimeBuffer);

    SC_HANDLE hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if(hSCM == NULL){ wprintf(L"OpenSCManager failed: %d\n", GetLastError()); return; }

    for(int i = 0; i < CurrentServiceCount; i++){
        int found = 0;
        for(int j = 0; j < PrevServiceCount; j++){
            if(wcscmp(CurrentServiceList[i].ServiceName, PrevServiceList[j].ServiceName) == 0){
                found = 1;
                break;
            }
        }

        if(!found){
            wchar_t Description[1024] = L"No Description";
            GetServiceDescription(hSCM, CurrentServiceList[i].ServiceName, Description);
            wprintf(L"[%ls] New Service | Name: %ls | PID: %lu | Description: %ls\n", TimeBuffer, CurrentServiceList[i].ServiceName, CurrentServiceList[i].ServiceStatus.ServiceStatusProcess.dwProcessId, Description);
        }
    }

    for(int i = 0; i < PrevServiceCount; i++){
        int found = 0;
        for(int j = 0; j < CurrentServiceCount; j++){
            if (wcscmp(PrevServiceList[i].ServiceName, CurrentServiceList[j].ServiceName) == 0) {
                found = 1;
                break;
            }
        }

        if(!found){
            wprintf(L"[%ls] Service Terminated | Name: %ls | PID: %lu\n", TimeBuffer, PrevServiceList[i].ServiceName, PrevServiceList[i].ServiceStatus.ServiceStatusProcess.dwProcessId);
        }
    }

    CloseServiceHandle(hSCM);

    PrevServiceCount = CurrentServiceCount;
    for(int i = 0; i < CurrentServiceCount; i++){
        PrevServiceList[i] = CurrentServiceList[i]; 

        wcsncpy(PrevServiceList[i].ServiceName, CurrentServiceList[i].ServiceName, MAX_PATH - 1);
        PrevServiceList[i].ServiceName[MAX_PATH - 1] = 0;
    }
}

int wmain(){
    _wsetlocale(LC_ALL, L"");
    SetConsoleOutputCP(CP_UTF8);

    hNtDll = LoadLibraryW(L"ntdll.dll");
    for(int i=0; i<sizeof(Privileges)/sizeof(Privileges[0]); i++){
        if(!EnablePrivilege(Privileges[i])){
            wprintf(L"특권 활성화 실패로 인해 프로세스 정보 조회에 실패할 수 있습니다.\n[Privilege Name]:%ls", Privileges[i]);
        }   
    }

    PrevProcessCount = GetProcessList(PrevProcessList, PrevProcessNameList);
    PrevServiceCount = GetServiceList(PrevServiceList);

    while(1){
        Sleep(5000);
        DetectProcessChanges();
        DetectServiceChanges();
    }

    if(hNtDll != NULL) { FreeLibrary(hNtDll); }
    return 0;
}

