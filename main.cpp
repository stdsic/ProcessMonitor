#include <windows.h>
#include <winsvc.h>
#include <psapi.h>
#include <stdlib.h>
#include <locale.h>
#include <stdio.h>
#include <string.h>

#define PROCESSLIST		0x400
#define SERVICELIST		0x400

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

int GetProcessList(DWORD *ProcessList, wchar_t ProcessNameList[PROCESSLIST][MAX_PATH]){
	int cnt = 0;
	DWORD dwBytes;

	if(EnumProcesses(ProcessList, sizeof(DWORD) * PROCESSLIST, &dwBytes)){
		cnt = dwBytes / sizeof(DWORD);
		for(int i=0; i<cnt; i++){
			HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, ProcessList[i]);
			if(!hProcess){ 
				DWORD Error = GetLastError();
				if(Error == ERROR_ACCESS_DENIED){
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
						wchar_t *filename = wcsrchr(ProcessNameList[i], '\\');
						if(filename && (*filename + 1)){
							wcscpy(ProcessNameList[i], filename + 1);
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

void DetectServiceChanges() {
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

	PrevProcessCount = GetProcessList(PrevProcessList, PrevProcessNameList);
	PrevServiceCount = GetServiceList(PrevServiceList);

	while(1){
		Sleep(5000);
		DetectProcessChanges();
		DetectServiceChanges();
	}

	return 0;
}
