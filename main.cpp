#include <windows.h>
#include <winsvc.h>
#include <psapi.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define PROCESSLIST		0x400
#define SERVICELIST		0x400

DWORD PrevProcessList[PROCESSLIST];
ENUM_SERVICE_STATUS_PROCESS PrevServiceList[SERVICELIST];

wchar_t PrevProcessNameList[PROCESSLIST][MAX_PATH];
int PrevProcessCount, PrevServiceCount;

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
			HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION| PROCESS_VM_READ, FALSE, ProcessList[i]);
			if(!hProcess){ 
				DWORD Error = GetLastError();
				if(Error == ERROR_ACCESS_DENIED){
					wcscpy(ProcessNameList[i], L"Protected Process Light(PPL)");
				}else{
					wcscpy(ProcessNameList[i], L"Warning: Unknown Process");
				}
			}

			if(!GetModuleBaseName(hProcess, NULL, ProcessNameList[i], MAX_PATH)){
				if(!GetModuleFileNameEx(hProcess, NULL, ProcessNameList[i], MAX_PATH)){
					DWORD dwSize;
					if(QueryFullProcessImageName(hProcess, 0, ProcessNameList[i], &dwSize)){
						// 경로에서 파일명만 추출
						wchar_t *filename = wcsrchr(ProcessNameList[i], '\\');
						if (filename) {
							wcscpy(ProcessNameList[i], filename + 1);
						}
					}else{
						wcscpy(ProcessNameList[i], L"Warning: Unknown Process");
					}
				}
			}

			CloseHandle(hProcess);
		}
	}

	return cnt;
}

int GetServiceList(ENUM_SERVICE_STATUS_PROCESS *ServiceList){
	SC_HANDLE hScm = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
	if(hScm == NULL){ wprintf(L"OpenSCManager failed: %d\n", GetLastError()); }

	DWORD dwSize = 0, dwReturn = 0;
	if(!EnumServicesStatusEx(hScm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_ACTIVE, (LPBYTE)ServiceList, sizeof(ENUM_SERVICE_STATUS_PROCESS) * SERVICELIST, &dwSize, &dwReturn, NULL, NULL)){
		wprintf(L"EnumServicesStatusEx failed: %d\n", GetLastError());
	}

	CloseHandle(hScm);
	return dwReturn;
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

void GetServiceDescription(SC_HANDLE hSCM, const wchar_t *ServiceName, wchar_t *Description){
	SC_HANDLE hService = OpenService(hSCM, ServiceName, SERVICE_QUERY_CONFIG);
	if(hService == NULL){ wsprintf(Description, L"No Description"); return; }

	DWORD dwBytes;
	BYTE* pDescription = NULL;
	if(QueryServiceConfig2(hService, SERVICE_CONFIG_DESCRIPTION, pDescription, dwBytes, &dwBytes)){
		wsprintf(Description, L"%ls", ((SERVICE_DESCRIPTION*)pDescription)->lpDescription);
	}else{
		wsprintf(Description, L"No Description");
	}

	free(pDescription);
	CloseServiceHandle(hService);
}

void DetectServiceChanges(){
	ENUM_SERVICE_STATUS_PROCESS CurrentServiceList[SERVICELIST];
	
	int CurrentServiceCount = GetServiceList(CurrentServiceList);
	wchar_t TimeBuffer[0x20];
	CurrentTime(TimeBuffer);

	SC_HANDLE hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
	if(!hSCM){ wprintf(L"OpenSCManager failed: %d\n", GetLastError()); return; }

	for(int i=0; i<CurrentServiceCount; i++){
		int found = 0;
		for(int j=0; j<PrevServiceCount; j++){
			if(wcscmp(CurrentServiceList[i].lpServiceName, PrevServiceList[j].lpServiceName) == 0){
				found = 1;
				break;
			}
		}

		if(!found){
			wchar_t Description[0x400];
			GetServiceDescription(hSCM, CurrentServiceList[i].lpServiceName, Description);
			wprintf(L"[%ls] New Service | Name: %ls | PID: %lu | Description: %ls\n", TimeBuffer, CurrentServiceList[i].lpServiceName, CurrentServiceList[i].ServiceStatusProcess.dwProcessId, Description);
		}
	}

	for(int i=0; i<PrevServiceCount; i++){
		int found = 0;
		for(int j=0; j<CurrentServiceCount; j++){
			if(wcscmp(PrevServiceList[i].lpServiceName, CurrentServiceList[i].lpServiceName) == 0){
				found = 1;
				break;
			}
		}

		if(!found){
			wprintf(L"[%ls] Service Terminated | Name: %ls | PID: %lu\n", TimeBuffer, PrevServiceList[i].lpServiceName, PrevServiceList[i].ServiceStatusProcess.dwProcessId);
		}
	}

	CloseServiceHandle(hSCM);
	PrevServiceCount = CurrentServiceCount;
	memcpy(PrevServiceList, CurrentServiceList, sizeof(ENUM_SERVICE_STATUS_PROCESS) * CurrentServiceCount);
}

int wmain(){
	PrevProcessCount = GetProcessList(PrevProcessList, PrevProcessNameList);
	PrevServiceCount = GetServiceList(PrevServiceList);

	while(1){
		Sleep(5000);
		DetectProcessChanges();
		DetectServiceChanges();
	}

	return 0;
}
