#include <stdio.h>
#include <windows.h>
#include <psapi.h>
#define NTDLL_DLL "NTDLL.dll"
#define NTDLL_PATH "C:\\Windows\\System32\\ntdll.dll"

BOOL SetuphProcessNtDllContext(OUT HANDLE  *hCurrentProcess ,OUT HMODULE  *hNtdllModule  , OUT LPVOID  *HookedNtDllBaseAddress) {

	 *hCurrentProcess = GetCurrentProcess();
	 *hNtdllModule = GetModuleHandleA(NTDLL_DLL);
	 if (*hCurrentProcess != NULL) {
		 printf("[+] Current Process Handle Retrieved Successfully\n");
	 }
	 else {
		 printf("[!] Failed To Get Current Process Handle\n");
		 return FALSE; 
	 }

	 MODULEINFO ntdllmoduleinfo = { 0 };

	 if (!*hNtdllModule){
	 
		 printf("[!] ERROR: NTDLL not found");
		 return FALSE;
	 }

	 SIZE_T ntdllmoduleinfoSIZE = sizeof(MODULEINFO);

	 GetModuleInformation(*hCurrentProcess, *hNtdllModule , &ntdllmoduleinfo ,ntdllmoduleinfoSIZE);

	 *HookedNtDllBaseAddress = (LPVOID)ntdllmoduleinfo.lpBaseOfDll;
	 printf("[+] NTDLL Base Address -> %p\n", *HookedNtDllBaseAddress);

	 return TRUE;
}

BOOL MapNtDllFromDisk(OUT HANDLE* hNtdllFile, OUT HANDLE* CreateNtDllFileMapping, OUT  LPVOID   *ntdllMappingAddress) {

	*hNtdllFile = CreateFileA(NTDLL_PATH,
		GENERIC_READ, FILE_SHARE_READ, NULL,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (*hNtdllFile == INVALID_HANDLE_VALUE) {
		printf("[!] CreateFileA Failed -> %ld\n", GetLastError());
		return FALSE;
	}
	else {
		printf("[+] Successfully opened NTDLL.dll\n");
	}

	*CreateNtDllFileMapping = CreateFileMappingA(*
		    hNtdllFile, NULL ,
		                PAGE_READONLY | 
		SEC_IMAGE, 0, 0, 0);


	*ntdllMappingAddress = MapViewOfFile(*CreateNtDllFileMapping, FILE_MAP_READ, 0, 0, 0);

	return TRUE;
}


int main() {
	
	printf("###################### NtDll_Unhooking #######################\n");
	printf("##############################################################\n");

	printf("\n");
	HANDLE  hCurrentProcess = NULL;
	HMODULE hNtdllModule = NULL;
	LPVOID  HookedNtDllBaseAddress = NULL;
	HANDLE  hNtdllFile = NULL; 
	DWORD   lpflOldProtect = NULL;
	LPVOID  ntdllMappingAddress = NULL;
	HANDLE  FILEMAPPING = NULL;
	
	if (!SetuphProcessNtDllContext(&hCurrentProcess, &hNtdllModule, &HookedNtDllBaseAddress))
	{
		printf("[!] Failed to setup DLL context\n");
		return -1;
	}
	printf("[+] DLL context initialized successfully\n");
	
	if (!MapNtDllFromDisk(&hNtdllFile, &FILEMAPPING, &ntdllMappingAddress))
	{
		printf("[!] Failed to map NTDLL from disk\n");
		return -1;
	}
	else
	{
		printf("[+] NTDLL mapped from disk\n");
	}

	PIMAGE_DOS_HEADER HOOKEDDOSHEADER = (PIMAGE_DOS_HEADER)HookedNtDllBaseAddress;
	PIMAGE_NT_HEADERS HOOKEDNTHEADERS = (PIMAGE_NT_HEADERS)((DWORD_PTR)HookedNtDllBaseAddress + HOOKEDDOSHEADER->e_lfanew);


	for (DWORD c = 0; c < HOOKEDNTHEADERS->FileHeader.NumberOfSections; c++) {

		PIMAGE_SECTION_HEADER HOOKEDSECTIONHEADER = (PIMAGE_SECTION_HEADER)

			((DWORD_PTR)IMAGE_FIRST_SECTION(HOOKEDNTHEADERS) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * c));


		if (!strcmp((const char*)HOOKEDSECTIONHEADER->Name, (const char*)".text")) {

			if (!VirtualProtect((LPVOID)((DWORD_PTR)HookedNtDllBaseAddress + (DWORD_PTR)HOOKEDSECTIONHEADER->VirtualAddress),
				HOOKEDSECTIONHEADER->Misc.VirtualSize,
				PAGE_EXECUTE_READWRITE,
				&lpflOldProtect))
			{
				printf("[!] Memory protection update failed\n");
			}
			else
			{
				printf("[+] Memory protection updated\n");
			}

			memcpy((LPVOID)((DWORD_PTR)HookedNtDllBaseAddress + (DWORD_PTR)HOOKEDSECTIONHEADER->VirtualAddress),
				(LPVOID)((DWORD_PTR)ntdllMappingAddress + (DWORD_PTR)HOOKEDSECTIONHEADER->VirtualAddress),
				HOOKEDSECTIONHEADER->Misc.VirtualSize);

			printf("[+] NTDLL code section updated\n");

			if (!VirtualProtect((LPVOID)((DWORD_PTR)HookedNtDllBaseAddress + (DWORD_PTR)HOOKEDSECTIONHEADER->VirtualAddress),
				HOOKEDSECTIONHEADER->Misc.VirtualSize, lpflOldProtect, &lpflOldProtect)) {

				printf("[!] Couldn't restore memory protection\n");
			}
			else {
				printf("[+] Memory protection restored\n");

			}
		}
	}

	printf("-------------------------------------------------------------\n");
	printf("|Done|-NTDLL .text section replaced with clean version from disk\n");
	printf("---------------------------------------------------------------\n");
	
	printf("[+] Press Enter to exit.....\n");
	getchar();
	return 0;
}
