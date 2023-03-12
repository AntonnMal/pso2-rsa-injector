#include <stdio.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>

#include <string.h>

#define min(a, b) (((a) < (b)) ? (a) : (b))
#define KEYSIZE 0x80
#define RSASIZE 0xA0
#define KEYAMNT 4

__declspec(dllexport) volatile char userkey[KEYSIZE] = {0};
__declspec(dllexport) volatile char keys[KEYSIZE * KEYAMNT] = {0};

__declspec(dllexport) void changekey(
unsigned char*		pbInput,
unsigned long		cbInput
) {
	int i, ii;
	for (ii = 0; ii < 4; ii++) {
		i = memcmp(pbInput + 0x23, (char*)(keys + KEYSIZE * ii), min(cbInput - 0x23, KEYSIZE));
		if (!i)
		{
			memcpy(pbInput + 0x23, (char*)userkey, KEYSIZE);
			return;
		}
	}
	return;
}

//-----------------------------------------------------------
// NGS stuff
//-----------------------------------------------------------

void writereverse(char* dst, const char* src, size_t len)
{
	int i;
	for (i = 0; i < len; i++)
		dst[i] = src[len - 1 - i];
}

unsigned char RSAHeader[] = {
	0x06, 0x02, 0x00, 0x00, 0x00, 0xA4, 0x00, 0x00, 0x52, 0x53, 0x41, 0x31, 0x00, 0x04, 0x00, 0x00
};

unsigned long pso2_pid = 0;
char* reboot_addr = (char*)0;
size_t reboot_size = 0;
int got_key = 0;

void get_reboot_addr() {
	if (pso2_pid == 0) {
		PROCESSENTRY32 ps_entry;
		ps_entry.dwSize = sizeof(PROCESSENTRY32);
		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (Process32First(snapshot, &ps_entry) == TRUE) {
			do {
				if (stricmp(ps_entry.szExeFile, "pso2.exe") == 0) {
					pso2_pid = ps_entry.th32ProcessID;
					break;
				}
			} while (Process32Next(snapshot, &ps_entry) == TRUE);
		}
		CloseHandle(snapshot);
	}
	if (pso2_pid == 0){
		return;
	} else if (reboot_addr == 0) {
		MODULEENTRY32 md_entry;
		md_entry.dwSize = sizeof(MODULEENTRY32);
		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pso2_pid);
		if (Module32First(snapshot, &md_entry) == TRUE) {
			do {
				if (stricmp(md_entry.szModule, "pso2reboot.dll") == 0) {
					reboot_addr = md_entry.modBaseAddr;
					reboot_size = md_entry.modBaseSize;
					break;
				}
			} while (Module32Next(snapshot, &md_entry) == TRUE);
		}
		CloseHandle(snapshot);
	}
}


__declspec(dllexport) void cap_key() {
	
	size_t HeaderSize = sizeof(RSAHeader);
	size_t i;
	char* RSAaddr = (char*) 0;

	get_reboot_addr();
	if (got_key != 0) {
		return;
	}
	if (reboot_addr == 0) {
		return;
	}
	for (i = 0; i < reboot_size; i++) {
		int ii = memcmp(reboot_addr + i, RSAHeader, HeaderSize);
		if (!ii)
		{
			RSAaddr = reboot_addr + i;
			break;
		}
	}
	if (RSAaddr == 0) {
		return;
	}

	char* str = "SEGAKey.blob";
	FILE* outFile;
	// Open the output file-stream:
	#if !defined(_CRT_SECURE_NO_WARNINGS) && (defined(_MSC_VER) || defined(MINGW_HAS_SECURE_API))
	// This is just for the sake of shutting MSVC up:
	fopen_s(&outFile, str, "wb");
	#else
	// Here's the standard C version:
	outFile = fopen(str, "wb");
	#endif
	if (outFile)
	{
		for (i = 0; i < KEYAMNT; i++)
		{
			// Setup the pointer.
			const char* ptr = RSAaddr + (i * RSASIZE);
			// Write to detour's keys array
			writereverse((char*)(keys + i * KEYSIZE), ptr + 0x14, KEYSIZE);
			// Write to the disk.
			fwrite(ptr, RSASIZE, 1, outFile);
		}
		// Close the output-file.
		fclose(outFile);
	}
	got_key = 1;
}