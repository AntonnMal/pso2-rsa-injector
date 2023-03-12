// Preprocessor related:

// Specify to the Windows API that we're not using all of it.
#define WIN32_LEAN_AND_MEAN

// Includes:
// Windows specific headers:
#include <windows.h>

// Standard C includes:
#include <stdio.h>
#include <stdint.h>


#include "defines.h"

// Functions:
//-----------------------------------------------------------
// findRSA() -> pointer to RSA blobs
// Find the memory location of RSA key blobs (pre-NGS only)
//-----------------------------------------------------------
char* findRSA()
{
	char* psoBase = (char*) 0x140000000;
	size_t HeaderSize = sizeof(RSAHeader);
	size_t ImageSize = 0x411C000;
	size_t i;
	char* RSAaddr = (char*) 0;
	
	for (i = 0; i < ImageSize; i++)
	{
		int ii;
		for (ii = 0; (ii < HeaderSize) && (*(psoBase + i + ii) == RSAHeader[ii]); ii++);
		if (ii == HeaderSize)
		{
			RSAaddr = psoBase + i;
			break;
		}
	}
	return RSAaddr;
}

//-----------------------------------------------------------
// writereverse(destination address, source address, length)
// Write data in reverse order
//-----------------------------------------------------------
VOID writereverse(char* dst, const char* src, size_t len)
{
	int i;
	for (i = 0; i < len; i++)
		dst[i] = src[len - 1 - i];
}

//-----------------------------------------------------------
// grabRSAKeys(keys array address)
// Find and dump RSA keys
//-----------------------------------------------------------
VOID grabRSAKeys(char* keys)
{
	// Find RSA blobs
	char* RSAaddr = findRSA();
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
	/*
		This is for the loop, if we didn't care about C99 compatibility,
		we would have this in the 'for' loop.
	*/
	int i;
	if (outFile)
	{
		for (i = 0; i < KEYAMNT; i++)
		{
			// Setup the pointer.
			const char* ptr = RSAaddr + (i * RSASIZE);
			// Write to detour's keys array
			writereverse(keys + i * KEYSIZE, ptr + 0x14, KEYSIZE);
			// Write to the disk.
			fwrite(ptr, RSASIZE, 1, outFile);
		}
		// Close the output-file.
		fclose(outFile);
	}
	return;
}

//-----------------------------------------------------------
// getemptyspaceoffset(initial address, desired length)
// Find offset to block of empty space
//-----------------------------------------------------------
size_t getemptyspaceoffset(char* init_addr, size_t len) {
	char* addr = init_addr;
	len += 4;
	int x;
	for (x = 0; x < len; x++) {
		if (*(addr + x) != 0) {
			addr += x;
			x = 0;
		}
			
	}
	return addr - init_addr + 4;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	UNREFERENCED_PARAMETER(hinstDLL);
	UNREFERENCED_PARAMETER(lpvReserved);

	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		char cryptbase_path[128];
		// Get path to Windows folder
		GetSystemDirectoryA(cryptbase_path, sizeof(cryptbase_path));
		// Append the real dll name
		#if !defined(_CRT_SECURE_NO_WARNINGS) && (defined(_MSC_VER) || defined(MINGW_HAS_SECURE_API))
		strcat_s(cryptbase_path, sizeof(cryptbase_path), "\\cryptbase.dll");
		#else
		strcat(cryptbase_path, "\\cryptbase.dll");
		#endif
		// Load that dll
		LoadLibraryA(cryptbase_path);
		HINSTANCE bcrypt_h = GetModuleHandleA("bcrypt.dll");
		HINSTANCE detour_h = LoadLibraryA("detour.dll");
		if (detour_h == NULL || bcrypt_h == NULL)
		{
			MessageBoxA(NULL, LoadLibraryAText, LoadLibraryACaptionText, InjectBoxFlags);
			return FALSE;
		}

		char* ImportKeyPairAddr = (char*)GetProcAddress(bcrypt_h, "BCryptImportKeyPair");
		
		if (ImportKeyPairAddr == NULL)
		{
			MessageBoxA(NULL, LoadLibraryAText, LoadLibraryACaptionText, InjectBoxFlags);
			return FALSE;
		}
		char* detour_func = (char*)GetProcAddress(detour_h, "changekey");
		char* userkey = (char*)GetProcAddress(detour_h, "userkey");
		char* keys = (char*)GetProcAddress(detour_h, "keys");
		char* cap_key_func = (char*)GetProcAddress(detour_h, "cap_key");
		if (detour_func == NULL || userkey == NULL || keys == NULL)
		{
			MessageBoxA(NULL, LoadLibraryAText, LoadLibraryACaptionText, InjectBoxFlags);
			return FALSE;
		}

		// Search for empty space
		size_t offset = getemptyspaceoffset(ImportKeyPairAddr, sizeof(jumptodetour));
		// Copy original instruction
		memcpy(jumptodetour + 90, ImportKeyPairAddr, sizeof(jumpfromimport));
		// Setup jump to detour
		*(uint32_t*)(jumpfromimport + 1) = offset - 5;
		// Setup detour function location
		*(uint64_t*)(jumptodetour + 50) = (uint64_t)detour_func;
		// Setup jump back
		*(int32_t*)(jumptodetour + 96) = -((int32_t)(offset + sizeof(jumptodetour) - sizeof(jumpfromimport)));
		
		DWORD oldmempr = 0;
		// Mark bcrypt.dll's memory as read/write/exec
		VirtualProtect(ImportKeyPairAddr, sizeof(jumptodetour) + offset, PAGE_EXECUTE_READWRITE, &oldmempr);
		// Put detour in bcrypt.dll's memory
		memcpy(ImportKeyPairAddr, jumpfromimport, sizeof(jumpfromimport));
		memcpy(ImportKeyPairAddr + offset, jumptodetour, sizeof(jumptodetour));
		// Return original permissions
		VirtualProtect(ImportKeyPairAddr, sizeof(jumptodetour) + offset, oldmempr, &oldmempr);


		FILE* pubkeys;
		// Open the public-key file.
		#if !defined(_CRT_SECURE_NO_WARNINGS) && (defined(_MSC_VER) || defined(MINGW_HAS_SECURE_API))
		fopen_s(&pubkeys, "publickey.blob", "rb");
		#else
		pubkeys = fopen("publickey.blob", "rb");
		#endif
		if (!pubkeys)
		{
			MessageBoxA(NULL, fopenText, fopenCaptionText, InjectBoxFlags);
			return FALSE;
		}
		char buff[RSASIZE] = {0};
		fread(buff, RSASIZE, 1, pubkeys);
		writereverse(userkey, buff + 0x14, KEYSIZE);
		fclose(pubkeys);
		
		FILE* segakeys;
		#if !defined(_CRT_SECURE_NO_WARNINGS) && (defined(_MSC_VER) || defined(MINGW_HAS_SECURE_API))
		fopen_s(&segakeys, "SEGAKey.blob", "rb");
		#else
		segakeys = fopen("SEGAKey.blob", "rb");
		#endif
		if (segakeys)
		{
			int i;
			for (i = 0; i < KEYAMNT; i++)
			{
				fread(buff, RSASIZE, 1, segakeys);
				writereverse(keys + i * KEYSIZE, buff + 0x14, KEYSIZE);
			}
			fclose(segakeys);
		}
		else
		{
			char buff2[128];
			// Check if this is NGS
			unsigned long le = SearchPathA(NULL, "pso2reboot.dll", NULL, sizeof(buff2), buff2, NULL);
			if (le == 0) {
				grabRSAKeys(keys);
			}
			//NGS
			else {
				char* OpenAlgAddr = (char*)GetProcAddress(bcrypt_h, "BCryptOpenAlgorithmProvider");
				if (cap_key_func == NULL)
				{
					MessageBoxA(NULL, LoadLibraryAText, LoadLibraryACaptionText, InjectBoxFlags);
					return FALSE;
				}

				offset = getemptyspaceoffset(OpenAlgAddr, sizeof(jumptodetour));
				memcpy(jumptodetour + 90, OpenAlgAddr, sizeof(jumpfromimport));
				*(uint32_t*)(jumpfromimport + 1) = offset - 5;
				*(uint64_t*)(jumptodetour + 50) = (uint64_t)cap_key_func;
				*(int32_t*)(jumptodetour + 96) = -((int32_t)(offset + sizeof(jumptodetour) - sizeof(jumpfromimport)));
				
				DWORD oldmempr = 0;
				VirtualProtect(OpenAlgAddr, sizeof(jumptodetour) + offset, PAGE_EXECUTE_READWRITE, &oldmempr);
				memcpy(OpenAlgAddr, jumpfromimport, sizeof(jumpfromimport));
				memcpy(OpenAlgAddr + offset, jumptodetour, sizeof(jumptodetour));
				VirtualProtect(OpenAlgAddr, sizeof(jumptodetour) + offset, oldmempr, &oldmempr);
			}	
		}
	}

	// Return the default response.
	return FALSE;
}
