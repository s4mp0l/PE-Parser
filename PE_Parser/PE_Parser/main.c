#include <windows.h>
#include <stdio.h>
#include <time.h>

// Print Timestamp from "pImageNtHeaders->FileHeader.TimeDateStamp"
VOID PrintTimeDateStamp(DWORD dwTimeDateStamp) {
    time_t      tRawTime;
    struct tm   tmUtc;
    errno_t     err;
    CHAR        szBuffer[64];

    tRawTime = (time_t)dwTimeDateStamp;

    err = gmtime_s(&tmUtc, &tRawTime);
    
    if (err == 0)  {
        if (strftime(szBuffer, ARRAYSIZE(szBuffer), "%Y-%m-%d %H:%M:%S UTC", &tmUtc) > 0) {
            printf("\t - TimeDateStamp: %s\n", szBuffer);
        }
        else {
            printf("[!] strftime failed.\n");
        }
    }
    else {
        printf("[!] gmtime_s failed with error code: %d\n", err);
    }
}

// Load the PE file into memory already aligned and parsed
BOOL LoadPeFile(LPCWSTR lpwPeFileName, PBYTE* pPeBase, HANDLE* hMap, HANDLE* hFile) {
    *hFile = CreateFileW(lpwPeFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    
    if (*hFile == INVALID_HANDLE_VALUE) {
        printf("[!] CreateFile failed: %lu\n", GetLastError());
        return FALSE;
    }

    *hMap = CreateFileMappingW(*hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    
    if (*hMap == NULL) {
        printf("[!] CreateFileMappingW failed (Probably not a valid PE) with error code: %lu\n", GetLastError());
        CloseHandle(*hFile);
        return FALSE;
    }

    *pPeBase = (PBYTE)MapViewOfFile(*hMap, FILE_MAP_READ, 0, 0, 0);
    
    if (*pPeBase == NULL) {
        printf("[!] MapViewOfFile failed with error code: %lu\n", GetLastError());
        CloseHandle(*hMap);
        CloseHandle(*hFile);
        return FALSE;
    }

    return TRUE;
}

// parse and print the PE information
BOOL ParsePe(PBYTE pPe) {
    PIMAGE_DOS_HEADER pImageDosHeader = NULL;
    PIMAGE_NT_HEADERS pImageNtHeaders = NULL;
    IMAGE_FILE_HEADER ImageFileHeader = { 0 };
    IMAGE_OPTIONAL_HEADER ImageOptionalHeader = { 0 };
    PIMAGE_DATA_DIRECTORY pImageDataDirectory = NULL;
    PIMAGE_SECTION_HEADER pImageSectionHeader = NULL;
    PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = NULL;
    PIMAGE_IMPORT_DESCRIPTOR pImageImportDescriptor = NULL;
    PIMAGE_RESOURCE_DIRECTORY pImageResourceDirectory = NULL;
    PIMAGE_BASE_RELOCATION pImageBaseRelocation = NULL;
    PIMAGE_DEBUG_DIRECTORY pImageDebugDirectory = NULL;
    PIMAGE_TLS_DIRECTORY pImageTlsDirectory = NULL;

    // parsing DOS Header
    pImageDosHeader = (PIMAGE_DOS_HEADER)pPe;

    if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[!] The file is not a valid PE (Missing MZ)\n");
        return FALSE;
    }

    printf("--- [ DOS Header ] ---\n");
    printf("\t - Magic (MZ signature): 0x%X\n", pImageDosHeader->e_magic);
    printf("\t - e_lfanew (Offset to the NT Headers): 0x%X\n", pImageDosHeader->e_lfanew);

    // parsing NT Headers
    pImageNtHeaders = (PIMAGE_NT_HEADERS)(pPe + pImageDosHeader->e_lfanew);

    if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        printf("[!] Invalid PE signature\n");
        return FALSE;
    }

    printf("\n--- [ NT Headers ] ---\n");
    printf("\t - Signature: 0x%X (Should be 0x4550 'PE')\n", pImageNtHeaders->Signature);

    // parsing File Header
    ImageFileHeader = pImageNtHeaders->FileHeader;
    
    printf("\n--- [ File Header ] ---\n");

    switch (pImageNtHeaders->FileHeader.Machine) {
    case IMAGE_FILE_MACHINE_I386:
        printf("\t - Machine: i386 (32-bit x86)\n");
        break;
    case IMAGE_FILE_MACHINE_AMD64:
        printf("\t - Machine: x86_64 (64-bit x86)\n");
        break;
    case IMAGE_FILE_MACHINE_ARM:
        printf("\t - Machine: ARM (32-bit)\n");
        break;
    case IMAGE_FILE_MACHINE_ARM64:
        printf("\t - Machine: ARM64 (64-bit ARM)\n");
        break;
    default:
        printf("\t - Machine: 0x%04x (Unknown architecture)\n", pImageNtHeaders->FileHeader.Machine);
        break;
    }

    printf("\t - Number Of Sections: %d\n", pImageNtHeaders->FileHeader.NumberOfSections);
    PrintTimeDateStamp(pImageNtHeaders->FileHeader.TimeDateStamp);
    printf("\t - Size Of Optional Header: %d bytes\n", pImageNtHeaders->FileHeader.SizeOfOptionalHeader);
    printf("\t - Characteristics: 0x%04X\n", pImageNtHeaders->FileHeader.Characteristics);

    if (pImageNtHeaders->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED)
        printf("\t\t - IMAGE_FILE_RELOCS_STRIPPED\n");

    if (pImageNtHeaders->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)
        printf("\t\t - IMAGE_FILE_EXECUTABLE_IMAGE\n");

    if (pImageNtHeaders->FileHeader.Characteristics & IMAGE_FILE_LINE_NUMS_STRIPPED)
        printf("\t\t - IMAGE_FILE_LINE_NUMS_STRIPPED\n");

    if (pImageNtHeaders->FileHeader.Characteristics & IMAGE_FILE_LOCAL_SYMS_STRIPPED)
        printf("\t\t - IMAGE_FILE_LOCAL_SYMS_STRIPPED\n");

    if (pImageNtHeaders->FileHeader.Characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE)
        printf("\t\t - IMAGE_FILE_LARGE_ADDRESS_AWARE\n");

    if (pImageNtHeaders->FileHeader.Characteristics & IMAGE_FILE_DLL)
        printf("\t\t - IMAGE_FILE_DLL\n");

    if (pImageNtHeaders->FileHeader.Characteristics & IMAGE_FILE_SYSTEM)
        printf("\t\t - IMAGE_FILE_SYSTEM\n");

    // parsing Optional Header
    ImageOptionalHeader = pImageNtHeaders->OptionalHeader;

    if (ImageOptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC) {
        printf("[!] Invalid PE signature\n");
        return FALSE;
    }

    printf("\n--- [ Optional Header ] ---\n");
    printf("\t - Magic: 0x%X (0x10b for PE32 and 0x20b for PE32+)\n", ImageOptionalHeader.Magic);
    printf("\t - Base Of Code (RVA): 0x%X\n", ImageOptionalHeader.BaseOfCode);
    printf("\t - Size Of Code: 0x%X\n", ImageOptionalHeader.SizeOfCode);
    printf("\t - Size Of Initialized Data: 0x%X\n", ImageOptionalHeader.SizeOfInitializedData);
    printf("\t - Size Of Uninitialized Data: 0x%X\n", ImageOptionalHeader.SizeOfUninitializedData);
    printf("\t - RVA of Entry Point: 0x%X\n", ImageOptionalHeader.AddressOfEntryPoint);
    printf("\t - Required Version: %d.%d\n", ImageOptionalHeader.MajorOperatingSystemVersion, ImageOptionalHeader.MinorOperatingSystemVersion);
    printf("\t - Image Base: 0x%llX\n", ImageOptionalHeader.ImageBase);
    printf("\t - CheckSum: 0x%X \n", ImageOptionalHeader.CheckSum);

    // parsing DataDirectory
    printf("\n--- [ Data Directories ] ---\n");
    printf("\t - Number of Entries: %d\n", IMAGE_NUMBEROF_DIRECTORY_ENTRIES);

    for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++) {
        pImageDataDirectory = &pImageNtHeaders->OptionalHeader.DataDirectory[i];

        LPCSTR lpName = "Unknown";

        switch (i) {
        case IMAGE_DIRECTORY_ENTRY_EXPORT:
            lpName = "EXPORT";
            if (pImageDataDirectory->VirtualAddress != 0) {
                printf("\t\t[EXPORT DIRECTORY]\n");

                pImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(pPe + pImageDataDirectory->VirtualAddress);

                printf("\t\t\t - Export Directory Address: 0x%p\n", pImageExportDirectory);
                printf("\t\t\t - Export Directory Size: %d\n", pImageDataDirectory->Size);
                printf("\t\t\t - Number Of Functions: %d\n", pImageExportDirectory->NumberOfFunctions);
                printf("\t\t\t - Number Of Names: %d\n", pImageExportDirectory->NumberOfNames);
            }
            else {
                printf("\t\t[%2d] %-12s Not present\n", i, lpName);
            }
            break;

        case IMAGE_DIRECTORY_ENTRY_IMPORT:
            lpName = "IMPORT";
            if (pImageDataDirectory->VirtualAddress != 0) {
                printf("\t\t[IMPORT DIRECTORY]\n");

                pImageImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(pPe + pImageDataDirectory->VirtualAddress);

                printf("\t\t\t - Import Directory Address: 0x%p\n", pImageImportDescriptor);
                printf("\t\t\t - Import Directory Size: %d\n", pImageDataDirectory->Size);
                printf("\t\t\t - First Import Name RVA: 0x%08X\n", pImageImportDescriptor->Name);
            }
            else {
                printf("\t\t[%2d] %-12s Not present\n", i, lpName);
            }
            break;

        case IMAGE_DIRECTORY_ENTRY_RESOURCE:
            lpName = "RESOURCE";
            if (pImageDataDirectory->VirtualAddress != 0) {
                printf("\t\t[RESOURCE DIRECTORY]\n");

                pImageResourceDirectory = (PIMAGE_RESOURCE_DIRECTORY)(pPe + pImageDataDirectory->VirtualAddress);

                printf("\t\t\t - Resource Directory Address: 0x%p\n", pImageResourceDirectory);
                printf("\t\t\t - Number of Named Entries: %d\n", pImageResourceDirectory->NumberOfNamedEntries);
                printf("\t\t\t - Number of ID Entries: %d\n", pImageResourceDirectory->NumberOfIdEntries);
            }
            else {
                printf("\t\t[%2d] %-12s Not present\n", i, lpName);
            }
            break;

        case IMAGE_DIRECTORY_ENTRY_EXCEPTION:
            lpName = "EXCEPTION";
            if (pImageDataDirectory->VirtualAddress != 0) {
                printf("\t\t[EXCEPTION DIRECTORY]\n");

                DWORD dwEntryCount = pImageDataDirectory->Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);

                printf("\t\t\t - Table Address: 0x%p\n", (PVOID)(pPe + pImageDataDirectory->VirtualAddress));
                printf("\t\t\t - Table Size: %d bytes\n", pImageDataDirectory->Size);
                printf("\t\t\t - Runtime Function Entries: %d\n", dwEntryCount);
            }
            else {
                printf("\t\t[%2d] %-12s Not present\n", i, lpName);
            }
            break;

        case IMAGE_DIRECTORY_ENTRY_SECURITY:
            lpName = "SECURITY";
            if (pImageDataDirectory->VirtualAddress != 0) {
                printf("\t\t[SECURITY DIRECTORY]\n");
                printf("\t\t\t - File Offset: 0x%08X\n", pImageDataDirectory->VirtualAddress);
                printf("\t\t\t - Size: %d bytes\n", pImageDataDirectory->Size);
            }
            else {
                printf("\t\t[%2d] %-12s Not present\n", i, lpName);
            }
            break;

        case IMAGE_DIRECTORY_ENTRY_BASERELOC:
            lpName = "BASERELOC";
            if (pImageDataDirectory->VirtualAddress != 0) {
                printf("\t\t[BASE RELOCATION]\n");

                pImageBaseRelocation = (PIMAGE_BASE_RELOCATION)(pPe + pImageDataDirectory->VirtualAddress);

                printf("\t\t\t - Reloc Address: 0x%p\n", pImageBaseRelocation);
                printf("\t\t\t - Total Size: %d bytes\n", pImageDataDirectory->Size);
            }
            else {
                printf("\t\t[%2d] %-12s Not present\n", i, lpName);
            }
            break;

        case IMAGE_DIRECTORY_ENTRY_DEBUG:
            lpName = "DEBUG";
            if (pImageDataDirectory->VirtualAddress != 0) {
                printf("\t\t[DEBUG DIRECTORY]\n");

                pImageDebugDirectory = (PIMAGE_DEBUG_DIRECTORY)(pPe + pImageDataDirectory->VirtualAddress);

                DWORD dwEntries = pImageDataDirectory->Size / sizeof(IMAGE_DEBUG_DIRECTORY);

                printf("\t\t\t - Debug Dir Address: 0x%p\n", pImageDebugDirectory);
                printf("\t\t\t - Number of Entries: %d\n", dwEntries);
                printf("\t\t\t - Type: %d\n", pImageDebugDirectory->Type);
                printf("\t\t");
                PrintTimeDateStamp(pImageDebugDirectory->TimeDateStamp);
            }
            else {
                printf("\t\t[%2d] %-12s Not present\n", i, lpName);
            }
            break;

        case IMAGE_DIRECTORY_ENTRY_TLS:
            lpName = "TLS";
            if (pImageDataDirectory->VirtualAddress != 0) {
                printf("\t\t[TLS DIRECTORY]\n");

                pImageTlsDirectory = (PIMAGE_TLS_DIRECTORY)(pPe + pImageDataDirectory->VirtualAddress);

                printf("\t\t\t - TLS Address: 0x%p\n", pImageTlsDirectory);
                printf("\t\t\t - Start Address of Raw Data: 0x%llX\n", pImageTlsDirectory->StartAddressOfRawData);
                printf("\t\t\t - End Address of Raw Data: 0x%llX\n", pImageTlsDirectory->EndAddressOfRawData);
            }
            else {
                printf("\t\t[%2d] %-12s Not present\n", i, lpName);
            }
            break;

        case IMAGE_DIRECTORY_ENTRY_IAT:
            lpName = "IAT";
            if (pImageDataDirectory->VirtualAddress != 0) {
                printf("\t\t[IAT DIRECTORY]\n");
                printf("\t\t\t - IAT Address (RVA): 0x%08X\n", pImageDataDirectory->VirtualAddress);
                printf("\t\t\t - IAT Size: %d bytes\n", pImageDataDirectory->Size);
            }
            else {
                printf("\t\t[%2d] %-12s Not present\n", i, lpName);
            }
            break;

        default:
            if (pImageDataDirectory->VirtualAddress == 0) {
                printf("\t\t[%2d] Reserved/Other Not present\n", i);
            }
            else {
                printf("\t\t[%2d] Reserved/Other Present (RVA: 0x%X)\n", i, pImageDataDirectory->VirtualAddress);
            }
            break;
        }
    }

    // parsing PE sections
    printf("\n--- [ Sections ] ---\n");
    printf("\t - Number of Sections: %d\n", pImageNtHeaders->FileHeader.NumberOfSections);

    pImageSectionHeader = (PIMAGE_SECTION_HEADER)(((PBYTE)pImageNtHeaders) + sizeof(IMAGE_NT_HEADERS));

    for (SIZE_T i = 0; i < pImageNtHeaders->FileHeader.NumberOfSections; i++) {
        printf("\t - Section Name: %.8s\n", (CHAR*)pImageSectionHeader->Name);
        printf("\t\t - RVA: 0x%X\n", pImageSectionHeader->VirtualAddress);
        printf("\t\t - Section Address: 0x%p\n", (PVOID)(pPe + pImageSectionHeader->VirtualAddress));
        printf("\t\t - Size: %d\n", pImageSectionHeader->SizeOfRawData);
        printf("\t\t - Offset to Realocations: 0x%X\n", pImageSectionHeader->PointerToRelocations);
        printf("\t\t - Number Of Relocations: %d\n", pImageSectionHeader->NumberOfRelocations);
        printf("\t\t - Permissions:\n");
        
        printf("\t\t\t - ");

        if (pImageSectionHeader->Characteristics & IMAGE_SCN_MEM_READ)
            printf("PAGE_READONLY | ");
        
        if (pImageSectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE && pImageSectionHeader->Characteristics & IMAGE_SCN_MEM_READ)
            printf("PAGE_READWRITE | ");
        
        if (pImageSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE)
            printf("PAGE_EXECUTE | ");
        
        if (pImageSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE && pImageSectionHeader->Characteristics & IMAGE_SCN_MEM_READ)
            printf("PAGE_EXECUTE_READWRITE");

        printf("\n\n");

        pImageSectionHeader = (PIMAGE_SECTION_HEADER)((PBYTE)pImageSectionHeader + (DWORD)sizeof(IMAGE_SECTION_HEADER));
    }

    return TRUE;
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc != 2) {
        wprintf(L"[!] Usage: %ls <pe_file.exe/dll>\n\n", argv[0]);
        return 1;
    }

    LPCWSTR lpwPeFileName = argv[1];
    
    PBYTE  pPe = NULL;
    HANDLE hMap = NULL;
    HANDLE hFile = INVALID_HANDLE_VALUE;

    // load the PE file from disk into memory
    wprintf(L"[*] Loading %ls...\n", lpwPeFileName);

    if (!LoadPeFile(lpwPeFileName, &pPe, &hMap, &hFile)) {
        printf("[!] LoadPeFile failed\n");
        return 1;
    }

    printf("[*] Parsing PE...\n\n");

    // parse the PE
    if (!ParsePe(pPe)) {
        printf("[!] ParsePe failed\n");
        return 1;
    }

    // cleanup
    if (pPe) UnmapViewOfFile(pPe);
    if (hMap) CloseHandle(hMap);
    if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);

    printf("[#] DONE. Press <Enter> to Exit...");
    (void)getchar();

    return 0;
}