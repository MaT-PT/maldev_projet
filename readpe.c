#include <Windows.h>
#include <stdio.h>
#include <string.h>
#include "utils.h"

static inline VOID TimestampToFiletime(IN CONST DWORD dwTimestamp, OUT LPFILETIME pFiletime) {
    ULARGE_INTEGER uli;
    uli.QuadPart = (dwTimestamp + 11'644'473'600ULL) * 10'000'000ULL;
    pFiletime->dwLowDateTime = uli.LowPart;
    pFiletime->dwHighDateTime = uli.HighPart;
}

int main(int argc, char* argv[]) {
    int ret = 0;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <filename.exe>\n", argv[0]);
        ret = 1;
        goto exit;
    }

    printf("Reading file: %s\n", argv[1]);

    CONST HANDLE hFile = CreateFile(argv[1], GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
                                    FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        PrintError("CreateFile");
        ret = 1;
        goto exit;
    }

    CONST DWORD dwFileSize = GetFileSize(hFile, NULL);
    printf("File size: %lu bytes\n", dwFileSize);
    ULARGE_INTEGER uliSize;
    LIQUAD(uliSize) = dwFileSize;

    CONST HANDLE hMapFile = CreateFileMapping(hFile, NULL, PAGE_READWRITE, LIHILO(uliSize), NULL);
    if (hMapFile == NULL) {
        PrintError("CreateFileMapping");
        ret = 1;
        goto close_file;
    }

    ULARGE_INTEGER uliOffset;
    LIQUAD(uliOffset) = 0;
    CONST LPCVOID pMapAddress = MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, LIHILO(uliOffset), 0);
    if (pMapAddress == NULL) {
        PrintError("MapViewOfFile");
        ret = 1;
        goto close_map;
    }

    CONST PCIMAGE_DOS_HEADER pDosHeader = (PCIMAGE_DOS_HEADER)pMapAddress;
    CONST PCIMAGE_NT_HEADERS64 pNtHeader =
        (PCIMAGE_NT_HEADERS64)((PCBYTE)pDosHeader + pDosHeader->e_lfanew);
    CONST PCIMAGE_FILE_HEADER pFileHeader = &pNtHeader->FileHeader;
    CONST PCIMAGE_OPTIONAL_HEADER64 pOptionalHeader = &pNtHeader->OptionalHeader;
    PCIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeader);
    PCIMAGE_SECTION_HEADER pFirstSection = pSection;

    CONST WORD wNbSections = pFileHeader->NumberOfSections;
    CONST DWORD dwTimestamp = pFileHeader->TimeDateStamp;
    FILETIME ftTimestamp;
    SYSTEMTIME stTimestamp;
    TimestampToFiletime(dwTimestamp, &ftTimestamp);
    FileTimeToSystemTime(&ftTimestamp, &stTimestamp);
    SystemTimeToTzSpecificLocalTimeEx(NULL, &stTimestamp, &stTimestamp);

    printf("========================================\n");
    printf("DOS magic:            %#06hx     (\"%.2s\")\n", pDosHeader->e_magic,
           (LPCSTR)&pDosHeader->e_magic);
    printf("PE signature:         %#010lx (\"%.4s\")\n", pNtHeader->Signature,
           (LPCSTR)&pNtHeader->Signature);
    printf("Machine:              %#06hx\n", pFileHeader->Machine);
    printf("Number of sections:   %hu\n", wNbSections);
    printf("Timestamp:            %#010lx (%hu-%02hu-%02hu %02hu:%02hu:%02hu)\n", dwTimestamp,
           stTimestamp.wYear, stTimestamp.wMonth, stTimestamp.wDay, stTimestamp.wHour,
           stTimestamp.wMinute, stTimestamp.wSecond);
    printf("Ptr to symbol table:  %#010lx\n", pFileHeader->PointerToSymbolTable);
    printf("Number of symbols:    %lu\n", pFileHeader->NumberOfSymbols);
    printf("Characteristics:      %#06hx\n", pFileHeader->Characteristics);
    printf("Optional header size: %hu\n", pFileHeader->SizeOfOptionalHeader);

    printf("========================================\n");
    printf("Optional magic:       %#06hx\n", pOptionalHeader->Magic);
    printf("Major linker version: %hhu\n", pOptionalHeader->MajorLinkerVersion);
    printf("Minor linker version: %hhu\n", pOptionalHeader->MinorLinkerVersion);
    printf("Size of code:         %lu\n", pOptionalHeader->SizeOfCode);
    printf("Size of init data:    %lu\n", pOptionalHeader->SizeOfInitializedData);
    printf("Size of uninit data:  %lu\n", pOptionalHeader->SizeOfUninitializedData);
    printf("Entry point RVA:      %#010lx\n", pOptionalHeader->AddressOfEntryPoint);
    printf("Base of code:         %#010lx\n", pOptionalHeader->BaseOfCode);
    printf("Image base:           %#018llx\n", pOptionalHeader->ImageBase);
    printf("Section alignment:    %lu\n", pOptionalHeader->SectionAlignment);
    printf("File alignment:       %lu\n", pOptionalHeader->FileAlignment);
    printf("Major OS version:     %hu\n", pOptionalHeader->MajorOperatingSystemVersion);
    printf("Minor OS version:     %hu\n", pOptionalHeader->MinorOperatingSystemVersion);
    printf("Major image version:  %hu\n", pOptionalHeader->MajorImageVersion);
    printf("Minor image version:  %hu\n", pOptionalHeader->MinorImageVersion);
    printf("Major subsystem ver:  %hu\n", pOptionalHeader->MajorSubsystemVersion);
    printf("Minor subsystem ver:  %hu\n", pOptionalHeader->MinorSubsystemVersion);
    printf("Win32 version value:  %lu\n", pOptionalHeader->Win32VersionValue);
    printf("Size of image:        %lu\n", pOptionalHeader->SizeOfImage);
    printf("Size of headers:      %lu\n", pOptionalHeader->SizeOfHeaders);
    printf("Checksum:             %lu\n", pOptionalHeader->CheckSum);
    printf("Subsystem:            %hu\n", pOptionalHeader->Subsystem);
    printf("DLL characteristics:  %#06hx\n", pOptionalHeader->DllCharacteristics);
    printf("Size of stack res.:   %#018llx\n", pOptionalHeader->SizeOfStackReserve);
    printf("Size of stack commit: %#018llx\n", pOptionalHeader->SizeOfStackCommit);
    printf("Size of heap reserve: %#018llx\n", pOptionalHeader->SizeOfHeapReserve);
    printf("Size of heap commit:  %#018llx\n", pOptionalHeader->SizeOfHeapCommit);
    printf("Loader flags:         %lu\n", pOptionalHeader->LoaderFlags);
    printf("Number of RVA/sizes:  %lu\n", pOptionalHeader->NumberOfRvaAndSizes);

    printf("========================================\n");
    for (WORD i = 1; i <= wNbSections; i++, pSection++) {
        if (i > 1) {
            printf("-----------------------------\n");
        }
        printf("Section %hu: %s\n", i, pSection->Name);
        printf("  Virtual size:    %lu\n", pSection->Misc.VirtualSize);
        printf("  Virtual address: %#010lx\n", pSection->VirtualAddress);
        printf("  Raw data size:   %lu\n", pSection->SizeOfRawData);
        printf("  Ptr to raw data: %#010lx\n", pSection->PointerToRawData);
        printf("  Ptr to relocs:   %#010lx\n", pSection->PointerToRelocations);
        printf("  Ptr to linenums: %#010lx\n", pSection->PointerToLinenumbers);
        printf("  Nb of relocs:    %hu\n", pSection->NumberOfRelocations);
        printf("  Nb of linenums:  %hu\n", pSection->NumberOfLinenumbers);
        printf("  Characteristics: %#010lx\n", pSection->Characteristics);
        printf("  Permissions:     %c%c%c%c\n",
               pSection->Characteristics & IMAGE_SCN_MEM_READ ? 'r' : '-',
               pSection->Characteristics & IMAGE_SCN_MEM_WRITE ? 'w' : '-',
               pSection->Characteristics & IMAGE_SCN_MEM_EXECUTE ? 'x' : '-',
               pSection->Characteristics & IMAGE_SCN_MEM_SHARED ? 's' : '-');
    }

    PCBYTE pFirstSectionData =
        (PCBYTE)((PCBYTE)pDosHeader + ((DWORD)pFirstSection->PointerToRawData));
    SIZE_T szFreeSpace = pFirstSectionData - (PCBYTE)&pFirstSection[wNbSections];
    printf("========================================\n");
    printf("Free space in section header: %zu bytes (%zu sections)\n", szFreeSpace,
           szFreeSpace / sizeof(IMAGE_SECTION_HEADER));

    UnmapViewOfFile(pMapAddress);
close_map:
    CloseHandle(hMapFile);
close_file:
    CloseHandle(hFile);
exit:
    return ret;
}
