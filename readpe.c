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
        fprintf(stderr, "Usage: %s <filename.exe>\r\n", argv[0]);
        ret = 1;
        goto exit;
    }

    printf("Reading file: %s\r\n", argv[1]);

    CONST HANDLE hFile = CreateFile(argv[1], GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
                                    FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        PrintError("CreateFile");
        ret = 1;
        goto exit;
    }

    CONST DWORD dwFileSize = GetFileSize(hFile, NULL);
    printf("File size: %lu bytes\r\n", dwFileSize);
    ULARGE_INTEGER uliSize;
    DWQUAD(uliSize) = dwFileSize;

    CONST HANDLE hMapFile = CreateFileMapping(hFile, NULL, PAGE_READWRITE, DWHILO(uliSize), NULL);
    if (hMapFile == NULL) {
        PrintError("CreateFileMapping");
        ret = 1;
        goto close_file;
    }

    ULARGE_INTEGER uliOffset;
    DWQUAD(uliOffset) = 0;
    CONST LPCVOID pMapAddress = MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, DWHILO(uliOffset), 0);
    if (pMapAddress == NULL) {
        PrintError("MapViewOfFile");
        ret = 1;
        goto close_map;
    }

    CONST PCIMAGE_DOS_HEADER pDosHeader = (PCIMAGE_DOS_HEADER)pMapAddress;
    CONST PCIMAGE_NT_HEADERS64 pNtHeader =
        (PCIMAGE_NT_HEADERS64)((PCBYTE)pDosHeader + pDosHeader->e_lfanew);
    PCIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeader);

    CONST WORD wNbSections = pNtHeader->FileHeader.NumberOfSections;
    CONST DWORD dwTimestamp = pNtHeader->FileHeader.TimeDateStamp;
    FILETIME ftTimestamp;
    SYSTEMTIME stTimestamp;
    TimestampToFiletime(dwTimestamp, &ftTimestamp);
    FileTimeToSystemTime(&ftTimestamp, &stTimestamp);
    SystemTimeToTzSpecificLocalTimeEx(NULL, &stTimestamp, &stTimestamp);

    printf("========================================\r\n");
    printf("DOS magic:            %#06hx     (\"%.2s\")\r\n", pDosHeader->e_magic,
           (LPCSTR)&pDosHeader->e_magic);
    printf("PE signature:         %#010lx (\"%.4s\")\r\n", pNtHeader->Signature,
           (LPCSTR)&pNtHeader->Signature);
    printf("Machine:              %#06hx\r\n", pNtHeader->FileHeader.Machine);
    printf("Number of sections:   %hu\r\n", wNbSections);
    printf("Timestamp:            %#010lx (%hu-%02hu-%02hu %02hu:%02hu:%02hu)\r\n", dwTimestamp,
           stTimestamp.wYear, stTimestamp.wMonth, stTimestamp.wDay, stTimestamp.wHour,
           stTimestamp.wMinute, stTimestamp.wSecond);
    printf("Ptr to symbol table:  %#010lx\r\n", pNtHeader->FileHeader.PointerToSymbolTable);
    printf("Number of symbols:    %lu\r\n", pNtHeader->FileHeader.NumberOfSymbols);
    printf("Characteristics:      %#06hx\r\n", pNtHeader->FileHeader.Characteristics);
    printf("Optional header size: %hu\r\n", pNtHeader->FileHeader.SizeOfOptionalHeader);

    printf("========================================\r\n");
    printf("Optional magic:       %#06hx\r\n", pNtHeader->OptionalHeader.Magic);
    printf("Major linker version: %hhu\r\n", pNtHeader->OptionalHeader.MajorLinkerVersion);
    printf("Minor linker version: %hhu\r\n", pNtHeader->OptionalHeader.MinorLinkerVersion);
    printf("Size of code:         %lu\r\n", pNtHeader->OptionalHeader.SizeOfCode);
    printf("Size of init data:    %lu\r\n", pNtHeader->OptionalHeader.SizeOfInitializedData);
    printf("Size of uninit data:  %lu\r\n", pNtHeader->OptionalHeader.SizeOfUninitializedData);
    printf("Entry point RVA:      %#010lx\r\n", pNtHeader->OptionalHeader.AddressOfEntryPoint);
    printf("Base of code:         %#010lx\r\n", pNtHeader->OptionalHeader.BaseOfCode);
    printf("Image base:           %#018llx\r\n", pNtHeader->OptionalHeader.ImageBase);
    printf("Section alignment:    %lu\r\n", pNtHeader->OptionalHeader.SectionAlignment);
    printf("File alignment:       %lu\r\n", pNtHeader->OptionalHeader.FileAlignment);
    printf("Major OS version:     %hu\r\n", pNtHeader->OptionalHeader.MajorOperatingSystemVersion);
    printf("Minor OS version:     %hu\r\n", pNtHeader->OptionalHeader.MinorOperatingSystemVersion);
    printf("Major image version:  %hu\r\n", pNtHeader->OptionalHeader.MajorImageVersion);
    printf("Minor image version:  %hu\r\n", pNtHeader->OptionalHeader.MinorImageVersion);
    printf("Major subsystem ver:  %hu\r\n", pNtHeader->OptionalHeader.MajorSubsystemVersion);
    printf("Minor subsystem ver:  %hu\r\n", pNtHeader->OptionalHeader.MinorSubsystemVersion);
    printf("Win32 version value:  %lu\r\n", pNtHeader->OptionalHeader.Win32VersionValue);
    printf("Size of image:        %lu\r\n", pNtHeader->OptionalHeader.SizeOfImage);
    printf("Size of headers:      %lu\r\n", pNtHeader->OptionalHeader.SizeOfHeaders);
    printf("Checksum:             %lu\r\n", pNtHeader->OptionalHeader.CheckSum);
    printf("Subsystem:            %hu\r\n", pNtHeader->OptionalHeader.Subsystem);
    printf("DLL characteristics:  %#06hx\r\n", pNtHeader->OptionalHeader.DllCharacteristics);
    printf("Size of stack res.:   %#018llx\r\n", pNtHeader->OptionalHeader.SizeOfStackReserve);
    printf("Size of stack commit: %#018llx\r\n", pNtHeader->OptionalHeader.SizeOfStackCommit);
    printf("Size of heap reserve: %#018llx\r\n", pNtHeader->OptionalHeader.SizeOfHeapReserve);
    printf("Size of heap commit:  %#018llx\r\n", pNtHeader->OptionalHeader.SizeOfHeapCommit);
    printf("Loader flags:         %lu\r\n", pNtHeader->OptionalHeader.LoaderFlags);
    printf("Number of RVA/sizes:  %lu\r\n", pNtHeader->OptionalHeader.NumberOfRvaAndSizes);

    printf("========================================\r\n");
    for (WORD i = 1; i <= wNbSections; i++, pSection++) {
        if (i > 1) {
            printf("-----------------------------\r\n");
        }
        printf("Section %hu: %s\r\n", i, pSection->Name);
        printf("  Virtual size:    %lu\r\n", pSection->Misc.VirtualSize);
        printf("  Virtual address: %#010lx\r\n", pSection->VirtualAddress);
        printf("  Raw data size:   %lu\r\n", pSection->SizeOfRawData);
        printf("  Ptr to raw data: %#010lx\r\n", pSection->PointerToRawData);
        printf("  Ptr to relocs:   %#010lx\r\n", pSection->PointerToRelocations);
        printf("  Ptr to linenums: %#010lx\r\n", pSection->PointerToLinenumbers);
        printf("  Nb of relocs:    %hu\r\n", pSection->NumberOfRelocations);
        printf("  Nb of linenums:  %hu\r\n", pSection->NumberOfLinenumbers);
        printf("  Characteristics: %#010lx\r\n", pSection->Characteristics);
        printf("  Permissions:     %c%c%c%c\r\n",
               pSection->Characteristics & IMAGE_SCN_MEM_READ ? 'r' : '-',
               pSection->Characteristics & IMAGE_SCN_MEM_WRITE ? 'w' : '-',
               pSection->Characteristics & IMAGE_SCN_MEM_EXECUTE ? 'x' : '-',
               pSection->Characteristics & IMAGE_SCN_MEM_SHARED ? 's' : '-');
    }

    UnmapViewOfFile(pMapAddress);
close_map:
    CloseHandle(hMapFile);
close_file:
    CloseHandle(hFile);
exit:
    return ret;
}
