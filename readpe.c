#include <Windows.h>
#include <stdio.h>
#include <string.h>
#include "utils.h"

int main(int argc, char *argv[]) {
    int ret = 0;
    HANDLE hFile, hMapFile;
    LPVOID pMapAddress;
    DWORD dwFileSize;
    ULARGE_INTEGER uliSize, uliOffset;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <filename.exe>\n", argv[0]);
        ret = 1;
        goto exit;
    }

    printf("Reading file: %s\n", argv[1]);

    hFile = CreateFile(argv[1], GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
                       FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        PrintError("CreateFile");
        ret = 1;
        goto exit;
    }

    dwFileSize = GetFileSize(hFile, NULL);
    printf("File size: %lu bytes\n", dwFileSize);
    DWQUAD(uliSize) = dwFileSize;

    hMapFile = CreateFileMapping(hFile, NULL, PAGE_READWRITE, DWHILO(uliSize), NULL);
    if (hMapFile == NULL) {
        PrintError("CreateFileMapping");
        ret = 1;
        goto close_file;
    }

    DWQUAD(uliOffset) = 0;
    pMapAddress = MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, DWHILO(uliOffset), 0);
    if (pMapAddress == NULL) {
        PrintError("MapViewOfFile");
        ret = 1;
        goto close_map;
    }

    printf("========================================\n");
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pMapAddress;
    printf("DOS magic:            %#06hx (%.2s)\n", pDosHeader->e_magic,
           (LPCSTR)&pDosHeader->e_magic);

    PIMAGE_NT_HEADERS64 pNtHeader =
        (PIMAGE_NT_HEADERS64)((PCBYTE)pDosHeader + pDosHeader->e_lfanew);
    printf("PE signature:         %#010lx (%.4s)\n", pNtHeader->Signature,
           (LPCSTR)&pNtHeader->Signature);
    printf("Machine:              %#hx\n", pNtHeader->FileHeader.Machine);
    printf("Timestamp:            %#lx\n", pNtHeader->FileHeader.TimeDateStamp);
    printf("Ptr to symbol table:  %#010lx\n", pNtHeader->FileHeader.PointerToSymbolTable);
    printf("Number of symbols:    %lu\n", pNtHeader->FileHeader.NumberOfSymbols);
    printf("Characteristics:      %#hx\n", pNtHeader->FileHeader.Characteristics);

    WORD wOptHeaderSize = pNtHeader->FileHeader.SizeOfOptionalHeader;
    printf("Optional header size: %#hx (%hu)\n", wOptHeaderSize, wOptHeaderSize);

    printf("========================================\n");
    printf("Optional magic:       %#hx\n", pNtHeader->OptionalHeader.Magic);
    printf("Major linker version: %hhu\n", pNtHeader->OptionalHeader.MajorLinkerVersion);
    printf("Minor linker version: %hhu\n", pNtHeader->OptionalHeader.MinorLinkerVersion);
    printf("Size of code:         %lu\n", pNtHeader->OptionalHeader.SizeOfCode);
    printf("Size of init data:    %lu\n", pNtHeader->OptionalHeader.SizeOfInitializedData);
    printf("Size of uninit data:  %lu\n", pNtHeader->OptionalHeader.SizeOfUninitializedData);
    printf("Entry point RVA:      %#010lx\n", pNtHeader->OptionalHeader.AddressOfEntryPoint);
    printf("Base of code:         %#010lx\n", pNtHeader->OptionalHeader.BaseOfCode);
    printf("Image base:           %#018llx\n", pNtHeader->OptionalHeader.ImageBase);
    printf("Section alignment:    %lu\n", pNtHeader->OptionalHeader.SectionAlignment);
    WORD wNbSections = pNtHeader->FileHeader.NumberOfSections;
    printf("Number of sections:   %hu\n", wNbSections);

    printf("========================================\n");
    // offsetof(IMAGE_NT_HEADERS64, OptionalHeader) + pNtHeader->FileHeader.SizeOfOptionalHeader
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeader);
    for (WORD i = 0; i < wNbSections; i++) {
        // printf("Section %hu: %-8s (%lu bytes)\tRVA: %#010lx\n", i, pSection->Name,
        //        pSection->SizeOfRawData, pSection->VirtualAddress, pSection->Characteristics);
        printf("Section %hu: %s\n", i, pSection->Name);
        printf("  RVA:             %#010lx\n", pSection->VirtualAddress);
        printf("  Raw data size:   %lu\n", pSection->SizeOfRawData);
        printf("  Ptr to raw data: %#010lx\n", pSection->PointerToRawData);
        printf("  Ptr to relocs:   %#010lx\n", pSection->PointerToRelocations);
        printf("  Ptr to linenums: %#010lx\n", pSection->PointerToLinenumbers);
        printf("  Nb of relocs:    %hu\n", pSection->NumberOfRelocations);
        printf("  Nb of linenums:  %hu\n", pSection->NumberOfLinenumbers);
        printf("  Characteristics: %#010lx\n", pSection->Characteristics);
        printf("  Permissions:    %c%c%c%c\n",
               pSection->Characteristics & IMAGE_SCN_MEM_READ ? 'r' : '-',
               pSection->Characteristics & IMAGE_SCN_MEM_WRITE ? 'w' : '-',
               pSection->Characteristics & IMAGE_SCN_MEM_EXECUTE ? 'x' : '-',
               pSection->Characteristics & IMAGE_SCN_MEM_SHARED ? 's' : '-');
        pSection++;
    }

    UnmapViewOfFile(pMapAddress);
close_map:
    CloseHandle(hMapFile);
close_file:
    CloseHandle(hFile);
exit:
    return ret;
}
