#include <Windows.h>
#include <stdio.h>
#include <string.h>

#define DWQUAD(x) ((x).QuadPart)
#define DWHIGH(x) ((x).HighPart)
#define DWLOW(x) ((x).LowPart)
#define DWHILO(x) DWHIGH(x), DWLOW(x)

VOID PrintError(IN CONST LPCSTR lpFuncName) {
    // Get the latest error ID
    CONST DWORD dwErrId = GetLastError();
    printf("[ERR:%d] %s: ", dwErrId, lpFuncName);

    // Pring the error message based on the response
    if (dwErrId) {
        LPSTR lpMsgBuf;
        CONST DWORD dwRes = FormatMessageA(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL, dwErrId, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&lpMsgBuf, 0, NULL);
        if (dwRes) {
            printf("%s\n", lpMsgBuf);
            LocalFree(lpMsgBuf);
        } else {
            printf("Unknown error\n");
        }
    } else {
        printf("Something went wrong\n");
    }
}

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
    printf("File size: %u bytes\n", dwFileSize);
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
    printf("DOS magic:            %#06x (%.2s)\n", pDosHeader->e_magic,
           (LPCSTR)&pDosHeader->e_magic);

    PIMAGE_NT_HEADERS64 pNtHeader =
        (PIMAGE_NT_HEADERS64)((PUCHAR)pDosHeader + pDosHeader->e_lfanew);
    printf("PE signature:         %#010x (%.4s)\n", pNtHeader->Signature,
           (LPCSTR)&pNtHeader->Signature);
    printf("Machine:              %#hx\n", pNtHeader->FileHeader.Machine);
    printf("Timestamp:            %#x\n", pNtHeader->FileHeader.TimeDateStamp);
    printf("Ptr to symbol table:  %#010x\n", pNtHeader->FileHeader.PointerToSymbolTable);
    printf("Number of symbols:    %u\n", pNtHeader->FileHeader.NumberOfSymbols);
    printf("Characteristics:      %#hx\n", pNtHeader->FileHeader.Characteristics);

    WORD wOptHeaderSize = pNtHeader->FileHeader.SizeOfOptionalHeader;
    printf("Optional header size: %#hx (%hu)\n", wOptHeaderSize, wOptHeaderSize);

    printf("========================================\n");
    printf("Optional magic:       %#hx\n", pNtHeader->OptionalHeader.Magic);
    printf("Major linker version: %hhu\n", pNtHeader->OptionalHeader.MajorLinkerVersion);
    printf("Minor linker version: %hhu\n", pNtHeader->OptionalHeader.MinorLinkerVersion);
    printf("Size of code:         %u\n", pNtHeader->OptionalHeader.SizeOfCode);
    printf("Size of init data:    %u\n", pNtHeader->OptionalHeader.SizeOfInitializedData);
    printf("Size of uninit data:  %u\n", pNtHeader->OptionalHeader.SizeOfUninitializedData);
    printf("Entry point RVA:      %#010x\n", pNtHeader->OptionalHeader.AddressOfEntryPoint);
    printf("Base of code:         %#010x\n", pNtHeader->OptionalHeader.BaseOfCode);
    printf("Image base:           %#018llx\n", pNtHeader->OptionalHeader.ImageBase);
    printf("Section alignment:    %u\n", pNtHeader->OptionalHeader.SectionAlignment);
    WORD wNbSections = pNtHeader->FileHeader.NumberOfSections;
    printf("Number of sections:   %hu\n", wNbSections);

    printf("========================================\n");
    // offsetof(IMAGE_NT_HEADERS64, OptionalHeader) + pNtHeader->FileHeader.SizeOfOptionalHeader
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeader);
    for (WORD i = 0; i < wNbSections; i++) {
        // printf("Section %hu: %-8s (%u bytes)\tRVA: %#010x\n", i, pSection->Name,
        //        pSection->SizeOfRawData, pSection->VirtualAddress, pSection->Characteristics);
        printf("Section %hu: %s\n", i, pSection->Name);
        printf("  RVA:             %#010x\n", pSection->VirtualAddress);
        printf("  Raw data size:   %u\n", pSection->SizeOfRawData);
        printf("  Ptr to raw data: %#010x\n", pSection->PointerToRawData);
        printf("  Ptr to relocs:   %#010x\n", pSection->PointerToRelocations);
        printf("  Ptr to linenums: %#010x\n", pSection->PointerToLinenumbers);
        printf("  Nb of relocs:    %hu\n", pSection->NumberOfRelocations);
        printf("  Nb of linenums:  %hu\n", pSection->NumberOfLinenumbers);
        printf("  Characteristics: %#010x\n", pSection->Characteristics);
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
