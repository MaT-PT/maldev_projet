#define WIN32_LEAN_AND_MEAN
#include "libproc.hpp"
#include <Windows.h>
#include <stdio.h>
#include <winternl.h>
#include "utils.h"

__declspec(code_seg("injected")) PVOID GetDll(IN CONST ULONGLONG ullDllNameHash) {
    CONST PTEB pTeb = NT_CURRENT_TEB();
    CONST PPEB pPeb = pTeb->ProcessEnvironmentBlock;
    CONST PPEB_LDR_DATA pLdr = pPeb->Ldr;
    CONST PLIST_ENTRY pList = &pLdr->InMemoryOrderModuleList;

    LOG("TEB: %p", pTeb);
    LOG("PEB: %p", pPeb);
    LOG("Ldr: %p", pLdr);
    LOG("Lst: %p", pList);

    PLDR_DATA_TABLE_ENTRY pLdrEntry;
    PCUNICODE_STRING pDllName;

    for (PLIST_ENTRY pNode = pList->Flink; pNode != pList; pNode = pNode->Flink) {
        pLdrEntry = CONTAINING_RECORD(pNode, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        pDllName = (PCUNICODE_STRING)(&pLdrEntry->Reserved4);
        LOG("Module %p: %ls", pLdrEntry->DllBase, pDllName->Buffer);
        if (my_strhash(pDllName->Buffer) == ullDllNameHash) {
            return pLdrEntry->DllBase;
        }
    }

    return NULL;
}

__declspec(code_seg("injected")) PVOID GetFunc(IN CONST PVOID pDllBase,
                                               IN CONST ULONGLONG ullFuncNameHash) {
    CONST PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pDllBase;
    LOG("DOS Header: %p", pDosHeader);
    CONST PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((PBYTE)pDllBase + pDosHeader->e_lfanew);
    LOG("NT Header: %p", pNtHeader);
    CONST PIMAGE_DATA_DIRECTORY pDataDir =
        &pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    LOG("Data Directory: %p", pDataDir);
    LOG("Virtual Address: %#x", pDataDir->VirtualAddress);
    CONST PIMAGE_EXPORT_DIRECTORY pExportDir =
        (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pDllBase + pDataDir->VirtualAddress);
    LOG("Export Directory: %p", pExportDir);

    PDWORD pRvaNames, pRvaFuncs;
    PWORD pRvaOrdinals;
    PCHAR pFuncName;
    DWORD dwRva;
    PVOID pFunc;
    for (DWORD i = 0; i < pExportDir->NumberOfFunctions; i++) {
        pRvaNames = (PDWORD)((PBYTE)pDllBase + pExportDir->AddressOfNames);
        pRvaOrdinals = (PWORD)((PBYTE)pDllBase + pExportDir->AddressOfNameOrdinals);
        pRvaFuncs = (PDWORD)((PBYTE)pDllBase + pExportDir->AddressOfFunctions);
        pFuncName = (PCHAR)((PBYTE)pDllBase + pRvaNames[i]);
        LOG("Function %u: %s", i, pFuncName);

        if (my_strhash(pFuncName) == ullFuncNameHash) {
            dwRva = pRvaFuncs[pRvaOrdinals[i]];
            pFunc = (PVOID)((PBYTE)pDllBase + dwRva);
            return pFunc;
        }
    }

    return NULL;
}
