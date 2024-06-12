#include "libproc.hpp"
#include <Windows.h>
#include <stdio.h>
#include <winternl.h>
#include "utils.h"

__declspec(code_seg("injected")) HMODULE GetDll(IN CONST ULONGLONG ullDllNameHash) {
    CONST PCTEB pTeb = NT_CURRENT_TEB();
    CONST PCPEB pPeb = pTeb->ProcessEnvironmentBlock;
    CONST PCPEB_LDR_DATA pLdr = pPeb->Ldr;
    CONST PCLIST_ENTRY pList = &pLdr->InMemoryOrderModuleList;

    LOG("TEB: %p", pTeb);
    LOG("PEB: %p", pPeb);
    LOG("Ldr: %p", pLdr);
    LOG("Lst: %p", pList);

    PCLDR_DATA_TABLE_ENTRY pLdrEntry;
    PCUNICODE_STRING pDllName;

    for (PCLIST_ENTRY pNode = pList->Flink; pNode != pList; pNode = pNode->Flink) {
        pLdrEntry = CONTAINING_RECORD(pNode, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        pDllName = (PCUNICODE_STRING)(&pLdrEntry->Reserved4);
        LOG("Module %p: %ls", pLdrEntry->DllBase, pDllName->Buffer);
        if (my_strhash(pDllName->Buffer) == ullDllNameHash) {
            return (HMODULE)pLdrEntry->DllBase;
        }
    }

    return NULL;
}

__declspec(code_seg("injected")) PCVOID GetFunc(IN CONST PCVOID pDllBase,
                                                IN CONST ULONGLONG ullFuncNameHash) {
    CONST PCIMAGE_DOS_HEADER pDosHeader = (PCIMAGE_DOS_HEADER)pDllBase;
    LOG("DOS Header: %p", pDosHeader);
    CONST PCIMAGE_NT_HEADERS64 pNtHeader =
        (PCIMAGE_NT_HEADERS64)((PCBYTE)pDllBase + pDosHeader->e_lfanew);
    LOG("NT Header: %p", pNtHeader);
    CONST PCIMAGE_DATA_DIRECTORY pDataDir =
        &pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    LOG("Data Directory: %p", pDataDir);
    LOG("Virtual Address: %#x", pDataDir->VirtualAddress);
    CONST PCIMAGE_EXPORT_DIRECTORY pExportDir =
        (PCIMAGE_EXPORT_DIRECTORY)((PCBYTE)pDllBase + pDataDir->VirtualAddress);
    LOG("Export Directory: %p", pExportDir);

    PCDWORD pRvaNames, pRvaFuncs;
    PCWORD pRvaOrdinals;
    LPCSTR pFuncName;
    DWORD dwRva;
    PCVOID pFunc;
    for (DWORD i = 0; i < pExportDir->NumberOfFunctions; i++) {
        pRvaNames = (PCDWORD)((PCBYTE)pDllBase + pExportDir->AddressOfNames);
        pRvaOrdinals = (PCWORD)((PCBYTE)pDllBase + pExportDir->AddressOfNameOrdinals);
        pRvaFuncs = (PCDWORD)((PCBYTE)pDllBase + pExportDir->AddressOfFunctions);
        pFuncName = (LPCSTR)((PCBYTE)pDllBase + pRvaNames[i]);
        LOG("Function %u: %s", i, pFuncName);

        if (my_strhash(pFuncName) == ullFuncNameHash) {
            dwRva = pRvaFuncs[pRvaOrdinals[i]];
            pFunc = (PCVOID)((PCBYTE)pDllBase + dwRva);
            return pFunc;
        }
    }

    return NULL;
}
