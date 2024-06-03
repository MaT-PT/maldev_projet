#define WIN32_LEAN_AND_MEAN
#include "libproc.h"
#include <Windows.h>
#include <stdio.h>
#include <winternl.h>
#include "utils.h"

__declspec(code_seg("injected")) static inline int my_toupper(int c) {
    if (c >= 'a' && c <= 'z') {
        return c & ~0x20;
    }
    return c;
}

__declspec(code_seg("injected")) int my_stricmp(PCSTR s1, PCSTR s2) {
    int c1 = 0, c2 = 0;
    while (*s1 && *s2 && (c1 = my_toupper(*s1)) == (c2 = my_toupper(*s2))) {
        s1++;
        s2++;
    }
    return c1 - c2;
}

__declspec(code_seg("injected")) int my_wstricmp(PCWSTR ws1, PCWSTR ws2) {
    int c1 = 0, c2 = 0;
    while (*ws1 && *ws2 && (c1 = my_toupper(*ws1)) == (c2 = my_toupper(*ws2))) {
        ws1++;
        ws2++;
    }
    return c1 - c2;
}

#ifdef DEBUG
VOID ListDll() {
    PTEB pTeb = NtCurrentTeb();
    PPEB pPeb = pTeb->ProcessEnvironmentBlock;
    PPEB_LDR_DATA pLdr = pPeb->Ldr;

    LOG("TEB: %p", pTeb);
    LOG("PEB: %p", pPeb);
    LOG("Ldr: %p", pLdr);

    PLIST_ENTRY pList = &pLdr->InMemoryOrderModuleList;
    PLDR_DATA_TABLE_ENTRY pEntry = NULL;

    for (PLIST_ENTRY pNode = pList->Flink; pNode != pList; pNode = pNode->Flink) {
        pEntry = (PLDR_DATA_TABLE_ENTRY)pNode;
        LOG("Module %p: %ls", pEntry->DllBase, pEntry->FullDllName.Buffer);
    }
}

VOID ListFunc(IN CONST PVOID pDllBase) {
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pDllBase;
    LOG("DOS Header: %p", pDosHeader);
    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((PBYTE)pDllBase + pDosHeader->e_lfanew);
    LOG("NT Header: %p", pNtHeader);
    PIMAGE_DATA_DIRECTORY pDataDir =
        &pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    LOG("Data Directory: %p", pDataDir);
    LOG("Virtual Address: %#x", pDataDir->VirtualAddress);
    PIMAGE_EXPORT_DIRECTORY pExportDir =
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
        dwRva = pRvaFuncs[pRvaOrdinals[i]];
        pFunc = (PVOID)((PBYTE)pDllBase + dwRva);
        LOG("Function %u: %#010x %p %s", i, dwRva, pFunc, pFuncName);
    }
}
#endif

__declspec(code_seg("injected")) PVOID GetDll(IN CONST PCWSTR wsDllName) {
    PTEB pTeb = NtCurrentTeb();
    PPEB pPeb = pTeb->ProcessEnvironmentBlock;
    PPEB_LDR_DATA pLdr = pPeb->Ldr;

    LOG("TEB: %p", pTeb);
    LOG("PEB: %p", pPeb);
    LOG("Ldr: %p", pLdr);

    PLIST_ENTRY pList = &pLdr->InMemoryOrderModuleList;
    PLDR_DATA_TABLE_ENTRY pLdrEntry = NULL;
    PCUNICODE_STRING pDllName = NULL;

    for (PLIST_ENTRY pNode = pList->Flink; pNode != pList; pNode = pNode->Flink) {
        pLdrEntry = CONTAINING_RECORD(pNode, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        pDllName = (PCUNICODE_STRING)(&pLdrEntry->Reserved4);
        LOG("Module %p: %ls", pLdrEntry->DllBase, pDllName->Buffer);
        if (!my_wstricmp(wsDllName, pDllName->Buffer)) {
            return pLdrEntry->DllBase;
        }
    }

    return NULL;
}

__declspec(code_seg("injected")) PVOID GetFunc(IN CONST PVOID pDllBase, IN CONST PCSTR sFuncName) {
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pDllBase;
    LOG("DOS Header: %p", pDosHeader);
    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((PBYTE)pDllBase + pDosHeader->e_lfanew);
    LOG("NT Header: %p", pNtHeader);
    PIMAGE_DATA_DIRECTORY pDataDir =
        &pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    LOG("Data Directory: %p", pDataDir);
    LOG("Virtual Address: %#x", pDataDir->VirtualAddress);
    PIMAGE_EXPORT_DIRECTORY pExportDir =
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

        if (!my_stricmp(sFuncName, pFuncName)) {
            dwRva = pRvaFuncs[pRvaOrdinals[i]];
            pFunc = (PVOID)((PBYTE)pDllBase + dwRva);
            return pFunc;
        }
    }

    return NULL;
}
