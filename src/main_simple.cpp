#include <windows.h>
#include <cstdint>
#include <cstdio>

typedef int(__cdecl* MAIN_ENTRY)(int, char**);

// 从资源读取内嵌EXE
PBYTE LoadResourceExe(DWORD& outSize) {
    HMODULE hModule = GetModuleHandleA(NULL);
    HRSRC hRes = FindResourceA(hModule, MAKEINTRESOURCEA(1001), RT_RCDATA);
    HGLOBAL hGlobal = LoadResource(hModule, hRes);
    outSize = SizeofResource(hModule, hRes);
    return (PBYTE)LockResource(hGlobal);
}

bool RunRustExe(int argc, char** argv) {
    DWORD rawSize = 0;
    PBYTE pRaw = LoadResourceExe(rawSize);

    // 1. 解析PE头
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pRaw;
    PIMAGE_NT_HEADERS64 pNt = (PIMAGE_NT_HEADERS64)(pRaw + pDos->e_lfanew);

    // 2. 分配内存
    LPVOID pBase = VirtualAlloc(
        NULL,
        pNt->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    if (!pBase) return false;

    // 3. 拷贝头部和节区
    memcpy(pBase, pRaw, pNt->OptionalHeader.SizeOfHeaders);
    PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        memcpy(
            (BYTE*)pBase + pSec[i].VirtualAddress,
            pRaw + pSec[i].PointerToRawData,
            pSec[i].SizeOfRawData
        );
    }

    // 4. 修复导入表
    DWORD importRva = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    PIMAGE_IMPORT_DESCRIPTOR pImp = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)pBase + importRva);
    for (; pImp->Name; pImp++) {
        HMODULE hMod = LoadLibraryA((LPCSTR)((BYTE*)pBase + pImp->Name));
        PIMAGE_THUNK_DATA64 pThunk = (PIMAGE_THUNK_DATA64)((BYTE*)pBase + pImp->FirstThunk);
        for (; pThunk->u1.AddressOfData; pThunk++) {
            PIMAGE_IMPORT_BY_NAME pByName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)pBase + (DWORD)pThunk->u1.AddressOfData);
            pThunk->u1.Function = (ULONGLONG)GetProcAddress(hMod, (LPCSTR)pByName->Name);
        }
    }

    // 5. 64位重定位修复
    ULONGLONG delta = (ULONGLONG)pBase - pNt->OptionalHeader.ImageBase;
    if (delta != 0) {
        DWORD relocRva = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
        PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)((BYTE*)pBase + relocRva);
        while (pReloc->SizeOfBlock) {
            int cnt = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
            PWORD pData = (PWORD)(pReloc + 1);
            for (int i = 0; i < cnt; i++) {
                if ((pData[i] >> 12) == IMAGE_REL_BASED_DIR64) {
                    PULONGLONG pAddr = (PULONGLONG)((BYTE*)pBase + pReloc->VirtualAddress + (pData[i] & 0xFFF));
                    *pAddr += delta;
                }
            }
            pReloc = (PIMAGE_BASE_RELOCATION)((BYTE*)pReloc + pReloc->SizeOfBlock);
        }
    }

    // 6. 运行程序，透传参数
    printf("DEBUG: 调用入口点: 0x%p\n", (BYTE*)pBase + pNt->OptionalHeader.AddressOfEntryPoint);
    printf("DEBUG: argc=%d, argv[0]=%s\n", argc, argv[0]);

    MAIN_ENTRY entry = (MAIN_ENTRY)((BYTE*)pBase + pNt->OptionalHeader.AddressOfEntryPoint);
    int result = entry(argc, argv);

    printf("DEBUG: 入口点返回: %d\n", result);
    return true;
}

int main(int argc, char** argv) {
    RunRustExe(argc, argv);
    return 0;
}