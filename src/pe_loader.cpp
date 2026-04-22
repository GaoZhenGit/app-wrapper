#include "pe_loader.h"
#include "logger.h"

LPVOID PELoader::AllocateMemory(const PEMetadata& metadata) {
    LPVOID pBase = VirtualAlloc(
        NULL,
        metadata.sizeOfImage,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (!pBase) {
        LogError("内存分配失败: SizeOfImage=%dKB, 错误码=0x%X",
                 metadata.sizeOfImage / 1024, GetLastError());
        return NULL;
    }

    LogInfo("内存分配成功: 基址=0x%p, 大小=%dKB", pBase, metadata.sizeOfImage / 1024);
    return pBase;
}

bool PELoader::MapHeaders(LPVOID pBase, PBYTE pRawData, const PEMetadata& metadata) {
    memcpy(pBase, pRawData, metadata.sizeOfHeaders);
    LogInfo("头部映射完成: %d字节", metadata.sizeOfHeaders);
    return true;
}

bool PELoader::MapSections(LPVOID pBase, PBYTE pRawData, const PEMetadata& metadata) {
    for (size_t i = 0; i < metadata.sections.size(); i++) {
        const SectionInfo& sec = metadata.sections[i];

        if (sec.sizeOfRawData == 0) {
            // 未初始化数据(.bss)，已分配但无需拷贝
            continue;
        }

        BYTE* targetAddr = (BYTE*)pBase + sec.virtualAddress;
        BYTE* sourceAddr = pRawData + sec.pointerToRawData;

        memcpy(targetAddr, sourceAddr, sec.sizeOfRawData);

        LogInfo("节区映射[%d]: 目标=0x%p, 源=0x%p, 大小=%d字节",
                i, targetAddr, sourceAddr, sec.sizeOfRawData);
    }

    LogInfo("节区映射完成: %d个节", metadata.sections.size());
    return true;
}

LPVOID PELoader::Load(PBYTE pRawData, const PEMetadata& metadata) {
    LogInfo("开始PE加载流程");

    // 步骤1: 分配内存
    LPVOID pBase = AllocateMemory(metadata);
    if (!pBase) return NULL;

    // 步骤2: 映射头部
    if (!MapHeaders(pBase, pRawData, metadata)) {
        VirtualFree(pBase, 0, MEM_RELEASE);
        return NULL;
    }

    // 步骤3: 映射节区
    if (!MapSections(pBase, pRawData, metadata)) {
        VirtualFree(pBase, 0, MEM_RELEASE);
        return NULL;
    }

    // 步骤4: 修复导入表
    if (!FixImports(pBase, metadata)) {
        LogError("导入表修复失败");
        VirtualFree(pBase, 0, MEM_RELEASE);
        return NULL;
    }

    // 步骤5: 修复重定位
    if (!FixRelocations(pBase, metadata)) {
        LogError("重定位修复失败");
        VirtualFree(pBase, 0, MEM_RELEASE);
        return NULL;
    }

    // 步骤6: 执行TLS回调（在入口点前）
    if (!ExecuteTLSCallbacks(pBase, metadata)) {
        LogError("TLS回调执行失败");
        VirtualFree(pBase, 0, MEM_RELEASE);
        return NULL;
    }

    // 步骤7: 注册异常处理表
    if (!RegisterExceptionTable(pBase, metadata)) {
        LogError("异常处理表注册失败");
        VirtualFree(pBase, 0, MEM_RELEASE);
        return NULL;
    }

    LogInfo("PE加载完成（所有修复步骤已完成）");
    return pBase;
}

// 步骤4: 修复导入表
bool PELoader::FixImports(LPVOID pBase, const PEMetadata& metadata) {
    if (!metadata.importTable.exists) {
        LogInfo("导入表不存在，跳过修复");
        return true;
    }

    PIMAGE_IMPORT_DESCRIPTOR pImp = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)pBase + metadata.importTable.rva);
    int dllCount = 0;
    int funcCount = 0;

    while (pImp->Name != 0) {
        char* dllName = (char*)((BYTE*)pBase + pImp->Name);

        // 加载DLL
        HMODULE hMod = LoadLibraryA(dllName);
        if (!hMod) {
            LogError("导入表修复失败: 无法加载DLL %s, 错误码=0x%X", dllName, GetLastError());
            return false;
        }

        LogInfo("导入DLL[%d]: %s -> 0x%p", dllCount, dllName, hMod);
        dllCount++;

        // 遍历IAT，修复函数地址
        PIMAGE_THUNK_DATA64 pThunk = (PIMAGE_THUNK_DATA64)((BYTE*)pBase + pImp->FirstThunk);
        while (pThunk->u1.AddressOfData != 0) {
            // 检查是否通过名称导入（而非序号）
            if (!(pThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64)) {
                PIMAGE_IMPORT_BY_NAME pByName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)pBase + pThunk->u1.AddressOfData);
                FARPROC procAddr = GetProcAddress(hMod, pByName->Name);

                if (!procAddr) {
                    LogError("导入表修复失败: 无法找到函数 %s (DLL: %s)", pByName->Name, dllName);
                    return false;
                }

                pThunk->u1.Function = (ULONGLONG)procAddr;
                funcCount++;
            }
            pThunk++;
        }

        pImp++;
    }

    LogInfo("导入表修复完成: %d个DLL, %d个函数", dllCount, funcCount);
    return true;
}

// 步骤5: 修复重定位
bool PELoader::FixRelocations(LPVOID pBase, const PEMetadata& metadata) {
    if (!metadata.relocation.exists) {
        LogInfo("重定位表不存在，跳过修复");
        return true;
    }

    PIMAGE_NT_HEADERS64 pNt = (PIMAGE_NT_HEADERS64)((BYTE*)pBase + ((PIMAGE_DOS_HEADER)pBase)->e_lfanew);
    ULONGLONG delta = (ULONGLONG)pBase - pNt->OptionalHeader.ImageBase;

    if (delta == 0) {
        LogInfo("无需重定位: 基址匹配（实际=0x%p, 期望=0x%llx）", pBase, pNt->OptionalHeader.ImageBase);
        return true;
    }

    LogInfo("开始重定位修复: delta=0x%llX", delta);

    PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)((BYTE*)pBase + metadata.relocation.rva);
    int blockCount = 0;
    int relocCount = 0;

    while (pReloc->SizeOfBlock != 0) {
        // 每个块包含的重定位项数量
        WORD itemCount = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        PWORD pRelocData = (PWORD)(pReloc + 1);

        for (WORD i = 0; i < itemCount; i++) {
            WORD type = pRelocData[i] >> 12;      // 高4位：类型
            WORD offset = pRelocData[i] & 0x0FFF; // 低12位：偏移

            if (type == IMAGE_REL_BASED_DIR64) {
                // 64位地址修正
                PULONGLONG pAddr = (PULONGLONG)((BYTE*)pBase + pReloc->VirtualAddress + offset);
                *pAddr += delta;
                relocCount++;
            }
        }

        blockCount++;
        pReloc = (PIMAGE_BASE_RELOCATION)((BYTE*)pReloc + pReloc->SizeOfBlock);
    }

    LogInfo("重定位修复完成: %d个块, %d个地址修正", blockCount, relocCount);
    return true;
}

// 步骤6: 执行TLS回调
bool PELoader::ExecuteTLSCallbacks(LPVOID pBase, const PEMetadata& metadata) {
    if (!metadata.tls.exists || metadata.tls.callbackRVAs.empty()) {
        LogInfo("TLS回调不存在，跳过执行");
        return true;
    }

    LogInfo("开始执行TLS回调: %d个回调", metadata.tls.callbackRVAs.size());

    typedef void(*TLS_CALLBACK)(PVOID, DWORD, PVOID);

    for (size_t i = 0; i < metadata.tls.callbackRVAs.size(); i++) {
        DWORD callbackRVA = metadata.tls.callbackRVAs[i];
        TLS_CALLBACK callback = (TLS_CALLBACK)((BYTE*)pBase + callbackRVA);

        LogInfo("TLS回调[%d]: RVA=0x%X, 地址=0x%p", i, callbackRVA, callback);

        // MinGW不支持SEH，直接调用（如果崩溃则程序终止）
        // 如果需要异常捕获，可考虑其他方案
        callback(pBase, DLL_PROCESS_ATTACH, NULL);
        LogInfo("TLS回调[%d]执行成功", i);
    }

    LogInfo("TLS回调执行完成");
    return true;
}

// 步骤7: 注册异常处理表
bool PELoader::RegisterExceptionTable(LPVOID pBase, const PEMetadata& metadata) {
    if (!metadata.exception.exists) {
        LogInfo("异常处理表不存在，跳过注册");
        return true;
    }

    PRUNTIME_FUNCTION pFunctionTable = (PRUNTIME_FUNCTION)((BYTE*)pBase + metadata.exception.rva);
    DWORD entryCount = metadata.exception.size / sizeof(RUNTIME_FUNCTION);

    BOOLEAN result = RtlAddFunctionTable(
        pFunctionTable,
        entryCount,
        (DWORD64)pBase
    );

    if (!result) {
        LogError("异常处理表注册失败: 错误码=0x%X", GetLastError());
        return false;
    }

    LogInfo("异常处理表注册成功: %d个函数", entryCount);
    return true;
}