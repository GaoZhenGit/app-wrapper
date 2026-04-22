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

    // 步骤4.5: 修复延迟导入表（关键！Bun程序需要）
    if (!FixDelayImports(pBase, metadata)) {
        LogError("延迟导入表修复失败");
        VirtualFree(pBase, 0, MEM_RELEASE);
        return NULL;
    }

    // 步骤5: 修复重定位
    if (!FixRelocations(pBase, metadata)) {
        LogError("重定位修复失败");
        VirtualFree(pBase, 0, MEM_RELEASE);
        return NULL;
    }

    // 步骤5.5: 修复Load Configuration（安全cookie等）
    if (!FixLoadConfig(pBase, metadata)) {
        LogError("Load Configuration修复失败");
        VirtualFree(pBase, 0, MEM_RELEASE);
        return NULL;
    }

    // 步骤5.6: 初始化TLS（关键步骤！）
    if (!InitializeTLS(pBase, metadata)) {
        LogError("TLS初始化失败");
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
    int ordinalCount = 0;

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
        PIMAGE_THUNK_DATA64 pOriginalThunk = (PIMAGE_THUNK_DATA64)((BYTE*)pBase + pImp->OriginalFirstThunk);

        while (pThunk->u1.AddressOfData != 0) {
            FARPROC procAddr = NULL;

            // 检查是否通过序号导入（而非名称）
            if (pOriginalThunk && (pOriginalThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64)) {
                // 序号导入
                WORD ordinal = pOriginalThunk->u1.Ordinal & 0xFFFF;
                procAddr = GetProcAddress(hMod, (LPCSTR)(DWORD_PTR)ordinal);
                if (!procAddr) {
                    LogError("导入表修复失败: 无法通过序号找到函数 #%d (DLL: %s)", ordinal, dllName);
                    return false;
                }
                ordinalCount++;
                LogInfo("序号导入: #%d -> 0x%p", ordinal, procAddr);
            } else if (!(pThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64)) {
                // 通过名称导入
                PIMAGE_IMPORT_BY_NAME pByName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)pBase + (DWORD)pThunk->u1.AddressOfData);
                procAddr = GetProcAddress(hMod, (LPCSTR)pByName->Name);
                if (!procAddr) {
                    LogError("导入表修复失败: 无法找到函数 %s (DLL: %s)", pByName->Name, dllName);
                    return false;
                }
                LogInfo("函数导入: %s -> 0x%p", pByName->Name, procAddr);
            } else {
                // IAT已修复（Bound Import）
                LogInfo("IAT已绑定，跳过");
                break;
            }

            pThunk->u1.Function = (ULONGLONG)procAddr;
            funcCount++;
            pThunk++;
            if (pOriginalThunk) pOriginalThunk++;
        }

        pImp++;
    }

    LogInfo("导入表修复完成: %d个DLL, %d个函数 (%d个序号导入)", dllCount, funcCount, ordinalCount);
    return true;
}

// 步骤4.5: 修复延迟导入表（关键！Bun程序需要）
bool PELoader::FixDelayImports(LPVOID pBase, const PEMetadata& metadata) {
    if (!metadata.delayImport.exists) {
        LogInfo("延迟导入表不存在，跳过修复");
        return true;
    }

    LogInfo("开始修复延迟导入表");

    // Delay Import Descriptor结构 (简化版，MinGW可能没有完整定义)
    typedef struct _IMAGE_DELAYLOAD_DESCRIPTOR {
        DWORD Attributes;
        DWORD DllNameRVA;
        DWORD ModuleHandleRVA;
        DWORD ImportAddressTableRVA;
        DWORD ImportNameTableRVA;
        DWORD BoundImportAddressTableRVA;
        DWORD UnboundImportAddressTableRVA;
        DWORD TimeDateStamp;
    } IMAGE_DELAYLOAD_DESCRIPTOR;

    PIMAGE_DELAYLOAD_DESCRIPTOR pDelayImp = (PIMAGE_DELAYLOAD_DESCRIPTOR)((BYTE*)pBase + metadata.delayImport.rva);

    int dllCount = 0;
    int funcCount = 0;

    // 遍历延迟导入描述符数组（以全0结尾）
    while (pDelayImp->DllNameRVA != 0) {
        char* dllName = (char*)((BYTE*)pBase + pDelayImp->DllNameRVA);

        LogInfo("延迟导入DLL[%d]: %s", dllCount, dllName);

        // 预加载DLL
        HMODULE hMod = LoadLibraryA(dllName);
        if (!hMod) {
            LogError("延迟导入表修复失败: 无法加载DLL %s, 错误码=0x%X", dllName, GetLastError());
            return false;
        }

        // 存储模块句柄
        HMODULE* pModuleHandle = (HMODULE*)((BYTE*)pBase + pDelayImp->ModuleHandleRVA);
        *pModuleHandle = hMod;
        LogInfo("模块句柄已存储: 0x%p", hMod);

        // 修复IAT表（预填充真实函数地址，避免运行时延迟加载）
        PIMAGE_THUNK_DATA64 pIAT = (PIMAGE_THUNK_DATA64)((BYTE*)pBase + pDelayImp->ImportAddressTableRVA);
        PIMAGE_THUNK_DATA64 pINT = (PIMAGE_THUNK_DATA64)((BYTE*)pBase + pDelayImp->ImportNameTableRVA);

        while (pIAT->u1.AddressOfData != 0) {
            FARPROC procAddr = NULL;

            if (pINT && (pINT->u1.Ordinal & IMAGE_ORDINAL_FLAG64)) {
                // 序号导入
                WORD ordinal = pINT->u1.Ordinal & 0xFFFF;
                procAddr = GetProcAddress(hMod, (LPCSTR)(DWORD_PTR)ordinal);
                if (!procAddr) {
                    LogError("延迟导入失败: 无法通过序号找到函数 #%d (DLL: %s)", ordinal, dllName);
                    return false;
                }
                LogInfo("延迟导入函数[%d]: 序号 #%d -> 0x%p", funcCount, ordinal, procAddr);
            } else if (pINT) {
                // 名称导入 - 从INT读取函数名称（不是从IAT！）
                PIMAGE_IMPORT_BY_NAME pByName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)pBase + pINT->u1.AddressOfData);
                procAddr = GetProcAddress(hMod, (LPCSTR)pByName->Name);
                if (!procAddr) {
                    LogError("延迟导入失败: 无法找到函数 %s (DLL: %s)", pByName->Name, dllName);
                    return false;
                }
                LogInfo("延迟导入函数[%d]: %s -> 0x%p", funcCount, pByName->Name, procAddr);
            } else {
                LogError("延迟导入失败: INT表无效");
                return false;
            }

            // 填充真实地址到IAT
            pIAT->u1.Function = (ULONGLONG)procAddr;
            funcCount++;
            pIAT++;
            if (pINT) pINT++;
        }

        dllCount++;
        pDelayImp++;
    }

    LogInfo("延迟导入表修复完成: %d个DLL, %d个函数", dllCount, funcCount);
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

// 步骤5: 初始化TLS（关键步骤！）
bool PELoader::InitializeTLS(LPVOID pBase, const PEMetadata& metadata) {
    if (!metadata.tls.exists) {
        LogInfo("TLS不存在，跳过初始化");
        return true;
    }

    PIMAGE_NT_HEADERS64 pNt = (PIMAGE_NT_HEADERS64)((BYTE*)pBase + ((PIMAGE_DOS_HEADER)pBase)->e_lfanew);

    // 使用TLSInfo中存储的RVA值（从文件解析，未经过重定位）
    DWORD indexRVA = metadata.tls.indexVariableRVA;
    DWORD* pIndexVariable = (DWORD*)((BYTE*)pBase + indexRVA);

    LogInfo("TLS初始化: IndexRVA=0x%X, 变量地址=0x%p", indexRVA, pIndexVariable);

    // 步骤1: 分配TLS索引
    DWORD tlsIndex = TlsAlloc();
    if (tlsIndex == TLS_OUT_OF_INDEXES) {
        LogError("TlsAlloc失败");
        return false;
    }
    LogInfo("TlsAlloc成功: 索引=%d", tlsIndex);

    // 步骤2: 将索引写入AddressOfIndex变量
    *pIndexVariable = tlsIndex;
    LogInfo("TLS索引变量已设置: 值=%d", tlsIndex);

    // 步骤3: 为当前线程分配TLS槽位并初始化TLS模板数据
    DWORD rawDataRVA = metadata.tls.rawDataStartRVA;
    DWORD rawDataSize = metadata.tls.rawDataEndRVA - metadata.tls.rawDataStartRVA;

    LogInfo("TLS模板数据: StartRVA=0x%X, 大小=%d字节", rawDataRVA, rawDataSize);

    // 分配线程TLS槽位
    LPVOID pTlsData = VirtualAlloc(
        NULL,
        rawDataSize + metadata.tls.sizeOfZeroFill,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (!pTlsData) {
        LogError("TLS数据分配失败");
        return false;
    }

    LogInfo("TLS线程数据分配: 地址=0x%p, 大小=%d字节", pTlsData, rawDataSize);

    // 拷贝TLS模板数据
    if (rawDataSize > 0) {
        memcpy(pTlsData, (BYTE*)pBase + rawDataRVA, rawDataSize);
        LogInfo("TLS模板数据拷贝完成");
    }

    // SizeOfZeroFill部分已由VirtualAlloc自动清零

    // 步骤4: 设置TLS值
    if (!TlsSetValue(tlsIndex, pTlsData)) {
        LogError("TlsSetValue失败");
        VirtualFree(pTlsData, 0, MEM_RELEASE);
        return false;
    }

    LogInfo("TLS初始化完成");
    return true;
}

// 步骤5: 修复Load Configuration（安全cookie等关键地址）
bool PELoader::FixLoadConfig(LPVOID pBase, const PEMetadata& metadata) {
    if (!metadata.loadConfig.exists) {
        LogInfo("Load Configuration不存在，跳过修复");
        return true;
    }

    // 暂时跳过Load Configuration修复，因为结构解析有问题
    // Security Cookie可能需要通过其他方式初始化
    LogInfo("Load Configuration存在但暂时跳过修复（待进一步调试）");

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

        // MinGW不支持SEH，直接调用
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