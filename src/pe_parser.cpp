#include "pe_parser.h"
#include "logger.h"

bool PEParser::ValidatePE(PBYTE pRawData) {
    // 检查DOS头魔数MZ
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pRawData;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) {
        LogError("PE验证失败: DOS头魔数无效 (期望0x%04X, 实际0x%04X)",
                 IMAGE_DOS_SIGNATURE, pDos->e_magic);
        return false;
    }

    // 检查NT头签名PE\0\0
    PIMAGE_NT_HEADERS64 pNt = (PIMAGE_NT_HEADERS64)(pRawData + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) {
        LogError("PE验证失败: NT头签名无效 (期望0x%08X, 实际0x%08X)",
                 IMAGE_NT_SIGNATURE, pNt->Signature);
        return false;
    }

    // 验证64位PE32+格式
    if (pNt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        LogError("PE验证失败: 非64位程序 (Machine=0x%04X)", pNt->FileHeader.Machine);
        return false;
    }

    LogInfo("PE验证成功: 64位PE32+程序");
    return true;
}

PEMetadata PEParser::Parse(PBYTE pRawData, DWORD rawSize) {
    PEMetadata metadata;
    metadata.isValid = false;

    // 基础验证
    if (!ValidatePE(pRawData)) {
        return metadata;
    }

    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pRawData;
    PIMAGE_NT_HEADERS64 pNt = (PIMAGE_NT_HEADERS64)(pRawData + pDos->e_lfanew);

    // 提取基础信息
    metadata.isValid = true;
    metadata.numberOfSections = pNt->FileHeader.NumberOfSections;
    metadata.sizeOfImage = pNt->OptionalHeader.SizeOfImage;
    metadata.sizeOfHeaders = pNt->OptionalHeader.SizeOfHeaders;
    metadata.imageBase = pNt->OptionalHeader.ImageBase;
    metadata.entryPointRVA = pNt->OptionalHeader.AddressOfEntryPoint;

    LogInfo("PE基础信息: 节数=%d, SizeOfImage=%dKB, ImageBase=0x%llx, EntryPointRVA=0x%X",
            metadata.numberOfSections,
            metadata.sizeOfImage / 1024,
            metadata.imageBase,
            metadata.entryPointRVA);

    // 提取节区信息
    ExtractSections(pRawData, metadata);

    // 提取数据目录
    ExtractDataDirectories(pRawData, metadata);

    // 提取TLS详情
    ExtractTLS(pRawData, rawSize, metadata);

    // 提取异常处理详情
    ExtractException(pRawData, metadata);

    // 提取Load Configuration详情
    ExtractLoadConfig(pRawData, metadata);

    return metadata;
}

void PEParser::ExtractSections(PBYTE pRawData, PEMetadata& metadata) {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pRawData;
    PIMAGE_NT_HEADERS64 pNt = (PIMAGE_NT_HEADERS64)(pRawData + pDos->e_lfanew);
    PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);

    for (WORD i = 0; i < metadata.numberOfSections; i++) {
        SectionInfo sec;
        sec.virtualAddress = pSec[i].VirtualAddress;
        sec.sizeOfRawData = pSec[i].SizeOfRawData;
        sec.pointerToRawData = pSec[i].PointerToRawData;
        sec.characteristics = pSec[i].Characteristics;
        metadata.sections.push_back(sec);

        // 提取节名（最多8字节）
        char secName[9] = {0};
        memcpy(secName, pSec[i].Name, 8);
        LogInfo("节区[%d]: 名称=%s, VA=0x%X, Size=%d字节, Offset=0x%X, Attr=0x%X",
                i, secName, sec.virtualAddress, sec.sizeOfRawData,
                sec.pointerToRawData, sec.characteristics);
    }
}

void PEParser::ExtractDataDirectories(PBYTE pRawData, PEMetadata& metadata) {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pRawData;
    PIMAGE_NT_HEADERS64 pNt = (PIMAGE_NT_HEADERS64)(pRawData + pDos->e_lfanew);

    // 导入表 (索引1)
    DWORD importRVA = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    DWORD importSize = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    metadata.importTable.exists = (importRVA != 0);
    metadata.importTable.rva = importRVA;
    metadata.importTable.size = importSize;
    LogInfo("导入表: 存在=%d, RVA=0x%X, Size=%d字节",
            metadata.importTable.exists, importRVA, importSize);

    // 重定位表 (索引5)
    DWORD relocRVA = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    DWORD relocSize = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    metadata.relocation.exists = (relocRVA != 0);
    metadata.relocation.rva = relocRVA;
    metadata.relocation.size = relocSize;
    LogInfo("重定位表: 存在=%d, RVA=0x%X, Size=%d字节",
            metadata.relocation.exists, relocRVA, relocSize);

    // TLS表 (索引9)
    DWORD tlsRVA = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
    DWORD tlsSize = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size;
    metadata.tls.exists = (tlsRVA != 0);
    LogInfo("TLS表: 存在=%d, RVA=0x%X, Size=%d字节",
            metadata.tls.exists, tlsRVA, tlsSize);

    // 异常处理表 (索引3)
    DWORD exceptionRVA = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
    DWORD exceptionSize = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;
    metadata.exception.exists = (exceptionRVA != 0);
    metadata.exception.rva = exceptionRVA;
    metadata.exception.size = exceptionSize;
    LogInfo("异常处理表: 存在=%d, RVA=0x%X, Size=%d字节",
            metadata.exception.exists, exceptionRVA, exceptionSize);

    // Load Configuration表 (索引10)
    DWORD loadConfigRVA = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress;
    DWORD loadConfigSize = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size;
    metadata.loadConfig.exists = (loadConfigRVA != 0);
    metadata.loadConfig.rva = loadConfigRVA;
    metadata.loadConfig.size = loadConfigSize;
    LogInfo("Load Configuration表: 存在=%d, RVA=0x%X, Size=%d字节",
            metadata.loadConfig.exists, loadConfigRVA, loadConfigSize);

    // 延迟导入表 (索引13)
    DWORD delayImportRVA = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress;
    DWORD delayImportSize = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size;
    metadata.delayImport.exists = (delayImportRVA != 0);
    metadata.delayImport.rva = delayImportRVA;
    metadata.delayImport.size = delayImportSize;
    LogInfo("延迟导入表: 存在=%d, RVA=0x%X, Size=%d字节",
            metadata.delayImport.exists, delayImportRVA, delayImportSize);
}

void PEParser::ExtractTLS(PBYTE pRawData, DWORD rawSize, PEMetadata& metadata) {
    if (!metadata.tls.exists) return;

    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pRawData;
    PIMAGE_NT_HEADERS64 pNt = (PIMAGE_NT_HEADERS64)(pRawData + pDos->e_lfanew);

    DWORD tlsRVA = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;

    // 将TLS目录RVA转换为文件偏移
    DWORD tlsFileOffset = 0;
    PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
    for (WORD i = 0; i < metadata.numberOfSections; i++) {
        DWORD secStart = pSec[i].VirtualAddress;
        DWORD secEnd = secStart + pSec[i].SizeOfRawData;
        if (tlsRVA >= secStart && tlsRVA < secEnd) {
            tlsFileOffset = tlsRVA - secStart + pSec[i].PointerToRawData;
            break;
        }
    }

    if (tlsFileOffset == 0) {
        LogError("TLS目录RVA无法转换为文件偏移: RVA=0x%X", tlsRVA);
        return;
    }

    PIMAGE_TLS_DIRECTORY64 pTls = (PIMAGE_TLS_DIRECTORY64)(pRawData + tlsFileOffset);

    // 提取TLS模板数据字段（从文件数据，转换为RVA）
    ULONGLONG rawDataStartVA = pTls->StartAddressOfRawData;
    ULONGLONG rawDataEndVA = pTls->EndAddressOfRawData;

    if (rawDataStartVA >= pNt->OptionalHeader.ImageBase) {
        metadata.tls.rawDataStartRVA = (DWORD)(rawDataStartVA - pNt->OptionalHeader.ImageBase);
    } else {
        metadata.tls.rawDataStartRVA = (DWORD)rawDataStartVA;
    }

    if (rawDataEndVA >= pNt->OptionalHeader.ImageBase) {
        metadata.tls.rawDataEndRVA = (DWORD)(rawDataEndVA - pNt->OptionalHeader.ImageBase);
    } else {
        metadata.tls.rawDataEndRVA = (DWORD)rawDataEndVA;
    }

    metadata.tls.sizeOfZeroFill = (DWORD)pTls->SizeOfZeroFill;

    // 提取TLS索引变量RVA
    ULONGLONG indexVA = pTls->AddressOfIndex;
    if (indexVA >= pNt->OptionalHeader.ImageBase) {
        metadata.tls.indexVariableRVA = (DWORD)(indexVA - pNt->OptionalHeader.ImageBase);
    } else {
        metadata.tls.indexVariableRVA = (DWORD)indexVA;
    }

    LogInfo("TLS目录: StartRVA=0x%X, EndRVA=0x%X, IndexRVA=0x%X, ZeroFill=%d",
            metadata.tls.rawDataStartRVA, metadata.tls.rawDataEndRVA,
            metadata.tls.indexVariableRVA, metadata.tls.sizeOfZeroFill);

    // 提取回调函数数组（AddressOfCallBacks是VA，需要转换为文件偏移）
    ULONGLONG callbackArrayVA = pTls->AddressOfCallBacks;

    // 检查VA是否有效
    if (callbackArrayVA == 0) {
        LogInfo("TLS目录: 无回调函数数组");
        return;
    }

    // 计算回调数组在文件中的偏移
    // VA可能在ImageBase范围内，也可能已经是RVA
    ULONGLONG callbackArrayRVA;
    if (callbackArrayVA >= pNt->OptionalHeader.ImageBase) {
        callbackArrayRVA = callbackArrayVA - pNt->OptionalHeader.ImageBase;
    } else {
        // AddressOfCallBacks可能已经是RVA形式
        callbackArrayRVA = callbackArrayVA;
    }

    // 安全检查：确保RVA在合理范围内
    if (callbackArrayRVA > rawSize) {
        LogError("TLS回调数组RVA超出文件范围: RVA=0x%llX, 文件大小=%d", callbackArrayRVA, rawSize);
        return;
    }

    // 将回调数组RVA转换为文件偏移
    DWORD callbackArrayFileOffset = 0;
    for (WORD i = 0; i < metadata.numberOfSections; i++) {
        DWORD secStart = pSec[i].VirtualAddress;
        DWORD secEnd = secStart + pSec[i].SizeOfRawData;
        if (callbackArrayRVA >= secStart && callbackArrayRVA < secEnd) {
            callbackArrayFileOffset = (DWORD)(callbackArrayRVA - secStart + pSec[i].PointerToRawData);
            break;
        }
    }

    if (callbackArrayFileOffset == 0) {
        LogError("TLS回调数组RVA无法转换为文件偏移: RVA=0x%llX", callbackArrayRVA);
        return;
    }

    PULONGLONG pCallbacks = (PULONGLONG)(pRawData + callbackArrayFileOffset);

    LogInfo("TLS目录: CallbackArrayVA=0x%llX, CallbackArrayFileOffset=0x%X", callbackArrayVA, callbackArrayFileOffset);

    // 首先检查第一个回调值是否有效
    if (pCallbacks[0] != 0) {
        ULONGLONG firstCallbackVA = pCallbacks[0];
        // 有效的回调VA应该在ImageBase到ImageBase+SizeOfImage范围内
        ULONGLONG imageEndVA = pNt->OptionalHeader.ImageBase + pNt->OptionalHeader.SizeOfImage;
        if (firstCallbackVA < pNt->OptionalHeader.ImageBase || firstCallbackVA >= imageEndVA) {
            LogInfo("TLS回调数组第一个值无效（不在映像范围内），跳过回调执行: VA=0x%llX", firstCallbackVA);
            return;
        }
    }

    // 遍历回调数组（以NULL结尾）
    int callbackCount = 0;
    int maxCallbacks = 100; // 防止无限循环的安全限制
    while (pCallbacks[callbackCount] != 0 && callbackCount < maxCallbacks) {
        ULONGLONG callbackVA = pCallbacks[callbackCount];

        // 转换VA到RVA
        DWORD callbackRVA;
        if (callbackVA >= pNt->OptionalHeader.ImageBase) {
            callbackRVA = (DWORD)(callbackVA - pNt->OptionalHeader.ImageBase);
        } else {
            callbackRVA = (DWORD)callbackVA;
        }

        metadata.tls.callbackRVAs.push_back(callbackRVA);
        LogInfo("TLS回调[%d]: VA=0x%llX, RVA=0x%X", callbackCount, callbackVA, callbackRVA);
        callbackCount++;
    }

    LogInfo("TLS回调总数: %d", callbackCount);
}

void PEParser::ExtractException(PBYTE pRawData, PEMetadata& metadata) {
    if (!metadata.exception.exists) return;

    // 计算异常处理函数数量
    DWORD entryCount = metadata.exception.size / sizeof(RUNTIME_FUNCTION);
    LogInfo("异常处理函数数量: %d", entryCount);

    // 实际的函数表内容在PELoader阶段使用，这里只记录存在性
}

void PEParser::ExtractLoadConfig(PBYTE pRawData, PEMetadata& metadata) {
    if (!metadata.loadConfig.exists) return;

    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pRawData;
    PIMAGE_NT_HEADERS64 pNt = (PIMAGE_NT_HEADERS64)(pRawData + pDos->e_lfanew);

    PIMAGE_LOAD_CONFIG_DIRECTORY64 pLoadConfig = (PIMAGE_LOAD_CONFIG_DIRECTORY64)(pRawData + metadata.loadConfig.rva);

    // SecurityCookie字段在结构体中，需要重定位
    LogInfo("Load Configuration: Size=%d, SecurityCookie=0x%llX",
            pLoadConfig->Size, pLoadConfig->SecurityCookie);

    // 注意：SecurityCookie字段需要重定位
    // 这些字段在PELoader阶段处理
}