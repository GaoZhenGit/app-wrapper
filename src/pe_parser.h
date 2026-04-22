#pragma once
#include <windows.h>
#include <vector>
#include <string>

// 节区信息
struct SectionInfo {
    DWORD virtualAddress;     // 内存RVA
    DWORD sizeOfRawData;      // 文件大小
    DWORD pointerToRawData;   // 文件偏移
    DWORD characteristics;    // 属性标志
};

// 导入表信息
struct ImportTableInfo {
    bool exists;
    DWORD rva;
    DWORD size;
    std::vector<std::string> dllNames; // DLL名称列表（可选，用于日志）
};

// TLS信息
struct TLSInfo {
    bool exists;
    std::vector<DWORD> callbackRVAs; // TLS回调函数RVA列表
    DWORD indexVariableRVA;          // TLS索引变量RVA（从文件解析）
    DWORD rawDataStartRVA;           // TLS模板数据起始RVA（新增）
    DWORD rawDataEndRVA;             // TLS模板数据结束RVA（新增）
    DWORD sizeOfZeroFill;            // TLS零填充大小（新增）
};

// 异常处理信息
struct ExceptionInfo {
    bool exists;
    DWORD rva;
    DWORD size;
};

// Load Configuration信息
struct LoadConfigInfo {
    bool exists;
    DWORD rva;
    DWORD size;
};

// 重定位信息
struct RelocationInfo {
    bool exists;
    DWORD rva;
    DWORD size;
};

// 延迟导入信息
struct DelayImportInfo {
    bool exists;
    DWORD rva;
    DWORD size;
};

// PE元数据
struct PEMetadata {
    bool isValid;
    WORD numberOfSections;
    DWORD sizeOfImage;
    DWORD sizeOfHeaders;
    ULONGLONG imageBase;
    DWORD entryPointRVA;

    std::vector<SectionInfo> sections;
    ImportTableInfo importTable;
    RelocationInfo relocation;
    TLSInfo tls;
    ExceptionInfo exception;
    LoadConfigInfo loadConfig;
    DelayImportInfo delayImport; // 新增
};

class PEParser {
public:
    // 解析PE文件（原始二进制数据）
    static PEMetadata Parse(PBYTE pRawData, DWORD rawSize);

private:
    // 内部验证步骤
    static bool ValidatePE(PBYTE pRawData);
    static void ExtractSections(PBYTE pRawData, PEMetadata& metadata);
    static void ExtractDataDirectories(PBYTE pRawData, PEMetadata& metadata);
    static void ExtractTLS(PBYTE pRawData, DWORD rawSize, PEMetadata& metadata);
    static void ExtractException(PBYTE pRawData, PEMetadata& metadata);
    static void ExtractLoadConfig(PBYTE pRawData, PEMetadata& metadata); // 新增
};