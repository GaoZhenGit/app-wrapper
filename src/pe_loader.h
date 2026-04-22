#pragma once
#include <windows.h>
#include "pe_parser.h"

class PELoader {
public:
    // 加载PE到内存（返回内存基址）
    static LPVOID Load(PBYTE pRawData, const PEMetadata& metadata);

private:
    // 内部加载步骤
    static LPVOID AllocateMemory(const PEMetadata& metadata);
    static bool MapHeaders(LPVOID pBase, PBYTE pRawData, const PEMetadata& metadata);
    static bool MapSections(LPVOID pBase, PBYTE pRawData, const PEMetadata& metadata);
    static bool FixImports(LPVOID pBase, const PEMetadata& metadata);
    static bool FixDelayImports(LPVOID pBase, const PEMetadata& metadata); // 新增
    static bool FixRelocations(LPVOID pBase, const PEMetadata& metadata);
    static bool FixLoadConfig(LPVOID pBase, const PEMetadata& metadata);
    static bool InitializeTLS(LPVOID pBase, const PEMetadata& metadata);
    static bool ExecuteTLSCallbacks(LPVOID pBase, const PEMetadata& metadata);
    static bool RegisterExceptionTable(LPVOID pBase, const PEMetadata& metadata);
};