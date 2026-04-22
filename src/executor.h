#pragma once
#include <windows.h>

class Executor {
public:
    // 启用VT序列支持
    static bool EnableVTSequence();

    // 执行入口点（进入交互运行态）
    static bool Execute(LPVOID pBase, DWORD entryPointRVA, int argc, char** argv);
};