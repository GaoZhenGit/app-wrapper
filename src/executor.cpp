#include "executor.h"
#include "logger.h"

bool Executor::EnableVTSequence() {
    HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hStdOut == INVALID_HANDLE_VALUE) {
        LogInfo("VT序列启用失败: 无法获取stdout句柄");
        return false;
    }

    DWORD mode = 0;
    if (!GetConsoleMode(hStdOut, &mode)) {
        LogInfo("VT序列启用失败: 无法获取控制台模式");
        return false;
    }

    mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    if (!SetConsoleMode(hStdOut, mode)) {
        LogInfo("VT序列启用失败: 系统不支持（Windows 10+可用）");
        return false;
    }

    LogInfo("VT序列启用成功: 支持ANSI控制码");
    return true;
}

bool Executor::Execute(LPVOID pBase, DWORD entryPointRVA) {
    typedef void(*ENTRY_POINT)();
    ENTRY_POINT entry = (ENTRY_POINT)((BYTE*)pBase + entryPointRVA);

    LogInfo("准备调用入口点: RVA=0x%X, 地址=0x%p", entryPointRVA, entry);

    // MinGW不支持SEH，直接调用
    // 如果崩溃则程序终止，日志会有记录
    entry(); // 直接调用，不传参数（CRT Startup自行处理）

    LogInfo("入口点执行完成");
    return true;
}