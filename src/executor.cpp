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

bool Executor::Execute(LPVOID pBase, DWORD entryPointRVA, int argc, char** argv) {
    // Rust程序的entry point是mainCRTStartup，它会自己初始化C runtime并获取命令行
    // 所以我们不应该传递参数，而是让entry point自己处理

    typedef void(__cdecl* ENTRY_POINT)();
    ENTRY_POINT entry = (ENTRY_POINT)((BYTE*)pBase + entryPointRVA);

    LogInfo("准备调用入口点: RVA=0x%X, 地址=0x%p", entryPointRVA, entry);
    LogInfo("注意: Rust entry point (mainCRTStartup) 会自己从GetCommandLineW获取参数");

    // x64 ABI要求栈必须16字节对齐
    // 检查当前栈对齐状态
    ULONG_PTR stackAddr = (ULONG_PTR)&argc;
    ULONG_PTR alignment = stackAddr % 16;
    LogInfo("当前栈地址: 0x%p, 对齐状态: %d字节偏移", stackAddr, alignment);

    LogInfo("开始调用入口点（无参数）...");

    // 直接调用，不传递参数（entry point会自己获取命令行）
    entry();

    LogInfo("入口点执行完成");
    return true;
}