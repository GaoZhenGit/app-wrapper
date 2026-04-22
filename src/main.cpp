#include <windows.h>
#include "logger.h"
#include "pe_parser.h"
#include "pe_loader.h"
#include "executor.h"

// 从资源加载内嵌EXE
PBYTE LoadResourceExe(DWORD& outSize) {
    HMODULE hModule = GetModuleHandleA(NULL);
    HRSRC hRes = FindResourceA(hModule, MAKEINTRESOURCEA(1001), RT_RCDATA);
    if (!hRes) {
        LogError("查找资源失败: ID=1001");
        return NULL;
    }

    HGLOBAL hGlobal = LoadResource(hModule, hRes);
    if (!hGlobal) {
        LogError("加载资源失败");
        return NULL;
    }

    outSize = SizeofResource(hModule, hRes);
    PBYTE pRaw = (PBYTE)LockResource(hGlobal);
    LogInfo("资源加载成功: 大小=%dKB", outSize / 1024);
    return pRaw;
}

int main(int argc, char** argv) {
    LogInit();

    LogInfo("wrapper.exe启动: argc=%d", argc);
    for (int i = 0; i < argc; i++) {
        LogInfo("参数[%d]: %s", i, argv[i]);
    }

    // 1. 从资源加载claude.exe
    DWORD rawSize = 0;
    PBYTE pRaw = LoadResourceExe(rawSize);
    if (!pRaw) {
        LogError("资源加载失败");
        LogClose();
        return 1;
    }

    // 2. 解析PE结构
    PEMetadata metadata = PEParser::Parse(pRaw, rawSize);
    if (!metadata.isValid) {
        LogError("PE解析失败");
        LogClose();
        return 1;
    }

    // 3. 加载PE到内存（映射+修复）
    LPVOID pBase = PELoader::Load(pRaw, metadata);
    if (!pBase) {
        LogError("PE加载失败");
        LogClose();
        return 1;
    }

    // 4. 启用VT序列（可选）
    Executor::EnableVTSequence();

    // 修改argv[0]为claude.exe路径（被加载程序期望）
    // argv数组需要保持，但argv[0]改为claude.exe路径
    char** modified_argv = argv;
    modified_argv[0] = "claude.exe"; // 临时修改argv[0]

    // 5. 执行入口点（进入交互运行态）
    if (!Executor::Execute(pBase, metadata.entryPointRVA, argc, modified_argv)) {
        LogError("入口点执行失败");
        LogClose();
        return 1;
    }

    // 6. 程序自然退出（入口点调用ExitProcess或return）
    LogInfo("wrapper.exe正常退出");
    LogClose();
    return 0;
}