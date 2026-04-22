#include "logger.h"
#include <windows.h>

FILE* g_logFile = NULL;

void LogInit() {
    // 创建logs目录（如果已存在会失败，忽略）
    CreateDirectoryA("logs", NULL);

    // 生成带时间戳的文件名
    SYSTEMTIME st;
    GetLocalTime(&st);
    char filename[256];
    sprintf(filename, "logs/wrapper_%04d%02d%02d_%02d%02d%02d.log",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

    // 打开文件
    g_logFile = fopen(filename, "w");
    if (g_logFile) {
        LogInfo("日志系统初始化成功: %s", filename);
    }
}

void LogInfo(const char* format, ...) {
    if (!g_logFile) return;

    // 获取当前时间
    SYSTEMTIME st;
    GetLocalTime(&st);

    // 写时间戳和级别
    fprintf(g_logFile, "[%04d-%02d-%02d %02d:%02d:%02d] INFO  ",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

    // 写具体内容
    va_list args;
    va_start(args, format);
    vfprintf(g_logFile, format, args);
    va_end(args);

    fprintf(g_logFile, "\n");
    fflush(g_logFile); // 立即刷新，确保崩溃时也有日志
}

void LogError(const char* format, ...) {
    SYSTEMTIME st;
    GetLocalTime(&st);

    // 写文件
    if (g_logFile) {
        fprintf(g_logFile, "[%04d-%02d-%02d %02d:%02d:%02d] ERROR ",
                st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
        va_list args;
        va_start(args, format);
        vfprintf(g_logFile, format, args);
        va_end(args);
        fprintf(g_logFile, "\n");
        fflush(g_logFile);
    }

    // 同时输出控制台（用户可见）
    printf("[%04d-%02d-%02d %02d:%02d:%02d] ERROR ",
           st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    printf("\n");
}

void LogClose() {
    if (g_logFile) {
        LogInfo("日志系统关闭");
        fclose(g_logFile);
        g_logFile = NULL;
    }
}